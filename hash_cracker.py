import crypt
import subprocess

def get_password_hash(username):
    """ Extract the password hash of a given user from /etc/shadow """
    try:
        output = subprocess.check_output(['sudo', 'cat', '/etc/shadow'], text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error accessing /etc/shadow: {e}")
        return None

    for line in output.splitlines():
        if line.startswith(username + ":"):
            parts = line.split(":")
            hash_value = parts[1]
            if hash_value in ['*', '!', '']:  # Account locked or no password
                print(f"[!] No password set or account locked for user: {username}")
                return None
            return hash_value
    print(f"[!] User not found: {username}")
    return None

def crack_password(hash_value, wordlist_file):
    """ Attempt to crack the hash using a wordlist """
    salt = "$".join(hash_value.split("$")[:3])  # Extract $id$salt format

    try:
        with open(wordlist_file, 'r', encoding='utf-8') as file:
            passwords = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist_file}")
        return None

    print(f"[+] Loaded {len(passwords)} passwords. Starting brute-force...")

    for password in passwords:
        hashed_attempt = crypt.crypt(password, salt)
        if hashed_attempt == hash_value:
            return password
    return None

if __name__ == "__main__":
    username = input("Enter Kali username (e.g., root): ").strip()
    wordlist_file = input("Enter wordlist file path: ").strip()

    hash_value = get_password_hash(username)

    if hash_value:
        print(f"[+] Hash found: {hash_value}")
        result = crack_password(hash_value, wordlist_file)

        if result:
            print(f"\nPassword is: {result}")
        else:
            print("\n[-] Password not found in wordlist.")

#usage:
#sudo python3 hash_cracker.py
#Enter Kali username (e.g., root): root
#Enter wordlist file path: /usr/share/wordlists/rockyou.txt
#Password is: <password>
