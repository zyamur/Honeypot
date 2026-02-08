import socket
import sqlite3
from datetime import datetime

# --- Ayarlar ---
HOST = '0.0.0.0'
PORT = 5000
DB_FILE = 'honeypot_advanced.db'

def init_db():
    """İlişkisel veri tabanı yapısını oluşturur."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # 1. Tablo: Ana saldırı oturumları
    cursor.execute('''CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip_address TEXT,
        username TEXT,
        password TEXT
    )''')
    # 2. Tablo: Saldırganın girdiği komutlar (İlişkisel)
    cursor.execute('''CREATE TABLE IF NOT EXISTS command_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_id INTEGER,
        command TEXT,
        timestamp TEXT,
        FOREIGN KEY(attack_id) REFERENCES attacks(id)
    )''')
    conn.commit()
    conn.close()

def save_attack(ip, user, pwd):
    """Saldırı özetini kaydeder ve oturum ID'sini döner."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO attacks (timestamp, ip_address, username, password) VALUES (?, ?, ?, ?)", 
                   (ts, ip, user, pwd))
    attack_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return attack_id

def save_command(attack_id, cmd):
    """Saldırganın girdiği her komutu ilgili oturuma bağlayarak kaydeder."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO command_history (attack_id, command, timestamp) VALUES (?, ?, ?)", 
                   (attack_id, cmd, ts))
    conn.commit()
    conn.close()

def read_line_from_socket(conn):
    """Karakterlerin çift basılmasını engeller ve silme işlemini yönetir."""
    buffer = []
    while True:
        try:
            data = conn.recv(1)
            if not data or data == b'\n':
                break
            if data == b'\r':
                continue
            
            # Silme (Backspace/Delete) işlemi
            if data in [b'\x08', b'\x7f']:
                if len(buffer) > 0:
                    buffer.pop()
                    # Terminalde görsel silme için bu komut ŞART:
                    conn.sendall(b'\b \b')
                continue
                
            # KRİTİK DEĞİŞİKLİK: conn.sendall(data) satırı kaldırıldı!
            # Sadece tampona ekliyoruz, geri göndermiyoruz (yankı yapmıyoruz).
            buffer.append(data.decode('utf-8', 'ignore'))
            
        except:
            break
    
    clean_text = "".join(filter(lambda x: 32 <= ord(x) <= 126, "".join(buffer)))
    return clean_text.strip()

def handle_connection(conn, addr):
    attacker_ip = addr[0]
    print(f"[*] Yeni bağlantı: {attacker_ip}")

    try:
        conn.settimeout(120.0) # Etkileşim süresi
        # \r\n kullanımı Telnet istemcilerinde doğru hizalama sağlar
        conn.sendall(b"Debian GNU/Linux 11 (bullseye)\r\n\r\nLogin: ")
        username = read_line_from_socket(conn)
        
        conn.sendall(b"Password: ")
        password = read_line_from_socket(conn)
        
        # Giriş verilerini ana tabloya kaydet
        attack_id = save_attack(attacker_ip, username, password)
        print(f"[+] Oturum Başladı (ID: {attack_id}): {username} / {password}")

        # Sahte terminal karşılama mesajı
        conn.sendall(f"\r\nLast login: {datetime.now().strftime('%a %b %d %H:%M:%S')} from 192.168.1.105\r\n".encode())
        
        while True:
            # Komut istemi (Prompt)
            prompt = f"{username}@debian-server:~$ ".encode()
            conn.sendall(prompt)
            
            cmd = read_line_from_socket(conn).lower()
            
            if not cmd:
                continue
            
            # Komutu veritabanına kaydet
            save_command(attack_id, cmd)
            print(f"    [ID:{attack_id}] Komut: {cmd}")

            if cmd in ["exit", "logout", "quit"]:
                conn.sendall(b"Logout\r\n")
                break
            elif cmd == "ls":
                conn.sendall(b"conf  etc  home  secret_credentials.txt  backup.sql\r\n")
            elif cmd == "whoami":
                conn.sendall(f"{username}\r\n".encode())
            elif cmd == "pwd":
                conn.sendall(b"/home/remote_user\r\n")
            elif cmd == "help":
                conn.sendall(b"Available: ls, pwd, whoami, uname, help, exit\r\n")
            elif cmd == "uname":
                conn.sendall(b"Linux debian-server 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4\r\n")
            else:
                conn.sendall(f"bash: {cmd}: command not found\r\n".encode())

    except Exception as e:
        print(f"!!! Bağlantı koptu ({attacker_ip}): {e}")
    finally:
        conn.close()

def main():
    init_db()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[!] Honeypot AKTİF. Port: {PORT} | Veri tabanı: {DB_FILE}")

        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)

if __name__ == "__main__":
    main()