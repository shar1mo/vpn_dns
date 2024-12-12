import socket
from cryptography.fernet import Fernet
import base64
import os

# Конфигурация клиента
SERVER_IP = "127.0.0.1"
DNS_PORT = 5354
ENCRYPTION_KEY = b'Mwj6yHtnmR5BfENEbQAGFFbSdQJ5OHh6OPUH_pIwmlA='  # Должно совпадать с серверным

# Генерация шифра
cipher = Fernet(ENCRYPTION_KEY)

# Функция для отправки DNS-запроса
def send_dns_query(vpn_data):
    # Шифрование данных
    encrypted_data = cipher.encrypt(vpn_data.encode())
    
    # Добавляем случайные байты (паддинг)
    padding_length = 16  # Длина шума
    padding = os.urandom(padding_length)  # Генерация случайных байтов
    
    # Объединяем зашифрованные данные с шумом
    obfuscated_data = encrypted_data + padding
    
    # Кодируем обфусцированные данные для отправки
    encoded_data = base64.urlsafe_b64encode(obfuscated_data).decode()

    # Формируем домен с зашифрованными данными
    domain = f"{encoded_data}.example.com"
    
    # Формируем DNS-запрос
    query = b'\xaa\xbb'  # ID запроса
    query += b"\x01\x00"  # Флаги (стандартный запрос)
    query += b"\x00\x01"  # Количество вопросов
    query += b"\x00\x00"  # Количество ответов
    query += b"\x00\x00"  # Количество authority RRs
    query += b"\x00\x00"  # Количество additional RRs
    query += b''.join(len(label).to_bytes(1, 'big') + label.encode() for label in domain.split('.'))
    query += b'\x00'  # Конец имени домена
    query += b"\x00\x01"  # Тип A
    query += b"\x00\x01"  # Класс IN
    
    # Отправка через UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (SERVER_IP, DNS_PORT))
    response, _ = sock.recvfrom(4096)
    return response

# Основная функция клиента
def main():
    print("Starting DNS VPN client...")
    vpn_data = "my_vpn_payload"
    response = send_dns_query(vpn_data)
    print(f"Received response: {response}")

if __name__ == "__main__":
    main()
