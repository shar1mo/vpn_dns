import socket
import logging
from dns_handler import handle_dns_request  # Импортируем функцию из нового файла

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Конфигурация сервера
DNS_IP = "0.0.0.0"  # Слушаем на всех интерфейсах
DNS_PORT = 5354     # Порт DNS

# Запуск сервера
def start_server():
    """
    Запуск DNS сервера
    """
    logger.info("Starting DNS VPN server...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DNS_IP, DNS_PORT))
    logger.info(f"Listening on {DNS_IP}:{DNS_PORT}")
    
    while True:
        data, addr = sock.recvfrom(4096)
        handle_dns_request(data, addr, sock)

if __name__ == "__main__":
    start_server()
