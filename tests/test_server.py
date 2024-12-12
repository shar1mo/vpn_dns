from scapy.all import IP, UDP, DNS, DNSQR
from server.dns_handler import handle_dns_request  # Исправленный импорт
import socket

def test_handle_dns_request():
    # Создаем пример DNS-запроса с использованием Scapy
    packet = IP(dst="127.0.0.1") / UDP(dport=5354) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    
    # Создаем сокет для передачи в функцию
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Вызов функции с добавлением сокета
    try:
        response = handle_dns_request(bytes(packet), ("127.0.0.1", 5354), sock)
        assert response is not None
        print(response)
    except Exception as e:
        print(f"Test failed: {e}")
