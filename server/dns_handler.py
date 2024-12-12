import logging
from cryptography.fernet import Fernet
import base64
import time

# Настройка логирования
logger = logging.getLogger(__name__)

# Конфигурация шифрования
ENCRYPTION_KEY = b'Mwj6yHtnmR5BfENEbQAGFFbSdQJ5OHh6OPUH_pIwmlA='  # Должно быть 32 байта
cipher = Fernet(ENCRYPTION_KEY)

# Простая реализация кеша
cache = {}

# Лимит запросов (например, 10 запросов в минуту)
request_limits = {}

# Функция для создания DNS-ответа
def create_dns_response(request_id, response_data):
    """
    Формирует DNS-ответ с переданными данными.
    """
    response = request_id  # Используем тот же ID, что и в запросе
    response += b"\x81\x80"  # Флаги ответа (стандартный ответ)
    response += b"\x00\x01"  # Количество вопросов
    response += b"\x00\x01"  # Количество ответов
    response += b"\x00\x00"  # Количество authority RRs
    response += b"\x00\x00"  # Количество additional RRs
    response += b"\xc0\x0c"  # Указатель на домен (смещение 12 байт)
    response += b"\x00\x01"  # Тип A (запись IPv4)
    response += b"\x00\x01"  # Класс IN (Internet)
    response += b"\x00\x00\x00\x3c"  # TTL (60 секунд)
    
    # Мы не преобразуем в IP-адрес, а просто передаем данные как есть
    response += base64.urlsafe_b64encode(response_data.encode('utf-8'))  # Кодируем строку как base64
    
    return response

# Функция для извлечения имени домена из запроса
def extract_domain(data):
    """
    Извлекает домен из DNS-запроса
    """
    domain = []
    offset = 12  # Смещение имени домена начинается после заголовка
    while True:
        length = data[offset]
        if length == 0:  # Конец имени домена
            break
        offset += 1
        if offset + length > len(data):  # Проверка выхода за пределы данных
            raise ValueError("DNS query is malformed or too short")
        domain.append(data[offset:offset + length])
        offset += length
    return b'.'.join(domain).decode('ascii'), offset + 1

# Проверка лимита запросов
def check_request_limit(addr):
    """
    Проверяет, не превышен ли лимит запросов с данного адреса
    """
    current_time = time.time()
    if addr not in request_limits:
        request_limits[addr] = []
    
    # Очищаем старые записи (больше 60 секунд назад)
    request_limits[addr] = [timestamp for timestamp in request_limits[addr] if current_time - timestamp < 60]
    
    # Добавляем текущий запрос
    request_limits[addr].append(current_time)
    
    # Проверяем лимит (например, 10 запросов в минуту)
    return len(request_limits[addr]) <= 10

# Функция для обработки DNS-запросов
def handle_dns_request(data, addr, sock):
    """
    Обрабатывает входящий DNS-запрос
    """
    logger.info(f"Received DNS query from {addr}")
    request_id = data[:2]

    try:
        # Проверка лимита запросов
        if not check_request_limit(addr):
            logger.warning(f"Request limit exceeded from {addr}")
            response = create_dns_response(request_id, "127.0.0.1")  # Возвращаем стандартный ответ
            sock.sendto(response, addr)
            return

        # Извлечение имени домена
        domain, _ = extract_domain(data)
        logger.info(f"Received DNS query for domain: {domain}")
        
        # Проверка наличия кэша
        if domain in cache:
            vpn_data = cache[domain]
        else:
            # Расшифровка данных (первый сегмент домена содержит зашифрованные данные)
            encrypted_data = domain.split('.')[0]
            vpn_data = cipher.decrypt(base64.urlsafe_b64decode(encrypted_data)).decode('utf-8')
            cache[domain] = vpn_data  # Кэшируем данные
        logger.info(f"Decrypted VPN data: {vpn_data}")
        
        # Мы возвращаем расшифрованные VPN-данные, но не как IP-адрес
        response = create_dns_response(request_id, vpn_data)  # Возвращаем строку VPN-данных
        sock.sendto(response, addr)
    except ValueError as e:
        logger.warning(f"Malformed DNS query: {e}")
        response = create_dns_response(request_id, "127.0.0.1")  # Стандартный ответ на ошибку
        sock.sendto(response, addr)
    except Exception as e:
        logger.warning(f"Error processing request: {e}")
        response = create_dns_response(request_id, "127.0.0.1")  # Стандартный ответ на ошибку
        sock.sendto(response, addr)

