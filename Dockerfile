FROM python:3.9-slim

# Установка зависимостей для scapy и libpcap
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libcap2-bin \
    libpcap0.8 \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем requirements.txt и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект
COPY . .

# Ожидаем, что server.py будет запускаться при старте контейнера
CMD ["python", "server/server.py"]
