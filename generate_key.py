from cryptography.fernet import Fernet

# Генерация ключа
key = Fernet.generate_key()
print(f"Your encryption key: {key.decode()}")
