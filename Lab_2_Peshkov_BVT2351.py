import pandas as pd
import hashlib
import re
from cryptography.fernet import Fernet

file_path = "C:\Users\peshkov.s\Desktop\Учеба в МТУСИ\Проганье_4семак\Laptop_price.csv"
try:
    data_frame = pd.read_csv(file_path)
except Exception as e:
    print(f"Ошибка загрузки файла: {e}")


def check_csv_injection(data_frame):                                                # Проверка CSV на уязвимости. Добавлена проверка на пробелы
    dangerous_chars = ('=', '+', '-', '@')
    for collum in data_frame.select_dtypes(include=['object']).columns:
        if data_frame[collum].astype(str).apply(
            lambda x: x.startswith(dangerous_chars) or  
            x.lstrip().startswith(dangerous_chars)).any():
            print(f"Обнаружены потенциальные CSV-инъекции в столбце {collum}!")
        else:
            print(f"Столбец {collum} безопасен.")

check_csv_injection(data_frame)

def clean_input(value):                                                             # Фильтрация данных от SQL-инъекций и XSS-атак. Написана проверка на xss-атаки, добавлена проверка на SQL-комментарии
    sql_keys = ["SELECT", "DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "UNION", "--"]  
    xss_keys = [r'<script.*>,*></script>', r'javascript:.*', r'onerror=.*']

    for key in sql_keys:
        if key.lower() in value.lower():
            return "[BLOCKED_SQL]"

    for key in xss_keys:
        if re.search(key, value, re.IGNORECASE):
            return "[BLOCKED_XSS]"
    return value

data_frame = data_frame.map(lambda x: clean_input(str(x)) if isinstance(x, str) else x)
print("Фильтрация данных завершена.")

def hash_price(price):                                                              # Хеширование столбца с ценами.
    return hashlib.sha256(str(price).encode()).hexdigest()

data_frame['Price_hashed'] = data_frame['Price'].apply(hash_price)
print("Столбец с хешированными ценами добавлен.")

"""Шифрование цены ноутбуков."""
key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt_price(price):
    return cipher.encrypt(str(price).encode()).decode()

def decrypt_price(encrypted_price):
    return cipher.decrypt(encrypted_price.encode()).decode()

data_frame['Price_Encrypted'] = data_frame['Price'].apply(encrypt_price)
print("Столбец с зашифрованными ценами добавлен.")

def encrypt_ram_size(ram_size):                                                     # Шифрование значений RAM. Используется тот же ключ, что и для шифрования цен
        return cipher.encrypt(str(ram_size).encode()).decode()

data_frame['RAM_Size_Enc'] = data_frame['RAM_Size'].apply(encrypt_ram_size)         # Добавление нового столбца с зашифрованными значениями RAM
print("Столбец с зашифрованной RAM_Size добавлен.")

def decrypt_ram_size(encrypted_ram_size):                                           # Расшифровка
    return cipher.decrypt(encrypted_ram_size.encode()).decode()

if 'RAM_Size_Enc' in data_frame.columns:                                            # Расшифруем первые 5 значений
    decrypted_values = data_frame['RAM_Size_Enc'].head(5).apply(decrypt_ram_size)
    print("Первые 5 расшифрованных значений RAM_Size:")
    print(decrypted_values)
else:
    print("Столбец RAM_Size_Enc отсутствует. Сначала зашифруйте данные.")

"""Сохранение обработанных данных"""
output_path = "Laptop_price_sec.csv"
data_frame.to_csv(output_path, index=False)
print(f"Обработанный файл сохранен: {output_path}")