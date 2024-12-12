### Описание:
1. **Скрипты сборки и тестирования** — инструкции для автоматической сборки и тестирования с использованием Docker.
# Сборка docker-compose

```python
**bash
 ./scripts/build.sh**
```
# Запуст автоматических тестов

```python
**bash
 ./scripts/test.sh**
```


2. **Ручной запуск и тестирование** — пошаговые инструкции по запуску сервера и клиента вручную.
# Запуск серера

```python
**bash
 python3 server/server.py
**
```
# Запуск клиента

```python
**bash
 python3 client/client.py
**
```

3. **Структура проекта** — описание основных каталогов в проекте.
server/: Каталог с кодом сервера DNS.
client/: Каталог с кодом клиента для отправки запросов.
scripts/: Скрипты для сборки, тестирования и других задач.
tests/: Каталог с тестами для проверки функционала.

4. **Зависимости** — перечень необходимых зависимостей для запуска проекта.

Вся перечень находится в requirements.txt

Команда для скачивания всех зависимостей

```python
**bash
 pip install -r requirements.txt
**
```