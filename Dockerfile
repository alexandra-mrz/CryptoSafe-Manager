# DEP-2: Заглушка Dockerfile для упаковки в Спринте 8
# Спринт 1: базовый образ без сборки приложения

FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# CMD и точка входа будут добавлены в Спринте 8
# CMD ["python", "main.py"]
