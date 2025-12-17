FROM python:3.12-slim

WORKDIR /app


COPY requirements.txt .

# Installera dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Kopiera resten av koden
COPY app.py .

EXPOSE 8080

CMD ["python", "app.py"]
