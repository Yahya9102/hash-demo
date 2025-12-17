# Välj en liten Python-image
FROM python:3.12-slim

# Sätt arbetskatalog i containern
WORKDIR /app

# Kopiera dependencies först (bra för cache)
COPY requirements.txt .

# Installera dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Kopiera resten av koden
COPY app.py .

# Appen lyssnar på 8080 (info till människor/tools)
EXPOSE 8080

# Starta appen
CMD ["python", "app.py"]
