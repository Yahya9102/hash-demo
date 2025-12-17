from flask import Flask  # importerar Flask-ramverket

app = Flask(__name__)    # skapar Flask-appen

@app.get("/")            # GET / ska svara
def home():
    return "Hello from Flask in Kubernetes!\n"  # enkel text-sträng

if __name__ == "__main__":
    # Viktigt: host="0.0.0.0" så appen kan nås utanför containern/podden
    app.run(host="0.0.0.0", port=8080)
