from flask import Flask, make_response
import ssl

app = Flask(__name__)

@app.route("/")
def home():
    response = make_response("<html><head><title>Environment Test</title></head></html>")
    response.headers["Content-Type"] = "text/html"
    response.headers["Connection"] = "close"  # Ensures proper termination
    return response

if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='localhost.pem', password="third-wheel")
    app.run(host='localhost', port=4443, ssl_context=context)
