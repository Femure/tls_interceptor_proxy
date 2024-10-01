import http.server
import ssl
import time

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write("<html><head><title>Environment Test</title></head></html>\n".encode("utf-8"))
            time.sleep(1)  # Allow time for the response to be sent before closing

server_address = ('localhost', 4443)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='localhost.pem', password=(lambda: "third-wheel"))

httpd = http.server.HTTPServer(server_address, RequestHandler)
httpd.socket = context.wrap_socket(httpd.socket, server_hostname='my_test_site.com')

print(f"Serving on https://{server_address[0]}:{server_address[1]}")
httpd.serve_forever()
