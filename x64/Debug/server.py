import http.server
import socketserver

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Content-Disposition", "attachment; filename=Agent_VS2019.exe")
        super().end_headers()

PORT = 8000

with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
    print("Serving at port", PORT)
    httpd.serve_forever()