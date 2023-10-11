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

# import http.server
# import socketserver
# import subprocess
# from urllib.parse import urlparse, parse_qs

# class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
#     def end_headers(self):
#         self.send_header("Content-Disposition", "attachment; filename=Agent_VS2019.exe")
#         super().end_headers()

#     def do_GET(self):
#         # 解析查询参数
#         query_components = parse_qs(urlparse(self.path).query)
#         ip = query_components.get('ip', [''])[0]
#         port = query_components.get('port', [''])[0]
#         detect_port = query_components.get('detect_port', [''])[0]

#         if not ip or not port or not detect_port:
#             self.send_error(400, "Missing required parameters (ip, port, detect_port)")
#             return

#         # 执行命令
#         command = f"./AgentGenerator.exe {ip} {port} {detect_port}"
#         try:
#             subprocess.run(command, shell=True, check=True)
#         except subprocess.CalledProcessError as e:
#             self.send_error(500, f"Failed to run the command: {str(e)}")
#             return

#         # 发送生成的 Agent.exe 文件给客户端
#         with open("Agent.exe", "rb") as agent_file:
#             self.send_response(200)
#             self.send_header("Content-Type", "application/octet-stream")
#             self.end_headers()
#             self.wfile.write(agent_file.read())

# PORT = 8000

# with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
#     print("Serving at port", PORT)
#     httpd.serve_forever()