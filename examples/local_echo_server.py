#!/usr/bin/env python3
import socketserver

class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(4096)
            if not data:
                break
            self.request.sendall(data)

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
    with socketserver.ThreadingTCPServer(("0.0.0.0", port), EchoHandler) as srv:
        print(f"[echo] listening on 0.0.0.0:{port}")
        srv.serve_forever()
