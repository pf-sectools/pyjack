#!/usr/bin/env python3
import json
import sys
import ssl
import argparse
import socket
import threading
from dataclasses import dataclass
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from http.server import HTTPServer, BaseHTTPRequestHandler


HTTPS_CONTEXT = ssl.create_default_context()

HTTP_HEAD = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; "
        "rv:142.0) Gecko/20100101 Firefox/142.0"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/xml;q=0.9,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "identity",
    "Upgrade-Insecure-Requests": "1",
    "Connection": "close",
}

# Helper Functions
# ----------------------------

def help():
    print("PyJack - HTTP Clickjack Tester")

def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port

def mk_request(url: str) -> Request:
    return Request(
        url,
        headers=HTTP_HEAD
    )



# Clickjack Request
# ----------------------------


@dataclass
class ClickjackRequest:
    target: str

    def get_headers(self):
        try:
            response = urlopen(
                mk_request(self.target),
                context=HTTPS_CONTEXT,
                timeout=10
            )

            return response.info()

        except HTTPError as exc:
            print(f"[!] Target returned HTTP {exc.code}")
            return exc.headers

        except (URLError, TimeoutError, OSError) as exc:
            print(f"[x] Request failed: {exc}")
            return None

    def has_xfo(self) -> bool:
        headers = self.get_headers()
        return headers is not None and "X-Frame-Options" in headers

    def is_vulnerable(self) -> bool:
        if self.has_xfo():
            return False

        return True

    def mk_recv(self) -> str:
        return """
        <!doctype html>
        <html>
        <head>
            <title>PyJack - Clickjack Tester</title>
            <style>
                body {{background:#640fd3;color:#eeeeee;display:block;}}
                h1,p {{margin-top:20px;margin-left:40px;line-height:0.5em;}}
                iframe {{width:1080px;height:720px;margin:auto;display:block;}}
            </style>
            <script>
                src={0}

                function setWindowOrigin()
                {{
                    document.getElementById("window-origin").innerHTML = window.origin;
                }}

                function setIFrameSrc()
                {{
                    document.getElementById("iframe-src").innerHTML = src;
                    document.getElementById("iframe").src = {0};
                }}

                function main()
                {{
                    setWindowOrigin();
                    setIFrameSrc();
                }}
            </script>
        </head>
        <body onload="main()">
            <h1>Framable Response Check</h1>
            <p>
                window.origin:
                <b id="window-origin"></b>
                --
                IFrame Target:
                <b id="iframe-src"></b>
            </p>
            <iframe id="iframe" src=""></iframe>
        </body>
        </html>
        """.format(json.dumps(self.target))




# Optional PyQt5 WebCamera
# ----------------------------

def mk_webcamera():

    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore import Qt, QUrl, QTimer
        from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineSettings
    except ImportError:
        return None


    class WebCamera(QWebEngineView):

            def __init__(self, app: QApplication):
                super().__init__()
                self.app = app
                self.output_file = None

                # Hidden view (no on-screen window)
                self.setAttribute(Qt.WA_DontShowOnScreen)
                self.page().settings().setAttribute(QWebEngineSettings.ShowScrollBars, False)



            def _take_screenshot(self):
                if self.output_file:
                    print(f"saving file: {self.output_file}")
                    self.grab().save(self.output_file, b"PNG")
                self.app.quit()


            def _on_load(self, ok: bool):
                if not ok:
                    print("Failed to load page for screenshot.")
                    self.app.quit()
                    return

                # Resize to full contents, then wait a beat and screenshot
                size = self.page().contentsSize().toSize()
                self.resize(size)
                QTimer.singleShot(800, self._take_screenshot)

            def capture(self, url: str, output_file: str):
                self.output_file = output_file
                self.loadFinished.connect(self._on_load)
                self.load(QUrl(url))
                self.show()

    return WebCamera




def mk_srv(packet: ClickjackRequest):

    class ClickjackHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            try:
                html = packet.mk_recv().encode("utf-8")

                self.send_response(200)

                self.send_header("Content-Type", "text/html; charset=utf-8")

                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)

            except Exception as exc:
                print(f"unexpected error: {exc}")

    return ClickjackHandler

def parse_args():
    p = argparse.ArgumentParser(description="Mini HTTP server for ClickJack Testing.")
    p.add_argument("--target", required=True, type=str, help="Specify target url")
    p.add_argument("--host", default="127.0.0.1", help="specify Host Address (Optional)")
    p.add_argument("--port", type=int, default=get_free_tcp_port(), help="Specify Bind port (Optional)")
    p.add_argument("--screencap", action=argparse.BooleanOptionalAction, default=False, help="Screenshot test page, then exit")
    args = p.parse_args()

    # Sanity checks
    if "http" not in args.target:
        print('[!] looks like your target is missing a schema!')
        print('[?] did you mean http://{}'.format(args.target))
        sys.exit(2)

    parsed = urlparse(args.target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print("[x] Target must be a complete HTTP or HTTPS URL.")
        print("[?] Example: https://example.com/")
        sys.exit(2)


    return args

def main():

    args = parse_args()
    target = args.target
    host,port = args.host, args.port
    clickjack = ClickjackRequest(args.target)
    handler_cls = mk_srv(clickjack)
    httpd = HTTPServer((host, port), handler_cls)
    host_url = "http://{}:{}".format(host,port)


    print('\n----------------------------')
    print('[+] Checking if target is vulnerable...')


    if clickjack.is_vulnerable():
        print("[!] Target is vulnerable!")
    else:
        print("[x] Target is not vulnerable. Exiting.")
        sys.exit()

    # Start server in background so we can run Qt in main thread
    print('\n----------------------------')
    print('[+] Serving ClickJack test: {}'.format(host_url))
    print("[+] Iframe Target: {}".format(target))

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()


    # Optional screencap
    if args.screencap:
        print('\n----------------------------')
        print("[+] Attempting to screenshot ClickJack page...\n")

        WebCamera = mk_webcamera()
        if WebCamera is None:
            print("[!] Skipping screenshot: PyQt5 not installed.")
            print("[?] Install on Debian/Ubuntu:")
            print("    sudo apt install python3-pyqt5 python3-pyqt5.qtwebengine")
        else:
            from PyQt5.QtWidgets import QApplication

            app = QApplication(sys.argv)
            cam = WebCamera(app)
            cam.capture(host_url, "ClickJack.png")
            app.exec_()

            # Clean shutdown after screencap
            print('\n----------------------------\n')
            print( "[!] Success!! closing down.")
            httpd.shutdown()
            httpd.server_close()
            sys.exit()

    print('\n----------------------------\n')
    print("[!] Serving ClickJack. CTRL+C to exit.")
    # If not screencapping, just keep serving
    try:
        t.join()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()




if __name__ == "__main__":
    main()
