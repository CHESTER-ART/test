
#!/usr/bin/env python3
# Written by Rafe Hart (@rafael_hart)
# Updated for Python 3.12+ by M365 Copilot
"""
Test an IP address (TLS port, default 443) for CVE-2000-0649-like behavior:
Perform an HTTPS GET to the target and search the response body for IPv4 patterns.
"""

import ssl
import socket
import re
import sys
import argparse
from typing import List


def make_tls_socket(host: str, port: int, timeout: int = 8) -> socket.socket:
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    raw.connect((host, port))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls_sock = context.wrap_socket(raw, server_hostname=host)
    return tls_sock


def is_private_ipv4(ip: str) -> bool:
