
#!/usr/bin/env python3
import argparse
import ftplib
import socket
from contextlib import contextmanager

def info(msg): print(f"[+] {msg}")
def warn(msg): print(f"[!] {msg}")
def err(msg):  print(f"[-] {msg}")

@contextmanager
def ftp_connect(host, port, timeout):
    ftp = ftplib.FTP()
    ftp.encoding = "utf-8"
    ftp.set_debuglevel(0)
    try:
        ftp.connect(host=host, port=port, timeout=timeout)
        yield ftp
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

def check_anonymous_login(host, port, timeout=8):
    """Attempt anonymous login and basic listing."""
    info(f"Connecting to {host}:{port}")
    with ftp_connect(host, port, timeout) as ftp:
        welcome = ftp.getwelcome() if hasattr(ftp, "getwelcome") else ""
        if welcome:
            info(f"FTP banner: {welcome.strip()}")
        try:
            ftp.login(user="anonymous", passwd="anonymous@example.com")
            info("Anonymous login: ENABLED")
        except ftplib.error_perm as e:
            warn(f"Anonymous login denied: {e}")
            return {
                "anonymous": False,
                "cwd": None,
                "list_root": None,
                "ftp": None
            }
        except (socket.timeout, OSError, ftplib.Error) as e:
            err(f"Connection/login error: {e}")
            return {"anonymous": None, "cwd": None, "list_root": None, "ftp": None}

        # Try to get current directory and list root
        cwd = None
        listing = []
        try:
            if hasattr(ftp, "pwd"):
                cwd = ftp.pwd()
                info(f"Current directory: {cwd}")
        except Exception as e:
            warn(f"PWD not supported or failed: {e}")

        try:
            ftp.retrlines("LIST", listing.append)
            info(f"Root listing entries: {len(listing)}")
        except ftplib.error_perm as e:
            warn(f"LIST denied: {e}")
        except Exception as e:
            warn(f"LIST failed: {e}")

        return {
            "anonymous": True,
            "cwd": cwd,
            "list_root": listing,
            "ftp": ftp  # NOTE: returned but invalid after context exit; not used outside.
        }

def try_cwd_up(ftp, max_updir):
    """Attempt directory traversal by issuing CWD .. repeatedly."""
    traversed_levels = 0
    pwd_values = []
    for i in range(max_updir):
        try:
            ftp.cwd("..")
            traversed_levels += 1
            if hasattr(ftp, "pwd"):
                pwd_values.append(ftp.pwd())
        except ftplib.error_perm:
            break
        except Exception:
            break
    return traversed_levels, pwd_values

def try_retr_traversal_files(ftp):
    """
    Try to read *first bytes* of harmless, well-known files via path traversal.
    We do not store content; only confirm access.
    """
    # Candidate paths (Windows-focused, relative traversal)
    candidate_files = []

    windows_targets = [
        "Windows/win.ini",
        "Windows/System32/drivers/etc/hosts",
        "Windows/System32/license.rtf"
    ]
    # Build traversal paths like ../../Windows/win.ini up to 6 levels
    for up in range(1, 7):
        prefix = "../" * up
        for t in windows_targets:
            candidate_files.append(prefix + t)

    # Also add generic paths that sometimes exist in FTP virtual roots
    candidate_files += [
        "../README.txt", "../readme.txt", "../.gitignore"
    ]

    accessible = []
    def sink(data):
        # read at most first 256 bytes then abort by raising to stop transfer early
        raise KeyboardInterrupt  # Use interrupt to stop after first chunk

    for path in candidate_files:
        try:
            ftp.retrbinary(f"RETR {path}", sink, blocksize=256)
        except KeyboardInterrupt:
            accessible.append(path)
            info(f"File accessible via traversal: {path} (first bytes read)")
        except ftplib.error_perm:
            # Not accessible or server denied RETR
            continue
        except Exception:
            # Other errors; ignore to keep test safe and non-intrusive
            continue
    return accessible

def check_directory_traversal(host, port, timeout=8, max_updir=8):
    """Check whether we can escape FTP root via '..' and read files."""
    with ftp_connect(host, port, timeout) as ftp:
        try:
            ftp.login(user="anonymous", passwd="anonymous@example.com")
        except ftplib.error_perm as e:
            warn(f"Traversal check skipped (anonymous denied): {e}")
            return {"can_escape": False, "levels": 0, "pwd_trace": [], "files_accessible": []}
        except Exception as e:
            err(f"Login/traversal setup failed: {e}")
            return {"can_escape": None, "levels": 0, "pwd_trace": [], "files_accessible": []}

        levels, pwd_trace = try_cwd_up(ftp, max_updir)
        can_escape = levels > 0
        if can_escape:
            info(f"Performed {levels} × 'CWD ..' (PWD trace length: {len(pwd_trace)})")
        else:
            info("Server did not allow moving up with 'CWD ..'")

        accessible = try_retr_traversal_files(ftp)
        return {
            "can_escape": can_escape,
            "levels": levels,
            "pwd_trace": pwd_trace,
            "files_accessible": accessible
        }

def main():
    parser = argparse.ArgumentParser(
        description="Safe checker for anonymous FTP login and directory traversal (read-only)."
    )
    parser.add_argument("--host", required=True, help="Target FTP hostname or IP")
    parser.add_argument("--port", type=int, default=21, help="FTP port (default 21)")
    parser.add_argument("--timeout", type=int, default=8, help="Socket timeout seconds")
    parser.add_argument("--max-updir", type=int, default=8, help="Max '..' attempts for traversal")
    args = parser.parse_args()

    # Anonymous login check
    res1 = check_anonymous_login(args.host, args.port, args.timeout)
    if res1["anonymous"] is True:
        info("Anonymous login appears ENABLED.")
    elif res1["anonymous"] is False:
        warn("Anonymous login appears DISABLED.")
    else:
        err("Could not determine anonymous login (network or server error).")

    # Directory traversal check
    res2 = check_directory_traversal(args.host, args.port, args.timeout, args.max_updir)

    print("\n=== Summary ===")
    print(f"Anonymous login: {res1['anonymous']}")
    print(f"Traversal via 'CWD ..': {res2['can_escape']} (levels attempted: {res2['levels']})")
    if res2["pwd_trace"]:
        print("PWD trace:")
        for p in res2["pwd_trace"]:
            print(f"  - {p}")
    if res2["files_accessible"]:
        print("Files accessible via relative traversal (first bytes confirmed):")
        for f in res2["files_accessible"]:
            print(f"  - {f}")
    else:
        print("No files confirmed accessible via traversal candidates.")

if __name__ == "__main__":
    main()
``
