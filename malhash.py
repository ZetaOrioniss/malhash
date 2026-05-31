#!/usr/bin/env python3

import sys
import shlex
import readline
import hashlib
import os
import json
import urllib.request
import urllib.error
import time
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime


class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    END     = "\033[0m"

    @staticmethod
    def r(s): return f"{C.RED}{s}{C.END}"
    @staticmethod
    def g(s): return f"{C.GREEN}{s}{C.END}"
    @staticmethod
    def y(s): return f"{C.YELLOW}{s}{C.END}"
    @staticmethod
    def b(s): return f"{C.BLUE}{s}{C.END}"
    @staticmethod
    def c(s): return f"{C.CYAN}{s}{C.END}"
    @staticmethod
    def m(s): return f"{C.MAGENTA}{s}{C.END}"
    @staticmethod
    def bold(s): return f"{C.BOLD}{s}{C.END}"
    @staticmethod
    def dim(s): return f"{C.DIM}{s}{C.END}"


VT_API_URL   = "https://www.virustotal.com/api/v3/files/{}"
RATE_LIMIT   = 15        # seconds between requests (free tier: 4/min)
CONFIG_FILE  = Path.home() / ".hashcheck_config"
HASH_TYPES   = {"32": "MD5", "40": "SHA-1", "64": "SHA-256"}


@dataclass
class Result:
    hash_value:   str
    hash_type:    str
    malicious:    int = 0
    suspicious:   int = 0
    undetected:   int = 0
    harmless:     int = 0
    total:        int = 0
    name:         str = ""
    file_type:    str = ""
    size:         int = 0
    first_seen:   str = ""
    last_seen:    str = ""
    error:        str = ""

    @property
    def verdict(self) -> str:
        if self.error:
            return "ERROR"
        if self.malicious >= 5:
            return "MALICIOUS"
        if self.malicious >= 1 or self.suspicious >= 1:
            return "SUSPICIOUS"
        if self.total == 0:
            return "UNKNOWN"
        return "CLEAN"

    @property
    def verdict_colored(self) -> str:
        v = self.verdict
        if v == "MALICIOUS":  return C.r(C.bold(v))
        if v == "SUSPICIOUS": return C.y(C.bold(v))
        if v == "CLEAN":      return C.g(C.bold(v))
        if v == "UNKNOWN":    return C.dim(v)
        return C.r(v)

    @property
    def ratio(self) -> str:
        if self.total == 0:
            return "-/-"
        return f"{self.malicious}/{self.total}"


class Session:
    def __init__(self):
        self.api_key: str | None    = None
        self.delay:   int           = RATE_LIMIT
        self.results: list[Result]  = []
        self._load_config()

    def _load_config(self) -> None:
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text())
                self.api_key = data.get("api_key")
            except Exception:
                pass

    def save_config(self) -> None:
        try:
            CONFIG_FILE.write_text(json.dumps({"api_key": self.api_key}))
            CONFIG_FILE.chmod(0o600)
        except Exception as e:
            print(C.r(f"  [-] Could not save config: {e}"))

    def clear_results(self) -> None:
        self.results = []


def detect_hash_type(h: str) -> str | None:
    h = h.strip()
    return HASH_TYPES.get(str(len(h))) if all(c in "0123456789abcdefABCDEF" for c in h) else None


def hash_file(path: str) -> tuple[str, str, str] | None:
    p = Path(path)
    if not p.exists():
        return None
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except PermissionError:
        return None


def query_virustotal(hash_value: str, api_key: str) -> dict:
    url = VT_API_URL.format(hash_value)
    req = urllib.request.Request(
        url,
        headers={"x-apikey": api_key, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "not_found"}
        if e.code == 401:
            return {"error": "invalid_key"}
        if e.code == 429:
            return {"error": "rate_limited"}
        return {"error": f"http_{e.code}"}
    except urllib.error.URLError as e:
        return {"error": f"network: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}


def parse_vt_response(hash_value: str, hash_type: str, data: dict) -> Result:
    if "error" in data:
        code = data["error"]
        if code == "not_found":
            return Result(hash_value=hash_value, hash_type=hash_type,
                          error="Not found in VirusTotal")
        return Result(hash_value=hash_value, hash_type=hash_type,
                      error=code.replace("_", " ").capitalize())

    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        names = attrs.get("names", [])
        return Result(
            hash_value  = hash_value,
            hash_type   = hash_type,
            malicious   = stats.get("malicious", 0),
            suspicious  = stats.get("suspicious", 0),
            undetected  = stats.get("undetected", 0),
            harmless    = stats.get("harmless", 0),
            total       = sum(stats.values()),
            name        = names[0] if names else attrs.get("meaningful_name", ""),
            file_type   = attrs.get("type_description", ""),
            size        = attrs.get("size", 0),
            first_seen  = attrs.get("first_submission_date", ""),
            last_seen   = attrs.get("last_analysis_date", ""),
        )
    except (KeyError, IndexError) as e:
        return Result(hash_value=hash_value, hash_type=hash_type,
                      error=f"Parse error: {e}")


def format_timestamp(ts) -> str:
    if not ts:
        return "-"
    try:
        return datetime.fromtimestamp(datetime.timezone.utc)
    except Exception:
        return str(ts)


def format_size(b: int) -> str:
    if b == 0:
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def print_result(r: Result, index: int | None = None) -> None:
    W    = 80
    sep  = f"{C.YELLOW}{'─' * W}{C.END}"
    idx  = f"[{index}] " if index is not None else ""

    print(f"\n{sep}")
    print(f"  {idx}{C.bold(r.hash_value)}")
    print(f"  Type: {C.dim(r.hash_type)}")
    print(sep)

    if r.error:
        print(f"  Status  : {C.dim(r.error)}\n")
        return

    print(f"  Verdict : {r.verdict_colored}")
    print(f"  Score   : {C.bold(r.ratio)}  ({r.malicious} malicious · {r.suspicious} suspicious · {r.undetected} undetected)")
    if r.name:       print(f"  Name    : {r.name}")
    if r.file_type:  print(f"  Type    : {r.file_type}")
    if r.size:       print(f"  Size    : {format_size(r.size)}")
    print(f"  First   : {format_timestamp(r.first_seen)}")
    print(f"  Last    : {format_timestamp(r.last_seen)}")
    print(f"  VT link : https://www.virustotal.com/gui/file/{r.hash_value}")
    print()


def print_summary(results: list[Result]) -> None:
    if not results:
        print(C.dim("  No results yet."))
        return

    W       = 80
    total   = len(results)
    mal     = sum(1 for r in results if r.verdict == "MALICIOUS")
    sus     = sum(1 for r in results if r.verdict == "SUSPICIOUS")
    clean   = sum(1 for r in results if r.verdict == "CLEAN")
    unknown = sum(1 for r in results if r.verdict in ("UNKNOWN", "ERROR"))

    print(f"\n{C.BOLD}{C.CYAN}{'═' * W}{C.END}")
    print(f"{C.BOLD}{C.CYAN}{'  SCAN SUMMARY'.center(W)}{C.END}")
    print(f"{C.BOLD}{C.CYAN}{'═' * W}{C.END}\n")
    print(f"  {'Total hashes':<20} {total}")
    print(f"  {'Malicious':<20} {C.r(str(mal)) if mal else C.dim('0')}")
    print(f"  {'Suspicious':<20} {C.y(str(sus)) if sus else C.dim('0')}")
    print(f"  {'Clean':<20} {C.g(str(clean)) if clean else C.dim('0')}")
    print(f"  {'Unknown / Error':<20} {C.dim(str(unknown))}")
    print()

    print(f"  {C.bold('HASH'):<{66 + len(C.BOLD) + len(C.END)}}{'SCORE':<10}VERDICT")
    print(f"  {C.dim('─' * 76)}")
    for r in results:
        h     = r.hash_value[:20] + "…" if len(r.hash_value) > 20 else r.hash_value
        score = r.ratio if not r.error else r.error[:12]
        print(f"  {C.dim(h):<{20 + len(C.DIM) + len(C.END)}}  {score:<10}  {r.verdict_colored}")
    print(f"\n{C.BOLD}{C.CYAN}{'═' * W}{C.END}\n")


def export_report(results: list[Result], path: str) -> None:
    rows = []
    for r in results:
        rows.append({
            "hash":        r.hash_value,
            "type":        r.hash_type,
            "verdict":     r.verdict,
            "malicious":   r.malicious,
            "suspicious":  r.suspicious,
            "undetected":  r.undetected,
            "total":       r.total,
            "name":        r.name,
            "file_type":   r.file_type,
            "size":        r.size,
            "first_seen":  format_timestamp(r.first_seen),
            "last_seen":   format_timestamp(r.last_seen),
            "error":       r.error,
            "vt_link":     f"https://www.virustotal.com/gui/file/{r.hash_value}" if not r.error else "",
        })
    p = Path(path)
    ext = p.suffix.lower()

    if ext == ".json":
        p.write_text(json.dumps(rows, indent=2))
    elif ext == ".csv":
        import csv
        with open(p, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
    else:
        lines = []
        for r in rows:
            lines.append("─" * 60)
            for k, v in r.items():
                lines.append(f"{k:<15}: {v}")
        p.write_text("\n".join(lines))

    print(C.g(f"  [+] Report saved → {p.resolve()}"))


def check_single(hash_value: str, session: Session) -> Result | None:
    hash_value = hash_value.strip().lower()
    hash_type  = detect_hash_type(hash_value)
    if not hash_type:
        print(C.r(f"  [-] Invalid hash: '{hash_value}'"))
        return None
    print(f"  {C.dim('Querying VirusTotal for')} {hash_type} {C.dim('hash...')}")
    data   = query_virustotal(hash_value, session.api_key)
    result = parse_vt_response(hash_value, hash_type, data)
    print_result(result)
    session.results.append(result)
    return result


def check_bulk(hashes: list[str], session: Session) -> None:
    valid = []
    for h in hashes:
        h = h.strip().lower()
        if not h or h.startswith("#"):
            continue
        ht = detect_hash_type(h)
        if ht:
            valid.append((h, ht))
        else:
            print(C.y(f"  [!] Skipping invalid: '{h}'"))

    if not valid:
        print(C.r("  [-] No valid hashes found."))
        return

    total = len(valid)
    print(f"\n  {C.bold(str(total))} hash(es) to check — delay: {session.delay}s between requests\n")

    for i, (h, ht) in enumerate(valid, 1):
        print(f"  [{i}/{total}] {C.dim(h[:20] + '…' if len(h) > 20 else h)} ", end="", flush=True)
        data   = query_virustotal(h, session.api_key)
        result = parse_vt_response(h, ht, data)
        session.results.append(result)
        print(result.verdict_colored)

        if i < total:
            for remaining in range(session.delay, 0, -1):
                print(f"\r  Waiting {remaining}s...  ", end="", flush=True)
                time.sleep(1)
            print("\r" + " " * 30 + "\r", end="")

    print()
    print_summary(session.results[-total:])


BANNER = f"""
{C.BOLD}{C.CYAN}
   ▄▄▄▄███▄▄▄▄      ▄████████  ▄█          ▄█    █▄       ▄████████    ▄████████    ▄█    █▄    
 ▄██▀▀▀███▀▀▀██▄   ███    ███ ███         ███    ███     ███    ███   ███    ███   ███    ███   
 ███   ███   ███   ███    ███ ███         ███    ███     ███    ███   ███    █▀    ███    ███   
 ███   ███   ███   ███    ███ ███        ▄███▄▄▄▄███▄▄   ███    ███   ███         ▄███▄▄▄▄███▄▄ 
 ███   ███   ███ ▀███████████ ███       ▀▀███▀▀▀▀███▀  ▀███████████ ▀███████████ ▀▀███▀▀▀▀███▀  
 ███   ███   ███   ███    ███ ███         ███    ███     ███    ███          ███   ███    ███   
 ███   ███   ███   ███    ███ ███▌    ▄   ███    ███     ███    ███    ▄█    ███   ███    ███   
  ▀█   ███   █▀    ███    █▀  █████▄▄██   ███    █▀      ███    █▀   ▄████████▀    ███    █▀    
                              ▀                                                                 
{C.END}{C.DIM}  Hash reputation checker via VirusTotal API  •  MD5 / SHA-1 / SHA-256{C.END}
{C.DIM}  Type {C.END}{C.BOLD}help{C.END}{C.DIM} to list available commands.{C.END}
"""

HELP = f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════╗
║                       COMMANDS                               ║
╚══════════════════════════════════════════════════════════════╝{C.END}

  {C.bold('API Key')}
  {C.g('set apikey <key>')}         Set your VirusTotal API key (saved to ~/.hashcheck_config)
  {C.g('show apikey')}              Display the current API key (masked)
  {C.g('unset apikey')}             Remove the stored API key

  {C.bold('Hash Checking')}
  {C.g('check <hash>')}             Check a single hash (MD5 / SHA-1 / SHA-256)
  {C.g('bulk <h1> <h2> ...')}       Check multiple hashes in one command
  {C.g('file <path>')}              Hash a local file and check it on VirusTotal
  {C.g('import <file.txt>')}        Load hashes from a file (one per line) and check all

  {C.bold('Results')}
  {C.g('results')}                  Show summary of all results in this session
  {C.g('clear results')}            Clear session results
  {C.g('export <file>')}            Export results to file (.json / .csv / .txt)

  {C.bold('Settings')}
  {C.g('set delay <seconds>')}      Delay between bulk requests (default: 15s, free tier: ≥15s)
  {C.g('show options')}             Show current configuration

  {C.bold('Other')}
  {C.g('clear')}                    Clear the screen
  {C.g('help')}                     Show this help
  {C.g('exit')}  /  {C.g('quit')}             Exit
"""


COMMANDS = [
    "set", "unset", "show", "check", "bulk", "file", "import",
    "results", "export", "clear", "help", "exit", "quit"
]
SET_KEYS  = ["apikey", "delay"]
SHOW_KEYS = ["apikey", "options"]


def completer(text: str, state: int):
    line   = readline.get_line_buffer().lstrip()
    parts  = line.split()
    nparts = len(parts)

    if nparts == 0 or (nparts == 1 and not line.endswith(" ")):
        opts = [c for c in COMMANDS if c.startswith(text)]
    elif parts[0] == "set" and nparts <= 2:
        opts = [k for k in SET_KEYS if k.startswith(text)]
    elif parts[0] == "show" and nparts <= 2:
        opts = [k for k in SHOW_KEYS if k.startswith(text)]
    elif parts[0] in ("file", "import", "export") and nparts <= 2:
        prefix = text
        base   = os.path.dirname(prefix) or "."
        try:
            opts = [
                os.path.join(base, e) if base != "." else e
                for e in os.listdir(base)
                if e.startswith(os.path.basename(prefix))
            ]
        except OSError:
            opts = []
    else:
        opts = []

    return opts[state] if state < len(opts) else None


readline.set_completer(completer)
readline.parse_and_bind("tab: complete")


def prompt(session: Session) -> str:
    key = C.g("key ✓") if session.api_key else C.r("no key")
    n   = C.dim(f"  {len(session.results)} result(s)") if session.results else ""
    return f"{C.BOLD}{C.CYAN}hashcheck{C.END} {C.dim(f'({key})')}{n} {C.BOLD}{C.GREEN}>{C.END} "


def run_console() -> None:
    print(BANNER)
    session = Session()

    if session.api_key:
        print(C.g(f"  [+] API key loaded from {CONFIG_FILE}"))
    else:
        print(C.y("  [!] No API key set — type: set apikey <your_key>"))
        print(C.dim("      Get a free key at https://www.virustotal.com/gui/join-us\n"))

    while True:
        try:
            raw = input(prompt(session)).strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.dim('Goodbye.')}\n")
            break

        if not raw:
            continue

        try:
            parts = shlex.split(raw)
        except ValueError as e:
            print(C.r(f"[-] Parse error: {e}"))
            continue

        cmd  = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit", "quit"):
            print(f"\n{C.dim('Goodbye.')}\n")
            break

        elif cmd == "help":
            print(HELP)

        elif cmd == "clear":
            if args and args[0] == "results":
                session.clear_results()
                print(C.dim("  Session results cleared."))
            else:
                print("\033[2J\033[H", end="")
                print(BANNER)

        elif cmd == "set":
            if len(args) < 2:
                print(C.r("  Usage: set <apikey|delay> <value>"))
            elif args[0].lower() == "apikey":
                session.api_key = args[1]
                session.save_config()
                print(C.g(f"  [+] API key saved."))
            elif args[0].lower() == "delay":
                try:
                    session.delay = int(args[1])
                    print(f"  Delay => {C.g(str(session.delay))}s")
                except ValueError:
                    print(C.r("  [-] Delay must be an integer."))
            else:
                print(C.r(f"  [-] Unknown key: '{args[0]}'"))

        elif cmd == "unset":
            if not args:
                print(C.r("  Usage: unset apikey"))
            elif args[0].lower() == "apikey":
                session.api_key = None
                session.save_config()
                print(C.dim("  API key removed."))
            else:
                print(C.r(f"  [-] Unknown key: '{args[0]}'"))

        elif cmd == "show":
            sub = args[0].lower() if args else "options"
            if sub == "apikey":
                if session.api_key:
                    masked = session.api_key[:4] + "*" * (len(session.api_key) - 8) + session.api_key[-4:]
                    print(f"\n  API key: {C.g(masked)}\n")
                else:
                    print(C.r("\n  No API key set.\n"))
            elif sub == "options":
                key = C.g("set") if session.api_key else C.r("not set")
                print(f"\n  API key  =>  {key}")
                print(f"  Delay    =>  {C.g(str(session.delay))}s")
                print(f"  Results  =>  {len(session.results)} in session\n")
            else:
                print(C.r(f"  [-] Unknown option: '{sub}'"))

        elif cmd == "check":
            if not session.api_key:
                print(C.r("  [-] No API key — type: set apikey <key>"))
            elif not args:
                print(C.r("  Usage: check <hash>"))
            else:
                check_single(args[0], session)

        elif cmd == "bulk":
            if not session.api_key:
                print(C.r("  [-] No API key — type: set apikey <key>"))
            elif not args:
                print(C.r("  Usage: bulk <hash1> <hash2> ..."))
            else:
                check_bulk(args, session)

        elif cmd == "file":
            if not session.api_key:
                print(C.r("  [-] No API key — type: set apikey <key>"))
            elif not args:
                print(C.r("  Usage: file <path>"))
            else:
                path = " ".join(args)
                print(f"  {C.dim('Hashing file...')} {path}")
                hashes = hash_file(path)
                if hashes is None:
                    print(C.r(f"  [-] Cannot read file: '{path}'"))
                else:
                    md5, sha1, sha256 = hashes
                    size = Path(path).stat().st_size
                    print(f"\n  {C.bold('File:')}  {path}  {C.dim('(' + format_size(size) + ')')}")
                    print(f"  MD5     : {C.dim(md5)}")
                    print(f"  SHA-1   : {C.dim(sha1)}")
                    print(f"  SHA-256 : {C.dim(sha256)}")
                    print()
                    print(f"  {C.dim('Checking SHA-256 on VirusTotal...')}")
                    check_single(sha256, session)

        elif cmd == "import":
            if not session.api_key:
                print(C.r("  [-] No API key — type: set apikey <key>"))
            elif not args:
                print(C.r("  Usage: import <file.txt>"))
            else:
                path = " ".join(args)
                try:
                    lines = Path(path).read_text().splitlines()
                    hashes = [l.split()[0] for l in lines if l.strip() and not l.startswith("#")]
                    if not hashes:
                        print(C.r("  [-] No hashes found in file."))
                    else:
                        check_bulk(hashes, session)
                except FileNotFoundError:
                    print(C.r(f"  [-] File not found: '{path}'"))
                except Exception as e:
                    print(C.r(f"  [-] Error reading file: {e}"))

        elif cmd == "results":
            print_summary(session.results)

        elif cmd == "export":
            if not args:
                print(C.r("  Usage: export <file.json|file.csv|file.txt>"))
            elif not session.results:
                print(C.y("  [!] No results to export."))
            else:
                try:
                    export_report(session.results, " ".join(args))
                except Exception as e:
                    print(C.r(f"  [-] Export failed: {e}"))

        else:
            print(C.r(f"  [-] Unknown command: '{cmd}'"))
            print(f"  {C.dim('Type')} help {C.dim('for available commands.')}")


if __name__ == "__main__":
    run_console()