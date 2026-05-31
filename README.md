<div align="center">

```
   ▄▄▄▄███▄▄▄▄      ▄████████  ▄█          ▄█    █▄       ▄████████    ▄████████    ▄█    █▄    
 ▄██▀▀▀███▀▀▀██▄   ███    ███ ███         ███    ███     ███    ███   ███    ███   ███    ███   
 ███   ███   ███   ███    ███ ███         ███    ███     ███    ███   ███    █▀    ███    ███   
 ███   ███   ███   ███    ███ ███        ▄███▄▄▄▄███▄▄   ███    ███   ███         ▄███▄▄▄▄███▄▄ 
 ███   ███   ███ ▀███████████ ███       ▀▀███▀▀▀▀███▀  ▀███████████ ▀███████████ ▀▀███▀▀▀▀███▀  
 ███   ███   ███   ███    ███ ███         ███    ███     ███    ███          ███   ███    ███   
 ███   ███   ███   ███    ███ ███▌    ▄   ███    ███     ███    ███    ▄█    ███   ███    ███   
  ▀█   ███   █▀    ███    █▀  █████▄▄██   ███    █▀      ███    █▀   ▄████████▀    ███    █▀  
```

**Hash reputation checker via VirusTotal API — interactive forensic console**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square&logo=linux)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![API](https://img.shields.io/badge/API-VirusTotal%20v3-1976d2?style=flat-square)](https://www.virustotal.com)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/youruser/hashcheck/pulls)

[Features](#-features) · [Why hashcheck?](#-why-hashcheck) · [Install](#-installation) · [Usage](#-usage) · [Commands](#-commands) · [Export](#-exporting-results) · [FAQ](#-faq)

</div>

---

## What is hashcheck?

**hashcheck** is a lightweight, dependency-free interactive console for checking whether file hashes are malicious using the [VirusTotal API v3](https://docs.virustotal.com/). Built for forensic analysts, incident responders, SOC analysts, and CTF players who need to triage IOCs quickly without switching between browser tabs, curl commands, or Python scripts.

It works like `msfconsole` — set your API key once, and run any check from a single persistent session.


![screenshot](https://github.com/ZetaOrioniss/malhash/blob/main/assets/screen.png)

```
hashcheck (key ✓) > check 44d88612fea8a8f36de82e1278abb02f

  ────────────────────────────────────────────────────────────────────────────
  44d88612fea8a8f36de82e1278abb02f
  Type: MD5
  ────────────────────────────────────────────────────────────────────────────
  Verdict : MALICIOUS
  Score   : 62/72  (62 malicious · 0 suspicious · 9 undetected)
  Name    : eicar.com
  Type    : EICAR virus test files
  Size    : 68.0 B
  First   : 2012-07-20 08:01 UTC
  Last    : 2024-11-05 12:30 UTC
  VT link : https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f
```

---

## ✨ Features

| | Feature | Detail |
|---|---|---|
| 🖥️ | **Interactive REPL console** | Persistent session — set your key once, run any check instantly |
| 🔴 | **Dynamic prompt** | Shows API key status and result count at all times |
| 🔀 | **Multi-hash support** | Accepts MD5, SHA-1, and SHA-256 — auto-detected by length |
| 📦 | **Bulk checking** | Check dozens of hashes in one command with automatic rate limiting |
| 📂 | **File import** | Load a `.txt` IOC list (one hash per line, `#` comments supported) |
| 🗂️ | **Local file hashing** | Compute MD5 / SHA-1 / SHA-256 of any local file and query VT in one step |
| 🟢🟡🔴 | **Color-coded verdicts** | MALICIOUS · SUSPICIOUS · CLEAN · UNKNOWN — instantly readable |
| ⏱️ | **Built-in rate limiter** | Countdown between bulk requests — safe for VirusTotal free tier (4 req/min) |
| 📤 | **Export** | Save results as `.json`, `.csv`, or `.txt` for reporting or further analysis |
| 🔑 | **Persistent API key** | Key stored in `~/.hashcheck_config` (chmod 600) — never re-enter it |
| ⌨️ | **Tab completion** | Commands, keys, and file paths all autocomplete |
| ⬆️ | **Command history** | Navigate previous commands with arrow keys |
| 📦 | **Zero dependencies** | Pure Python standard library — nothing to install beyond Python 3.10 |

---

## 💡 Why hashcheck?

When triaging an incident or working through a CTF, checking a hash reputation typically means:

1. Opening a browser and navigating to VirusTotal
2. Pasting the hash and waiting for the result
3. Going back and repeating for every single IOC

For bulk checks, analysts usually resort to writing ad-hoc curl one-liners or Python scripts just to loop through a list — and none of those tools give you a clean, color-coded summary or a ready-to-share report.

**hashcheck collapses all of that into one persistent console.** Your API key is saved. Hashes are auto-detected. Bulk checks run with rate limiting built in. Results accumulate in the session and export to JSON or CSV in one command.

### Compared to alternatives

| | hashcheck | VirusTotal website | curl + VT API | vt-cli |
|---|:---:|:---:|:---:|:---:|
| Works offline (local hashing) | ✅ | ❌ | ❌ | ❌ |
| No dependencies | ✅ | ✅ | ✅ | ❌ |
| Bulk check with rate limiting | ✅ | ❌ | manual | ✅ |
| Session results + summary | ✅ | ❌ | ❌ | ❌ |
| Export JSON / CSV | ✅ | limited | manual | ✅ |
| Tab completion | ✅ | ❌ | ❌ | ✅ |
| Interactive REPL | ✅ | ❌ | ❌ | ❌ |
| Zero install | ✅ | ✅ | ✅ | ❌ |

---

## 📦 Installation

No pip, no virtualenv, no setup. Python 3.10+ is the only hard requirement.

```bash
git clone https://github.com/youruser/hashcheck.git
cd hashcheck
chmod +x hashcheck.py
```

**Optional — install system-wide:**

```bash
sudo cp hashcheck.py /usr/local/bin/hashcheck
```

Then just run:

```bash
hashcheck
```

### Getting a VirusTotal API key

hashcheck requires a free VirusTotal account to use the API.

1. Sign up at [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
2. Go to your profile → **API Key**
3. Copy your key and paste it into the console:

```
hashcheck (no key) > set apikey YOUR_KEY_HERE
```

The key is saved automatically to `~/.hashcheck_config` with permissions `600`.

> **Free tier limits:** 4 requests/minute · 500 requests/day. hashcheck defaults to a 15-second delay between bulk requests to stay within these limits. Adjust with `set delay <seconds>`.

---

## 🚀 Usage

```bash
python3 hashcheck.py
```

### Typical workflow

```
hashcheck (no key) > set apikey xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

hashcheck (key ✓) > check 44d88612fea8a8f36de82e1278abb02f
# → queries VT and prints full result with verdict

hashcheck (key ✓) > file /home/user/suspicious.exe
# → computes MD5 / SHA-1 / SHA-256 locally, then queries VT with SHA-256

hashcheck (key ✓) > bulk 44d88612fea8a8f36de82e1278abb02f aabbccdd...
# → checks multiple hashes inline with rate limiting between each

hashcheck (key ✓) > import /home/user/iocs.txt
# → loads hashes from a file and checks them all

hashcheck (key ✓) > results
# → prints a summary table of all results in the current session

hashcheck (key ✓) > export report.csv
# → exports all results to a CSV file
```

### IOC file format (`import`)

hashcheck accepts plain text files with one hash per line. Lines starting with `#` are treated as comments and ignored. Mixed hash types (MD5, SHA-1, SHA-256) in the same file are supported.

```
# IOC list - incident 2024-11-05
44d88612fea8a8f36de82e1278abb02f
da39a3ee5e6b4b0d3255bfef95601890afd80709
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# Windows hashes
aabbccddeeff00112233445566778899
```

---

## 📋 Commands

### API Key

| Command | Description |
|---|---|
| `set apikey <key>` | Set your VirusTotal API key — saved to `~/.hashcheck_config` |
| `show apikey` | Display the current API key (masked) |
| `unset apikey` | Remove the stored API key |

### Hash Checking

| Command | Description |
|---|---|
| `check <hash>` | Check a single hash — MD5, SHA-1, or SHA-256 auto-detected |
| `bulk <h1> <h2> ...` | Check multiple hashes inline |
| `file <path>` | Hash a local file (MD5/SHA-1/SHA-256) and query VirusTotal |
| `import <file.txt>` | Load hashes from a file and check all of them |

### Results

| Command | Description |
|---|---|
| `results` | Show a summary table of all results in the current session |
| `clear results` | Clear session results |
| `export <file>` | Export results to `.json`, `.csv`, or `.txt` |

### Settings

| Command | Description |
|---|---|
| `set delay <seconds>` | Delay between bulk requests (default: `15`) |
| `show options` | Display current configuration and session state |

### Other

| Command | Description |
|---|---|
| `clear` | Clear the screen |
| `help` | Show the full command reference |
| `exit` / `quit` | Exit the console |

---

## 🟢 Verdict Logic

| Verdict | Condition | Color |
|---|---|---|
| `MALICIOUS` | 5 or more engines flagged the hash | 🔴 Red |
| `SUSPICIOUS` | 1–4 engines flagged, or 1+ suspicious | 🟡 Yellow |
| `CLEAN` | 0 detections, at least 1 engine scanned | 🟢 Green |
| `UNKNOWN` | Hash not found in VirusTotal database | ⬛ Grey |
| `ERROR` | API error, network issue, or invalid key | 🔴 Red |

---

## 📤 Exporting Results

Results accumulate across the entire session. Export at any time:

```
hashcheck (key ✓)  3 result(s) > export report.json
hashcheck (key ✓)  3 result(s) > export report.csv
hashcheck (key ✓)  3 result(s) > export report.txt
```

Each exported record contains:

```
hash · type · verdict · malicious · suspicious · undetected · total ·
name · file_type · size · first_seen · last_seen · error · vt_link
```

---

## ❓ FAQ

**Do I need a paid VirusTotal account?**
No. A free account is sufficient. The free API tier allows 4 requests/minute and 500/day. hashcheck's default 15-second delay keeps you safely within these limits.

**What hash types are supported?**
MD5 (32 chars), SHA-1 (40 chars), and SHA-256 (64 chars). The type is detected automatically from the hash length.

**Can I mix hash types in the same import file?**
Yes. Each hash is detected individually, so an IOC list with MD5, SHA-1, and SHA-256 hashes all in the same file works without any configuration.

**What if a hash is not found?**
hashcheck will return an `UNKNOWN` verdict with the message "Not found in VirusTotal". This means the file has never been submitted to VT — it does not mean the file is safe.

**Is my API key secure?**
The key is stored in `~/.hashcheck_config` with `chmod 600` (readable only by your user). It is never sent anywhere other than the official VirusTotal API endpoint.

**Can I run it on Windows?**
The core logic works on Windows with Python 3.10+. Tab completion via `readline` may require the `pyreadline3` package on Windows (`pip install pyreadline3`).

---

## ⚠️ Disclaimer

This tool is intended **for authorized forensic analysis, incident response, CTF competitions, and educational purposes only**.

hashcheck queries the public VirusTotal API. By using this tool you agree to [VirusTotal's Terms of Service](https://docs.virustotal.com/docs/terms-of-service). The author is not responsible for any misuse or violation of third-party terms.

---

<div align="center">

Powered by [VirusTotal API v3](https://docs.virustotal.com/) &nbsp;•&nbsp; Built for the terminal &nbsp;•&nbsp; Made with ❤️ for the security community

</div>
