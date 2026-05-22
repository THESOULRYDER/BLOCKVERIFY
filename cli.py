#!/usr/bin/env python3
"""
BlockVerify CLI
Terminal interface for file integrity verification.

Usage:
    python cli.py upload   <file_path>
    python cli.py verify   <file_path> --id <file_id>
    python cli.py list
    python cli.py status   <file_id>
    python cli.py batch    <directory>
    python cli.py merkle   <file1> <file2> ...
    python cli.py alerts
    python cli.py stats

Environment:
    BLOCKVERIFY_URL=http://localhost:5000   (default)
    or run standalone (no server needed) with --offline flag
"""

import sys
import os
import argparse
import json
import hashlib
from datetime import datetime

# ── Colors ────────────────────────────────────────────────────────────────────
G  = "\033[92m"   # green
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue/accent
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DIM= "\033[2m"
RESET = "\033[0m"
BOLD  = "\033[1m"

def ok(msg):   print(f"  {G}✔{RESET}  {msg}")
def err(msg):  print(f"  {R}✘{RESET}  {msg}")
def warn(msg): print(f"  {Y}!{RESET}  {msg}")
def info(msg): print(f"  {C}→{RESET}  {msg}")
def dim(msg):  print(f"  {DIM}{msg}{RESET}")

def header(title):
    print(f"\n{BOLD}{W} BlockVerify — {title}{RESET}")
    print(f"  {DIM}{'─'*50}{RESET}\n")

def fmt_size(b):
    if b < 1024: return f"{b} B"
    if b < 1048576: return f"{b/1024:.1f} KB"
    return f"{b/1048576:.1f} MB"

def fmt_date(s):
    if not s: return "—"
    try:
        d = datetime.fromisoformat(s.replace("Z",""))
        return d.strftime("%Y-%m-%d %H:%M")
    except: return s

def short(h, n=12):
    return f"{h[:n]}…{h[-6:]}" if h and len(h) > n+8 else (h or "—")


# ── Offline helpers (no server needed) ───────────────────────────────────────

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ai_module"))

from merkle_tree import hash_file, build_merkle_from_files, MerkleTree


def offline_hash(path):
    with open(path, "rb") as f:
        return hash_file(f.read()), os.path.getsize(path)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

BASE_URL = os.environ.get("BLOCKVERIFY_URL", "http://localhost:5000")

def api_get(endpoint):
    try:
        import urllib.request
        with urllib.request.urlopen(BASE_URL + endpoint, timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        err(f"Server unreachable ({e}). Is the Flask server running?")
        err(f"Start it with: cd backend && python app.py")
        sys.exit(1)

def api_post_file(endpoint, file_path, extra_fields=None):
    """POST multipart/form-data with a file."""
    import urllib.request, urllib.parse
    import email.generator
    import io

    boundary = "----BlockVerifyBoundary7C6BFF"

    def field(name, value):
        return (f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n").encode()

    body = b""
    if extra_fields:
        for k, v in extra_fields.items():
            body += field(k, str(v))

    filename = os.path.basename(file_path)
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    body += (f"--{boundary}\r\n"
             f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
             f"Content-Type: application/octet-stream\r\n\r\n").encode()
    body += file_bytes + b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        BASE_URL + endpoint,
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        err(f"Request failed: {e}")
        sys.exit(1)


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_upload(args):
    header("Upload File")
    if not os.path.exists(args.file):
        err(f"File not found: {args.file}")
        sys.exit(1)

    info(f"File: {os.path.basename(args.file)} ({fmt_size(os.path.getsize(args.file))})")
    info("Computing SHA-256 hash...")

    h, size = offline_hash(args.file)
    dim(f"Hash: {h}")

    if args.offline:
        # Offline mode — just show the hash and Merkle root, don't store
        tree = build_merkle_from_files([h])
        print()
        ok(f"SHA-256:     {h}")
        ok(f"Merkle Root: {tree.get_root()}")
        warn("Offline mode — not stored to blockchain. Remove --offline to register.")
        return

    info("Uploading to BlockVerify server...")
    data = api_post_file("/api/upload", args.file)

    if data.get("error"):
        err(data["error"]); sys.exit(1)

    print()
    ok(f"File registered on blockchain!")
    print(f"\n  {W}File ID:{RESET}      #{data['file_id']}")
    print(f"  {W}SHA-256:{RESET}      {short(data['file_hash'])}")
    print(f"  {W}Merkle Root:{RESET}  {short(data['merkle_root'])}")
    print(f"  {W}Tx Hash:{RESET}      {short(data['blockchain'].get('tx_hash',''))}")
    print(f"  {W}Chain Mode:{RESET}   {data['blockchain'].get('mode','mock')}")

    if data.get("anomalies"):
        print()
        for a in data["anomalies"]:
            warn(f"AI Alert [{a['severity']}]: {a['message']}")
    print()


def cmd_verify(args):
    header("Verify File Integrity")
    if not os.path.exists(args.file):
        err(f"File not found: {args.file}"); sys.exit(1)
    if not args.id:
        err("--id required. Use 'bv list' to find file IDs."); sys.exit(1)

    info(f"File: {os.path.basename(args.file)}")
    info(f"Checking against record #{args.id}...")

    data = api_post_file("/api/verify", args.file, {"file_id": args.id})

    if data.get("error"):
        err(data["error"]); sys.exit(1)

    print()
    if data["is_intact"]:
        print(f"  {G}{BOLD}✔  FILE INTEGRITY VERIFIED — SAFE{RESET}")
    else:
        print(f"  {R}{BOLD}✘  TAMPER DETECTED — FILE HAS BEEN MODIFIED!{RESET}")

    print(f"\n  {W}File:{RESET}          {data['file_name']}")
    print(f"  {W}Original hash:{RESET} {short(data['original_hash'])}")
    print(f"  {W}Current hash:{RESET}  {short(data['new_hash'])}")
    match_str = f"{G}✔ MATCH{RESET}" if data["is_intact"] else f"{R}✘ MISMATCH{RESET}"
    print(f"  {W}Hash match:{RESET}    {match_str}")
    print(f"  {W}Blockchain:{RESET}    {data['blockchain'].get('mode','mock')} · tx {short(data['blockchain'].get('tx_hash',''))}")

    if data.get("anomalies"):
        print()
        for a in data["anomalies"]:
            warn(f"AI Alert [{a['severity']}]: {a['message']}")
    print()
    sys.exit(0 if data["is_intact"] else 2)


def cmd_list(args):
    header("Registered Files")
    files = api_get("/api/files")
    if not files:
        info("No files registered yet. Use 'bv upload <file>' to register one.")
        return

    # Table
    print(f"  {DIM}{'ID':<5} {'Name':<28} {'Hash':<18} {'Status':<12} {'Uploaded'}{RESET}")
    print(f"  {DIM}{'─'*75}{RESET}")
    for f in files:
        status_color = G if f['status'] == 'safe' else (R if f['status'] == 'tampered' else Y)
        print(f"  {C}#{f['id']:<4}{RESET} "
              f"{W}{f['file_name'][:27]:<28}{RESET} "
              f"{DIM}{short(f['file_hash'],10):<18}{RESET} "
              f"{status_color}{f['status']:<12}{RESET} "
              f"{DIM}{fmt_date(f['uploaded_at'])}{RESET}")
    print(f"\n  {DIM}Total: {len(files)} file(s){RESET}\n")


def cmd_status(args):
    header(f"File Record #{args.id}")
    data = api_get(f"/api/files/{args.id}")
    if data.get("error"):
        err(data["error"]); sys.exit(1)

    status_color = G if data['status'] == 'safe' else R
    print(f"  {W}Name:{RESET}         {data['file_name']}")
    print(f"  {W}Status:{RESET}       {status_color}{data['status'].upper()}{RESET}")
    print(f"  {W}File Size:{RESET}    {fmt_size(data['file_size'] or 0)}")
    print(f"  {W}Uploaded:{RESET}     {fmt_date(data['uploaded_at'])}")
    print(f"  {W}SHA-256:{RESET}")
    print(f"    {DIM}{data['file_hash']}{RESET}")
    print(f"  {W}Merkle Root:{RESET}")
    print(f"    {DIM}{data['merkle_root']}{RESET}")
    print(f"  {W}Blockchain:{RESET}   mode={data['chain_mode']}  block_id={data['block_id']}")
    print(f"  {W}Tx Hash:{RESET}")
    print(f"    {DIM}{data['tx_hash']}{RESET}")

    verifs = data.get("verifications", [])
    if verifs:
        print(f"\n  {W}Verification History:{RESET}")
        for v in verifs[:5]:
            icon = f"{G}✔{RESET}" if v["is_intact"] else f"{R}✘{RESET}"
            print(f"    {icon} {fmt_date(v['verified_at'])}  hash={short(v['new_hash'])}")
    print()


def cmd_batch(args):
    header(f"Batch Verify Directory: {args.directory}")
    if not os.path.isdir(args.directory):
        err(f"Not a directory: {args.directory}"); sys.exit(1)

    files = [os.path.join(args.directory, f)
             for f in os.listdir(args.directory)
             if os.path.isfile(os.path.join(args.directory, f))]

    if not files:
        warn("No files found in directory."); return

    info(f"Found {len(files)} file(s). Computing hashes...")
    hashes = []
    for fp in files:
        h, size = offline_hash(fp)
        hashes.append(h)
        dim(f"  {os.path.basename(fp):<35} {short(h)}")

    tree = build_merkle_from_files(hashes)
    print()
    ok(f"Merkle Root for {len(files)} files:")
    print(f"\n  {C}{tree.get_root()}{RESET}\n")
    info("This root can be stored on blockchain to represent the entire directory.")
    info("Any single file change will produce a completely different root.")

    # Show tree structure
    struct = tree.get_tree_structure()
    print(f"\n  {DIM}Tree depth: {struct['depth']} levels  ·  Leaves: {struct['leaf_count']}{RESET}\n")


def cmd_merkle(args):
    header("Merkle Tree — Custom Items")
    items = args.items
    if not items:
        err("Provide at least one item"); sys.exit(1)

    hashes = [hashlib.sha256(i.encode()).hexdigest() for i in items]
    tree = MerkleTree(hashes)
    root = tree.get_root()

    print(f"  {W}Items:{RESET} {', '.join(items[:6])}{'...' if len(items)>6 else ''}")
    print(f"  {W}Count:{RESET} {len(items)}")
    print(f"\n  {W}Merkle Root:{RESET}")
    print(f"  {C}{root}{RESET}\n")

    if len(items) <= 8:
        print(f"  {W}Tree levels:{RESET}")
        struct = tree.get_tree_structure()
        for i, level in enumerate(reversed(struct["levels"])):
            label = "ROOT" if i == 0 else f"L{i} "
            nodes = "  ".join(h[:12]+"…" for h in level[:6])
            if len(level) > 6: nodes += f"  (+{len(level)-6} more)"
            print(f"    {DIM}{label}: {nodes}{RESET}")
        print()

    # Verify proof for first item
    proof = tree.get_proof(0)
    valid = MerkleTree.verify_proof(hashes[0], proof, root)
    print(f"  {W}Proof for '{items[0]}':{RESET} {G}valid ✔{RESET}" if valid else f"  Proof: {R}invalid{RESET}")
    print()


def cmd_alerts(args):
    header("System Alerts")
    alerts = api_get("/api/alerts")
    if not alerts:
        ok("No alerts — system is clean."); return

    severity_colors = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": B}
    for a in alerts[:20]:
        sc = severity_colors.get(a["severity"], W)
        read_marker = f"{DIM}(read){RESET}" if a.get("read") else f"{Y}NEW{RESET}"
        print(f"  {sc}[{a['severity']:<8}]{RESET}  {W}{a['message'][:65]}{RESET}")
        print(f"             {DIM}{fmt_date(a['timestamp'])}  ·  {a['type']}  {read_marker}{RESET}\n")


def cmd_stats(args):
    header("System Statistics")
    data = api_get("/api/stats")
    bc   = data.get("blockchain", {})

    rows = [
        ("Files monitored",    data.get("total_files", 0),    W),
        ("Safe files",         data.get("safe_files", 0),     G),
        ("Tampered files",     data.get("tampered_files", 0), R),
        ("Total verifications",data.get("verifications", 0),  C),
        ("Anomalies detected", data.get("anomalies", 0),      Y),
    ]
    for label, val, color in rows:
        bar_len = min(int(val), 30)
        bar = "█" * bar_len
        print(f"  {W}{label:<25}{RESET} {color}{val:<6}{RESET} {DIM}{bar}{RESET}")

    print(f"\n  {W}Blockchain:{RESET}  {bc.get('mode','mock')} mode  ·  connected={bc.get('connected','?')}")
    if bc.get("block"):
        print(f"  {W}Block height:{RESET} #{bc['block']}")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="bv",
        description="BlockVerify CLI — file integrity on blockchain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py upload report.pdf
  python cli.py verify report.pdf --id 1
  python cli.py list
  python cli.py status 1
  python cli.py batch ./documents/
  python cli.py merkle file1.pdf file2.pdf file3.pdf
  python cli.py alerts
  python cli.py stats
        """
    )
    sub = parser.add_subparsers(dest="command")

    # upload
    p_up = sub.add_parser("upload", help="Register a file on blockchain")
    p_up.add_argument("file", help="Path to file")
    p_up.add_argument("--offline", action="store_true", help="Hash only, don't store")

    # verify
    p_vr = sub.add_parser("verify", help="Verify file integrity")
    p_vr.add_argument("file", help="Path to file")
    p_vr.add_argument("--id", type=int, required=True, help="File record ID")

    # list
    sub.add_parser("list", help="List all registered files")

    # status
    p_st = sub.add_parser("status", help="Show file record details")
    p_st.add_argument("id", type=int, help="File record ID")

    # batch
    p_bt = sub.add_parser("batch", help="Compute Merkle root for a directory")
    p_bt.add_argument("directory", help="Directory to process")

    # merkle
    p_mk = sub.add_parser("merkle", help="Build Merkle tree from items")
    p_mk.add_argument("items", nargs="+", help="Strings to hash into Merkle tree")

    # alerts
    sub.add_parser("alerts", help="Show system alerts")

    # stats
    sub.add_parser("stats", help="Show system statistics")

    args = parser.parse_args()

    dispatch = {
        "upload":  cmd_upload,
        "verify":  cmd_verify,
        "list":    cmd_list,
        "status":  cmd_status,
        "batch":   cmd_batch,
        "merkle":  cmd_merkle,
        "alerts":  cmd_alerts,
        "stats":   cmd_stats,
    }

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
