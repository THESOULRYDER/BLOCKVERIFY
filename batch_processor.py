"""
BlockVerify — Batch File Processor
Register and verify multiple files in one go, building a shared Merkle tree.

Usage:
    python batch_processor.py register ./documents/
    python batch_processor.py verify   ./documents/ --session session_id
    python batch_processor.py report   --session session_id
"""

import sys
import os
import json
import hashlib
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ai_module"))

from merkle_tree import hash_file, build_merkle_from_files, MerkleTree
from blockchain_connector import get_connector
from database import init_db, insert_file, get_file_by_id, insert_verification, update_file_status

SESSIONS_FILE = os.path.join(os.path.dirname(__file__), "batch_sessions.json")


def load_sessions():
    if os.path.exists(SESSIONS_FILE):
        with open(SESSIONS_FILE) as f:
            return json.load(f)
    return {}


def save_sessions(sessions):
    with open(SESSIONS_FILE, "w") as f:
        json.dump(sessions, f, indent=2, default=str)


def make_session_id():
    return datetime.utcnow().strftime("batch_%Y%m%d_%H%M%S")


def collect_files(directory, recursive=False):
    """Collect all files from a directory."""
    files = []
    if recursive:
        for root, _, fnames in os.walk(directory):
            for fn in fnames:
                files.append(os.path.join(root, fn))
    else:
        for fn in os.listdir(directory):
            fp = os.path.join(directory, fn)
            if os.path.isfile(fp):
                files.append(fp)
    return sorted(files)


def register_batch(directory, recursive=False):
    """
    Hash all files in a directory, build a Merkle tree,
    store each file + the batch Merkle root on blockchain.
    Returns a session_id for later verification.
    """
    print(f"\n  BlockVerify — Batch Register")
    print(f"  Directory: {directory}")
    print(f"  {'─'*50}\n")

    init_db()
    bc = get_connector()
    files = collect_files(directory, recursive)

    if not files:
        print("  No files found.")
        return None

    print(f"  Found {len(files)} file(s). Hashing...\n")

    file_records = []
    hashes = []

    for fp in files:
        with open(fp, "rb") as f:
            raw = f.read()
        h = hash_file(raw)
        size = len(raw)
        hashes.append(h)
        file_records.append({
            "path": fp,
            "name": os.path.basename(fp),
            "hash": h,
            "size": size,
        })
        status_str = f"{h[:16]}…"
        print(f"  ✓  {os.path.basename(fp):<35} {status_str}")

    # Build shared Merkle tree for the whole batch
    tree = build_merkle_from_files(hashes)
    batch_root = tree.get_root()

    print(f"\n  Merkle Root (batch): {batch_root}\n")
    print(f"  Storing {len(file_records)} files on blockchain...")

    session_id = make_session_id()
    session_files = []

    for i, record in enumerate(file_records):
        # Individual Merkle proof within the batch tree
        proof = tree.get_proof(i)
        bc_result = bc.store_file(record["name"], batch_root, record["hash"])

        db_id = insert_file(
            file_name  = record["name"],
            file_hash  = record["hash"],
            merkle_root= batch_root,
            file_size  = record["size"],
            block_id   = bc_result.get("file_id"),
            tx_hash    = bc_result.get("tx_hash"),
            chain_mode = bc_result.get("mode", "mock"),
        )

        session_files.append({
            "db_id":    db_id,
            "path":     record["path"],
            "name":     record["name"],
            "hash":     record["hash"],
            "size":     record["size"],
            "proof":    proof,
            "bc_result":bc_result,
        })
        print(f"  [{i+1:02d}/{len(file_records)}] #{db_id} stored — tx {bc_result.get('tx_hash','')[:20]}…")

    # Save session
    sessions = load_sessions()
    sessions[session_id] = {
        "created_at":  datetime.utcnow().isoformat(),
        "directory":   directory,
        "batch_root":  batch_root,
        "file_count":  len(session_files),
        "files":       session_files,
    }
    save_sessions(sessions)

    print(f"\n  ✅ Batch complete!")
    print(f"  Session ID:  {session_id}")
    print(f"  Batch root:  {batch_root[:32]}…")
    print(f"  Files stored: {len(session_files)}")
    print(f"\n  To verify later:")
    print(f"  python batch_processor.py verify {directory} --session {session_id}\n")

    return session_id


def verify_batch(directory, session_id, recursive=False):
    """
    Re-hash all files and compare against the stored session.
    Reports which files are intact and which are tampered.
    """
    print(f"\n  BlockVerify — Batch Verify")
    print(f"  Session: {session_id}")
    print(f"  {'─'*50}\n")

    sessions = load_sessions()
    if session_id not in sessions:
        print(f"  ERROR: Session '{session_id}' not found.")
        print(f"  Available sessions: {list(sessions.keys()) or 'none'}")
        return

    session = sessions[session_id]
    bc = get_connector()

    total = 0
    intact_count = 0
    tampered = []

    new_hashes = []
    results = []

    for sf in session["files"]:
        fp = sf["path"]
        total += 1

        if not os.path.exists(fp):
            results.append({"name": sf["name"], "status": "MISSING", "path": fp})
            print(f"  ⚠  {sf['name']:<35} MISSING")
            tampered.append(sf["name"])
            new_hashes.append(sf["hash"])  # Use original so tree still builds
            continue

        with open(fp, "rb") as f:
            new_hash = hash_file(f.read())
        new_hashes.append(new_hash)

        is_intact = new_hash == sf["hash"]
        bc_result = bc.verify_file(sf.get("db_id", 1), new_hash)

        if sf.get("db_id"):
            update_file_status(sf["db_id"], "safe" if is_intact else "tampered")
            insert_verification(sf["db_id"], sf["name"], new_hash, is_intact,
                                bc_result.get("tx_hash"))

        status = "SAFE" if is_intact else "TAMPERED"
        icon = "✔" if is_intact else "✘"
        color_char = "" 
        results.append({
            "name":      sf["name"],
            "status":    status,
            "orig_hash": sf["hash"],
            "new_hash":  new_hash,
            "intact":    is_intact,
        })
        status_label = f"{'SAFE' if is_intact else 'TAMPERED'}"
        print(f"  {icon}  {sf['name']:<35} {status_label}")
        if is_intact:
            intact_count += 1
        else:
            tampered.append(sf["name"])

    # Verify batch Merkle root
    if new_hashes:
        new_tree = build_merkle_from_files(new_hashes)
        new_root = new_tree.get_root()
        original_root = session["batch_root"]
        root_match = new_root == original_root
    else:
        root_match = False
        new_root = "—"

    print(f"\n  {'─'*50}")
    print(f"  Results:  {intact_count}/{total} files intact")
    print(f"\n  Original batch Merkle root:")
    print(f"  {original_root}")
    print(f"\n  Current  batch Merkle root:")
    print(f"  {new_root}")
    print(f"\n  Root match: {'✔ YES — batch unmodified' if root_match else '✘ NO  — batch was modified'}")

    if tampered:
        print(f"\n  Tampered/missing files:")
        for t in tampered:
            print(f"    ✘ {t}")

    print()
    return results


def batch_report(session_id):
    """Print a formatted report for a session."""
    sessions = load_sessions()
    if session_id not in sessions:
        print(f"  ERROR: Session '{session_id}' not found.")
        return

    s = sessions[session_id]
    print(f"\n  BlockVerify — Batch Report")
    print(f"  {'─'*50}")
    print(f"  Session:    {session_id}")
    print(f"  Created:    {s['created_at']}")
    print(f"  Directory:  {s['directory']}")
    print(f"  Files:      {s['file_count']}")
    print(f"  Batch Root: {s['batch_root']}")
    print(f"\n  Files in session:")
    for f in s["files"]:
        print(f"    #{f['db_id']:<4} {f['name']:<35} {f['hash'][:20]}…")
    print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="BlockVerify Batch Processor")
    sub = parser.add_subparsers(dest="cmd")

    p_reg = sub.add_parser("register", help="Register all files in a directory")
    p_reg.add_argument("directory")
    p_reg.add_argument("--recursive", action="store_true")

    p_ver = sub.add_parser("verify", help="Verify all files against a session")
    p_ver.add_argument("directory")
    p_ver.add_argument("--session", required=True)
    p_ver.add_argument("--recursive", action="store_true")

    p_rep = sub.add_parser("report", help="Print session report")
    p_rep.add_argument("--session", required=True)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
    elif args.cmd == "register":
        register_batch(args.directory, args.recursive)
    elif args.cmd == "verify":
        verify_batch(args.directory, args.session, args.recursive)
    elif args.cmd == "report":
        batch_report(args.session)
