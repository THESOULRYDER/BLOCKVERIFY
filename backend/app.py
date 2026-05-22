"""
BlockVerify — Flask Backend
Blockchain-based File Integrity Verification System with AI Monitoring
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai_module'))

from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from werkzeug.utils import secure_filename
import hashlib
import threading
import time
import crypto_utils
import difflib

from database import (
    init_db, insert_file, get_file_by_id, get_all_files,
    update_file_status, insert_verification, get_verifications,
    insert_anomaly, get_anomalies, get_stats, create_user, verify_user, get_all_users,
    delete_user, delete_file_record, update_user_credentials
)
from merkle_tree import hash_file, build_merkle_from_files
from blockchain_connector import get_connector
from alert_system import fire_tamper_alert, fire_anomaly_alert, get_alerts, mark_all_read, store_alert, fire_upload_alert, fire_restore_alert

# Import AI module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai_module'))
from anomaly_detector import AnomalyDetector

# ── App setup ──────────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend', 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static')
)
CORS(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0 # Disable Static Cache
app.secret_key = os.environ.get("SECRET_KEY", "blockverify_secret_key_123")

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Globals initialised at startup
detector = AnomalyDetector(
    log_path=os.path.join(os.path.dirname(__file__), '..', 'anomaly_log.json')
)


def ai_monitoring_loop():
    """Background loop that continuously checks files for tampering."""
    while True:
        try:
            files = get_all_files()
            for record in files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], record["file_name"])
                if os.path.exists(file_path):
                    with open(file_path, "rb") as f:
                        current_hash = hash_file(f.read())

                    if current_hash != record["file_hash"]:
                        if record["status"] != "tampered":
                            update_file_status(record["id"], "tampered")
                            
                            # Phase 3: Diff Analysis using AES Decryption
                            diff_msg = ""
                            clean_bytes = None
                            backup_path = os.path.join(app.config['UPLOAD_FOLDER'], '..', 'backups', f'{record["id"]}.enc')
                            if os.path.exists(backup_path):
                                try:
                                    with open(backup_path, "rb") as bf:
                                        clean_bytes = crypto_utils.decrypt_data(bf.read())
                                    with open(file_path, "rb") as tf:
                                        tampered_bytes = tf.read()
                                        
                                    clean_text = clean_bytes.decode('utf-8', errors='ignore').splitlines()
                                    tampered_text = tampered_bytes.decode('utf-8', errors='ignore').splitlines()
                                    
                                    diffs = list(difflib.unified_diff(clean_text, tampered_text, n=0))
                                    additions = sum(1 for d in diffs if d.startswith('+') and not d.startswith('+++'))
                                    deletions = sum(1 for d in diffs if d.startswith('-') and not d.startswith('---'))
                                    diff_msg = f" Changes: +{additions} insertions, -{deletions} deletions."
                                except Exception as e:
                                    diff_msg = f" (Diff analysis failed: {e})"

                            # Alert
                            alert_email = record.get("owner_email")
                            fire_tamper_alert(record["file_name"], record["id"], alert_email, diff_msg)
                            insert_anomaly(record["file_name"], "TAMPER_DETECTED", "CRITICAL", 
                                           f"Background scan detected hash mismatch.{diff_msg}")
                            
                            print(f"[DEBUG] auto_correct config: {record.keys()} => dict={dict(record)}")
                            # Phase 4: Auto-Correction
                            if record.get("auto_correct") and os.path.exists(backup_path) and clean_bytes:
                                try:
                                    with open(file_path, "wb") as f_restore:
                                        f_restore.write(clean_bytes)
                                    update_file_status(record["id"], "safe")
                                    insert_anomaly(record["file_name"], "AUTO_HEALED", "INFO", 
                                                   f"File '{record['file_name']}' was automatically restored from secure backup.")
                                    fire_restore_alert(record["file_name"], record["id"], alert_email)
                                except Exception as e:
                                    print(f"[AI Monitor] Auto-Correction failed: {e}")
                    else:
                        # AI log event
                        anomalies = detector.log_event(record["file_name"], "verify", True, {"file_id": record["id"], "background": True})
                        for anom in anomalies:
                            insert_anomaly(record["file_name"], anom["type"], anom["severity"], anom["message"])
                            fire_anomaly_alert(anom, record.get("owner_email", ""))
        except Exception as e:
            print(f"[AI Monitor] Error: {e}")
        time.sleep(5)  # 5 second interval


@app.before_request
def startup():
    """Run once before first request."""
    app.before_request_funcs[None].remove(startup)
    init_db()
    
    # Start AI monitoring thread
    monitor_thread = threading.Thread(target=ai_monitoring_loop, daemon=True)
    monitor_thread.start()
    print("[AI Monitor] Background checking started.")


# ── Frontend ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/admin_choice")
def admin_choice():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    return render_template("admin_choice.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        is_valid, is_admin = verify_user(username, password)
        if is_valid:
            session["user"] = username
            session["is_admin"] = is_admin
            return redirect(url_for("admin_choice") if is_admin else url_for("index"))
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("is_admin", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    users = get_all_users()
    return render_template("dashboard.html", users=users)

@app.route("/api/users/add", methods=["POST"])
def add_user():
    if not session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 401
    username = request.form.get("username")
    password = request.form.get("password")
    is_admin = request.form.get("is_admin") == "on"
    if create_user(username, password, is_admin):
        return redirect(url_for("dashboard"))
    return jsonify({"error": "Username might already exist"}), 400

@app.route("/api/users/edit", methods=["POST"])
def edit_user():
    if not session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        user_id = int(request.form.get("user_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid user ID"}), 400
        
    password = request.form.get("password")
    is_admin = request.form.get("is_admin") == "on"
    
    update_user_credentials(user_id, password, is_admin)
    return redirect(url_for("dashboard"))

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def remove_user(user_id):
    if not session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 401
    delete_user(user_id)
    return jsonify({"success": True})



# ── Health ─────────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    bc = get_connector()
    return jsonify({"status": "ok", "blockchain": bc.status()})


# ── Upload ─────────────────────────────────────────────────────────────────────
@app.route("/api/upload", methods=["POST"])
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file part"}), 400

        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "No file selected"}), 400

        email = request.form.get("email", "")
        filename = secure_filename(f.filename)
        file_bytes = f.read()
        file_hash = hash_file(file_bytes)
        file_size = len(file_bytes)

        # Build Merkle tree (single file = tree of one leaf)
        tree = build_merkle_from_files([file_hash])
        merkle_root = tree.get_root()

        # Store on blockchain
        bc = get_connector()
        bc_result = bc.store_file(filename, merkle_root, file_hash)

        # Save to disk
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(save_path, 'wb') as out:
            out.write(file_bytes)

        auto_correct_str = request.form.get("auto_correct", "false").lower()
        auto_correct = auto_correct_str == "true"
        
        # Save to DB
        db_id = insert_file(
            file_name=filename,
            file_hash=file_hash,
            merkle_root=merkle_root,
            file_size=file_size,
            block_id=bc_result.get("file_id"),
            tx_hash=bc_result.get("tx_hash"),
            chain_mode=bc_result.get("mode", "mock"),
            owner_email=email,
            auto_correct=auto_correct
        )

        # Backup AES Encrypted
        try:
            backup_dir = os.path.join(app.config['UPLOAD_FOLDER'], '..', 'backups')
            os.makedirs(backup_dir, exist_ok=True)
            backup_path = os.path.join(backup_dir, f"{db_id}.enc")
            with open(save_path, "rb") as f2:
                enc_data = crypto_utils.encrypt_data(f2.read())
            with open(backup_path, "wb") as fb:
                fb.write(enc_data)
        except Exception as e:
            print("[WARNING] AES file backup failed:", e)

        # Log to AI monitor
        anomalies = detector.log_event(filename, "upload", True, {"file_id": db_id})
        for anom in anomalies:
            insert_anomaly(filename, anom["type"], anom["severity"], anom["message"])
            fire_anomaly_alert(anom, email)
            
        if email:
            fire_upload_alert(filename, email)

        try:
            return jsonify({
                "success": True,
                "file_id": db_id,
                "file_name": filename,
                "file_hash": file_hash,
                "merkle_root": merkle_root,
                "file_size": file_size,
                "blockchain": bc_result,
                "anomalies": anomalies
            })
        except Exception as ez:
            import traceback
            import sys
            return jsonify({"error": "JSON serialize failed", "trace": traceback.format_exc()}), 500
    except Exception as general_error:
        import traceback
        return jsonify({"error": traceback.format_exc()}), 500


# ── Verify ─────────────────────────────────────────────────────────────────────
@app.route("/api/verify", methods=["POST"])
def verify_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file_id_str = request.form.get("file_id")
    if not file_id_str:
        return jsonify({"error": "file_id required"}), 400

    try:
        file_id = int(file_id_str)
    except ValueError:
        return jsonify({"error": "file_id must be an integer"}), 400

    db_record = get_file_by_id(file_id)
    if not db_record:
        return jsonify({"error": f"No record for file ID {file_id}"}), 404

    f = request.files["file"]
    file_bytes = f.read()
    new_hash = hash_file(file_bytes)

    # Verify on blockchain
    bc = get_connector()
    bc_result = bc.verify_file(db_record["block_id"], new_hash)
    is_intact = bc_result["intact"]

    # Also cross-check DB hash
    db_intact = new_hash == db_record["file_hash"]
    final_intact = is_intact and db_intact

    # Update DB status
    previous_status = db_record["status"]
    status = "safe" if final_intact else "tampered"
    update_file_status(file_id, status)
    
    email = db_record.get("owner_email", "")

    # Record verification
    insert_verification(file_id, db_record["file_name"], new_hash, final_intact, bc_result.get("tx_hash"))

    # AI monitoring
    anomalies = detector.log_event(
        db_record["file_name"], "verify", final_intact,
        {"file_id": file_id, "intact": final_intact}
    )

    # Alerts
    if not final_intact and previous_status != "tampered":
        alert = fire_tamper_alert(db_record["file_name"], file_id, email)
        store_alert("TAMPER_DETECTED", "CRITICAL",
                    f"File '{db_record['file_name']}' has been tampered with.",
                    db_record["file_name"])
    elif final_intact and previous_status == "tampered":
        fire_restore_alert(db_record["file_name"], file_id, email)

    for anom in anomalies:
        insert_anomaly(db_record["file_name"], anom["type"], anom["severity"], anom["message"])
        fire_anomaly_alert(anom, email)

    return jsonify({
        "success": True,
        "file_id": file_id,
        "file_name": db_record["file_name"],
        "is_intact": final_intact,
        "status": status,
        "original_hash": db_record["file_hash"],
        "new_hash": new_hash,
        "merkle_root": db_record["merkle_root"],
        "blockchain": bc_result,
        "anomalies": anomalies
    })


# ── Files list ─────────────────────────────────────────────────────────────────
@app.route("/api/files")
def list_files():
    return jsonify(get_all_files())


@app.route("/api/files/<int:file_id>")
def get_file(file_id):
    record = get_file_by_id(file_id)
    if not record:
        return jsonify({"error": "Not found"}), 404
    verifs = get_verifications(file_id)
    return jsonify({**record, "verifications": verifs})

@app.route("/api/files/<int:file_id>", methods=["DELETE"])
def delete_file(file_id):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    record = get_file_by_id(file_id)
    if record:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], record["file_name"])
        if os.path.exists(file_path):
            os.remove(file_path)
            
        backup_path = os.path.join(app.config['UPLOAD_FOLDER'], '..', 'backups', f'{file_id}.enc')
        if os.path.exists(backup_path):
            os.remove(backup_path)
            
        delete_file_record(file_id)
    return jsonify({"success": True})


@app.route("/api/files/restore/<int:file_id>", methods=["POST"])
def restore_file(file_id):
    record = get_file_by_id(file_id)
    if not record:
        return jsonify({"error": "Not found"}), 404
        
    auth_email = ""
    if request.is_json:
        auth_email = request.json.get("email", "")
        
    is_admin = "user" in session
    is_owner = auth_email and auth_email == record.get("owner_email")
    if not is_admin and not is_owner:
        return jsonify({"error": "Unauthorized: Must be an admin or provide the uploader email."}), 401
        
    backup_path = os.path.join(app.config['UPLOAD_FOLDER'], '..', 'backups', f'{file_id}.enc')
    if not os.path.exists(backup_path):
        return jsonify({"error": "No secure backup available for this file."}), 400
        
    try:
        with open(backup_path, "rb") as bf:
            clean_bytes = crypto_utils.decrypt_data(bf.read())
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], record["file_name"])
        with open(file_path, "wb") as f_restore:
            f_restore.write(clean_bytes)
        
        # Reset specific statuses
        update_file_status(record["id"], "safe")
        insert_anomaly(record["file_name"], "MANUAL_RESTORE", "INFO", "File manually restored from secure backup.")
        fire_restore_alert(record["file_name"], record["id"], record.get("owner_email"))
        return jsonify({"success": True, "message": "File restored successfully."})
    except Exception as e:
        return jsonify({"error": f"Restoration failed: {e}"}), 500


# ── Verifications ──────────────────────────────────────────────────────────────
@app.route("/api/verifications")
def list_verifications():
    return jsonify(get_verifications())


# ── AI / Anomalies ─────────────────────────────────────────────────────────────
@app.route("/api/anomalies")
def list_anomalies():
    return jsonify(get_anomalies())


@app.route("/api/ai/stats")
def ai_stats():
    return jsonify(detector.get_stats())


# ── Alerts ─────────────────────────────────────────────────────────────────────
@app.route("/api/alerts")
def list_alerts():
    return jsonify(get_alerts())


@app.route("/api/alerts/read", methods=["POST"])
def read_alerts():
    mark_all_read()
    return jsonify({"success": True})


# ── Stats ──────────────────────────────────────────────────────────────────────
@app.route("/api/stats")
def stats():
    db_stats = get_stats()
    bc = get_connector()
    return jsonify({**db_stats, "blockchain": bc.status()})


# ── Merkle demo ────────────────────────────────────────────────────────────────
@app.route("/api/merkle/demo", methods=["POST"])
def merkle_demo():
    """Demo endpoint: build Merkle tree from list of strings."""
    data = request.json or {}
    items = data.get("items", ["file1", "file2", "file3", "file4"])
    hashes = [hashlib.sha256(i.encode()).hexdigest() for i in items]
    tree = build_merkle_from_files(hashes)
    proof = tree.get_proof(0)
    valid = type(tree).verify_proof(hashes[0], proof, tree.get_root())
    return jsonify({
        "items": items,
        "hashes": hashes,
        "merkle_root": tree.get_root(),
        "tree_structure": tree.get_tree_structure(),
        "proof_for_index_0": proof,
        "proof_valid": valid
    })


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"\n BlockVerify running on http://localhost:{port}\n")
    app.run(debug=True, port=port, use_reloader=False)


@app.route("/audit")
def audit_page():
    return render_template("audit.html")
