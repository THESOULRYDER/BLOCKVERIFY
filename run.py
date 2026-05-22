#!/usr/bin/env python3
"""
BlockVerify — Easy Launcher
Run this from the project root:
    python run.py
"""

import os
import sys

def main():
    print("""
  ===========================================
  BlockVerify - Blockchain File Integrity System
  ===========================================
    """)

    # Set working paths
    project_root = os.path.dirname(os.path.abspath(__file__))
    backend_dir  = os.path.join(project_root, "backend")
    uploads_dir  = os.path.join(project_root, "uploads")
    os.makedirs(uploads_dir, exist_ok=True)

    sys.path.insert(0, backend_dir)
    sys.path.insert(0, os.path.join(project_root, "ai_module"))

    # Check for .env file
    env_file = os.path.join(project_root, ".env")
    if os.path.exists(env_file):
        print("  Loading .env configuration...")
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ[k.strip()] = v.strip()

    ganache_url = os.environ.get("GANACHE_URL", "http://127.0.0.1:7545")
    contract    = os.environ.get("CONTRACT_ADDRESS", "")
    port        = int(os.environ.get("PORT", 5000))

    print(f"  Configuration:")
    print(f"  - Port:       {port}")
    print(f"  - Ganache:    {ganache_url}")
    print(f"  - Contract:   {contract or '(not set - mock mode)'}")
    print(f"  - Uploads:    {uploads_dir}")
    print()

    if not contract:
        try:
            print("  Attempting to deploy smart contract to Ganache automatically...")
            sys.path.insert(0, os.path.join(project_root, "contracts"))
            from deploy import deploy
            import builtins
            _orig_print = builtins.print
            builtins.print = lambda *args, **kwargs: None # suppress deploy prints
            contract = deploy()
            builtins.print = _orig_print
            os.environ["CONTRACT_ADDRESS"] = contract
            print(f"  Smart contract deployed automatically at {contract}")
        except Exception as e:
            try: builtins.print = _orig_print
            except: pass
            print(f"  !  Auto deployment failed: {e}")
            print("  !  Running in MOCK MODE (no blockchain)")
            print("     To use real Ganache, run: ganache --port 7545")
            print()

    print(f"  Starting server on http://localhost:{port}")
    print(f"  Press Ctrl+C to stop\n")

    # Init DB then run
    os.chdir(backend_dir)
    sys.path.insert(0, backend_dir)

    from database import init_db
    init_db()

    import unittest.mock as mock
    try:
        import flask_cors
        from app import app
    except ImportError:
        with mock.patch.dict('sys.modules', {'flask_cors': mock.MagicMock()}):
            from app import app

    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
