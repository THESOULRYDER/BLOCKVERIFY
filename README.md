<div align="center">

# 🛡️ BlockVerify
**Blockchain-based File Integrity Verification System with AI Monitoring**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-%23000.svg?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Solidity](https://img.shields.io/badge/Solidity-%23363636.svg?style=flat&logo=solidity&logoColor=white)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## 👥 Authors / Co-Creators
This project was co-created and developed by:
* **AJOI T VARGHESE** - [THESOULRYDER](https://github.com/THESOULRYDER)
* **PRAKASH M** - [RED-ARTIST](https://github.com/RED-ARTIST)


## Blockchain-based File Integrity Verification System with AI Monitoring

---

## Project Structure

```
blockverify/
├── contracts/
│   └── FileIntegrity.sol        ← Solidity smart contract
├── backend/
│   ├── app.py                   ← Flask API (main entry point)
│   ├── blockchain_connector.py  ← Web3.py / Ganache connector
│   ├── database.py              ← SQLite ORM layer
│   ├── merkle_tree.py           ← SHA-256 + Merkle tree implementation
│   └── alert_system.py         ← Email + dashboard alerts
├── ai_module/
│   └── anomaly_detector.py     ← Rule-based AI anomaly detection
├── frontend/
│   └── templates/
│       └── index.html           ← Full SPA frontend
├── tests/
│   └── test_all.py              ← Pytest unit + integration tests
├── requirements.txt
└── README.md
```

---

## Quick Start (No Blockchain — Mock Mode)

This mode runs **without Ganache** — perfect for demo and testing.

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install flask flask-cors werkzeug

# 3. Run the app
cd backend
python app.py
```

Open: **http://localhost:5000**

---

## Full Setup (With Ganache Blockchain)

### Step 1 — Install all dependencies
```bash
pip install -r requirements.txt
```

### Step 2 — Install Ganache
```bash
npm install -g ganache
ganache --port 7545
```
Or download Ganache GUI from https://trufflesuite.com/ganache/

### Step 3 — Deploy the Smart Contract

**Option A — Remix IDE (easiest)**
1. Go to https://remix.ethereum.org
2. Create a new file, paste contents of `contracts/FileIntegrity.sol`
3. Compile with Solidity 0.8.x
4. In Deploy tab: select "Web3 Provider", enter `http://127.0.0.1:7545`
5. Deploy — copy the contract address

**Option B — Truffle**
```bash
npm install -g truffle
truffle init
# copy FileIntegrity.sol to contracts/
truffle migrate --network development
```

### Step 4 — Configure environment
```bash
export GANACHE_URL=http://127.0.0.1:7545
export CONTRACT_ADDRESS=0xYOUR_CONTRACT_ADDRESS_HERE
export ALERT_EMAIL_USER=your_email@gmail.com       # optional
export ALERT_EMAIL_PASS=your_app_password          # optional
export SECRET_AES_KEY=your_generated_fernet_key    # required
```

### Step 5 — Run
```bash
cd backend
python app.py
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | System + blockchain status |
| POST | `/api/upload` | Upload + register file on blockchain |
| POST | `/api/verify` | Verify file integrity |
| GET | `/api/files` | List all registered files |
| GET | `/api/files/<id>` | Get file details + verification history |
| GET | `/api/verifications` | All verification records |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/anomalies` | AI-detected anomalies |
| GET | `/api/ai/stats` | AI monitoring stats |
| GET | `/api/alerts` | All system alerts |
| POST | `/api/alerts/read` | Mark all alerts as read |
| POST | `/api/merkle/demo` | Build Merkle tree from list |

### Upload example (curl)
```bash
curl -X POST http://localhost:5000/api/upload \
  -F "file=@/path/to/your/file.pdf"
```

### Verify example (curl)
```bash
curl -X POST http://localhost:5000/api/verify \
  -F "file=@/path/to/your/file.pdf" \
  -F "file_id=1"
```

---

## Running Tests

```bash
pip install pytest
cd blockverify
python -m pytest tests/test_all.py -v
```

Expected output:
```
PASSED tests/test_all.py::TestMerkleTree::test_single_leaf
PASSED tests/test_all.py::TestMerkleTree::test_two_leaves
PASSED tests/test_all.py::TestMerkleTree::test_four_leaves
PASSED tests/test_all.py::TestMerkleTree::test_proof_valid
PASSED tests/test_all.py::TestMerkleTree::test_tampered_proof_fails
PASSED tests/test_all.py::TestMerkleTree::test_odd_leaves
PASSED tests/test_all.py::TestMerkleTree::test_hash_file
PASSED tests/test_all.py::TestBlockchainConnector::test_store_and_get
PASSED tests/test_all.py::TestBlockchainConnector::test_verify_intact
PASSED tests/test_all.py::TestBlockchainConnector::test_verify_tampered
PASSED tests/test_all.py::TestAnomalyDetector::test_normal_activity_no_alert
PASSED tests/test_all.py::TestAnomalyDetector::test_high_frequency_detection
PASSED tests/test_all.py::TestAnomalyDetector::test_repeated_failures_detection
...
```

---

## How It Works

### File Upload Flow
```
User uploads file
       ↓
SHA-256 hash generated
       ↓
Merkle Tree built (root = combination of hashes)
       ↓
storeFile(name, merkleRoot, hash) → Smart Contract
       ↓
Record saved to SQLite
       ↓
AI monitor logs the event
```

### Verification Flow
```
User re-uploads file
       ↓
New SHA-256 hash computed
       ↓
verifyFile(id, newHash) called on blockchain
       ↓
Contract compares hashes
       ↓
If MATCH  → ✅ Safe
If NO MATCH → 🚨 TAMPERED → Alert fired
```

### AI Anomaly Rules
| Rule | Trigger | Severity |
|------|---------|----------|
| High-frequency writes | ≥10 events/hour per file | HIGH |
| Off-hours access | Activity outside 08:00–20:00 UTC | MEDIUM |
| Repeated failures | ≥3 failed verifications in 2h | CRITICAL |

---

## Viva Q&A

**Why blockchain?**
→ Immutable storage — once a hash is written to the chain, it cannot be altered without consensus. No central admin can tamper with it.

**Why Merkle Tree?**
→ Allows efficient verification of a single file in a large batch. Instead of re-hashing all files, you only need O(log n) sibling hashes to prove any leaf belongs to the root.

**Why AI monitoring?**
→ Static hash-checking detects *that* tampering happened. AI detects *suspicious behavior* that might indicate an attack in progress (frequent modifications, off-hours access) — proactive rather than reactive.

**What problem does this solve?**
→ Undetected file tampering in secure systems. Common in: legal documents, audit logs, medical records, supply chain manifests.

---

## Tech Stack Summary

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, Vanilla JS |
| Backend | Python 3.10+, Flask 3.x |
| Database | SQLite (via sqlite3) |
| Blockchain | Solidity 0.8.x, Ganache, Web3.py |
| AI | Rule-based anomaly detection (extendable to scikit-learn Isolation Forest) |
| Hashing | SHA-256 (hashlib), custom Merkle Tree |
| Alerts | SMTP email + in-app dashboard |
