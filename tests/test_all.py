"""
Unit tests for BlockVerify — run with: python -m pytest tests/
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai_module'))

import hashlib
import tempfile
import json
import pytest


# ─── Merkle Tree Tests ────────────────────────────────────────────────────────

from merkle_tree import MerkleTree, hash_file, sha256

class TestMerkleTree:

    def test_single_leaf(self):
        t = MerkleTree(["abc"])
        assert t.get_root() == sha256("abc" + "abc")  # duplicated leaf

    def test_two_leaves(self):
        h1, h2 = sha256("a"), sha256("b")
        t = MerkleTree([h1, h2])
        expected = sha256(h1 + h2)
        assert t.get_root() == expected

    def test_four_leaves(self):
        leaves = [sha256(str(i)) for i in range(4)]
        t = MerkleTree(leaves)
        assert len(t.get_root()) == 64

    def test_proof_valid(self):
        leaves = [sha256(str(i)) for i in range(8)]
        t = MerkleTree(leaves)
        for i in range(len(leaves)):
            proof = t.get_proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, t.get_root()), f"Proof failed for leaf {i}"

    def test_tampered_proof_fails(self):
        leaves = [sha256(str(i)) for i in range(4)]
        t = MerkleTree(leaves)
        proof = t.get_proof(0)
        bad_hash = sha256("tampered")
        assert not MerkleTree.verify_proof(bad_hash, proof, t.get_root())

    def test_odd_leaves(self):
        leaves = [sha256(str(i)) for i in range(5)]
        t = MerkleTree(leaves)
        assert t.get_root()
        proof = t.get_proof(0)
        assert MerkleTree.verify_proof(leaves[0], proof, t.get_root())

    def test_hash_file(self):
        data = b"hello world"
        h = hash_file(data)
        assert h == hashlib.sha256(data).hexdigest()

    def test_tree_structure(self):
        leaves = [sha256(str(i)) for i in range(4)]
        t = MerkleTree(leaves)
        struct = t.get_tree_structure()
        assert struct["leaf_count"] == 4
        assert "root" in struct


# ─── Anomaly Detector Tests ───────────────────────────────────────────────────

from anomaly_detector import AnomalyDetector

class TestAnomalyDetector:

    def setup_method(self):
        # Use a temp file for each test
        self.tmpfile = tempfile.mktemp(suffix='.json')
        self.detector = AnomalyDetector(log_path=self.tmpfile)

    def teardown_method(self):
        if os.path.exists(self.tmpfile):
            os.remove(self.tmpfile)

    def test_normal_activity_no_alert(self):
        anomalies = self.detector.log_event("test.pdf", "upload", True)
        assert isinstance(anomalies, list)

    def test_high_frequency_detection(self):
        # Log 11 events to trigger HIGH_FREQUENCY
        for _ in range(11):
            self.detector.log_event("busy.pdf", "modify", True)
        anomalies = self.detector.analyze("busy.pdf")
        types = [a["type"] for a in anomalies]
        assert "HIGH_FREQUENCY" in types

    def test_repeated_failures_detection(self):
        for _ in range(3):
            self.detector.log_event("compromised.pdf", "verify", False)
        anomalies = self.detector.analyze("compromised.pdf")
        types = [a["type"] for a in anomalies]
        assert "REPEATED_FAILURES" in types

    def test_stats_returns_dict(self):
        self.detector.log_event("file.pdf", "upload", True)
        stats = self.detector.get_stats()
        assert "total_events" in stats
        assert stats["total_events"] >= 1

    def test_persistence(self):
        self.detector.log_event("persist.pdf", "upload", True)
        # Reload from same file
        d2 = AnomalyDetector(log_path=self.tmpfile)
        assert len(d2.events) == 1


# ─── Blockchain Connector Tests (mock mode) ───────────────────────────────────

from blockchain_connector import BlockchainConnector

class TestBlockchainConnector:

    def setup_method(self):
        # Force mock mode (no Ganache in test environment)
        os.environ.pop("CONTRACT_ADDRESS", None)
        self.bc = BlockchainConnector()

    def test_status_returns_dict(self):
        status = self.bc.status()
        assert "connected" in status
        assert "mode" in status

    def test_store_and_get(self):
        result = self.bc.store_file("test.pdf", "merkle123", "hash456")
        assert "file_id" in result
        file_id = result["file_id"]
        record = self.bc.get_file(file_id)
        assert record["fileName"] == "test.pdf"
        assert record["merkleRoot"] == "merkle123"
        assert record["fileHash"] == "hash456"

    def test_verify_intact(self):
        r = self.bc.store_file("file.txt", "root1", "correcthash")
        result = self.bc.verify_file(r["file_id"], "correcthash")
        assert result["intact"] is True

    def test_verify_tampered(self):
        r = self.bc.store_file("file.txt", "root1", "originalhash")
        result = self.bc.verify_file(r["file_id"], "differenthash")
        assert result["intact"] is False

    def test_total_files_increments(self):
        before = self.bc.get_total_files()
        self.bc.store_file("new.pdf", "root", "hash")
        after = self.bc.get_total_files()
        assert after == before + 1


# ─── Database Tests ───────────────────────────────────────────────────────────

import database

class TestDatabase:

    def setup_method(self):
        self.tmpdb = tempfile.mktemp(suffix='.db')
        os.environ["DB_PATH"] = self.tmpdb
        import importlib
        importlib.reload(database)
        database.init_db()

    def teardown_method(self):
        if os.path.exists(self.tmpdb):
            os.remove(self.tmpdb)

    def test_insert_and_get_file(self):
        fid = database.insert_file("test.pdf","hash1","root1",1024,1,"0xtx","mock")
        record = database.get_file_by_id(fid)
        assert record is not None
        assert record["file_name"] == "test.pdf"
        assert record["status"] == "safe"

    def test_update_status(self):
        fid = database.insert_file("t.pdf","h","r",100,1,"tx","mock")
        database.update_file_status(fid, "tampered")
        record = database.get_file_by_id(fid)
        assert record["status"] == "tampered"

    def test_insert_verification(self):
        fid = database.insert_file("t.pdf","h","r",100,1,"tx","mock")
        vid = database.insert_verification(fid, "t.pdf", "newhash", True, "0xtx")
        verifs = database.get_verifications(fid)
        assert len(verifs) == 1
        assert verifs[0]["is_intact"] == 1

    def test_stats(self):
        database.insert_file("a.pdf","h1","r1",100,1,"tx1","mock")
        database.insert_file("b.pdf","h2","r2",100,2,"tx2","mock")
        stats = database.get_stats()
        assert stats["total_files"] >= 2

    def test_get_all_files(self):
        database.insert_file("x.pdf","h","r",100,1,"tx","mock")
        files = database.get_all_files()
        assert len(files) >= 1


# ─── Flask API Integration Tests ─────────────────────────────────────────────

import io

class TestFlaskAPI:

    def setup_method(self):
        self.tmpdb = tempfile.mktemp(suffix='.db')
        os.environ["DB_PATH"] = self.tmpdb
        import importlib
        import database as db_mod
        importlib.reload(db_mod)

        import backend.app as app_mod
        importlib.reload(app_mod)
        app_mod.init_db()
        self.app = app_mod.app.test_client()
        self.app_mod = app_mod

    def teardown_method(self):
        if os.path.exists(self.tmpdb):
            os.remove(self.tmpdb)

    def test_health(self):
        r = self.app.get('/api/health')
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["status"] == "ok"

    def test_upload_file(self):
        data = dict(file=(io.BytesIO(b"hello blockverify world"), "test.txt"))
        r = self.app.post('/api/upload', data=data, content_type='multipart/form-data')
        assert r.status_code == 200
        body = json.loads(r.data)
        assert body["success"] is True
        assert "file_hash" in body
        assert "merkle_root" in body

    def test_verify_intact(self):
        content = b"this is my document"
        # Upload
        up = self.app.post('/api/upload',
            data=dict(file=(io.BytesIO(content), "doc.txt")),
            content_type='multipart/form-data')
        file_id = json.loads(up.data)["file_id"]

        # Verify with same content
        rv = self.app.post('/api/verify',
            data=dict(file=(io.BytesIO(content), "doc.txt"), file_id=str(file_id)),
            content_type='multipart/form-data')
        body = json.loads(rv.data)
        assert body["is_intact"] is True

    def test_verify_tampered(self):
        content = b"original content"
        up = self.app.post('/api/upload',
            data=dict(file=(io.BytesIO(content), "orig.txt")),
            content_type='multipart/form-data')
        file_id = json.loads(up.data)["file_id"]

        rv = self.app.post('/api/verify',
            data=dict(file=(io.BytesIO(b"tampered content"), "orig.txt"), file_id=str(file_id)),
            content_type='multipart/form-data')
        body = json.loads(rv.data)
        assert body["is_intact"] is False
        assert body["status"] == "tampered"

    def test_stats_endpoint(self):
        r = self.app.get('/api/stats')
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "total_files" in data

    def test_merkle_demo(self):
        r = self.app.post('/api/merkle/demo',
            data=json.dumps({"items":["a","b","c","d"]}),
            content_type='application/json')
        body = json.loads(r.data)
        assert "merkle_root" in body
        assert body["proof_valid"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
