"""
Blockchain connector for BlockVerify.
Connects to Ganache (local) or any Web3-compatible chain.
Falls back to mock mode if no chain is available.
"""

import os
import json
from datetime import datetime

# Try importing web3 — gracefully degrade if not installed
try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False

# Compiled ABI for FileIntegrity.sol (matches the contract)
CONTRACT_ABI = [
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "fileId", "type": "uint256"},
            {"indexed": False, "name": "fileName", "type": "string"},
            {"indexed": False, "name": "merkleRoot", "type": "string"},
            {"indexed": False, "name": "timestamp", "type": "uint256"}
        ],
        "name": "FileStored",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "fileId", "type": "uint256"},
            {"indexed": False, "name": "isIntact", "type": "bool"},
            {"indexed": False, "name": "timestamp", "type": "uint256"}
        ],
        "name": "FileVerified",
        "type": "event"
    },
    {
        "inputs": [
            {"name": "_fileName", "type": "string"},
            {"name": "_merkleRoot", "type": "string"},
            {"name": "_fileHash", "type": "string"}
        ],
        "name": "storeFile",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"name": "_fileId", "type": "uint256"}],
        "name": "getFile",
        "outputs": [
            {"name": "fileName", "type": "string"},
            {"name": "merkleRoot", "type": "string"},
            {"name": "fileHash", "type": "string"},
            {"name": "timestamp", "type": "uint256"},
            {"name": "uploader", "type": "address"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"name": "_fileId", "type": "uint256"},
            {"name": "_newHash", "type": "string"}
        ],
        "name": "verifyFile",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getTotalFiles",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

# In-memory mock store for when Ganache isn't running
_mock_store = {}
_mock_counter = 0


def _mock_store_file(file_name, merkle_root, file_hash):
    global _mock_counter
    _mock_counter += 1
    _mock_store[_mock_counter] = {
        "fileName": file_name,
        "merkleRoot": merkle_root,
        "fileHash": file_hash,
        "timestamp": int(datetime.utcnow().timestamp()),
        "uploader": "0xMOCK0000000000000000000000000000000000"
    }
    return _mock_counter


def _mock_get_file(file_id):
    r = _mock_store.get(file_id)
    if not r:
        raise Exception(f"File ID {file_id} not found in mock store")
    return r


def _mock_verify_file(file_id, new_hash):
    r = _mock_store.get(file_id)
    if not r:
        raise Exception(f"File ID {file_id} not found")
    return r["fileHash"] == new_hash


class BlockchainConnector:
    def __init__(self):
        self.w3 = None
        self.contract = None
        self.account = None
        self.mock_mode = True
        self._connect()

    def _connect(self):
        ganache_url = os.environ.get("GANACHE_URL", "http://127.0.0.1:7545")
        contract_address = os.environ.get("CONTRACT_ADDRESS", "")

        if not WEB3_AVAILABLE:
            print("[Blockchain] web3 not installed — running in mock mode")
            return

        try:
            self.w3 = Web3(Web3.HTTPProvider(ganache_url))
            if not self.w3.is_connected():
                print(f"[Blockchain] Cannot connect to {ganache_url} — mock mode")
                return

            self.account = self.w3.eth.accounts[0]

            if contract_address:
                checksum = Web3.to_checksum_address(contract_address)
                self.contract = self.w3.eth.contract(address=checksum, abi=CONTRACT_ABI)
                self.mock_mode = False
                print(f"[Blockchain] Connected to {ganache_url}, contract at {contract_address}")
            else:
                print("[Blockchain] CONTRACT_ADDRESS not set — mock mode")
        except Exception as e:
            print(f"[Blockchain] Connection error: {e} — mock mode")

    def store_file(self, file_name: str, merkle_root: str, file_hash: str) -> dict:
        if self.mock_mode:
            file_id = _mock_store_file(file_name, merkle_root, file_hash)
            return {"file_id": file_id, "tx_hash": f"0xMOCK{file_id:064x}", "mode": "mock"}

        tx = self.contract.functions.storeFile(
            file_name, merkle_root, file_hash
        ).transact({"from": self.account, "gas": 3000000})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        # Parse FileStored event to get fileId
        logs = self.contract.events.FileStored().process_receipt(receipt)
        file_id = logs[0]["args"]["fileId"] if logs else None
        return {
            "file_id": file_id,
            "tx_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "mode": "blockchain"
        }

    def get_file(self, file_id: int) -> dict:
        if self.mock_mode:
            r = _mock_get_file(file_id)
            return {**r, "mode": "mock"}

        result = self.contract.functions.getFile(file_id).call()
        return {
            "fileName": result[0],
            "merkleRoot": result[1],
            "fileHash": result[2],
            "timestamp": result[3],
            "uploader": result[4],
            "mode": "blockchain"
        }

    def verify_file(self, file_id: int, new_hash: str) -> dict:
        if self.mock_mode:
            intact = _mock_verify_file(file_id, new_hash)
            return {"intact": intact, "tx_hash": "0xMOCK_VERIFY", "mode": "mock"}

        tx = self.contract.functions.verifyFile(
            file_id, new_hash
        ).transact({"from": self.account, "gas": 200000})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        logs = self.contract.events.FileVerified().process_receipt(receipt)
        intact = logs[0]["args"]["isIntact"] if logs else False
        return {
            "intact": intact,
            "tx_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "mode": "blockchain"
        }

    def get_total_files(self) -> int:
        if self.mock_mode:
            return _mock_counter
        return self.contract.functions.getTotalFiles().call()

    def is_connected(self) -> bool:
        if self.mock_mode:
            return True  # mock always "connected"
        return self.w3 and self.w3.is_connected()

    def status(self) -> dict:
        if self.mock_mode:
            return {"connected": True, "mode": "mock", "network": "local-mock"}
        return {
            "connected": self.w3.is_connected(),
            "mode": "blockchain",
            "network": "ganache",
            "block": self.w3.eth.block_number,
            "account": self.account
        }


# Singleton
_connector = None


def get_connector() -> BlockchainConnector:
    global _connector
    if _connector is None:
        _connector = BlockchainConnector()
    return _connector
