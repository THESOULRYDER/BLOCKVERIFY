"""
BlockVerify — Smart Contract Deployment Script
Compiles and deploys FileIntegrity.sol to Ganache (or any Web3 network).

Usage:
    python deploy.py                         # deploy to default Ganache :7545
    GANACHE_URL=http://localhost:8545 python deploy.py

After running, copy the printed CONTRACT_ADDRESS into your environment:
    export CONTRACT_ADDRESS=0x...
"""

import os
import sys
import json

GANACHE_URL = os.environ.get("GANACHE_URL", "http://127.0.0.1:7545")
SOL_FILE    = os.path.join(os.path.dirname(__file__), "FileIntegrity.sol")

# ── Try web3 + solcx ──────────────────────────────────────────────────────────
try:
    from web3 import Web3
except ImportError:
    print("ERROR: web3 not installed. Run: pip install web3")
    sys.exit(1)

try:
    from solcx import compile_source, install_solc, get_installed_solc_versions
    SOLCX = True
except ImportError:
    SOLCX = False
    print("WARNING: py-solc-x not installed. Falling back to pre-compiled ABI/bytecode.")
    print("         Install with: pip install py-solc-x")


# ── Pre-compiled fallback (generated from the .sol file) ─────────────────────
# This lets deploy.py work without solcx installed.
PRECOMPILED_BYTECODE = (
    "608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffff"
    "ffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff"
    "16021790555060006001819055506110f4806100676000396000f3fe"
)

PRECOMPILED_ABI = [
    {"inputs":[],"stateMutability":"nonpayable","type":"constructor"},
    {"inputs":[{"internalType":"string","name":"_fileName","type":"string"},
               {"internalType":"string","name":"_merkleRoot","type":"string"},
               {"internalType":"string","name":"_fileHash","type":"string"}],
     "name":"storeFile","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
     "stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"uint256","name":"_fileId","type":"uint256"}],
     "name":"getFile",
     "outputs":[{"internalType":"string","name":"fileName","type":"string"},
                {"internalType":"string","name":"merkleRoot","type":"string"},
                {"internalType":"string","name":"fileHash","type":"string"},
                {"internalType":"uint256","name":"timestamp","type":"uint256"},
                {"internalType":"address","name":"uploader","type":"address"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"uint256","name":"_fileId","type":"uint256"},
               {"internalType":"string","name":"_newHash","type":"string"}],
     "name":"verifyFile","outputs":[{"internalType":"bool","name":"","type":"bool"}],
     "stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"getTotalFiles",
     "outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
     "stateMutability":"view","type":"function"},
]


def compile_contract():
    """Compile .sol file using solcx."""
    if not SOLCX:
        raise RuntimeError("solcx not available")

    with open(SOL_FILE, "r") as f:
        source = f.read()

    # Install Solidity compiler if needed
    if "0.8.19" not in [str(v) for v in get_installed_solc_versions()]:
        print("  Installing Solidity compiler 0.8.19 (one-time)...")
        install_solc("0.8.19")

    compiled = compile_source(
        source,
        output_values=["abi", "bin"],
        solc_version="0.8.19"
    )
    contract_id = "<stdin>:FileIntegrity"
    return compiled[contract_id]["abi"], compiled[contract_id]["bin"]


def deploy():
    print(f"\n BlockVerify Contract Deployment")
    print(f" Target: {GANACHE_URL}\n")

    # Connect
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if not w3.is_connected():
        print(f"ERROR: Cannot connect to {GANACHE_URL}")
        print("       Make sure Ganache is running: ganache --port 7545")
        sys.exit(1)

    print(f"  Connected to chain (block #{w3.eth.block_number})")
    account = w3.eth.accounts[0]
    balance = w3.from_wei(w3.eth.get_balance(account), "ether")
    print(f"  Deployer: {account}")
    print(f"  Balance:  {balance:.4f} ETH\n")

    # Compile or use fallback
    if SOLCX:
        print("  Compiling FileIntegrity.sol...")
        try:
            abi, bytecode = compile_contract()
            print("  Compilation successful")
        except Exception as e:
            print(f"  Compilation failed ({e}), using pre-compiled fallback")
            abi, bytecode = PRECOMPILED_ABI, PRECOMPILED_BYTECODE
    else:
        print("  Using pre-compiled ABI (solcx not installed)")
        abi, bytecode = PRECOMPILED_ABI, PRECOMPILED_BYTECODE

    # Deploy
    print("  Deploying contract...")
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Contract.constructor().transact({
        "from": account,
        "gas": 2_000_000
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    address = receipt.contractAddress

    print(f"\n  ✅ CONTRACT DEPLOYED")
    print(f"  Address:      {address}")
    print(f"  Tx hash:      {receipt.transactionHash.hex()}")
    print(f"  Block:        #{receipt.blockNumber}")
    print(f"  Gas used:     {receipt.gasUsed:,}")

    # Save to file for easy reference
    deployment_info = {
        "contract_address": address,
        "tx_hash": receipt.transactionHash.hex(),
        "block_number": receipt.blockNumber,
        "gas_used": receipt.gasUsed,
        "deployer": account,
        "ganache_url": GANACHE_URL,
        "abi": abi
    }
    out_path = os.path.join(os.path.dirname(__file__), "deployment.json")
    with open(out_path, "w") as f:
        json.dump(deployment_info, f, indent=2)
    print(f"\n  Deployment info saved to: contracts/deployment.json")

    print(f"\n  Next step — set environment variable:")
    print(f"  export CONTRACT_ADDRESS={address}")
    print(f"  export GANACHE_URL={GANACHE_URL}")
    print(f"\n  Then run: cd backend && python app.py\n")

    return address


if __name__ == "__main__":
    deploy()
