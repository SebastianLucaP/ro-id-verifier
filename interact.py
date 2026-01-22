import argparse
import sys
import subprocess
import json
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Configuration
WALLET_PATH = "../wallet.json" # Relative to id-verifier/ directory where we verify running
PROXY = "https://devnet-gateway.multiversx.com"
CHAIN_ID = "D"
CONTRACT_WASM = "output/id-verifier.wasm"

def generate_identity():
    print("Generating P-384 Identity...")
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    
    # Get SEC1 Bytes (Compressed or Uncompressed - we'll use uncompressed for now as per contract comments, usually 97 bytes)
    # Rust p384 crate handles both, let's use Uncompressed (starts with 0x04)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return private_key, public_bytes

def sign_message(private_key, message_bytes):
    signature = private_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA384())
    )
    return signature

def run_command(cmd):
    print(f"Running: {cmd}")
    # Remove capture_output=True to allow user interaction (e.g. password prompt)
    result = subprocess.run(cmd, shell=True, text=True)
    if result.returncode != 0:
        # print(f"Error: {result.stderr}") # stderr is now printed to console directly
        raise Exception("Command failed")
    return "" # stdout is not captured anymore cannot return it.


def deploy_contract(public_key_hex):
    print("\nDeploying Contract...")
    cmd = (
        f"mxpy contract deploy "
        f"--bytecode {CONTRACT_WASM} "
        f"--gas-limit 500000000 "
        f"--arguments 0x{public_key_hex} "
        f"--keyfile {WALLET_PATH} "
        f"--proxy {PROXY} --chain {CHAIN_ID} "
        f"--send --outfile deploy.json"
    )
    run_command(cmd)
    
    with open("deploy.json", "r") as f:
        data = json.load(f)
        # Try to get address from top-level 'contractAddress' (standard in recent mxpy)
        # or fallback to emittedTransaction if needed (though top-level is safer)
        if "contractAddress" in data:
            address = data["contractAddress"]
        elif "emittedTransaction" in data and "address" in data["emittedTransaction"]:
             address = data["emittedTransaction"]["address"]
        else:
            print("\n⚠️  Could not automatically extract Contract Address from deploy.json.")
            print("Please copy the 'Contract address' from the logs above.")
            address = input("Enter Contract Address: ").strip()
            
        print(f"Contract deployed at: {address}")
        return address

def login(contract_address, private_key):
    print("\nAttempting Login...")
    message = b"login_request"
    signature = sign_message(private_key, message)
    
    msg_hex = message.hex()
    sig_hex = signature.hex() # DER encoded signature
    
    cmd = (
        f"mxpy contract call {contract_address} "
        f"--function login "
        f"--gas-limit 500000000 "
        f"--arguments 0x{msg_hex} 0x{sig_hex} "
        f"--keyfile {WALLET_PATH} "
        f"--proxy {PROXY} --chain {CHAIN_ID} "
        f"--send"
    )
    out = run_command(cmd)
    print("Login Transaction sent.")
    print(out)

def upgrade_contract(contract_address, public_key_hex):
    print(f"\nUpgrading Contract at {contract_address}...")
    cmd = (
        f"mxpy contract upgrade {contract_address} "
        f"--bytecode {CONTRACT_WASM} "
        f"--gas-limit 500000000 "
        f"--arguments 0x{public_key_hex} "
        f"--keyfile {WALLET_PATH} "
        f"--proxy {PROXY} --chain {CHAIN_ID} "
        f"--send"
    )
    run_command(cmd)
    print("Upgrade Transaction sent.")

def main():
    parser = argparse.ArgumentParser(description="MultiversX ID Verifier Interaction Script")
    parser.add_argument("--action", choices=["deploy", "upgrade", "login"], default="deploy", help="Action to perform")
    parser.add_argument("--address", help="Contract address (required for upgrade/login without deploy.json)")
    
    args = parser.parse_args()
    
    # 1. Generate ID (New session = New ID usually, unless we want to persist)
    # For testing 'upgrade', we want a new ID to verify we can change the key.
    # For 'login' only, this random key will likely fail unless it matches on-chain storage.
    priv_key, pub_bytes = generate_identity()
    pub_hex = pub_bytes.hex()
    print(f"Generated Mock ID Public Key (Hex): {pub_hex}")

    contract_address = args.address
    
    # Fallback to hardcoded/saved address if not provided and not deploying
    if not contract_address and args.action in ["upgrade", "login"]:
        if os.path.exists("deploy.json"):
             with open("deploy.json", "r") as f:
                data = json.load(f)
                if "contractAddress" in data:
                    contract_address = data["contractAddress"]
                elif "emittedTransaction" in data and "address" in data["emittedTransaction"]:
                    contract_address = data["emittedTransaction"]["address"]
        
        # Hardcoded fallback as requested earlier if file fails
        if not contract_address:
             print("Using hardcoded address: erd1qqqqqqqqqqqqqpgqcymtfdh86mcn4asv4smvcaqktrz3g0npsdfq2x2gzk")
             contract_address = "erd1qqqqqqqqqqqqqpgqcymtfdh86mcn4asv4smvcaqktrz3g0npsdfq2x2gzk"

    try:
        if args.action == "deploy":
            contract_address = deploy_contract(pub_hex)
            print("Waiting 10s for block propagation...")
            time.sleep(10)
            login(contract_address, priv_key)

        elif args.action == "upgrade":
            if not contract_address:
                raise ValueError("Contract address required for upgrade")
            upgrade_contract(contract_address, pub_hex)
            print("Waiting 10s for block propagation...")
            time.sleep(10)
            login(contract_address, priv_key)
            
        elif args.action == "login":
             if not contract_address:
                raise ValueError("Contract address required for login")
             print(f"Using Contract Address: {contract_address}")
             login(contract_address, priv_key)
             print("Note: Login will fail on-chain if this generated Key doesn't match the Contract's stored Key.")

    except Exception as e:
        print(f"Operation failed: {e}")
        print("Ensure 'mxpy' is installed, wallet has funds, and paths are correct.")

if __name__ == "__main__":
    main()
