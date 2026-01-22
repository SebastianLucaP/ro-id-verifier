#!/usr/bin/env python3
"""
Romanian ID Verifier - Multi-Account System
--------------------------------------------
Uses PKCS#11 to interact with physical Romanian ID card (C.E.I).

Usage:
    python3 id_card_login.py --action deploy      # Deploy contract
    python3 id_card_login.py --action register    # Register wallet with ID
    python3 id_card_login.py --action login       # Login with ID card
    python3 id_card_login.py --action delete      # Delete account
"""

import argparse
import subprocess
import json
import os
import time

# PKCS#11 and cryptography imports
import pkcs11
from pkcs11 import Mechanism, ObjectClass
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ===== CONFIGURATION =====
WALLET_PEM = "../wallet_first.pem"
PROXY = "https://devnet-gateway.multiversx.com"
CHAIN_ID = "D"
CONTRACT_WASM = "output/id-verifier.wasm"

# PKCS#11 Configuration (Romanian ID Card)
LIB_PATH = "/usr/lib/idplugclassic/libidplug-pkcs11.so"
TOKEN_LABEL = "PKI Application (User PIN)"
AUTH_KEY_LABEL = "Public Key ECC Authentication"  # Label of the authentication public key


def run_command(cmd):
    """Execute shell command."""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, text=True)
    if result.returncode != 0:
        raise Exception("Command failed")
    return ""


def get_wallet_address(pem_path: str = WALLET_PEM):
    """Get wallet address from PEM file."""
    result = subprocess.run(
        f"mxpy wallet convert --infile {pem_path} --in-format pem --out-format address-bech32",
        shell=True, text=True, capture_output=True
    )
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if line.startswith("erd1"):
            return line
    raise Exception(f"Could not extract address from PEM file: {pem_path}")


def generate_ed25519_keypair():
    """Generate Ed25519 keypair (for trusted verifier attestations)."""
    print("Generating Ed25519 Keypair (trusted verifier)...")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, public_bytes


def get_id_card_info(pin: str) -> tuple:
    """
    Extract key_id, public key, and Serial Number from ID card via PKCS#11.
    Returns (key_id_bytes, public_key_hex, serial_number_string, name_string)
    """
    print("Reading ID card info...")
    lib = pkcs11.lib(LIB_PATH)
    token = lib.get_token(token_label=TOKEN_LABEL)
    
    key_id = None
    public_key_hex = None
    serial_number = None
    
    with token.open(user_pin=pin) as session:
        for obj in session.get_objects({pkcs11.Attribute.CLASS: ObjectClass.PUBLIC_KEY}):
            label = obj[pkcs11.Attribute.LABEL]
            if "Authentication" in label and "ECC" in label:
                key_id = obj[pkcs11.Attribute.ID]
                ec_point = obj[pkcs11.Attribute.EC_POINT]
                
                if ec_point[0] == 0x04 and len(ec_point) > 2:
                    public_key_bytes = ec_point[2:]
                else:
                    public_key_bytes = ec_point
                
                public_key_hex = public_key_bytes.hex()
                print(f"Found Key ID: {key_id.hex()[:20]}...")
                print(f"Found Public Key: {public_key_hex[:40]}...")
        
        # Find the ECC Authentication certificate to extract Serial Number
        for obj in session.get_objects({pkcs11.Attribute.CLASS: ObjectClass.CERTIFICATE}):
            label = obj[pkcs11.Attribute.LABEL]
            if "Authentication" in label and "ECC" in label:
                cert_der = bytes(obj[pkcs11.Attribute.VALUE])
                
                from cryptography import x509
                cert = x509.load_der_x509_certificate(cert_der)
                
                for attr in cert.subject:
                    if attr.oid == x509.oid.NameOID.SERIAL_NUMBER:
                        serial_number = attr.value
                        print(f"Found Serial Number: {serial_number}")
    
    # Extract Name (Subject usually has CN)
    # Re-scan for CN to get name
    name = "Unknown Name"
    with token.open(user_pin=pin) as session:
        for obj in session.get_objects({pkcs11.Attribute.CLASS: ObjectClass.CERTIFICATE}):
            label = obj[pkcs11.Attribute.LABEL]
            if "Authentication" in label and "ECC" in label:
                cert_der = bytes(obj[pkcs11.Attribute.VALUE])
                from cryptography import x509
                cert = x509.load_der_x509_certificate(cert_der)
                for attr in cert.subject:
                    if attr.oid == x509.oid.NameOID.COMMON_NAME:
                        name = attr.value
                        # Clean name (remove suffix if present)
                        if " (Autentificare)" in name:
                            name = name.replace(" (Autentificare)", "")
                        print(f"Found Name: {name}")
                        break
                break
    
    if not key_id or not public_key_hex:
        raise Exception("Could not find ECC Authentication key on ID card")
    
    if not serial_number:
        raise Exception("Could not extract Serial Number from certificate")
    
    return key_id, public_key_hex, serial_number, name


def sign_with_id_card(message: bytes, key_id: bytes, pin: str) -> bytes:
    """Sign message using physical ID card via PKCS#11."""
    print("Connecting to ID card...")
    lib = pkcs11.lib(LIB_PATH)
    token = lib.get_token(token_label=TOKEN_LABEL)
    
    with token.open(user_pin=pin) as session:
        priv_key = session.get_key(object_class=ObjectClass.PRIVATE_KEY, id=key_id)
        
        # Hash the data first (P-384 uses SHA-384)
        digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
        digest.update(message)
        hashed_data = digest.finalize()
        
        # Get RAW signature (r|s) - 96 bytes for P-384
        raw_signature = priv_key.sign(hashed_data, mechanism=Mechanism.ECDSA)
        print(f"Raw Signature ({len(raw_signature)} bytes): {raw_signature.hex()[:30]}...")
        
        # Convert RAW (r|s) to DER format for Python cryptography library
        r = int.from_bytes(raw_signature[:48], byteorder='big')
        s = int.from_bytes(raw_signature[48:], byteorder='big')
        der_signature = utils.encode_dss_signature(r, s)
        
        return der_signature


def verify_p384(public_key_hex: str, message: bytes, der_signature: bytes) -> bool:
    """Verify P-384 signature off-chain."""
    public_key_bytes = bytes.fromhex(public_key_hex)
    pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP384R1(),
        public_key_bytes
    )
    
    try:
        pub_key.verify(
            der_signature,
            message,
            ec.ECDSA(hashes.SHA384())
        )
        return True
    except Exception as e:
        print(f"P-384 Verification failed: {e}")
        return False


def sign_ed25519(private_key, message: bytes) -> bytes:
    """Sign attestation with Ed25519 private key."""
    return private_key.sign(message)


def get_contract_address():
    """Load contract address from deploy.json."""
    if os.path.exists("deploy.json"):
        with open("deploy.json", "r") as f:
            data = json.load(f)
            if "contractAddress" in data:
                return data["contractAddress"]
    return None


def deploy_contract(verifier_address: str, verifier_pubkey_hex: str):
    """Deploy contract with trusted verifier."""
    print("\nDeploying Contract...")
    cmd = (
        f"mxpy contract deploy "
        f"--bytecode {CONTRACT_WASM} "
        f"--gas-limit 100000000 "
        f"--arguments addr:{verifier_address} 0x{verifier_pubkey_hex} "
        f"--pem {WALLET_PEM} "
        f"--proxy {PROXY} --chain {CHAIN_ID} "
        f"--send --outfile deploy.json"
    )
    run_command(cmd)
    
    with open("deploy.json", "r") as f:
        data = json.load(f)
        if "contractAddress" in data:
            return data["contractAddress"]
        else:
            return input("Enter Contract Address: ").strip()


def register_account(contract_address: str, serial_hash_hex: str, public_key_hex: str, key_id_hex: str, name: str, pem_path: str = WALLET_PEM):
    """Register account with Serial Number hash as unique identifier."""
    # Check 1: Serial Number not already registered (1 wallet per ID)
    if is_account_registered(contract_address, serial_hash_hex):
        raise Exception("This ID card is already registered! Please login instead.")

    # Check 2: Wallet not already linked to another ID (1 ID per wallet)
    wallet_address = get_wallet_address(pem_path)
    if is_wallet_linked(contract_address, wallet_address):
        raise Exception("This wallet is already linked to another ID! Each wallet can only be linked to one ID card.")

    # Convert name to hex for passing to contract
    name_hex = name.encode('utf-8').hex()
    
    print(f"\nRegistering account on {contract_address} using wallet {pem_path}...")
    cmd = (
        f"mxpy contract call {contract_address} "
        f"--function register "
        f"--gas-limit 10000000 "
        f"--arguments 0x{serial_hash_hex} 0x{public_key_hex} 0x{key_id_hex} 0x{name_hex} "
        f"--pem {pem_path} "
        f"--proxy {PROXY} --chain {CHAIN_ID} "
        f"--send --wait-result"
    )
    run_command(cmd)
    print("Account registered successfully!")


def delete_account(contract_address: str, serial_hash_hex: str, pem_path: str = WALLET_PEM):
    """Delete account by Serial Number hash."""
    # Check if account exists first
    if not is_account_registered(contract_address, serial_hash_hex):
        raise Exception("Account does not exist! Cannot delete.")

    # DEBUG: Check wallet address
    try:
        current_wallet = get_wallet_address(pem_path)
        registered_wallet = get_registered_wallet(contract_address, serial_hash_hex)
        print(f"\n[DEBUG] Deletion Attempt Info:")
        print(f"  - Identity (Serial Hash): {serial_hash_hex[:10]}...")
        print(f"  - Registered Owner:       {registered_wallet}")
        if registered_wallet != "Unknown":
            # Convert current_wallet (bech32) to hex for comparison
            import bech32
            hrp, data = bech32.bech32_decode(current_wallet)
            if data:
                current_wallet_hex = bytes(bech32.convertbits(data, 5, 8, False)).hex()
                if current_wallet_hex != registered_wallet:
                     # Convert registered hex to bech32 for display
                     registered_bech32 = bech32.bech32_encode("erd", bech32.convertbits(bytes.fromhex(registered_wallet), 8, 5, True))
                     raise Exception(f"Wallet mismatch! Account Owner: {registered_bech32}, You: {current_wallet}")
            else:
                 # Fallback
                 if current_wallet != registered_wallet:
                      raise Exception(f"Wallet mismatch! Account Owner: {registered_wallet}, You: {current_wallet}")

    except Exception as e:
        if "Wallet mismatch" in str(e):
             raise e # Propagate mismatch
        print(f"[DEBUG] Failed to get wallet info: {e}")

    print(f"\nDeleting account from {contract_address} using wallet {pem_path}...")
    cmd = (
        f"mxpy contract call {contract_address} "
        f"--function deleteAccount "
        f"--gas-limit 5000000 "
        f"--arguments 0x{serial_hash_hex} "
        f"--pem {pem_path} "
        f"--proxy {PROXY} --chain {CHAIN_ID} "
        f"--send --wait-result"
    )
    run_command(cmd)
    print("Account deleted successfully!")


def submit_attestation(contract_address: str, serial_hash_hex: str, timestamp: int, nonce: int, signature_hex: str, pem_path: str = WALLET_PEM):
    """Submit attestation with Serial Number hash, timestamp and nonce for replay protection."""
    
    # DEBUG: Check wallet address
    try:
        current_wallet = get_wallet_address(pem_path)
        registered_wallet = get_registered_wallet(contract_address, serial_hash_hex)
        print(f"\n[DEBUG] Login Attempt Info:")
        print(f"  - Identity (Serial Hash): {serial_hash_hex[:10]}...")
        print(f"  - Registered Owner:       {registered_wallet}")
        if registered_wallet != "Unknown":
            import bech32
            hrp, data = bech32.bech32_decode(current_wallet)
            if data:
                current_wallet_hex = bytes(bech32.convertbits(data, 5, 8, False)).hex()
                if current_wallet_hex != registered_wallet:
                     # Convert registered hex to bech32 for display
                     registered_bech32 = bech32.bech32_encode("erd", bech32.convertbits(bytes.fromhex(registered_wallet), 8, 5, True))
                     raise Exception(f"Wallet mismatch! Account Owner: {registered_bech32}, You: {current_wallet}")
            else:
                 if current_wallet != registered_wallet:
                      raise Exception(f"Wallet mismatch! Account Owner: {registered_wallet}, You: {current_wallet}")
             
    except Exception as e:
        if "Wallet mismatch" in str(e):
             raise e
        print(f"[DEBUG] Failed to get wallet info: {e}")

    print(f"\nSubmitting attestation for Serial hash (timestamp: {timestamp}, nonce: {nonce})...")
    cmd = (
        f"mxpy contract call {contract_address} "
        f"--function submitAttestation "
        f"--gas-limit 10000000 "
        f"--arguments 0x{serial_hash_hex} {timestamp} {nonce} 0x{signature_hex} "
        f"--pem {pem_path} "
        f"--proxy {PROXY} --chain {CHAIN_ID} "
        f"--send --wait-result"
    )
    run_command(cmd)
    print("Attestation submitted successfully!")


def compute_serial_hash(serial_number: str) -> str:
    """Compute SHA256 hash of Serial Number for privacy."""
    import hashlib
    return hashlib.sha256(serial_number.encode()).hexdigest()


def is_account_registered(contract_address: str, serial_hash_hex: str) -> bool:
    """Check if serial hash is already registered."""
    cmd = (
        f"mxpy contract query {contract_address} "
        f"--function isRegisteredBySerial "
        f"--arguments 0x{serial_hash_hex} "
        f"--proxy {PROXY}"
    )
    print(f"DEBUG: Checking isRegisteredBySerial for {serial_hash_hex[:10]}...")
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    output = res.stdout.strip()
    print(f"DEBUG: isRegistered output: {output}")
    
    # mxpy query output for boolean:
    # ["01"] -> True
    # [""] or [] -> False
    # Or JSON
    
    if not output: return False
    
    try:
        import json
        data = json.loads(output)
        if isinstance(data, list) and len(data) > 0:
            val = data[0]
            if val == "01" or val == "true": return True
            if val == "" or val == "00" or val == "false": return False
            # Check hex 01
            if val.lower() == "01": return True
        return False
    except:
        # Fallback text check
        return "01" in output


def is_wallet_linked(contract_address: str, wallet_address: str) -> bool:
    """Check if a wallet is already linked to an ID."""
    cmd = (
        f"mxpy contract query {contract_address} "
        f"--function isWalletLinked "
        f"--arguments addr:{wallet_address} "
        f"--proxy {PROXY}"
    )
    print(f"DEBUG: Checking isWalletLinked for {wallet_address[:15]}...")
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    output = res.stdout.strip()
    print(f"DEBUG: isWalletLinked output: {output}")
    
    if not output: return False
    
    try:
        import json
        data = json.loads(output)
        if isinstance(data, list) and len(data) > 0:
            val = data[0]
            if val == "01" or val == "true": return True
            if val == "" or val == "00" or val == "false": return False
            if val.lower() == "01": return True
        return False
    except:
        return "01" in output


def query_login_nonce(contract_address: str, serial_hash_hex: str) -> int:
    """Query the current login nonce from the smart contract."""
    cmd = (
        f"mxpy contract query {contract_address} "
        f"--function getLoginNonce "
        f"--arguments 0x{serial_hash_hex} "
        f"--proxy {PROXY}"
    )
    print(f"DEBUG: Querying login nonce for {serial_hash_hex[:10]}...")
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    output = res.stdout.strip()
    print(f"DEBUG: getLoginNonce output: {output}")
    
    if not output:
        return 0
    
    try:
        import json
        data = json.loads(output)
        if isinstance(data, list) and len(data) > 0:
            val = data[0]
            if val == "" or val is None:
                return 0
            # Parse hex string to int
            return int(val, 16) if val else 0
        return 0
    except:
        return 0

def query_registered_key(contract_address: str, serial_hash_hex: str) -> str:
    """Query the contract to get registered public key for a serial hash."""
    print(f"\nQuerying registration status...")
    
    # Debug: Check IsRegistered first
    if not is_account_registered(contract_address, serial_hash_hex):
        print(f"DEBUG: isRegisteredBySerial returned False")
    else:
        print(f"DEBUG: isRegisteredBySerial returned True")
    
    print(f"\nQuerying registered public key from contract...")
    cmd = (
        f"mxpy contract query {contract_address} "
        f"--function getPublicKeyBySerial "
        f"--arguments 0x{serial_hash_hex} "
        f"--proxy {PROXY}"
    )
    print(f"DEBUG: Running command: {cmd}")
    result = subprocess.run(
        cmd,
        shell=True, text=True, capture_output=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Query failed: {result.stderr}")
    
    # Parse the response
    output = result.stdout.strip()
    print(f"DEBUG: Raw Query Output: {output}")
    
    if not output:
        print("Debug: Query output empty")
        return None
    
    try:
        data = None
        if output.startswith('['):
            data = json.loads(output)
            # If it's a list, the first element is our result (hex or base64?)
            # mxpy usually returns base64 for buffers if complicated, but simple output can be hex?
            # Let's assume it's the hex string based on isRegistered output "01"
            if data and len(data) > 0:
                result_str = data[0]
                # If result looks like hex (2 chars per byte), use it directly
                # Public key is 97 bytes -> 194 hex chars
                # But it might be base64.
                # Let's try to decode as base64 first, if valid.
                import base64
                import binascii
                
                # Check if it's already hex (length match, chars match)
                if all(c in '0123456789abcdefABCDEF' for c in result_str):
                     # It is hex
                     if len(result_str) > 0:
                         return result_str
                
                # Try base64
                try:
                    pub_key_bytes = base64.b64decode(result_str)
                    if len(pub_key_bytes) > 0:
                        return pub_key_bytes.hex()
                except binascii.Error:
                    pass
                    
        elif output.startswith('{'):
            data = json.loads(output)
            if data and 'returnData' in data and data['returnData']:
                pub_key_b64 = data['returnData'][0]
                if pub_key_b64:
                    return base64.b64decode(pub_key_b64).hex()
                    
    except Exception as e:
        print(f"Failed to parse query response: {e}")
    
def get_registered_wallet(contract_address: str, serial_hash_hex: str) -> str:
    """Query the contract to get the registered wallet address for a serial hash."""
    cmd = (
        f"mxpy contract query {contract_address} "
        f"--function getWalletBySerial "
        f"--arguments 0x{serial_hash_hex} "
        f"--proxy {PROXY}"
    )
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    output = res.stdout.strip()
    
    try:
        data = json.loads(output)
        if isinstance(data, list) and len(data) > 0:
            # mxpy likely returns bech32 address or hex depending on type
            # ManagedAddress is usually returned as bech32 in recent mxpy versions for queries?
            # Or hex. Let's assume hex if not bech32.
            val = data[0]
            if val.startswith("erd1"): return val
            
            # If hex, convert using mxpy? No, just return hex or convert in python?
            # 32 bytes hex.
            # Let's try to interpret.
            return val 
    except:
        pass
    return "Unknown"




def main():
    parser = argparse.ArgumentParser(description="Romanian ID Card Verifier")
    parser.add_argument("--action", choices=["deploy", "register", "login", "delete"], 
                        required=True, help="Action to perform")
    parser.add_argument("--pin", help="ID card PIN (will prompt if not provided)")
    parser.add_argument("--address", help="Contract address")
    
    args = parser.parse_args()
    
    if args.action == "deploy":
        # Generate Ed25519 verifier key
        ed25519_privkey, ed25519_pubkey = generate_ed25519_keypair()
        
        # Save Ed25519 private key for login
        with open("verifier_key.json", "w") as f:
            json.dump({
                "private_key_hex": ed25519_privkey.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ).hex(),
                "public_key_hex": ed25519_pubkey.hex()
            }, f, indent=2)
        print("Saved verifier key to verifier_key.json")
        
        # Get deployer address
        deployer_address = get_wallet_address()
        print(f"Trusted Verifier Address: {deployer_address}")
        
        # Deploy
        contract_address = deploy_contract(deployer_address, ed25519_pubkey.hex())
        print(f"\n✅ Contract deployed at: {contract_address}")
        print("Next: python3 id_card_login.py --action register")
        

        
    elif args.action == "register":
        contract_address = args.address or get_contract_address()
        if not contract_address:
            print("Error: No contract address. Deploy first or use --address")
            return
        
        # Get PIN
        pin = args.pin
        if not pin:
            import getpass
            pin = getpass.getpass("Enter ID Card PIN: ")
        
        # Extract key info from ID card
        print("\n--- READING ID CARD ---")
        try:
            key_id, public_key_hex, serial_number, name = get_id_card_info(pin)
        except Exception as e:
            print(f"❌ Failed to read ID card: {e}")
            return
        
        # Compute Serial Hash
        serial_hash = compute_serial_hash(serial_number)
        print(f"Serial Hash: {serial_hash[:20]}...")
        
        # Save key info locally for login
        with open("id_card_info.json", "w") as f:
            json.dump({
                "key_id_hex": key_id.hex(),
                "public_key_hex": public_key_hex,
                "serial_hash_hex": serial_hash
            }, f, indent=2)
        print("Saved ID card info to id_card_info.json")
        
        # Register on contract
        register_account(contract_address, serial_hash, public_key_hex, key_id.hex(), name)
        
        print("\n✅ Account registered!")
        print("Next: python3 id_card_login.py --action login")
        
    elif args.action == "login":
        contract_address = args.address or get_contract_address()
        if not contract_address:
            print("Error: No contract address. Deploy first or use --address")
            return
        
        # Load Ed25519 verifier key
        if not os.path.exists("verifier_key.json"):
            print("Error: verifier_key.json not found. Run --action deploy first.")
            return
        
        with open("verifier_key.json", "r") as f:
            verifier_key_data = json.load(f)
        
        ed25519_privkey = ed25519.Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(verifier_key_data["private_key_hex"])
        )
        
        # Get user address
        user_address = get_wallet_address()
        print(f"User Address: {user_address}")
        
        # Get PIN
        pin = args.pin
        if not pin:
            import getpass
            pin = getpass.getpass("Enter ID Card PIN: ")
        
        # Load ID card info or extract fresh
        print("\n--- READING ID CARD (to get key_id and Serial No) ---")
        try:
            key_id, public_key_hex_card, serial_number, name = get_id_card_info(pin)
            serial_hash = compute_serial_hash(serial_number)
            print(f"Serial Hash: {serial_hash[:20]}...")
        except Exception as e:
            print(f"❌ Failed to read ID card: {e}")
            return
        
        # 1. Query registered public key from contract (CRITICAL SECURITY STEP)
        registered_pubkey_hex = query_registered_key(contract_address, serial_hash)
        
        if not registered_pubkey_hex:
            print("❌ Account not found on contract for this Serial Number!")
            return
        
        print(f"✅ Found registered account for Serial Number")
        print(f"Registered PubKey: {registered_pubkey_hex[:40]}...")
        print(f"Welcome, {name}!")
        
        # 2. Sign login request with physical ID card (with nonce + timestamp for replay protection)
        print("\n--- SIGNING WITH ID CARD ---")
        
        # Generate nonce and timestamp for replay protection
        login_nonce = os.urandom(16)  # 16 random bytes
        login_timestamp = int(time.time())
        login_message = b"login:" + login_nonce + str(login_timestamp).encode()
        print(f"Login message includes nonce + timestamp (T={login_timestamp})")
        
        try:
            p384_signature = sign_with_id_card(login_message, key_id, pin)
            print("✅ Message signed with ID card!")
        except Exception as e:
            print(f"❌ Failed to sign with ID card: {e}")
            return
        
        # 3. Verify P-384 signature against REGISTERED key (not the one from card)
        print("\n--- OFF-CHAIN P-384 VERIFICATION ---")
        # Verify against the key stored in contract
        is_valid = verify_p384(registered_pubkey_hex, login_message, p384_signature)
        
        if not is_valid:
            print("❌ P-384 signature verification failed against REGISTERED key!")
            print("SECURITY ALERT: ID card key does not match registered key!")
            return
        
        print("✅ P-384 signature verified against REGISTERED key!")
        
        # 4. Create Ed25519 attestation (with timestamp and nonce for on-chain replay protection)
        print("\n--- CREATING ED25519 ATTESTATION ---")
        import bech32
        _, data = bech32.bech32_decode(user_address)
        if data is None:
            print("Failed to decode user address")
            return
        user_address_bytes = bytes(bech32.convertbits(data, 5, 8, False))
        
        # Query current nonce and calculate next
        current_nonce = query_login_nonce(contract_address, serial_hash)
        next_nonce = current_nonce + 1
        print(f"Current nonce: {current_nonce}, using nonce: {next_nonce}")
        
        # Include timestamp AND nonce in attestation message (8 bytes each, big-endian)
        attestation_timestamp = int(time.time())
        attestation_msg = (b"login_ok:" + 
                          bytes.fromhex(serial_hash) + 
                          attestation_timestamp.to_bytes(8, 'big') +
                          next_nonce.to_bytes(8, 'big'))
        ed25519_signature = sign_ed25519(ed25519_privkey, attestation_msg)
        print(f"Ed25519 Signature: {ed25519_signature.hex()[:40]}...")
        print(f"Attestation timestamp: {attestation_timestamp}, nonce: {next_nonce}")
        
        # 5. Submit attestation to contract (including timestamp and nonce)
        print("\n--- SUBMITTING ON-CHAIN ATTESTATION ---")
        time.sleep(2)
        submit_attestation(contract_address, serial_hash, attestation_timestamp, next_nonce, ed25519_signature.hex())
        
        print("\n🎉 Login with Romanian ID Card complete!")
        print("Your identity has been verified on-chain!")
        
    elif args.action == "delete":
        contract_address = args.address or get_contract_address()
        if not contract_address:
            print("Error: No contract address. Deploy first or use --address")
            return
        
        # Need Serial to delete
        pin = args.pin
        if not pin:
            import getpass
            pin = getpass.getpass("Enter ID Card PIN (to identify account): ")
        
        try:
            _, _, serial_number, _ = get_id_card_info(pin)
            serial_hash = compute_serial_hash(serial_number)
        except Exception as e:
            print(f"❌ Failed to read ID card: {e}")
            return
            
        delete_account(contract_address, serial_hash)
        print("\n✅ Account deleted!")


if __name__ == "__main__":
    main()
