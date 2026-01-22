from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import json
import time

import tempfile

# Add current directory to path to import local modules
sys.path.append(os.getcwd())

# Import existing middleware logic
try:
    from id_card_login import (
        get_id_card_info, compute_serial_hash, 
        register_account, query_registered_key, 
        sign_with_id_card, verify_p384, 
        submit_attestation, delete_account,
        get_contract_address, generate_ed25519_keypair,
        sign_ed25519, get_wallet_address, is_wallet_linked,
        query_login_nonce,
        LIB_PATH, TOKEN_LABEL, WALLET_PEM, PROXY, CHAIN_ID
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    import bech32
except ImportError as e:
    print(f"Error importing middleware: {e}")
    sys.exit(1)

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

def get_verifier_key():
    if not os.path.exists("verifier_key.json"):
        raise Exception("Verifier key not found. Please deploy contract first.")
    
    with open("verifier_key.json", "r") as f:
        data = json.load(f)
        return ed25519.Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(data["private_key_hex"])
        )

@app.route('/api/status', methods=['GET'])
def status():
    contract_address = get_contract_address()
    return jsonify({
        "status": "online",
        "contract_address": contract_address,
        "is_deployed": bool(contract_address)
    })

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        pin = data.get('pin')
        pem_content = data.get('pemContent')
        contract_address = get_contract_address()
        
        if not contract_address:
            return jsonify({"error": "Contract not deployed"}), 400
        if not pin:
            return jsonify({"error": "PIN required"}), 400
        
        pem_path = WALLET_PEM  # Default
        temp_pem = None
        
        if pem_content:
            # Create temp file for PEM
            temp_pem = tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='w')
            temp_pem.write(pem_content)
            temp_pem.close()
            pem_path = temp_pem.name
            print(f"Using uploaded wallet: {pem_path}")

        # 1. Read ID Card
        try:
            key_id, public_key_hex, serial_number, name = get_id_card_info(pin)
        except Exception as e:
            if temp_pem: os.unlink(temp_pem.name)
            return jsonify({"error": f"Failed to read ID card: {str(e)}"}), 500

        # 2. Compute Hash
        serial_hash = compute_serial_hash(serial_number)
        
        # 3. Register
        try:
            register_account(contract_address, serial_hash, public_key_hex, key_id.hex(), name, pem_path)
        except Exception as e:
            if temp_pem: os.unlink(temp_pem.name)
            raise e
            
        if temp_pem: os.unlink(temp_pem.name)
        
        return jsonify({
            "success": True,
            "message": f"Account registered successfully for {name}!",
            "serial": serial_number,
            "serial_hash": serial_hash,
            "name": name
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        pin = data.get('pin')
        pem_content = data.get('pemContent')
        contract_address = get_contract_address()
        
        if not contract_address:
            return jsonify({"error": "Contract not deployed"}), 400
        if not pin:
            return jsonify({"error": "PIN required"}), 400
        if not pem_content:
            return jsonify({"error": "Wallet PEM file is REQUIRED for login"}), 400

        pem_path = None
        temp_pem = None
        
        # Create temp file for PEM
        temp_pem = tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='w')
        temp_pem.write(pem_content)
        temp_pem.close()
        pem_path = temp_pem.name
        print(f"Using uploaded wallet for login: {pem_path}")

        # 1. Read ID Card
        try:
            key_id, public_key_hex_card, serial_number, name = get_id_card_info(pin)
        except Exception as e:
            if temp_pem: os.unlink(temp_pem.name)
            return jsonify({"error": f"Failed to read ID card: {str(e)}"}), 500

        serial_hash = compute_serial_hash(serial_number)

        # 2. Query Contract
        registered_pubkey_hex = query_registered_key(contract_address, serial_hash)
        
        if not registered_pubkey_hex:
            return jsonify({
                "success": False,
                "error": "Account not found on contract for this Serial Number!"
            }), 404

        # 3. Sign Challenge (with nonce + timestamp for replay protection)
        login_nonce = os.urandom(16)  # 16 random bytes
        login_timestamp = int(time.time())
        login_message = b"login:" + login_nonce + str(login_timestamp).encode()
        
        try:
            p384_signature = sign_with_id_card(login_message, key_id, pin)
        except Exception as e:
            return jsonify({"error": f"Failed to sign with ID card: {str(e)}"}), 500

        # 4. Verify Signature
        is_valid = verify_p384(registered_pubkey_hex, login_message, p384_signature)
        
        if not is_valid:
            return jsonify({
                "success": False,
                "error": "Signature verification failed! ID card key matches NOT registered key."
            }), 401

        # 5. Submit Attestation (with timestamp and nonce for on-chain replay protection)
        try:
            verifier_privkey = get_verifier_key()
            
            # Query current nonce and calculate next
            current_nonce = query_login_nonce(contract_address, serial_hash)
            next_nonce = current_nonce + 1
            
            # Include timestamp AND nonce in attestation message (8 bytes each, big-endian)
            attestation_timestamp = int(time.time())
            attestation_msg = (b"login_ok:" + 
                              bytes.fromhex(serial_hash) + 
                              attestation_timestamp.to_bytes(8, 'big') +
                              next_nonce.to_bytes(8, 'big'))
            ed25519_signature = sign_ed25519(verifier_privkey, attestation_msg)
            
            submit_attestation(contract_address, serial_hash, attestation_timestamp, next_nonce, ed25519_signature.hex(), pem_path)
        except Exception as e:
            if temp_pem: os.unlink(temp_pem.name)
            return jsonify({"error": f"Attestation failed: {str(e)}"}), 500
            
        if temp_pem: os.unlink(temp_pem.name)

        return jsonify({
            "success": True,
            "message": f"Welcome back, {name}! Identity verified on-chain.",
            "serial": serial_number,
            "serial_hash": serial_hash,
            "name": name
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/delete', methods=['POST'])
def delete():
    try:
        data = request.json
        pin = data.get('pin')
        pem_content = data.get('pemContent')
        contract_address = get_contract_address()
        
        if not contract_address:
            return jsonify({"error": "Contract not deployed"}), 400
        if not pin:
            return jsonify({"error": "PIN required"}), 400

        pem_path = WALLET_PEM  # Default
        temp_pem = None
        
        if pem_content:
            # Create temp file for PEM
            temp_pem = tempfile.NamedTemporaryFile(delete=False, suffix='.pem', mode='w')
            temp_pem.write(pem_content)
            temp_pem.close()
            pem_path = temp_pem.name
            print(f"Using uploaded wallet for deletion: {pem_path}")

        # 1. Read ID for Serial
        try:
            _, _, serial_number, _ = get_id_card_info(pin)
            serial_hash = compute_serial_hash(serial_number)
        except Exception as e:
            if temp_pem: os.unlink(temp_pem.name)
            return jsonify({"error": f"Failed to read ID card: {str(e)}"}), 500

        # 2. Delete
        try:
            delete_account(contract_address, serial_hash, pem_path)
        except Exception as e:
            if temp_pem: os.unlink(temp_pem.name)
            raise e
            
        if temp_pem: os.unlink(temp_pem.name)
        
        return jsonify({
            "success": True,
            "message": "Account deleted successfully!"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Flask Middleware API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)
