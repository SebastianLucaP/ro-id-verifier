# Romanian ID Card Verifier

A blockchain-based identity verification system that uses Romanian electronic ID cards (C.E.I.) for secure authentication on the MultiversX blockchain.

## Description

This project implements a decentralized identity verification system that:
- Extracts authentication credentials from Romanian ID cards via PKCS#11
- Registers ID card identities on a MultiversX smart contract
- Provides cryptographic login verification with replay protection
- Features a React frontend for user interaction

### Architecture

- **Smart Contract** (Rust): MultiversX smart contract for storing and verifying identities
- **Backend** (Python/Flask): Middleware API that bridges the frontend with PKCS#11 and blockchain
- **Frontend** (React/Vite): Web interface for registration, login, and account management

## Prerequisites

### Hardware
- Romanian electronic ID card (C.E.I.) with valid PKI certificate
- Smart card reader compatible with PKCS#11

### Software
- **Linux**
- **Python 3.10+**
- **Node.js 18+** and npm
- **Rust** and Cargo (for contract compilation)
- **mxpy** (MultiversX SDK CLI)
- **PKCS#11 library** for Romanian ID cards

### Blockchain
- A MultiversX wallet with testnet/devnet EGLD
- Wallet PEM file for contract interactions

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/SebastianLucaP/ro-id-verifier.git
cd id-verifier
```

### 2. Backend Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Frontend Setup
```bash
cd frontend
npm install
```

### 4. Smart Contract (Optional - if you need to redeploy)
```bash
# Build the contract
sc-meta all build

# Deploy (requires wallet PEM and testnet EGLD)
python3 id_card_login.py --action deploy
```

## Running the Application

### 1. Start the Backend API
```bash
# From the id-verifier directory
source venv/bin/activate
python3 api.py
```
The API will start on `http://localhost:5000`

### 2. Start the Frontend
```bash
# From the frontend directory
cd frontend
npm run dev
```
The frontend will be available at `http://localhost:5173`

## Usage

1. **Connect Wallet**: Use the xPortal mobile app or web wallet extension to connect
2. **Insert ID Card**: Insert your Romanian ID card into the card reader
3. **Register**: Register your ID card identity on the blockchain
4. **Login**: Authenticate using your ID card credentials
5. **Delete Account**: Remove your identity from the blockchain when needed

## Project Structure

```
id-verifier/
├── src/
│   └── id_verifier.rs      # MultiversX smart contract
├── frontend/
│   └── src/
│       ├── App.jsx         # Main React component
│       └── index.css       # Styles
├── api.py                  # Flask REST API
├── id_card_login.py        # Core ID card interaction logic
├── requirements.txt        # Python dependencies
├── Cargo.toml              # Rust dependencies
└── deploy.json             # Contract deployment info
```

## Security Features

- **Replay Protection**: Nonce-based and timestamp validation
- **Ownership Enforcement**: Only the registering wallet can login/delete
- **Privacy**: Serial numbers are hashed (SHA-256) before on-chain storage
- **Ed25519 Attestations**: Trusted verifier signatures for login verification
