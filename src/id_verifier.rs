#![no_std]

multiversx_sc::imports!();
multiversx_sc::derive_imports!();

/// Account data stored by Serial Number hash
#[derive(TypeAbi, TopEncode, TopDecode, NestedEncode, NestedDecode, Clone)]
pub struct Account<M: ManagedTypeApi> {
    pub public_key: ManagedBuffer<M>,  // P-384 SEC1 bytes
    pub key_id: ManagedBuffer<M>,      // PKCS#11 key ID
    pub name: ManagedBuffer<M>,        // Name from ID Card
    pub wallet: ManagedAddress<M>,     // Owner wallet
}

#[multiversx_sc::contract]
pub trait IdVerifier {
    /// Initialize with trusted verifier address and Ed25519 pubkey
    #[init]
    fn init(&self, trusted_verifier: ManagedAddress, trusted_verifier_pubkey: ManagedBuffer) {
        self.trusted_verifier().set(&trusted_verifier);
        self.trusted_verifier_pubkey().set(&trusted_verifier_pubkey);
    }

    // ===== ACCOUNT MANAGEMENT =====

    /// Register account with Serial Number hash as unique identifier
    /// serial_hash: SHA256 of the ID Serial Number
    /// public_key: P-384 public key from ID card
    /// key_id: PKCS#11 key ID
    /// name: Name extracted from ID card (Common Name)
    #[endpoint]
    fn register(&self, serial_hash: ManagedBuffer, public_key: ManagedBuffer, key_id: ManagedBuffer, name: ManagedBuffer) {
        let caller = self.blockchain().get_caller();
        
        // Check 1: Serial Number not already registered (1 wallet per ID)
        require!(self.accounts_by_serial(&serial_hash).is_empty(), "Serial already registered");
        
        // Check 2: Wallet not already linked to another ID (1 ID per wallet)
        require!(self.serial_by_wallet(&caller).is_empty(), "Wallet already linked to another ID");
        
        let account = Account {
            public_key,
            key_id,
            name,
            wallet: caller.clone(),
        };
        
        // Store both mappings
        self.accounts_by_serial(&serial_hash).set(&account);
        self.serial_by_wallet(&caller).set(&serial_hash);
    }

    /// Delete account by Serial Number hash (only owner can delete)
    #[endpoint(deleteAccount)]
    fn delete_account(&self, serial_hash: ManagedBuffer) {
        let caller = self.blockchain().get_caller();
        
        require!(!self.accounts_by_serial(&serial_hash).is_empty(), "Account not found");
        
        let account = self.accounts_by_serial(&serial_hash).get();
        require!(account.wallet == caller, "Only owner can delete");
        
        // Clear both mappings
        self.accounts_by_serial(&serial_hash).clear();
        self.serial_by_wallet(&caller).clear();
        self.login_status(&serial_hash).clear();
    }

    /// Called by the user (owner) to login.
    /// serial_hash: The Serial Number hash to update login status for
    /// timestamp: Unix timestamp when attestation was created (for replay protection)
    /// nonce: Sequential counter to prevent replay attacks (must be current_nonce + 1)
    /// signature: Ed25519 attestation signature (signed by Trusted Verifier)
    #[endpoint(submitAttestation)]
    fn submit_attestation(&self, serial_hash: ManagedBuffer, timestamp: u64, nonce: u64, signature: ManagedBuffer) {
        let caller = self.blockchain().get_caller();
        
        require!(!self.accounts_by_serial(&serial_hash).is_empty(), "Account not registered");
        let account = self.accounts_by_serial(&serial_hash).get();
        
        // STRICT SECURITY: Only the registered wallet can submit the login proof
        require!(caller == account.wallet, "Only owner can login");
        
        // REPLAY PROTECTION 1: Validate timestamp is within 120 seconds (2 minutes)
        let current_time = self.blockchain().get_block_timestamp();
        require!(
            current_time >= timestamp && current_time - timestamp < 120,
            "Attestation expired (>120 seconds old)"
        );
        
        // REPLAY PROTECTION 2: Validate nonce is exactly current + 1
        let expected_nonce = self.login_nonce(&serial_hash).get() + 1;
        require!(nonce == expected_nonce, "Invalid nonce: expected next sequential value");
        
        // Construct attestation message: "login_ok:" + serial_hash + timestamp + nonce
        // The signature proves that the Verifier (middleware) validated the physical ID card off-chain
        let mut attestation_msg = ManagedBuffer::new_from_bytes(b"login_ok:");
        attestation_msg.append(&serial_hash);
        attestation_msg.append(&ManagedBuffer::from(&timestamp.to_be_bytes()[..]));
        attestation_msg.append(&ManagedBuffer::from(&nonce.to_be_bytes()[..]));
        
        // Verify Ed25519 signature from Trusted Verifier
        let trusted_pubkey = self.trusted_verifier_pubkey().get();
        self.crypto().verify_ed25519(
            &trusted_pubkey,
            &attestation_msg,
            &signature,
        );
        
        // Update nonce AFTER successful verification
        self.login_nonce(&serial_hash).set(nonce);
        self.login_status(&serial_hash).set(true);
    }

    /// Logout by Serial Number hash
    #[endpoint]
    fn logout(&self, serial_hash: ManagedBuffer) {
        let caller = self.blockchain().get_caller();
        
        if !self.accounts_by_serial(&serial_hash).is_empty() {
            let account = self.accounts_by_serial(&serial_hash).get();
            require!(account.wallet == caller, "Only owner can logout");
        }
        
        self.login_status(&serial_hash).set(false);
    }

    // ===== VIEW ENDPOINTS =====

    /// Get account data by Serial Number hash
    #[view(getAccountBySerial)]
    fn get_account_by_serial(&self, serial_hash: ManagedBuffer) -> Option<Account<Self::Api>> {
        if self.accounts_by_serial(&serial_hash).is_empty() {
            None
        } else {
            Some(self.accounts_by_serial(&serial_hash).get())
        }
    }

    /// Get ONLY the registered public key for a serial hash
    /// Returns empty buffer if not found
    #[view(getPublicKeyBySerial)]
    fn get_public_key_by_serial(&self, serial_hash: ManagedBuffer) -> ManagedBuffer {
        if self.accounts_by_serial(&serial_hash).is_empty() {
            ManagedBuffer::new()
        } else {
            self.accounts_by_serial(&serial_hash).get().public_key
        }
    }

    /// Get the registered name for a serial hash
    #[view(getNameBySerial)]
    fn get_name_by_serial(&self, serial_hash: ManagedBuffer) -> ManagedBuffer {
        if self.accounts_by_serial(&serial_hash).is_empty() {
            ManagedBuffer::new()
        } else {
            self.accounts_by_serial(&serial_hash).get().name
        }
    }

    /// Check if Serial Number is registered
    #[view(isRegisteredBySerial)]
    fn is_registered_by_serial(&self, serial_hash: ManagedBuffer) -> bool {
        !self.accounts_by_serial(&serial_hash).is_empty()
    }

    /// Get login status by Serial Number hash
    #[view(getLoginStatusBySerial)]
    fn get_login_status_by_serial(&self, serial_hash: ManagedBuffer) -> bool {
        self.login_status(&serial_hash).get()
    }

    /// Get the registered wallet address for a serial hash
    #[view(getWalletBySerial)]
    fn get_wallet_by_serial(&self, serial_hash: ManagedBuffer) -> ManagedAddress {
        if self.accounts_by_serial(&serial_hash).is_empty() {
            ManagedAddress::zero()
        } else {
            self.accounts_by_serial(&serial_hash).get().wallet
        }
    }

    /// Get the trusted verifier address
    #[view(getTrustedVerifier)]
    fn get_trusted_verifier(&self) -> ManagedAddress {
        self.trusted_verifier().get()
    }

    /// Check if a wallet is already linked to an ID
    #[view(isWalletLinked)]
    fn is_wallet_linked(&self, wallet: ManagedAddress) -> bool {
        !self.serial_by_wallet(&wallet).is_empty()
    }

    /// Get the serial hash linked to a wallet (empty if not linked)
    #[view(getSerialByWallet)]
    fn get_serial_by_wallet(&self, wallet: ManagedAddress) -> ManagedBuffer {
        if self.serial_by_wallet(&wallet).is_empty() {
            ManagedBuffer::new()
        } else {
            self.serial_by_wallet(&wallet).get()
        }
    }

    /// Get the current login nonce for a serial hash (0 if never logged in)
    #[view(getLoginNonce)]
    fn get_login_nonce_view(&self, serial_hash: ManagedBuffer) -> u64 {
        self.login_nonce(&serial_hash).get()
    }

    // ===== STORAGE =====

    /// Registered accounts (Serial hash -> Account)
    #[storage_mapper("accountsBySerial")]
    fn accounts_by_serial(&self, serial_hash: &ManagedBuffer) -> SingleValueMapper<Account<Self::Api>>;

    /// Trusted verifier address (who can submit attestations)
    #[storage_mapper("trustedVerifier")]
    fn trusted_verifier(&self) -> SingleValueMapper<ManagedAddress>;

    /// Trusted verifier's Ed25519 public key (32 bytes)
    #[storage_mapper("trustedVerifierPubkey")]
    fn trusted_verifier_pubkey(&self) -> SingleValueMapper<ManagedBuffer>;

    /// Login status per Serial Number hash
    #[storage_mapper("loginStatus")]
    fn login_status(&self, serial_hash: &ManagedBuffer) -> SingleValueMapper<bool>;

    /// Reverse mapping: wallet -> serial_hash (to enforce 1 ID per wallet)
    #[storage_mapper("serialByWallet")]
    fn serial_by_wallet(&self, wallet: &ManagedAddress) -> SingleValueMapper<ManagedBuffer>;

    /// Login nonce per Serial Number hash (for replay protection)
    #[storage_mapper("loginNonce")]
    fn login_nonce(&self, serial_hash: &ManagedBuffer) -> SingleValueMapper<u64>;
}
