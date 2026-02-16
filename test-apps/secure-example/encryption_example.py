"""
✅ ADVANCED: Secret Encryption Example

This shows how to encrypt secrets at rest.
Useful for storing secrets in configuration files or databases.
"""

from cryptography.fernet import Fernet
import os
import json
from pathlib import Path


class SecretVault:
    """
    Simple encrypted secret storage
    
    In production, use:
    - HashiCorp Vault
    - AWS Secrets Manager
    - Azure Key Vault
    - Google Cloud Secret Manager
    """
    
    def __init__(self, key_file: str = '.vault_key'):
        """
        Initialize the vault
        
        Args:
            key_file: Path to encryption key file
        """
        self.key_file = Path(key_file)
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
    
    def _load_or_create_key(self) -> bytes:
        """Load existing key or create new one"""
        if self.key_file.exists():
            # Load existing key
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            
            # Save key securely (chmod 600)
            with open(self.key_file, 'wb') as f:
                f.write(key)
            os.chmod(self.key_file, 0o600)  # Read/write for owner only
            
            print(f"🔑 Generated new encryption key: {self.key_file}")
            print(f"⚠️  Keep this file secure! Add to .gitignore!")
            
            return key
    
    def encrypt(self, secret: str) -> str:
        """
        Encrypt a secret
        
        Args:
            secret: The secret to encrypt
        
        Returns:
            Base64-encoded encrypted secret
        """
        encrypted = self.cipher.encrypt(secret.encode())
        return encrypted.decode()
    
    def decrypt(self, encrypted_secret: str) -> str:
        """
        Decrypt a secret
        
        Args:
            encrypted_secret: The encrypted secret
        
        Returns:
            The decrypted secret
        """
        decrypted = self.cipher.decrypt(encrypted_secret.encode())
        return decrypted.decode()
    
    def store_secret(self, name: str, value: str, vault_file: str = 'vault.json'):
        """
        Encrypt and store a secret
        
        Args:
            name: Secret name
            value: Secret value
            vault_file: File to store encrypted secrets
        """
        vault_path = Path(vault_file)
        
        # Load existing vault or create new
        if vault_path.exists():
            with open(vault_path, 'r') as f:
                vault = json.load(f)
        else:
            vault = {}
        
        # Encrypt and store
        vault[name] = self.encrypt(value)
        
        with open(vault_path, 'w') as f:
            json.dump(vault, f, indent=2)
        
        print(f"✅ Stored encrypted secret: {name}")
    
    def retrieve_secret(self, name: str, vault_file: str = 'vault.json') -> str:
        """
        Retrieve and decrypt a secret
        
        Args:
            name: Secret name
            vault_file: File containing encrypted secrets
        
        Returns:
            Decrypted secret
        """
        vault_path = Path(vault_file)
        
        if not vault_path.exists():
            raise FileNotFoundError(f"Vault file not found: {vault_file}")
        
        with open(vault_path, 'r') as f:
            vault = json.load(f)
        
        if name not in vault:
            raise KeyError(f"Secret not found: {name}")
        
        return self.decrypt(vault[name])


# ════════════════════════════════════════════════════════════════════
# EXAMPLE USAGE
# ════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("🔐 Secret Vault Example\n")
    
    # Initialize vault
    vault = SecretVault('.vault_key')
    
    # Store some secrets
    print("📝 Storing secrets...")
    vault.store_secret('stripe_api_key', 'sk_live_example_key_12345')
    vault.store_secret('database_password', 'super_secure_password_789')
    
    # Retrieve secrets
    print("\n🔓 Retrieving secrets...")
    api_key = vault.retrieve_secret('stripe_api_key')
    db_pass = vault.retrieve_secret('database_password')
    
    print(f"API Key: {api_key}")
    print(f"DB Password: {db_pass}")
    
    print("\n✅ Encryption/Decryption successful!")
    print("\n⚠️  IMPORTANT:")
    print("- Add .vault_key to .gitignore")
    print("- Add vault.json to .gitignore")
    print("- In production, use proper secret management services")
