"""
✅ SECURE EXAMPLE - Proper Secret Management

This demonstrates the CORRECT way to handle secrets in production.
Compare this with test-apps/vulnerable-app/app.py to see the difference.
"""

import os
from pathlib import Path

# ════════════════════════════════════════════════════════════════════
# ✅ CORRECT METHOD 1: Environment Variables
# ════════════════════════════════════════════════════════════════════

def get_secret_from_env(secret_name: str, required: bool = True) -> str:
    """
    Securely retrieve secrets from environment variables
    
    Args:
        secret_name: Name of the environment variable
        required: Whether this secret is required
    
    Returns:
        The secret value
    
    Raises:
        ValueError: If required secret is missing
    """
    secret = os.getenv(secret_name)
    
    if required and not secret:
        raise ValueError(
            f"❌ Required secret '{secret_name}' not found in environment variables!\n"
            f"Set it with: export {secret_name}='your_value'"
        )
    
    return secret


# ✅ CORRECT: Get secrets from environment
API_KEY = get_secret_from_env('STRIPE_API_KEY', required=False)
DATABASE_PASSWORD = get_secret_from_env('DATABASE_PASSWORD', required=False)
SECRET_KEY = get_secret_from_env('FLASK_SECRET_KEY', required=False)


# ════════════════════════════════════════════════════════════════════
# ✅ CORRECT METHOD 2: Configuration File (with .gitignore)
# ════════════════════════════════════════════════════════════════════

import json

def load_secrets_from_file(filepath: str = 'secrets.json') -> dict:
    """
    Load secrets from a JSON file
    
    IMPORTANT: Add secrets.json to .gitignore!
    
    Args:
        filepath: Path to secrets file
    
    Returns:
        Dictionary of secrets
    """
    secrets_path = Path(filepath)
    
    if not secrets_path.exists():
        print(f"⚠️  Secrets file not found: {filepath}")
        print(f"Create it from secrets.example.json template")
        return {}
    
    with open(secrets_path, 'r') as f:
        return json.load(f)


# ✅ Load from secure config file
# secrets = load_secrets_from_file('config/secrets.json')


# ════════════════════════════════════════════════════════════════════
# ✅ CORRECT METHOD 3: Use Secret Management Services
# ════════════════════════════════════════════════════════════════════

def get_secret_from_vault(secret_name: str) -> str:
    """
    Retrieve secrets from a secret management service
    
    Examples of secret management services:
    - AWS Secrets Manager
    - HashiCorp Vault
    - Azure Key Vault
    - Google Cloud Secret Manager
    
    Args:
        secret_name: Name of the secret
    
    Returns:
        The secret value
    """
    # Example pseudo-code for AWS Secrets Manager:
    # import boto3
    # client = boto3.client('secretsmanager')
    # response = client.get_secret_value(SecretId=secret_name)
    # return response['SecretString']
    
    pass  # Implement based on your cloud provider


# ════════════════════════════════════════════════════════════════════
# ✅ BEST PRACTICES SUMMARY
# ════════════════════════════════════════════════════════════════════

"""
DO ✅:
1. Use environment variables for secrets
2. Use secret management services (Vault, AWS Secrets Manager)
3. Keep secrets in .gitignore'd config files
4. Rotate secrets regularly
5. Use different secrets for dev/staging/prod
6. Limit secret access to necessary services only

DON'T ❌:
1. Hardcode secrets in source code
2. Commit secrets to git
3. Log secrets to files or console
4. Share secrets via email or chat
5. Use the same secret across environments
6. Store secrets in plain text files in the repo

SECURE SECRET WORKFLOW:
1. Developer: export STRIPE_API_KEY='sk_live_xxx' (locally)
2. CI/CD: Stored in GitHub Secrets / GitLab CI Variables
3. Production: Retrieved from AWS Secrets Manager / Vault
"""


# ════════════════════════════════════════════════════════════════════
# ✅ EXAMPLE: Secure Flask Application
# ════════════════════════════════════════════════════════════════════

from flask import Flask

app = Flask(__name__)

# ✅ CORRECT: Secret from environment
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-only-key')

# ✅ CORRECT: Database URL from environment
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'sqlite:///dev.db'  # Default for development only
)

@app.route('/api/payment')
def process_payment():
    # ✅ CORRECT: API key loaded from environment
    api_key = get_secret_from_env('STRIPE_API_KEY')
    
    # Use the API key securely
    # Never log or return it in responses
    return {"status": "success"}


if __name__ == '__main__':
    # ✅ Verify all required secrets are present
    required_secrets = ['STRIPE_API_KEY', 'DATABASE_PASSWORD']
    missing = [s for s in required_secrets if not os.getenv(s)]
    
    if missing:
        print(f"❌ Missing required secrets: {', '.join(missing)}")
        print(f"Set them with: export SECRET_NAME='value'")
        exit(1)
    
    print("✅ All secrets loaded successfully!")
    app.run(debug=False)  # ✅ Never use debug=True in production

