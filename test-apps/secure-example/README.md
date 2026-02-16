# ✅ Secure Secret Management Examples

This directory demonstrates **CORRECT** ways to handle secrets in production applications.

## 📚 What's Included

1. **`secure_app.py`** - Environment variables and best practices
2. **`encryption_example.py`** - Encrypting secrets at rest
3. **`.env.example`** - Template for environment variables

## 🔒 Security Principles

### ✅ DO:
- Use environment variables (`os.getenv()`)
- Use secret management services (Vault, AWS Secrets Manager)
- Add secrets to `.gitignore`
- Rotate secrets regularly
- Use different secrets per environment (dev/staging/prod)

### ❌ DON'T:
- Hardcode secrets in source code
- Commit secrets to git
- Log secrets
- Share secrets via email/Slack
- Use same secrets across environments

## 🚀 Quick Start

### Method 1: Environment Variables
```bash
# Set secrets as environment variables
export STRIPE_API_KEY='sk_live_xxx'
export DATABASE_PASSWORD='xxx'
export FLASK_SECRET_KEY='xxx'

# Run the app
python secure_app.py
```

### Method 2: .env File
```bash
# Copy template
cp .env.example .env

# Edit .env with your values
nano .env

# Install python-dotenv
pip install python-dotenv

# Run the app (it will load .env automatically)
python secure_app.py
```

### Method 3: Encrypted Vault
```bash
# Install cryptography
pip install cryptography

# Run encryption example
python encryption_example.py

# This creates:
# - .vault_key (encryption key)
# - vault.json (encrypted secrets)
# 
# ⚠️ Add both to .gitignore!
```

## 📖 Comparison

| ❌ Insecure (vulnerable-app) | ✅ Secure (this example) |
|------------------------------|--------------------------|
| `API_KEY = "sk_live_xxx"` | `API_KEY = os.getenv('STRIPE_API_KEY')` |
| Hardcoded in source | Loaded from environment |
| Committed to git | Never in git |
| Same key everywhere | Different per environment |

## 🎓 Learn More

- [OWASP: Cryptographic Storage](https://owasp.org/www-project-top-ten/)
- [12 Factor App: Config](https://12factor.net/config)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [HashiCorp Vault](https://www.vaultproject.io/)
