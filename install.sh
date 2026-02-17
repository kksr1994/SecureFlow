#!/bin/bash
# SecureFlow One-Command Installer

set -e

echo "╔═══════════════════════════════════════════════════════╗"
echo "║         🔒 SecureFlow Installer v2.0 🔒              ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}Installing Python dependencies...${NC}"
python3 -m venv venv 2>/dev/null || true
source venv/bin/activate
pip install flask cryptography python-dotenv 2>/dev/null

echo -e "${BLUE}Installing security tools...${NC}"
pip install semgrep 2>/dev/null || pip install semgrep --break-system-packages
echo -e "${GREEN}✓ Semgrep installed${NC}"

# Create shortcuts
cat > secureflow << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python3 cli/main.py "$@"
EOF
chmod +x secureflow

cat > secureflow-dashboard << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
echo "🚀 Starting SecureFlow Dashboard..."
echo "📊 Open: http://localhost:5000"
sleep 2
xdg-open http://localhost:5000 2>/dev/null || open http://localhost:5000 2>/dev/null || true
python3 dashboard/app.py
EOF
chmod +x secureflow-dashboard

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║           ✅ INSTALLATION COMPLETE! ✅               ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Quick Start:${NC}"
echo ""
echo "  1. Run a scan:"
echo -e "     ${YELLOW}./secureflow scan -t test-apps/vulnerable-app -s all${NC}"
echo ""
echo "  2. Start dashboard:"
echo -e "     ${YELLOW}./secureflow-dashboard${NC}"
echo ""
