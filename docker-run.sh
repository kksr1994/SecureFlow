#!/bin/bash
# Easy Docker launcher

echo "🐳 Building SecureFlow Docker image..."
docker build -t secureflow .

echo "🚀 Starting SecureFlow..."
docker run -d \
  --name secureflow \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/target:/app/target:ro \
  secureflow

echo "✅ SecureFlow is running!"
echo "📊 Dashboard: http://localhost:5000"
echo ""
echo "To scan a project:"
echo "  1. Copy it to ./target/"
echo "  2. docker exec secureflow ./secureflow scan -t target -s all"
