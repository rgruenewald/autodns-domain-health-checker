#!/bin/bash
set -e

echo "🚀 AutoDNS Domain Health Checker - Setup & Start"
echo "================================================"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found"
    echo "📝 Please copy .env.example to .env and configure it:"
    echo "   cp .env.example .env"
    echo "   nano .env"
    exit 1
fi

# Check if dkim.config.json exists
if [ ! -f dkim.config.json ]; then
    echo "❌ Error: dkim.config.json file not found"
    echo "📝 Please copy dkim.config.example.json to dkim.config.json and configure it:"
    echo "   cp dkim.config.example.json dkim.config.json"
    echo "   nano dkim.config.json"
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running"
    echo "   Please start Docker and try again"
    exit 1
fi

echo "✅ Configuration files found"
echo "🔨 Building and starting container..."
echo ""

# Build and start
docker-compose up -d --build

echo ""
echo "✅ Container started successfully!"
echo ""
echo "📊 Status:"
docker-compose ps
echo ""
echo "📋 View logs:"
echo "   docker-compose logs -f"
echo ""
echo "📁 Cron execution log:"
echo "   tail -f reports/cron.log"
echo ""
echo "🔄 The application will run automatically at:"
echo "   • 1:00 AM daily"
echo "   • 1:00 PM daily"
echo ""
echo "🏃 Run manually now:"
echo "   docker-compose exec diebasis-domain-health node src/index.js"
echo ""
echo "🛑 Stop the service:"
echo "   docker-compose down"
echo ""
