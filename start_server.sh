#!/bin/bash

# MCP Atlassian Server Startup Script
# This script starts the MCP Atlassian server in standalone mode

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo -e "${GREEN}🚀 Starting MCP Atlassian Server${NC}"
echo "================================"

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${RED}❌ Error: .env file not found!${NC}"
    echo "Please create a .env file with your Atlassian credentials."
    exit 1
fi

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo -e "${RED}❌ Error: uv is not installed!${NC}"
    echo "Install with: brew install uv"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d .venv ]; then
    echo -e "${YELLOW}📦 Creating virtual environment...${NC}"
    uv venv
    echo -e "${YELLOW}📦 Installing dependencies...${NC}"
    uv sync
fi

# Export environment variables from .env file
export $(grep -v '^#' .env | xargs)

# Display configuration (without sensitive data)
echo -e "${GREEN}Configuration:${NC}"
echo "  Jira URL: $JIRA_URL"
echo "  Jira User: $JIRA_USERNAME"
echo "  Confluence URL: $CONFLUENCE_URL"
echo "  Confluence User: $CONFLUENCE_USERNAME"
echo ""

# Function to handle shutdown gracefully
cleanup() {
    echo -e "\n${YELLOW}⏹  Shutting down MCP Atlassian Server...${NC}"
    kill $SERVER_PID 2>/dev/null
    exit 0
}

# Set up signal handlers
trap cleanup INT TERM

# Start the server
echo -e "${GREEN}▶️  Starting server...${NC}"
echo "================================"
echo ""

# Run the server in the background
uv run mcp-atlassian &
SERVER_PID=$!

echo -e "${GREEN}✅ Server started with PID: $SERVER_PID${NC}"
echo ""
echo "The server is now running and ready to accept MCP connections."
echo "Press Ctrl+C to stop the server."
echo ""
echo "To test the server, you can:"
echo "1. Use Claude Desktop or Claude Code CLI"
echo "2. Use the MCP Inspector: npx @modelcontextprotocol/inspector uv run mcp-atlassian"
echo ""

# Wait for the server process
wait $SERVER_PID