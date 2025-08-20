#!/usr/bin/env python3
"""
Standalone MCP Atlassian Server Runner
This script runs the MCP Atlassian server as a standalone service
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from dotenv import load_dotenv
from mcp_atlassian import main

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout if os.getenv("MCP_LOGGING_STDOUT") else sys.stderr)
    ]
)

logger = logging.getLogger("mcp-atlassian-standalone")

def verify_config():
    """Verify that required configuration is present"""
    required_vars = []
    
    # Check Jira configuration
    if os.getenv("JIRA_URL"):
        if not (os.getenv("JIRA_USERNAME") and os.getenv("JIRA_API_TOKEN")) and not os.getenv("JIRA_PERSONAL_TOKEN"):
            logger.error("Jira URL is configured but authentication is missing!")
            logger.error("Please set JIRA_USERNAME and JIRA_API_TOKEN, or JIRA_PERSONAL_TOKEN")
            return False
    
    # Check Confluence configuration
    if os.getenv("CONFLUENCE_URL"):
        if not (os.getenv("CONFLUENCE_USERNAME") and os.getenv("CONFLUENCE_API_TOKEN")) and not os.getenv("CONFLUENCE_PERSONAL_TOKEN"):
            logger.error("Confluence URL is configured but authentication is missing!")
            logger.error("Please set CONFLUENCE_USERNAME and CONFLUENCE_API_TOKEN, or CONFLUENCE_PERSONAL_TOKEN")
            return False
    
    # At least one service should be configured
    if not os.getenv("JIRA_URL") and not os.getenv("CONFLUENCE_URL"):
        logger.error("Neither Jira nor Confluence is configured!")
        logger.error("Please configure at least one service in your .env file")
        return False
    
    return True

def display_config():
    """Display the current configuration (without sensitive data)"""
    logger.info("=" * 50)
    logger.info("MCP Atlassian Server Configuration")
    logger.info("=" * 50)
    
    if os.getenv("JIRA_URL"):
        logger.info(f"Jira URL: {os.getenv('JIRA_URL')}")
        logger.info(f"Jira User: {os.getenv('JIRA_USERNAME', 'Using PAT')}")
    
    if os.getenv("CONFLUENCE_URL"):
        logger.info(f"Confluence URL: {os.getenv('CONFLUENCE_URL')}")
        logger.info(f"Confluence User: {os.getenv('CONFLUENCE_USERNAME', 'Using PAT')}")
    
    logger.info("=" * 50)

async def run_server():
    """Run the MCP server"""
    try:
        logger.info("Starting MCP Atlassian Server...")
        
        # The main function from mcp_atlassian handles the server lifecycle
        await main()
        
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    # Verify configuration
    if not verify_config():
        sys.exit(1)
    
    # Display configuration
    display_config()
    
    # Run the server
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        logger.info("\nShutting down gracefully...")
        sys.exit(0)