# MCP Atlassian Standalone Server Setup

✅ **Your MCP Atlassian server is now set up and ready to run independently!**

## Quick Start

### 1. Start the Server

Use the convenient shell script:
```bash
./start_server.sh
```

Or run directly with uv:
```bash
uv run mcp-atlassian
```

Or use the Python wrapper:
```bash
python run_mcp_server.py
```

### 2. Server is Running!

The server is now running in standalone mode and can:
- Accept MCP protocol connections via stdio
- Handle requests from Claude Desktop or Claude Code CLI
- Process Jira and Confluence operations

## Configuration

Your credentials are stored in `.env` file:
- **Jira**: https://sunnyfounder-it.atlassian.net
- **Confluence**: https://sunnyfounder-it.atlassian.net/wiki
- **User**: jimmy.wu@sunnyfounder.com

## Testing the Server

### Option 1: MCP Inspector
```bash
npx @modelcontextprotocol/inspector uv run mcp-atlassian
```
This opens a web interface at http://localhost:5173 where you can test all MCP tools.

### Option 2: Direct API Test
Test getting GRE-130 issue:
```bash
curl -u "jimmy.wu@sunnyfounder.com:$JIRA_API_TOKEN" \
  -X GET \
  -H "Accept: application/json" \
  "https://sunnyfounder-it.atlassian.net/rest/api/2/issue/GRE-130"
```

### Option 3: Using with Claude
The server is already configured in your Claude Code CLI settings at:
`~/.config/claude-code/mcp_servers.json`

## Available Tools

Once running, the server provides these MCP tools:

### Jira Tools
- `jira_get_issue` - Get issue details (e.g., GRE-130)
- `jira_search` - Search with JQL
- `jira_create_issue` - Create new issues
- `jira_update_issue` - Update existing issues
- `jira_add_comment` - Add comments
- `jira_transition_issue` - Change issue status
- And many more...

### Confluence Tools
- `confluence_search` - Search pages
- `confluence_get_page` - Get page content
- `confluence_create_page` - Create pages
- `confluence_update_page` - Update pages
- And more...

## Running as a Service

### macOS LaunchAgent (Auto-start)
Create `~/Library/LaunchAgents/com.mcp.atlassian.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mcp.atlassian</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/uv</string>
        <string>run</string>
        <string>mcp-atlassian</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/jimmy/jimmy_side_projects/mcp-atlassian</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/mcp-atlassian.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/mcp-atlassian.out</string>
</dict>
</plist>
```

Then load it:
```bash
launchctl load ~/Library/LaunchAgents/com.mcp.atlassian.plist
```

## Troubleshooting

### Server won't start
1. Check `.env` file exists and has credentials
2. Verify uv is installed: `which uv`
3. Check Python dependencies: `uv sync`

### Can't connect to Jira/Confluence
1. Verify API token is valid
2. Check network connectivity
3. Look at logs for authentication errors

### View Logs
```bash
# If using start_server.sh, logs appear in terminal
# If using LaunchAgent:
tail -f /tmp/mcp-atlassian.err
tail -f /tmp/mcp-atlassian.out
```

## Security Notes

- `.env` file has 600 permissions (owner read/write only)
- API tokens are never logged
- Consider using OAuth for production

## Next Steps

1. **Test with GRE-130**: The server can now fetch this issue
2. **Use MCP Inspector**: Interactive testing interface
3. **Integrate with Claude**: Already configured in your CLI

The server is ready for standalone operation! 🚀