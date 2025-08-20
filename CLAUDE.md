# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Environment Setup
```bash
# Install dependencies using uv
uv sync
uv sync --frozen --all-extras --dev

# Activate virtual environment
source .venv/bin/activate  # macOS/Linux
.venv\Scripts\activate.ps1  # Windows

# Install pre-commit hooks
pre-commit install

# Copy environment configuration
cp .env.example .env
```

### Running the Server
```bash
# Run with Docker (recommended)
docker run --rm -i --env-file .env ghcr.io/sooperset/mcp-atlassian:latest

# Run locally
mcp-atlassian

# Run OAuth setup wizard (for OAuth authentication)
docker run --rm -i -p 8080:8080 -v "${HOME}/.mcp-atlassian:/home/app/.mcp-atlassian" ghcr.io/sooperset/mcp-atlassian:latest --oauth-setup -v

# Run with HTTP transport
docker run --rm -p 9000:9000 --env-file .env ghcr.io/sooperset/mcp-atlassian:latest --transport streamable-http --port 9000
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mcp_atlassian

# Run specific test categories
pytest tests/unit/           # Unit tests
pytest tests/integration/     # Integration tests

# Run with verbose output
pytest -vv

# Run tests matching pattern
pytest -k "test_jira"        # Only Jira tests
pytest -k "test_confluence"  # Only Confluence tests

# Run tests with real API (requires environment setup)
./scripts/test_with_real_data.sh
```

### Code Quality
```bash
# Run linter
ruff check src/ tests/

# Run formatter
ruff format src/ tests/

# Run type checker
mypy tests/

# Run all pre-commit hooks
pre-commit run --all-files

# Auto-fix linting issues
ruff check --fix src/ tests/
```

### Building
```bash
# Build Docker image locally
docker build -t mcp-atlassian:local .

# Build Python package
uv build
```

## Architecture Overview

### Core Components

The MCP Atlassian server is a Model Context Protocol implementation that bridges Atlassian products (Jira and Confluence) with AI language models. The architecture consists of:

1. **Client Layer** (`src/mcp_atlassian/jira/client.py`, `src/mcp_atlassian/confluence/client.py`)
   - Handles API communication with Atlassian services
   - Manages authentication (API tokens, PATs, OAuth 2.0)
   - Implements request/response handling with retries and error management

2. **Model Layer** (`src/mcp_atlassian/models/`)
   - Pydantic models for type-safe data handling
   - Separate models for Jira (`models/jira/`) and Confluence (`models/confluence/`)
   - Base models in `models/base.py` for shared functionality

3. **Server Layer** (`src/mcp_atlassian/servers/`)
   - FastMCP-based server implementation
   - Main server orchestration in `servers/main.py`
   - Service-specific servers: `servers/jira.py`, `servers/confluence.py`
   - Context management in `servers/context.py`

4. **Tool Layer** (distributed across service modules)
   - Jira tools: issues, comments, search, boards, sprints, worklogs, etc.
   - Confluence tools: pages, spaces, search, comments, labels, etc.
   - Tool filtering and access control via `utils/tools.py`

5. **Authentication** (`src/mcp_atlassian/utils/oauth.py`, `utils/oauth_setup.py`)
   - Multi-auth support: API tokens, Personal Access Tokens, OAuth 2.0
   - OAuth setup wizard for interactive configuration
   - Token persistence and refresh for OAuth flows

6. **Preprocessing** (`src/mcp_atlassian/preprocessing/`)
   - Content transformation for AI consumption
   - HTML to Markdown conversion
   - Field filtering and formatting

### Authentication Flow

The server supports three authentication methods:

1. **API Token** (Cloud): Username + API token
2. **Personal Access Token** (Server/DC): Direct token authentication
3. **OAuth 2.0** (Cloud): Full OAuth flow with refresh tokens or BYOT (Bring Your Own Token)

OAuth flow includes:
- Interactive setup wizard (`scripts/oauth_authorize.py`)
- Token persistence in `~/.mcp-atlassian/`
- Automatic token refresh
- Multi-cloud support via headers

### Transport Modes

1. **stdio** (default): Standard input/output for IDE integration
2. **sse**: Server-Sent Events at `/sse` endpoint
3. **streamable-http**: HTTP streaming at `/mcp` endpoint

### Environment Configuration

Key environment variables:
- `JIRA_URL`, `CONFLUENCE_URL`: Service URLs
- `*_USERNAME`, `*_API_TOKEN`: Basic auth credentials
- `*_PERSONAL_TOKEN`: PAT authentication
- `ATLASSIAN_OAUTH_*`: OAuth configuration
- `*_SPACES_FILTER`, `*_PROJECTS_FILTER`: Content filtering
- `READ_ONLY_MODE`: Disable write operations
- `ENABLED_TOOLS`: Tool access control
- `*_CUSTOM_HEADERS`: Custom HTTP headers
- `*_SSL_VERIFY`: SSL verification control

## Testing Strategy

### Test Organization
- `tests/unit/`: Component-level tests with mocked dependencies
- `tests/integration/`: Cross-component and protocol tests
- `tests/fixtures/`: Mock data and test utilities
- `tests/utils/`: Test helpers and factories

### Key Test Patterns
- Session-scoped fixtures for performance (`conftest.py`)
- Factory-based fixtures for customizable test data
- Environment fixtures for auth scenario testing
- Mock clients with pre-configured responses

### Real API Testing
Use `./scripts/test_with_real_data.sh` with proper environment setup to test against actual Atlassian instances.

## Important Notes

- Always use `uv` for dependency management (not pip directly)
- Docker is the recommended deployment method
- Pre-commit hooks must pass before committing
- OAuth tokens are stored in `~/.mcp-atlassian/` (handle securely)
- The server supports both Cloud and Server/Data Center deployments
- Multi-user authentication is supported via HTTP transports
- Custom headers can be configured for corporate environments
- Proxy support via standard environment variables