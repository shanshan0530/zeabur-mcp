import os

# Import-time config for the FastAPI/FastMCP app. Dummy values only; never a live token.
os.environ.setdefault("MCP_PROXY_SECRET", "phase-a-test-secret")
os.environ.setdefault("ZEABUR_TOKEN", "phase-a-test-token")
os.environ.setdefault("PUBLIC_BASE_URL", "https://zeabur-mcp.test")
