#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}AuthOS Python SDK Generator${NC}"
echo "================================"

# Check if OpenAPI spec exists
if [ ! -f "public/openapi.json" ]; then
    echo -e "${YELLOW}OpenAPI spec not found. Generating...${NC}"
    herd php artisan openapi:generate
fi

# Check if openapi-python-client is installed
if ! command -v openapi-python-client &> /dev/null; then
    echo -e "${YELLOW}Installing openapi-python-client...${NC}"
    pip install openapi-python-client
fi

# Clean previous build
echo -e "${YELLOW}Cleaning previous build...${NC}"
rm -rf sdk/python/authos_client

# Generate Python client from OpenAPI spec
echo -e "${YELLOW}Generating Python client...${NC}"
openapi-python-client generate \
    --path public/openapi.json \
    --output-path sdk/python \
    --config sdk/scripts/python-config.yaml

# Create custom auth helpers
echo -e "${YELLOW}Creating custom auth helpers...${NC}"

cat > sdk/python/authos_client/auth.py << 'EOF'
"""
Authentication helpers for AuthOS Python SDK
"""

import hashlib
import secrets
import base64
from typing import Optional, Dict
from urllib.parse import urlencode


class PKCEManager:
    """PKCE challenge generator"""

    @staticmethod
    def generate_code_verifier() -> str:
        """Generate a cryptographically random code verifier"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    @staticmethod
    def generate_code_challenge(verifier: str) -> str:
        """Generate S256 code challenge from verifier"""
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

    @classmethod
    def generate_pkce_pair(cls) -> tuple[str, str]:
        """Generate PKCE verifier and challenge pair"""
        verifier = cls.generate_code_verifier()
        challenge = cls.generate_code_challenge(verifier)
        return verifier, challenge


class OAuthHelper:
    """OAuth 2.0 flow helper"""

    def __init__(self, client_id: str, redirect_uri: str, base_url: str):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.base_url = base_url.rstrip('/')

    def get_authorization_url(
        self,
        scopes: Optional[list[str]] = None,
        state: Optional[str] = None,
        use_pkce: bool = True
    ) -> tuple[str, Optional[str], Optional[str]]:
        """
        Generate OAuth authorization URL

        Returns:
            tuple: (authorization_url, state, code_verifier)
        """
        if scopes is None:
            scopes = ['openid', 'profile', 'email']

        if state is None:
            state = secrets.token_urlsafe(32)

        params: Dict[str, str] = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(scopes),
            'state': state,
        }

        code_verifier = None
        if use_pkce:
            code_verifier, code_challenge = PKCEManager.generate_pkce_pair()
            params['code_challenge'] = code_challenge
            params['code_challenge_method'] = 'S256'

        auth_url = f"{self.base_url}/oauth/authorize?{urlencode(params)}"

        return auth_url, state, code_verifier
EOF

# Create setup.py
echo -e "${YELLOW}Creating setup.py...${NC}"

cat > sdk/python/setup.py << 'EOF'
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="authos-client",
    version="1.0.0",
    author="AuthOS Team",
    author_email="support@authos.dev",
    description="Python SDK for AuthOS - Enterprise authentication service",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/authos/sdk-python",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.24.0",
        "attrs>=21.3.0",
        "python-dateutil>=2.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
        ],
    },
)
EOF

# Create README
echo -e "${YELLOW}Creating README.md...${NC}"

cat > sdk/python/README.md << 'EOF'
# AuthOS Python SDK

Official Python SDK for AuthOS - Enterprise authentication service.

## Installation

```bash
pip install authos-client
```

## Quick Start

```python
from authos_client import Client
from authos_client.auth import OAuthHelper

# Initialize client
client = Client(base_url="https://auth.example.com")

# OAuth flow helper
oauth = OAuthHelper(
    client_id="your-client-id",
    redirect_uri="http://localhost:8000/callback",
    base_url="https://auth.example.com"
)

# Get authorization URL
auth_url, state, code_verifier = oauth.get_authorization_url(
    scopes=["openid", "profile", "email"]
)

print(f"Visit: {auth_url}")
# Store state and code_verifier for callback validation
```

## Usage

### Authentication

```python
# After OAuth callback, exchange code for tokens
from authos_client.api.auth import login

response = client.post(
    "/v1/auth/login",
    json={"email": "user@example.com", "password": "password"}
)
```

### User Management

```python
from authos_client.api.users import list_users, get_user

# List users
users = list_users.sync(client=client)

# Get specific user
user = get_user.sync(user_id="user-id", client=client)
```

## Documentation

Full documentation: https://docs.authos.dev/sdk/python

## License

MIT
EOF

echo -e "${GREEN}✓ Python SDK generated successfully!${NC}"
echo -e "Location: ${YELLOW}sdk/python/${NC}"
echo ""
echo "Next steps:"
echo "  1. cd sdk/python"
echo "  2. pip install -e ."
echo "  3. Run tests: pytest"
