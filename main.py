
import base64
import hashlib
import json
import os
import random
import re
import string
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import requests
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

# --- Constants from src/auth/constants.ts ---
GOOGLE_CLIENT_ID = '1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
GOOGLE_SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/cclog',
    'https://www.googleapis.com/auth/experimentsandconfigs'
]
CLOUD_CODE_API_BASE = 'https://cloudcode-pa.googleapis.com'
LOAD_CODE_ASSIST_PATH = '/v1internal:loadCodeAssist'
FETCH_AVAILABLE_MODELS_PATH = '/v1internal:fetchAvailableModels'
CALLBACK_PATH = '/callback'
# --- End Constants ---

TOKEN_FILE = os.path.expanduser('~/.antigravity_quota_token.json')
SERVER_PORT = 8000

# ============================================================
# Token Manager
# ============================================================

class OAuthTokenManager:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0

    def load_tokens(self):
        if os.path.exists(TOKEN_FILE):
            try:
                with open(TOKEN_FILE, 'r') as f:
                    data = json.load(f)
                    self.access_token = data.get('access_token')
                    self.refresh_token = data.get('refresh_token')
                    self.expires_at = data.get('expires_at', 0)
                return True
            except json.JSONDecodeError:
                return False
        return False

    def save_tokens(self):
        with open(TOKEN_FILE, 'w') as f:
            json.dump({
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'expires_at': self.expires_at
            }, f)

    def is_access_token_valid(self):
        return self.access_token and self.expires_at > time.time() + 60

    def refresh_access_token(self):
        if not self.refresh_token:
            return False
        try:
            response = requests.post(
                GOOGLE_TOKEN_ENDPOINT,
                data={
                    'client_id': GOOGLE_CLIENT_ID,
                    'client_secret': GOOGLE_CLIENT_SECRET,
                    'refresh_token': self.refresh_token,
                    'grant_type': 'refresh_token',
                }
            )
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data['access_token']
            self.expires_at = time.time() + token_data['expires_in']
            self.save_tokens()
            return True
        except requests.exceptions.RequestException:
            self.clear_tokens()
            return False

    def get_access_token(self):
        if self.is_access_token_valid():
            return self.access_token
        if self.refresh_token:
            if self.refresh_access_token():
                return self.access_token
        return None

    def clear_tokens(self):
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)

# ============================================================
# Quota Checker
# ============================================================

class AntigravityQuotaChecker:
    def __init__(self, token_manager: OAuthTokenManager):
        self.token_manager = token_manager
        self.project_id = None
        self.tier = None

    def _get_headers(self, access_token: str) -> dict:
        return {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}',
            'User-Agent': 'AntigravityQuotaWatcherPython/1.0',
        }

    def fetch_project_info(self, access_token: str):
        try:
            response = requests.post(
                f"{CLOUD_CODE_API_BASE}{LOAD_CODE_ASSIST_PATH}",
                headers=self._get_headers(access_token),
                json={
                    'metadata': {
                        'ideType': 'ANTIGRAVITY',
                        'platform': 'PLATFORM_UNSPECIFIED',
                        'pluginType': 'GEMINI'
                    }
                }
            )
            response.raise_for_status()
            data = response.json()
            self.project_id = self._extract_project_id(data)
            self.tier = self._extract_tier_id(data) or self._extract_default_tier_id(data)
            return self.project_id, self.tier
        except requests.exceptions.RequestException:
            return None, None

    def _extract_project_id(self, response: dict):
        cp = response.get('cloudaicompanionProject')
        if not cp:
            return None
        if isinstance(cp, str):
            return cp
        if isinstance(cp, dict):
            return cp.get('id') or cp.get('projectId')
        return None

    def _extract_tier_id(self, response: dict):
        paid_tier = response.get('paidTier', {})
        current_tier = response.get('currentTier', {})
        return paid_tier.get('id') or paid_tier.get('name') or current_tier.get('id') or current_tier.get('name')

    def _extract_default_tier_id(self, response: dict):
        allowed_tiers = response.get('allowedTiers', [])
        for tier in allowed_tiers:
            if tier.get('isDefault') and tier.get('id'):
                return tier.get('id')
        if allowed_tiers:
            return 'LEGACY'
        return None

    def fetch_models_quota(self, access_token: str, project_id: str | None):
        body = {'project': project_id} if project_id else {}
        try:
            response = requests.post(
                f"{CLOUD_CODE_API_BASE}{FETCH_AVAILABLE_MODELS_PATH}",
                headers=self._get_headers(access_token),
                json=body
            )
            response.raise_for_status()
            data = response.json()
            return data.get('models', {})
        except requests.exceptions.RequestException:
            return {}

    @staticmethod
    def format_model_display_name(model_name: str) -> str:
        fixed = re.sub(r'(\d+)-(\d+)', r'\1.\2', model_name)
        parts = fixed.split('-')
        formatted = []
        for part in parts:
            if part and not part[0].isdigit():
                formatted.append(part.capitalize())
            else:
                formatted.append(part)
        return ' '.join(formatted)

    @staticmethod
    def compute_reset_text(reset_time_str: str | None) -> str:
        if not reset_time_str:
            return ''
        try:
            reset_time = datetime.fromisoformat(reset_time_str.replace('Z', '+00:00'))
            delta = reset_time - datetime.now(timezone.utc)
            days = delta.days
            hours = delta.seconds // 3600
            minutes = (delta.seconds % 3600) // 60

            if days > 0:
                return f"Resets in {days}d {hours}h"
            elif hours > 0:
                return f"Resets in {hours}h {minutes}m"
            elif minutes > 0:
                return f"Resets in {minutes}m"
            else:
                return "Resets very soon"
        except ValueError:
            return f"Reset: {reset_time_str}"

    def get_quota_payload(self):
        """Return a JSON-serializable dict with tier + formatted models."""
        access_token = self.token_manager.get_access_token()
        if not access_token:
            return None

        self.fetch_project_info(access_token)

        # Token may have been refreshed above; re-grab
        access_token = self.token_manager.get_access_token()
        if not access_token:
            return None

        raw_models = self.fetch_models_quota(access_token, self.project_id)

        models = {}
        for name, info in raw_models.items():
            quota_info = info.get('quotaInfo', {})
            remaining = quota_info.get('remainingFraction')
            if remaining is None:
                remaining = 0
            pct = remaining * 100

            models[name] = {
                'display_name': self.format_model_display_name(name),
                'remaining_percent': round(pct, 1),
                'reset_text': self.compute_reset_text(quota_info.get('resetTime')),
            }

        return {'tier': self.tier, 'models': models}


# ============================================================
# FastAPI App
# ============================================================

app = FastAPI(title="Antigravity Quota Watcher")
token_manager = OAuthTokenManager()
token_manager.load_tokens()
checker = AntigravityQuotaChecker(token_manager)

# In-memory PKCE state for the current login flow
_oauth_state: dict = {}

STATIC_DIR = Path(__file__).parent


def _generate_pkce():
    verifier = ''.join(random.choice(
        string.ascii_uppercase + string.ascii_lowercase + string.digits + '-._~'
    ) for _ in range(128))
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().replace('=', '')
    return verifier, challenge


# ---- Serve frontend ----

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    return FileResponse(STATIC_DIR / "index.html")


# ---- Auth status ----

@app.get("/api/status")
async def auth_status():
    access_token = token_manager.get_access_token()
    return {"authenticated": access_token is not None}


# ---- Login redirect ----

@app.get("/api/login")
async def login(request: Request):
    redirect_uri = f"http://127.0.0.1:{SERVER_PORT}{CALLBACK_PATH}"
    verifier, challenge = _generate_pkce()
    state = ''.join(random.choice(
        string.ascii_uppercase + string.ascii_lowercase + string.digits
    ) for _ in range(32))

    # Store for callback verification
    _oauth_state['verifier'] = verifier
    _oauth_state['state'] = state
    _oauth_state['redirect_uri'] = redirect_uri

    auth_url = (
        f"{GOOGLE_AUTH_ENDPOINT}?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={urllib.parse.quote(redirect_uri)}&"
        f"response_type=code&"
        f"scope={urllib.parse.quote(' '.join(GOOGLE_SCOPES))}&"
        f"state={state}&"
        f"code_challenge={challenge}&"
        f"code_challenge_method=S256&"
        f"access_type=offline&"
        f"prompt=consent"
    )
    return RedirectResponse(url=auth_url)


# ---- OAuth callback ----

@app.get(CALLBACK_PATH)
async def oauth_callback(code: str = '', state: str = ''):
    if not code or state != _oauth_state.get('state'):
        return HTMLResponse("<h1>Authentication failed</h1><p>State mismatch or missing code.</p>", status_code=400)

    try:
        response = requests.post(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'code': code,
                'redirect_uri': _oauth_state['redirect_uri'],
                'grant_type': 'authorization_code',
                'code_verifier': _oauth_state['verifier'],
            }
        )
        response.raise_for_status()
        token_data = response.json()

        token_manager.access_token = token_data['access_token']
        token_manager.refresh_token = token_data.get('refresh_token', token_manager.refresh_token)
        token_manager.expires_at = time.time() + token_data['expires_in']
        token_manager.save_tokens()

        _oauth_state.clear()
        return RedirectResponse(url="/")
    except requests.exceptions.RequestException as e:
        _oauth_state.clear()
        return HTMLResponse(f"<h1>Authentication error</h1><pre>{e}</pre>", status_code=500)


# ---- Quota endpoint ----

@app.get("/api/quota")
async def get_quota():
    payload = checker.get_quota_payload()
    if payload is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return payload


# ---- Logout ----

@app.post("/api/logout")
async def logout():
    token_manager.clear_tokens()
    return {"ok": True}


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    print(f"Starting Antigravity Quota Watcher on http://127.0.0.1:{SERVER_PORT}")
    uvicorn.run(app, host="0.0.0.0", port=SERVER_PORT)
