"""Google Workspace identity provider — OAuth2 + Admin Directory API."""

import urllib.parse
from datetime import datetime, timedelta

import httpx

from .base import BaseProvider


class GoogleWorkspaceProvider(BaseProvider):
    provider_type = "google_workspace"
    display_name = "Google Workspace"
    config_fields = [
        {"name": "client_id", "label": "Client ID", "placeholder": "xxxxx.apps.googleusercontent.com", "type": "text"},
        {"name": "client_secret", "label": "Client Secret", "placeholder": "GOCSPX-xxxxx", "type": "password"},
        {"name": "domain", "label": "Workspace Domain", "placeholder": "yourcompany.com", "type": "text"},
    ]

    SCOPES = "https://www.googleapis.com/auth/admin.directory.user.readonly"
    AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERS_URL = "https://admin.googleapis.com/admin/directory/v1/users"

    def get_auth_url(self, config: dict, redirect_uri: str, state: str = "") -> str:
        params = {
            "client_id": config["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": self.SCOPES,
            "access_type": "offline",
            "prompt": "consent",
        }
        if state:
            params["state"] = state
        return f"{self.AUTH_URL}?{urllib.parse.urlencode(params)}"

    def exchange_code(self, config: dict, code: str, redirect_uri: str) -> dict:
        resp = httpx.post(self.TOKEN_URL, data={
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        })
        resp.raise_for_status()
        data = resp.json()
        expires_at = (datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600))).isoformat()
        return {
            "access_token": data["access_token"],
            "refresh_token": data.get("refresh_token", ""),
            "expires_at": expires_at,
        }

    def refresh_tokens(self, config: dict, tokens: dict) -> dict:
        if not tokens.get("refresh_token"):
            raise ValueError("No refresh token available")
        resp = httpx.post(self.TOKEN_URL, data={
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "refresh_token": tokens["refresh_token"],
            "grant_type": "refresh_token",
        })
        resp.raise_for_status()
        data = resp.json()
        expires_at = (datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600))).isoformat()
        tokens["access_token"] = data["access_token"]
        tokens["expires_at"] = expires_at
        return tokens

    def _ensure_valid_token(self, config: dict, tokens: dict) -> dict:
        """Refresh token if expired."""
        expires_at = tokens.get("expires_at", "")
        if expires_at and expires_at < datetime.utcnow().isoformat():
            tokens = self.refresh_tokens(config, tokens)
        return tokens

    def list_users(self, config: dict, tokens: dict) -> list[dict]:
        tokens = self._ensure_valid_token(config, tokens)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        domain = config.get("domain", "")

        users = []
        page_token = ""
        while True:
            params = {"domain": domain, "maxResults": 200}
            if page_token:
                params["pageToken"] = page_token
            resp = httpx.get(self.USERS_URL, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            for u in data.get("users", []):
                name = u.get("name", {})
                users.append({
                    "email": u.get("primaryEmail", ""),
                    "firstname": name.get("givenName", ""),
                    "lastname": name.get("familyName", ""),
                    "suspended": u.get("suspended", False),
                    "org_unit": u.get("orgUnitPath", "/"),
                })
            page_token = data.get("nextPageToken", "")
            if not page_token:
                break

        return [u for u in users if not u["suspended"]]

    def get_setup_instructions(self) -> str:
        return """<ol style="color:#8b949e;font-size:.85rem;margin:.5rem 0;padding-left:1.2rem">
<li>Go to <a href="https://console.cloud.google.com/apis/credentials" target="_blank" style="color:#58a6ff">Google Cloud Console &rarr; Credentials</a></li>
<li>Create an <b>OAuth 2.0 Client ID</b> (Web application)</li>
<li>Add authorized redirect URI: <code style="color:#e1e4e8">{redirect_uri}</code></li>
<li>Enable the <b>Admin SDK API</b> in your project</li>
<li>The authenticating user must be a <b>Google Workspace admin</b></li>
</ol>"""
