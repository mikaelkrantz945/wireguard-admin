"""Base provider interface for identity integrations."""


class BaseProvider:
    provider_type: str = ""
    display_name: str = ""
    config_fields: list[dict] = []  # [{name, label, placeholder, type}]

    def get_auth_url(self, config: dict, redirect_uri: str) -> str:
        """Return the OAuth authorization URL."""
        raise NotImplementedError

    def exchange_code(self, config: dict, code: str, redirect_uri: str) -> dict:
        """Exchange auth code for tokens. Returns {access_token, refresh_token, expires_at}."""
        raise NotImplementedError

    def refresh_tokens(self, config: dict, tokens: dict) -> dict:
        """Refresh expired tokens. Returns updated tokens dict."""
        raise NotImplementedError

    def list_users(self, config: dict, tokens: dict) -> list[dict]:
        """Fetch users from the provider. Returns [{email, firstname, lastname, ...}]."""
        raise NotImplementedError

    def get_setup_instructions(self) -> str:
        """Return HTML instructions for setting up this provider."""
        return ""
