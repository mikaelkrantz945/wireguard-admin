from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # WireGuard
    wg_config_dir: str = "/etc/wireguard"
    wg_default_dns: str = "195.47.238.46, 195.47.238.48"
    wg_default_endpoint: str = "vpn.example.com"
    wg_default_subnet: str = "10.0.0.0/24"
    wg_default_port: int = 51820

    # HostBill webhook auth
    hostbill_enabled: bool = False
    hostbill_webhook_secret: str = ""

    # Server
    api_port: int = 8092

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
