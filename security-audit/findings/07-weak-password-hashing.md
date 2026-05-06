# 07 — Weak Password Hashing (SHA-256)

**Status:** Fix in progress
**Priority:** Critical
**Area:** Cryptography, Credential Storage

## Confirmed Findings

### Current implementation

**Admin passwords** (`app/users.py:18-20`):
```python
def _hash_password(password: str) -> str:
    salt = "wgadmin-salt"
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
```

**Portal passwords** (`app/portal.py:29-30`):
```python
def _hash(s: str) -> str:
    return hashlib.sha256(f"wgportal:{s}".encode()).hexdigest()
```

- Static salt (same for all users)
- SHA-256 is a fast hash — billions/sec on modern GPUs
- Direct `!=` comparison (not constant-time)
- 3 additional inline `hashlib.sha256("wgportal:...")` duplications

### All 11 hash/verify locations

| # | File | Line | Purpose |
|---|------|------|---------|
| 1 | `users.py` | 18-20 | `_hash_password()` definition |
| 2 | `users.py` | 69 | Accept invite — hash |
| 3 | `users.py` | 76 | Login — verify |
| 4 | `users.py` | 156 | Change password — hash |
| 5 | `main.py` | 100 | Bootstrap — hash |
| 6 | `portal.py` | 29-30 | `_hash()` definition |
| 7 | `portal.py` | 139 | Activate — hash |
| 8 | `portal.py` | 199 | Portal login — verify |
| 9 | `wireguard/routes.py` | 268 | Create peer — inline hash |
| 10 | `wireguard/routes.py` | 297 | Update peer — inline hash |
| 11 | `hostbill/routes.py` | 99 | Provision — inline hash |

## Remediation

- New `app/password.py` module with bcrypt via passlib
- Transparent rehash-on-login migration (detects legacy SHA-256 hashes)
- All 11 call sites updated
- `_hash()` in portal.py kept for session/activation tokens (non-password)
