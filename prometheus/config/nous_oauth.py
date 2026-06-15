"""Nous Portal OAuth device code flow for Prometheus.

Mirrors Hermes' nous_account.py and auth.py Nous OAuth implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

import httpx

# Constants (matching Hermes)
DEFAULT_NOUS_PORTAL_URL = "https://portal.nousresearch.com"
DEFAULT_NOUS_INFERENCE_URL = "https://inference-api.nousresearch.com/v1"
DEFAULT_NOUS_CLIENT_ID = "hermes-cli"
NOUS_DEVICE_CODE_SOURCE = "device_code"
NOUS_AUTH_PATH_INVOKE_JWT = "invoke_jwt"
ACCESS_TOKEN_REFRESH_SKEW_SECONDS = 120
NOUS_INVOKE_JWT_MIN_TTL_SECONDS = ACCESS_TOKEN_REFRESH_SKEW_SECONDS
DEVICE_AUTH_POLL_INTERVAL_CAP_SECONDS = 1

# Auth store path
PROMETHEUS_AUTH_DIR = Path.home() / ".prometheus"
PROMETHEUS_AUTH_FILE = PROMETHEUS_AUTH_DIR / "auth.json"
PROMETHEUS_AUTH_LOCK = PROMETHEUS_AUTH_DIR / "auth.json.lock"

# Cache
_ACCOUNT_INFO_CACHE_TTL = 60
_account_info_cache: tuple[str, float, "NousPortalAccountInfo"] | None = None
_ACCOUNT_INFO_CACHE_LOCK = threading.Lock()


# === Account Info Types (from Hermes) ===

NousAccountInfoSource = Literal["jwt", "account_api", "inference_key", "none", "error"]


@dataclass(frozen=True)
class NousPortalSubscriptionInfo:
    plan: Optional[str] = None
    tier: Optional[int] = None
    monthly_charge: Optional[float] = None
    current_period_end: Optional[str] = None
    credits_remaining: Optional[float] = None
    rollover_credits: Optional[float] = None


@dataclass(frozen=True)
class NousPaidServiceAccessInfo:
    allowed: Optional[bool] = None
    paid_access: Optional[bool] = None
    reason: Optional[str] = None
    organisation_id: Optional[str] = None
    effective_at_ms: Optional[int] = None
    has_active_subscription: Optional[bool] = None
    active_subscription_is_paid: Optional[bool] = None
    subscription_tier: Optional[int] = None
    subscription_monthly_charge: Optional[float] = None
    subscription_credits_remaining: Optional[float] = None
    purchased_credits_remaining: Optional[float] = None
    total_usable_credits: Optional[float] = None


@dataclass(frozen=True)
class NousToolAccessInfo:
    enabled: bool = False
    coverage: dict[str, bool] = field(default_factory=dict)


@dataclass(frozen=True)
class NousPortalAccountInfo:
    logged_in: bool
    source: NousAccountInfoSource
    fresh: bool
    user_id: Optional[str] = None
    org_id: Optional[str] = None
    client_id: Optional[str] = None
    product_id: Optional[str] = None
    nous_client: Optional[str] = None
    portal_base_url: Optional[str] = None
    inference_base_url: Optional[str] = None
    inference_credential_present: bool = False
    credential_source: Optional[str] = None
    expires_at: Optional[datetime] = None
    email: Optional[str] = None
    privy_did: Optional[str] = None
    subscription: Optional[NousPortalSubscriptionInfo] = None
    paid_service_access: Optional[bool] = None
    paid_service_access_info: Optional[NousPaidServiceAccessInfo] = None
    tool_access: Optional[NousToolAccessInfo] = None
    raw_claims: Optional[dict[str, Any]] = None
    raw_account: Optional[dict[str, Any]] = None
    error: Optional[str] = None

    @property
    def is_paid(self) -> bool:
        return self.paid_service_access is True

    @property
    def is_free_tier(self) -> bool:
        return self.paid_service_access is False

    @property
    def tool_gateway_entitled(self) -> bool:
        if self.paid_service_access is True:
            return True
        return self.tool_access is not None and self.tool_access.enabled

    def tool_gateway_entitled_for(self, category: str) -> bool:
        if self.paid_service_access is True:
            return True
        ta = self.tool_access
        return bool(ta and ta.enabled and ta.coverage.get(category) is True)


# === Auth Store Persistence ===


def _auth_file_path() -> Path:
    return PROMETHEUS_AUTH_FILE


def _auth_lock_path() -> Path:
    return PROMETHEUS_AUTH_LOCK


_auth_lock_holder = threading.local()


def _load_auth_store() -> dict[str, Any]:
    path = _auth_file_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_auth_store(store: dict[str, Any]) -> None:
    path = _auth_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")


def _load_provider_state(store: dict[str, Any], provider: str) -> dict[str, Any]:
    return store.get("providers", {}).get(provider, {})


def _save_provider_state(store: dict[str, Any], provider: str, state: dict[str, Any]) -> None:
    if "providers" not in store:
        store["providers"] = {}
    store["providers"][provider] = state


def _file_lock(lock_path: Path, holder: threading.local, timeout_seconds: float):
    """Cross-process advisory file lock."""
    try:
        import fcntl
    except ImportError:
        fcntl = None
    try:
        import msvcrt
    except ImportError:
        msvcrt = None

    if getattr(holder, "depth", 0) > 0:
        holder.depth += 1
        try:
            yield
        finally:
            holder.depth -= 1
        return

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if msvcrt and (not lock_path.exists() or lock_path.stat().st_size == 0):
        lock_path.write_text(" ", encoding="utf-8")

    with lock_path.open("r+" if msvcrt else "a+", encoding="utf-8") as lock_file:
        deadline = time.monotonic() + max(1.0, timeout_seconds)
        while True:
            try:
                if fcntl:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except (BlockingIOError, OSError):
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Could not acquire lock on {lock_path}")
                time.sleep(0.1)
        try:
            yield
        finally:
            if fcntl:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            else:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)


# === JWT Helpers ===


def _decode_jwt_claims(token: str) -> dict[str, Any] | None:
    """Decode JWT claims without verification (local UX only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        import base64

        payload = parts[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def _coerce_str(value: Any) -> Optional[str]:
    if isinstance(value, str) and value:
        return value
    return None


def _coerce_bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _coerce_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_iso_timestamp(value: Any) -> Optional[float]:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def _is_expiring(expires_at: Any | None, skew_seconds: int) -> bool:
    if not expires_at:
        return True
    exp_ts = _parse_iso_timestamp(expires_at)
    if exp_ts is None:
        return True
    return time.time() >= exp_ts - skew_seconds


# === Logging ===
import logging

logger = logging.getLogger(__name__)


# === Device Code Flow ===


def start_device_code_flow(
    portal_base_url: str | None = None,
    client_id: str | None = None,
    scope: str | None = None,
    timeout_seconds: float = 60.0,
) -> dict[str, Any]:
    """Start a device code OAuth flow with Nous Portal.

    Returns dict with: device_code, user_code, verification_uri, interval, etc.
    Raises RuntimeError on failure.
    """
    base = (portal_base_url or DEFAULT_NOUS_PORTAL_URL).rstrip("/")
    cid = client_id or DEFAULT_NOUS_CLIENT_ID
    scp = scope or "inference:invoke"

    resp = httpx.post(
        f"{base}/oauth/device/code",
        json={"client_id": cid, "scope": scp},
        timeout=timeout_seconds,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Nous device code request failed: HTTP {resp.status_code} - {resp.text[:200]}"
        )
    data = resp.json()
    if not isinstance(data, dict) or "device_code" not in data:
        raise RuntimeError(f"Nous device code response missing device_code: {data}")
    return data


def poll_device_code_flow(
    device_code: str,
    portal_base_url: str | None = None,
    client_id: str | None = None,
    interval: int = 5,
    max_wait_seconds: float = 300.0,
) -> dict[str, Any]:
    """Poll the device code flow until the user authorizes or it times out.

    Returns dict with: access_token, refresh_token, expires_in, etc.
    Raises TimeoutError if user doesn't authorize in time.
    """
    base = (portal_base_url or DEFAULT_NOUS_PORTAL_URL).rstrip("/")
    cid = client_id or DEFAULT_NOUS_CLIENT_ID
    deadline = time.monotonic() + max_wait_seconds

    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("Device code flow timed out")

        resp = httpx.post(
            f"{base}/oauth/device/token",
            json={
                "client_id": cid,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            timeout=30.0,
        )
        data = resp.json() if resp.content else {}

        if resp.status_code == 200 and data.get("access_token"):
            return data

        if data.get("error") == "authorization_pending":
            time.sleep(max(1, min(interval, 5)))
            continue
        elif data.get("error") == "slow_down":
            interval = min(interval + 2, 10)
            time.sleep(interval)
            continue
        elif data.get("error") in ("access_denied", "expired_token"):
            raise RuntimeError(f"Device code flow failed: {data.get('error')}")

        time.sleep(max(1, min(interval, 5)))


def run_interactive_login(
    portal_base_url: str | None = None,
    client_id: str | None = None,
) -> dict[str, Any]:
    """Run the full interactive device code login flow.

    Prints the URL/code for the user to visit, then polls for completion.
    Persists the credentials to ~/.prometheus/auth.json on success.
    """
    base = portal_base_url or DEFAULT_NOUS_PORTAL_URL
    cid = client_id or DEFAULT_NOUS_CLIENT_ID

    code_data = start_device_code_flow(portal_base_url=base, client_id=cid)
    device_code = code_data["device_code"]
    user_code = code_data["user_code"]
    verification_uri = code_data.get("verification_uri", f"{base}/activate")
    interval = int(code_data.get("interval", 5))

    print("=" * 60)
    print("NOUS PORTAL LOGIN")
    print("=" * 60)
    print(f"1. Open:  {verification_uri}")
    print(f"2. Enter code:  {user_code}")
    print(f"3. Authorize Prometheus to use your Nous Portal subscription")
    print(f"   (code expires in {code_data.get('expires_in', 300)} seconds)")
    print("=" * 60)

    token_data = poll_device_code_flow(
        device_code=device_code,
        portal_base_url=base,
        client_id=cid,
        interval=interval,
        max_wait_seconds=float(code_data.get("expires_in", 300)),
    )

    now = datetime.now(timezone.utc)
    access_ttl = int(token_data.get("expires_in", 3600))
    state = {
        "access_token": token_data["access_token"],
        "refresh_token": token_data.get("refresh_token", ""),
        "token_type": token_data.get("token_type", "Bearer"),
        "scope": token_data.get("scope", "inference:invoke"),
        "client_id": cid,
        "portal_base_url": base,
        "inference_base_url": DEFAULT_NOUS_INFERENCE_URL,
        "obtained_at": now.isoformat(),
        "expires_in": access_ttl,
        "expires_at": datetime.fromtimestamp(
            now.timestamp() + access_ttl, tz=timezone.utc
        ).isoformat(),
    }

    # Persist
    _persist_nous_credentials(state)
    return state


def _persist_nous_credentials(state: dict[str, Any]) -> None:
    """Persist Nous OAuth credentials to the auth store."""
    with _file_lock(PROMETHEUS_AUTH_LOCK, _auth_lock_holder, 15.0):
        store = _load_auth_store()
        _save_provider_state(store, "nous", state)
        _save_auth_store(store)


# === Token Refresh ===


def _refresh_access_token(
    *,
    portal_base_url: str,
    client_id: str,
    refresh_token: str,
    timeout_seconds: float = 15.0,
) -> dict[str, Any]:
    """Refresh a Nous Portal access token using the refresh token."""
    base = portal_base_url.rstrip("/")
    resp = httpx.post(
        f"{base}/oauth/token",
        json={
            "client_id": client_id,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=timeout_seconds,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Nous token refresh failed: HTTP {resp.status_code} - {resp.text[:200]}"
        )
    data = resp.json()
    if not isinstance(data, dict) or "access_token" not in data:
        raise RuntimeError(f"Nous token refresh response missing access_token: {data}")
    return data


def resolve_nous_access_token(
    *,
    force_refresh: bool = False,
    timeout_seconds: float = 15.0,
) -> str:
    """Resolve a fresh Nous Portal access token.

    Reads stored credentials, refreshes if expired, returns the access_token.
    Raises RuntimeError if no credentials stored or refresh fails.
    """
    with _file_lock(PROMETHEUS_AUTH_LOCK, _auth_lock_holder, timeout_seconds + 5.0):
        store = _load_auth_store()
        state = _load_provider_state(store, "nous")

        if not state or not state.get("access_token"):
            raise RuntimeError("No Nous Portal credentials found. Run login first.")

        access_token = str(state.get("access_token", ""))
        refresh_token = str(state.get("refresh_token", ""))
        portal_base_url = str(state.get("portal_base_url") or DEFAULT_NOUS_PORTAL_URL).rstrip("/")
        client_id = str(state.get("client_id") or DEFAULT_NOUS_CLIENT_ID)

        if not force_refresh and not _is_expiring(
            state.get("expires_at"), ACCESS_TOKEN_REFRESH_SKEW_SECONDS
        ):
            return access_token

        if not refresh_token:
            raise RuntimeError("Session expired and no refresh token available. Re-login required.")

        refreshed = _refresh_access_token(
            portal_base_url=portal_base_url,
            client_id=client_id,
            refresh_token=refresh_token,
            timeout_seconds=timeout_seconds,
        )

        now = datetime.now(timezone.utc)
        access_ttl = int(refreshed.get("expires_in", 3600))
        state["access_token"] = refreshed["access_token"]
        state["refresh_token"] = refreshed.get("refresh_token") or refresh_token
        state["token_type"] = refreshed.get("token_type") or state.get("token_type") or "Bearer"
        state["obtained_at"] = now.isoformat()
        state["expires_in"] = access_ttl
        state["expires_at"] = datetime.fromtimestamp(
            now.timestamp() + access_ttl, tz=timezone.utc
        ).isoformat()

        _save_provider_state(store, "nous", state)
        _save_auth_store(store)

        return state["access_token"]


# === Account Info ===


def get_nous_portal_account_info(
    *,
    force_fresh: bool = False,
    min_jwt_ttl_seconds: int = 60,
) -> NousPortalAccountInfo:
    """Return normalized Nous Portal account entitlement information.

    Uses local JWT decoding for fast cached responses.
    force_fresh=True always calls /api/oauth/account.
    """
    store = _load_auth_store()
    state = _load_provider_state(store, "nous")

    access_token = state.get("access_token", "")
    portal_base_url = str(state.get("portal_base_url") or DEFAULT_NOUS_PORTAL_URL).rstrip("/")

    if not access_token:
        return NousPortalAccountInfo(
            logged_in=False,
            source="none",
            fresh=False,
            portal_base_url=portal_base_url,
            error="no_access_token",
        )

    if not force_fresh:
        jwt_info = _info_from_valid_jwt(access_token, state, portal_base_url, min_jwt_ttl_seconds)
        if jwt_info is not None:
            return jwt_info

    return _fresh_account_info(state, portal_base_url)


def _info_from_valid_jwt(
    token: str,
    state: dict[str, Any],
    portal_base_url: str | None,
    min_jwt_ttl_seconds: int,
) -> NousPortalAccountInfo | None:
    """Try to build account info from local JWT claims."""
    claims = _decode_jwt_claims(token)
    if not claims:
        return None

    exp = _coerce_float(claims.get("exp"))
    if exp is None or exp <= time.time() + max(0, int(min_jwt_ttl_seconds)):
        return None

    paid_access = _coerce_bool(claims.get("paid_access"))
    access_info = NousPaidServiceAccessInfo(
        allowed=paid_access,
        paid_access=paid_access,
        organisation_id=_coerce_str(claims.get("org_id")),
        subscription_tier=_coerce_int(claims.get("subscription_tier")),
    )

    return NousPortalAccountInfo(
        logged_in=True,
        source="jwt",
        fresh=False,
        user_id=_coerce_str(claims.get("sub")),
        org_id=_coerce_str(claims.get("org_id")),
        client_id=_coerce_str(claims.get("client_id") or state.get("client_id")),
        portal_base_url=portal_base_url,
        inference_base_url=_coerce_str(state.get("inference_base_url")),
        inference_credential_present=True,
        credential_source="auth_store",
        expires_at=datetime.fromtimestamp(exp, tz=timezone.utc) if exp else None,
        paid_service_access=paid_access,
        paid_service_access_info=access_info,
        raw_claims=dict(claims),
    )


def _fresh_account_info(
    state: dict[str, Any],
    portal_base_url: str | None,
) -> NousPortalAccountInfo:
    """Fetch account info from the Portal API."""
    global _account_info_cache

    access_token = state.get("access_token", "")
    try:
        base = (portal_base_url or DEFAULT_NOUS_PORTAL_URL).rstrip("/")
        url = f"{base}/api/oauth/account"
        resp = httpx.get(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=8.0,
        )
        if resp.status_code != 200:
            return NousPortalAccountInfo(
                logged_in=True,
                source="error",
                fresh=False,
                portal_base_url=portal_base_url,
                error=f"account_api_http_{resp.status_code}",
            )
        payload = resp.json()
        if not isinstance(payload, dict):
            return NousPortalAccountInfo(
                logged_in=True,
                source="error",
                fresh=False,
                portal_base_url=portal_base_url,
                error="invalid_account_response",
            )

        user = payload.get("user") if isinstance(payload.get("user"), dict) else {}
        subscription = (
            NousPortalSubscriptionInfo(
                plan=_coerce_str(payload.get("subscription", {}).get("plan")),
                tier=_coerce_int(payload.get("subscription", {}).get("tier")),
                monthly_charge=_coerce_float(payload.get("subscription", {}).get("monthly_charge")),
                current_period_end=_coerce_str(
                    payload.get("subscription", {}).get("current_period_end")
                ),
                credits_remaining=_coerce_float(
                    payload.get("subscription", {}).get("credits_remaining")
                ),
                rollover_credits=_coerce_float(
                    payload.get("subscription", {}).get("rollover_credits")
                ),
            )
            if isinstance(payload.get("subscription"), dict)
            else None
        )

        info = NousPortalAccountInfo(
            logged_in=True,
            source="account_api",
            fresh=True,
            user_id=_coerce_str(user.get("id")),
            org_id=_coerce_str(payload.get("organisation", {}).get("id"))
            if isinstance(payload.get("organisation"), dict)
            else None,
            client_id=_coerce_str(state.get("client_id")),
            portal_base_url=portal_base_url,
            inference_base_url=_coerce_str(state.get("inference_base_url")),
            inference_credential_present=True,
            credential_source="auth_store",
            email=_coerce_str(user.get("email")),
            subscription=subscription,
            paid_service_access=_coerce_bool(payload.get("paid_service_access", {}).get("allowed"))
            if isinstance(payload.get("paid_service_access"), dict)
            else None,
            raw_account=dict(payload),
        )
        return info
    except Exception as exc:
        return NousPortalAccountInfo(
            logged_in=True,
            source="error",
            fresh=False,
            portal_base_url=portal_base_url,
            error=str(exc),
        )


# === Provider Integration ===


def get_nous_api_key_from_oauth() -> str:
    """Get a usable inference API key from Nous OAuth credentials.

    This resolves the access token (refreshing if needed) and returns
    it as the API key for use with the OpenAI-compatible inference endpoint.
    """
    try:
        return resolve_nous_access_token()
    except RuntimeError:
        return ""


def is_nous_oauth_configured() -> bool:
    """Check if Nous OAuth credentials are stored."""
    try:
        store = _load_auth_store()
        state = _load_provider_state(store, "nous")
        return bool(state.get("access_token"))
    except Exception:
        return False


def get_nous_oauth_state() -> dict[str, Any]:
    """Return the current Nous OAuth state for use in LLM config."""
    store = _load_auth_store()
    state = _load_provider_state(store, "nous")
    if not state:
        return {}
    token = get_nous_api_key_from_oauth()
    return {
        "access_token": token or state.get("access_token", ""),
        "base_url": str(state.get("inference_base_url") or DEFAULT_NOUS_INFERENCE_URL).rstrip("/")
        + "/",
        "portal_url": str(state.get("portal_base_url") or DEFAULT_NOUS_PORTAL_URL),
    }
