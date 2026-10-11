"""HTTP client for the TuxWall dashboard API.

The API sits behind the router's nginx (LAN/VPN only) and authenticates
with a session cookie (POST /api/auth/login). Sessions live 12h and are
idle-timeout refreshed by any poll, but the client re-logins
transparently on a 401 so long-running instances survive reboots,
restarts and password changes until the stored password stops working.
"""
from __future__ import annotations

import aiohttp
from typing import Any

from .const import LOGGER


class TuxwallAuthError(Exception):
    """Raised when login fails (bad credentials / locked / disabled)."""


class TuxwallApiError(Exception):
    """Raised on transport or non-auth API errors."""


class TuxwallApiClient:
    def __init__(self, base_url: str, username: str, password: str, totp_code: str = "") -> None:
        self._base_url = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._totp_code = totp_code or ""
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def login(self) -> None:
        session = await self._get_session()
        payload: dict[str, Any] = {
            "username": self._username,
            "password": self._password,
        }
        if self._totp_code:
            payload["totp_code"] = self._totp_code
        try:
            async with session.post(
                f"{self._base_url}/api/auth/login", json=payload
            ) as resp:
                body = await resp.json(content_type=None)
                if resp.status == 200 and body.get("ok") and not body.get("totp_required"):
                    return
                if body.get("totp_required"):
                    raise TuxwallAuthError(
                        "Account requires a TOTP code - add it in the integration settings"
                    )
                raise TuxwallAuthError(body.get("error") or f"Login failed (HTTP {resp.status})")
        except aiohttp.ClientError as exc:
            raise TuxwallApiError(f"Cannot reach TuxWall at {self._base_url}: {exc}") from exc

    async def get(self, path: str) -> Any:
        """GET an API path, transparently re-logging in once on a 401."""
        session = await self._get_session()
        url = f"{self._base_url}{path}"
        try:
            for attempt in (1, 2):
                async with session.get(url) as resp:
                    if resp.status == 401 and attempt == 1:
                        LOGGER.debug("Session expired, re-logging in")
                        await self.login()
                        continue
                    if resp.status == 401:
                        raise TuxwallAuthError("TuxWall rejected the session after re-login")
                    if resp.status != 200:
                        raise TuxwallApiError(f"GET {path} returned HTTP {resp.status}")
                    return await resp.json(content_type=None)
        except aiohttp.ClientError as exc:
            raise TuxwallApiError(f"GET {path} failed: {exc}") from exc

    async def post(self, path: str, payload: dict[str, Any]) -> Any:
        session = await self._get_session()
        url = f"{self._base_url}{path}"
        try:
            for attempt in (1, 2):
                async with session.post(url, json=payload) as resp:
                    if resp.status == 401 and attempt == 1:
                        await self.login()
                        continue
                    if resp.status == 401:
                        raise TuxwallAuthError("TuxWall rejected the session after re-login")
                    if resp.status != 200:
                        body = await resp.json(content_type=None)
                        raise TuxwallApiError(
                            body.get("error") or f"POST {path} returned HTTP {resp.status}"
                        )
                    return await resp.json(content_type=None)
        except aiohttp.ClientError as exc:
            raise TuxwallApiError(f"POST {path} failed: {exc}") from exc

    async def whoami(self) -> dict[str, Any]:
        return await self.get("/api/auth/session")
