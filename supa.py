"""Small Supabase REST helper (no SDK needed).

Two kinds of calls:
  * as_user(token)  - uses the customer's own access token, so Row Level Security limits
                      what they can see. Used for reads (balances, transactions, cards).
  * service         - uses SUPABASE_SERVICE_ROLE_KEY. Server only. Used for writing guard
                      events, fraud scores, and executing confirmed actions through
                      locked-down SQL functions.
"""
import logging
import os

import httpx

log = logging.getLogger("vaultsense.supabase")


class SupabaseError(Exception):
    pass


class Supabase:
    def __init__(self, http: httpx.AsyncClient, url=None, anon_key=None, service_key=None):
        self.http = http
        self.url = (url if url is not None else os.environ.get("SUPABASE_URL", "")).rstrip("/")
        self.anon = anon_key if anon_key is not None else os.environ.get("SUPABASE_ANON_KEY", "")
        self.service = service_key if service_key is not None else os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

    @property
    def enabled(self):
        return bool(self.url and self.anon)

    @property
    def can_write(self):
        return bool(self.url and self.service)

    def _headers(self, token, key):
        return {"apikey": key, "Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def select(self, table, params, user_token):
        """Read as the customer (RLS applies)."""
        r = await self.http.get(f"{self.url}/rest/v1/{table}", params=params,
                                headers=self._headers(user_token, self.anon))
        if r.status_code >= 400:
            raise SupabaseError(f"select {table}: {r.status_code}")
        return r.json()

    async def rpc(self, fn, args):
        """Call a SQL function with the service role (functions do their own ownership checks)."""
        if not self.can_write:
            raise SupabaseError("SUPABASE_SERVICE_ROLE_KEY not set")
        r = await self.http.post(f"{self.url}/rest/v1/rpc/{fn}", json=args,
                                 headers=self._headers(self.service, self.service))
        if r.status_code >= 400:
            # Surface the database's message (e.g. "insufficient funds") but nothing else.
            try:
                msg = r.json().get("message", "")
            except ValueError:
                msg = ""
            raise SupabaseError(msg or f"rpc {fn}: {r.status_code}")
        return r.json() if r.content else None

    async def update_service(self, table, match, values):
        if not self.can_write:
            raise SupabaseError("SUPABASE_SERVICE_ROLE_KEY not set")
        params = {k: f"eq.{v}" for k, v in match.items()}
        r = await self.http.patch(f"{self.url}/rest/v1/{table}", params=params, json=values,
                                  headers={**self._headers(self.service, self.service), "Prefer": "return=minimal"})
        if r.status_code >= 400:
            raise SupabaseError(f"update {table}: {r.status_code}")

    async def log_guard_event(self, row):
        """Best effort: a logging failure must never break the chatbot."""
        if not self.can_write:
            return False
        try:
            r = await self.http.post(f"{self.url}/rest/v1/guard_events", json=row,
                                     headers={**self._headers(self.service, self.service), "Prefer": "return=minimal"})
            if r.status_code >= 400:
                log.warning("guard_events insert failed: %s", r.status_code)
                return False
            return True
        except httpx.HTTPError as e:
            log.warning("guard_events insert error: %s", type(e).__name__)
            return False
