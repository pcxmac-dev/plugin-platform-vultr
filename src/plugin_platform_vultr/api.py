"""Vultr's API v2, as its reference gives it (https://www.vultr.com/api/, read 2026-11-11: an OpenAPI 3.0 document, "Vultr
API" version 2.0): https://api.vultr.com/v2, every request bearing the account's API key (`Authorization: Bearer`), JSON
both ways, a list paged by a cursor (`per_page`, at most 500, and `cursor` from the answer's `meta.links.next`), a 4xx
answered with a JSON `error`, more than 30 requests a second from one address answered 429 with a `Retry-After`. A key
answers only from the addresses its Access Control allows (Account > API in Vultr's console).

Every call the client makes is in ENDPOINTS, by the reference's own method and path (the API card's used calls are these,
test_contract checks it): the reads of the account and its parts, and the changes that cost nothing (an instance started,
rebooted or halted; a DNS record created, updated or deleted; a firewall rule added or removed; an SSH key added or
removed). Nothing here creates, resizes, restores or destroys anything billable, nor turns backups on. Its HTTP goes
through the library's RestClient (machines/rest.py): a 429 waited out, a read tried again, a write never sent twice, the
key scrubbed from every word."""
from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from urllib.parse import quote

from liminal_libs.machines.rest import Answer, RestClient, RestError, bearer

BASE = "https://api.vultr.com/v2"
PER_PAGE = 500  # the reference: "Default is 100 and Max is 500"
MOST_PAGES = 20  # pages read of one list at most (10,000 items)
GAP_S = 0.1  # at most ten requests a second: a third of Vultr's 30 a second per address
RATE = "30 requests a second per address"

ENDPOINTS: dict[str, tuple[str, str]] = {  # every call the client makes, by the reference's method and path
    # the reads
    "account": ("GET", "/account"),
    "instances": ("GET", "/instances"),
    "instance": ("GET", "/instances/{instance-id}"),
    "plans": ("GET", "/plans"),
    "regions": ("GET", "/regions"),
    "domains": ("GET", "/domains"),
    "records": ("GET", "/domains/{dns-domain}/records"),
    "firewalls": ("GET", "/firewalls"),
    "firewall": ("GET", "/firewalls/{firewall-group-id}"),
    "rules": ("GET", "/firewalls/{firewall-group-id}/rules"),
    "ssh_keys": ("GET", "/ssh-keys"),
    "blocks": ("GET", "/blocks"),
    "reserved_ips": ("GET", "/reserved-ips"),
    "bare_metals": ("GET", "/bare-metals"),
    "snapshots": ("GET", "/snapshots"),
    "backups": ("GET", "/backups"),
    "kubernetes": ("GET", "/kubernetes/clusters"),
    "load_balancers": ("GET", "/load-balancers"),
    "databases": ("GET", "/databases"),
    # the changes that cost nothing
    "start": ("POST", "/instances/{instance-id}/start"),
    "reboot": ("POST", "/instances/{instance-id}/reboot"),
    "halt": ("POST", "/instances/{instance-id}/halt"),
    "record_create": ("POST", "/domains/{dns-domain}/records"),
    "record_update": ("PATCH", "/domains/{dns-domain}/records/{record-id}"),
    "record_delete": ("DELETE", "/domains/{dns-domain}/records/{record-id}"),
    "rule_create": ("POST", "/firewalls/{firewall-group-id}/rules"),
    "rule_delete": ("DELETE", "/firewalls/{firewall-group-id}/rules/{firewall-rule-id}"),
    "key_create": ("POST", "/ssh-keys"),
    "key_delete": ("DELETE", "/ssh-keys/{ssh-key-id}"),
}
WRITES = frozenset(n for n, (m, _) in ENDPOINTS.items() if m != "GET")

# the other kinds counted (one cheap list each): ENDPOINTS name, the answer's list, its words, whether it takes per_page
COUNTED = (("bare_metals", "bare_metals", "Bare metal servers", True),
           ("snapshots", "snapshots", "Snapshots", True),
           ("backups", "backups", "Backups", True),
           ("kubernetes", "vke_clusters", "Kubernetes clusters", False),
           ("load_balancers", "load_balancers", "Load balancers", True),
           ("databases", "databases", "Managed databases", False))

HINTS = {  # an answer's status -> what to do, after Vultr's own words
    401: "the API key was refused: it is wrong or rotated, or this network's address is not in its Access Control "
         "(Vultr's console: Account > API)",
    403: "the key's user may not do this: its permissions are set in Vultr's console (Users, the user's permissions)",
    429: f"Vultr's rate limit ({RATE}): tried again later",
}
IP_REFUSED = ("this network's address is not in the API key's Access Control: add it in Vultr's console, Account > API > "
              "Access Control (a key answers only from the addresses its Access Control allows)")


def words_of(answer: Answer) -> tuple[str, str]:
    """Vultr's error in words (its `error`, then what to do about it) and its code (the answer's status)."""
    data = answer.data if isinstance(answer.data, Mapping) else {}
    said = str(data.get("error") or "").strip()
    if not said:
        said = answer.body[:200].decode("utf-8", "replace").strip() or f"HTTP {answer.status}"
    hint = IP_REFUSED if answer.status == 401 and "ip" in said.lower() and "address" in said.lower() else \
        HINTS.get(answer.status, "")
    return (f"{said} ({hint})" if hint else said), str(data.get("status") or answer.status)


def path_of(template: str, where: Mapping[str, object] | None = None) -> str:
    """A path of the reference's with its parameters filled in (each quoted whole: an ID or a domain never adds a /)."""
    out = template
    for name, value in (where or {}).items():
        text = str(value if value is not None else "").strip()
        if not text:
            raise ValueError(f"no {name} given")
        out = out.replace("{" + name + "}", quote(text, safe=""))
    if "{" in out:
        raise ValueError(f"{template}: {out[out.index('{'):]} is not given")
    return out


class VultrApi:
    """The account's API: its parts read, and the free changes. `transport`: a test's stand-in for HTTPS (RestClient's);
    `gap`: the least time between two requests (GAP_S)."""

    def __init__(self, key: str, transport=None, clock=time.time, sleep=time.sleep, gap: float = GAP_S,
                 monotonic=time.monotonic):
        if not key:
            raise ValueError("the API needs VULTR_API_KEY")
        self.rest = RestClient(BASE, auth=bearer(key), secrets=(key,), transport=transport, error=words_of, clock=clock,
                               sleep=sleep)
        self._sleep, self._gap, self._monotonic = sleep, max(0.0, gap), monotonic
        self._last = 0.0
        self._pace = threading.Lock()

    def __repr__(self) -> str:
        return f"<VultrApi {BASE}>"

    # -- sending ----------------------------------------------------------------------------------------------------------
    def call(self, name: str, where: Mapping[str, object] | None = None, params: Mapping | None = None, body=None):
        """One of ENDPOINTS asked (its path's parameters in `where`): the answer's JSON (None when it has none)."""
        method, template = ENDPOINTS[name]
        path = path_of(template, where)
        with self._pace:
            wait = self._last + self._gap - self._monotonic()
            if wait > 0:
                self._sleep(wait)
            self._last = self._monotonic()
        return self.rest.request(method, path, params=params, json=body).data

    def every(self, name: str, items: str, where: Mapping[str, object] | None = None, params: Mapping | None = None) -> list:
        """Every item of a list across its pages (per_page at its most, the cursor of meta.links.next)."""
        out: list = []
        cursor = None
        for _ in range(MOST_PAGES):
            asked = {"per_page": PER_PAGE, **(params or {}), **({"cursor": cursor} if cursor else {})}
            data = self.call(name, where, asked) or {}
            found = data.get(items) if isinstance(data, Mapping) else None
            out += list(found or [])
            cursor = next_cursor(data)
            if not cursor or not found:
                break
        return out

    def count(self, name: str, items: str, paged: bool = True) -> int:
        """How many a list holds: its meta.total, asked with a page of one where the list takes per_page."""
        data = self.call(name, None, {"per_page": 1} if paged else None) or {}
        total = ((data.get("meta") or {}) if isinstance(data, Mapping) else {}).get("total")
        if isinstance(total, int) and total >= 0:
            return total
        found = data.get(items) if isinstance(data, Mapping) else None
        return len(found or [])

    # -- the reads --------------------------------------------------------------------------------------------------------
    def account(self) -> dict:
        return dict((self.call("account") or {}).get("account") or {})

    def instances(self) -> list[dict]:
        return self.every("instances", "instances")

    def instance(self, instance_id: str) -> dict:
        return dict((self.call("instance", {"instance-id": instance_id}) or {}).get("instance") or {})

    def plans(self) -> list[dict]:
        return self.every("plans", "plans", params={"type": "all"})

    def regions(self) -> list[dict]:
        return self.every("regions", "regions")

    def domains(self) -> list[dict]:
        return self.every("domains", "domains")

    def records(self, domain: str, name: str | None = None, rtype: str | None = None) -> list[dict]:
        """A domain's records (`name`, relative to the domain, "" its apex; `rtype`: only those)."""
        return self.every("records", "records", {"dns-domain": domain}, {"name": name, "type": rtype})

    def firewalls(self) -> list[dict]:
        return self.every("firewalls", "firewall_groups")

    def firewall(self, group: str) -> dict:
        return dict((self.call("firewall", {"firewall-group-id": group}) or {}).get("firewall_group") or {})

    def rules(self, group: str) -> list[dict]:
        return self.every("rules", "firewall_rules", {"firewall-group-id": group})

    def ssh_keys(self) -> list[dict]:
        return self.every("ssh_keys", "ssh_keys")

    def blocks(self) -> list[dict]:
        return self.every("blocks", "blocks")

    def reserved_ips(self) -> list[dict]:
        return self.every("reserved_ips", "reserved_ips")

    # -- the changes that cost nothing ----------------------------------------------------------------------------------------
    def power(self, action: str, instance_id: str) -> None:
        """An instance started, rebooted or halted (POST, no body; 204)."""
        if action not in ("start", "reboot", "halt"):
            raise ValueError(f"{action!r} is no power change: start, reboot or halt")
        self.call(action, {"instance-id": instance_id})

    def create_record(self, domain: str, body: Mapping) -> dict:
        return dict((self.call("record_create", {"dns-domain": domain}, body=dict(body)) or {}).get("record") or {})

    def update_record(self, domain: str, record_id: str, body: Mapping) -> None:
        self.call("record_update", {"dns-domain": domain, "record-id": record_id}, body=dict(body))

    def delete_record(self, domain: str, record_id: str) -> None:
        self.call("record_delete", {"dns-domain": domain, "record-id": record_id})

    def create_rule(self, group: str, body: Mapping) -> dict:
        return dict((self.call("rule_create", {"firewall-group-id": group}, body=dict(body)) or {}).get("firewall_rule") or {})

    def delete_rule(self, group: str, rule_id) -> None:
        self.call("rule_delete", {"firewall-group-id": group, "firewall-rule-id": rule_id})

    def create_key(self, name: str, ssh_key: str) -> dict:
        return dict((self.call("key_create", body={"name": name, "ssh_key": ssh_key}) or {}).get("ssh_key") or {})

    def delete_key(self, key_id: str) -> None:
        self.call("key_delete", {"ssh-key-id": key_id})


def next_cursor(data) -> str:
    """The cursor of a list's next page ("" at its last)."""
    if not isinstance(data, Mapping):
        return ""
    links = (data.get("meta") or {}).get("links") or {}
    return str(links.get("next") or "") if isinstance(links, Mapping) else ""


__all__ = ["BASE", "COUNTED", "ENDPOINTS", "GAP_S", "PER_PAGE", "RATE", "RestError", "VultrApi", "WRITES", "next_cursor",
           "path_of", "words_of"]
