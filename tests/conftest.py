"""Stand-ins for Vultr and the network: the tests never reach Vultr, a resolver or the network. `FakeVultr` is Vultr's API
v2 as a transport (an account's parts in memory, its answers in the shapes the reference shows: the lists paged by a
cursor with meta.total, a 4xx with its `error` and `status`, a 204 with no body, a 429 with Retry-After); `Pairs` is a
Login holding pairs by name; `HOME` is this network's public address."""
from __future__ import annotations

import base64
import json
import struct
from urllib.parse import parse_qsl, unquote, urlsplit

import pytest

import liminal_libs.dns as dns_mod
import liminal_libs.machines.rest as rest_mod
from liminal_libs.apps import Login, Unauthorized, pair_name
from plugin_platform_vultr import VultrPlugin
from plugin_platform_vultr.settings import NAMES

BASE = "https://api.vultr.com/v2"
KEY = "VULTRTESTKEY0123456789ABCDEFGHIJKLMN"  # a stand-in key (no account's)
HOME = "93.184.216.34"  # this network's public address in the tests
WEB = "cb676a46-66fd-4dfb-b839-443f2e6c0b60"
DB = "1d651bd2-b93c-4bb6-8b91-0546fd765f15"
NEW = "c2790719-278d-474c-8dff-cb35d6e5503f"
G_WEB = "1e7bb4c2-7dbd-4ad4-a4b6-a6d6b8e0b0a1"
G_EMPTY = "5b1f0b3e-9c1d-4e7a-8f00-2d3c4b5a6f70"
G_LONE = "7d0c3a9e-1b2f-4c5d-8e6f-0a1b2c3d4e5f"
BARE_PASSWORD = "example-password"  # a bare metal server's default password, as the list gives it: never shown
KVM = "https://console.vultr.com/subs/vps/novnc/api.php?data=00example11223344"  # an instance's console link: never handed on


def public_key(seed: int = 1, kind: str = "ssh-ed25519", comment: str = "you@host") -> str:
    """A well-formed OpenSSH public key (its blob: the type and 32 bytes), as a .pub file's line."""
    raw = kind.encode()
    blob = struct.pack(">I", len(raw)) + raw + struct.pack(">I", 32) + bytes([seed]) * 32
    return f"{kind} {base64.b64encode(blob).decode()} {comment}".strip()


def answer(status: int, data=None, headers: dict | None = None):
    if data is None:
        return status, dict(headers or {}), b""
    return status, {"Content-Type": "application/json", **(headers or {})}, json.dumps(data).encode()


def error(status: int, words: str):
    return answer(status, {"error": words, "status": status})


class FakeVultr:
    """Vultr's API v2 in memory; every request kept (`requests`: method, path under /v2, query, JSON body)."""

    def __init__(self, key: str = KEY):
        self.key = key
        self.requests: list[tuple[str, str, dict, object]] = []
        self.refuse_ip: str | None = None  # every request answered 401 "Unauthorized IP address: ..."
        self.gate = None  # (test(method, path, query), reached, release): such a request held until `release` is set
        self.down = False  # no answer at all (a broken connection)
        self.fail: dict[tuple[str, str], tuple[int, str]] = {}  # (method, path) -> (status, words)
        self.limited = 0  # the next requests answered 429 (Retry-After: 1)
        self.page_most = 500  # the most a page holds (the reference's Max)
        self.next_id = 100
        self.account = {"name": "Example Account", "email": "admin@example.com",
                        "acls": ["manage_users", "subscriptions_view", "subscriptions", "billing", "dns", "firewall"],
                        "balance": -100.55, "pending_charges": 60.25, "last_payment_date": "2026-10-10T01:56:20+00:00",
                        "last_payment_amount": -1.25}
        self.instances = [
            {"id": WEB, "os": "Debian 12 x64 (bookworm)", "ram": 1024, "disk": 25, "main_ip": "203.0.113.10", "vcpu_count": 1,
             "region": "ewr", "plan": "vc2-1c-1gb", "date_created": "2026-01-05T10:00:00+00:00", "status": "active",
             "power_status": "running", "server_status": "ok", "v6_main_ip": "2001:db8::10", "label": "web-1",
             "hostname": "web-1", "firewall_group_id": G_WEB, "features": ["ipv6"], "tags": ["web"], "kvm": KVM},
            {"id": DB, "os": "Ubuntu 24.04 LTS x64", "ram": 2048, "disk": 64, "main_ip": "203.0.113.20", "vcpu_count": 1,
             "region": "ams", "plan": "vhf-1c-2gb", "date_created": "2026-02-01T08:30:00+00:00", "status": "active",
             "power_status": "stopped", "server_status": "ok", "v6_main_ip": "", "label": "db-1", "hostname": "db-1",
             "firewall_group_id": G_LONE, "features": ["auto_backups"], "tags": []},
            {"id": NEW, "os": "Debian 12 x64 (bookworm)", "ram": 1024, "disk": 25, "main_ip": "0.0.0.0", "vcpu_count": 1,
             "region": "ewr", "plan": "vc2-1c-1gb", "date_created": "2026-11-11T09:00:00+00:00", "status": "pending",
             "power_status": "running", "server_status": "installingbooting", "v6_main_ip": "", "label": "",
             "hostname": "new-1", "firewall_group_id": "", "features": [], "tags": []},
        ]
        self.plans = [
            {"id": "vc2-1c-1gb", "vcpu_count": 1, "ram": 1024, "disk": 25, "bandwidth": 1024, "monthly_cost": 5,
             "hourly_cost": 0.007, "type": "vc2", "locations": ["ewr", "ams"], "invoice_type": "hourly"},
            {"id": "vhf-1c-2gb", "vcpu_count": 1, "ram": 2048, "disk": 64, "bandwidth": 2048, "monthly_cost": 12,
             "hourly_cost": 0.018, "type": "vhf", "locations": ["ams"], "invoice_type": "hourly",
             "location_cost": {"ams": {"monthly_cost": 13, "hourly_cost": 0.019}}},
        ]
        self.regions = [{"id": "ewr", "city": "New Jersey", "country": "US", "continent": "North America", "options": []},
                        {"id": "ams", "city": "Amsterdam", "country": "NL", "continent": "Europe", "options": []}]
        self.domains = [{"domain": "example.com", "date_created": "2025-05-01T00:00:00+00:00", "dns_sec": "disabled"},
                        {"domain": "example.net", "date_created": "2025-06-01T00:00:00+00:00", "dns_sec": "enabled"}]
        self.records = {
            "example.com": [
                {"id": "a0a0a0a0-0000-4000-8000-000000000001", "type": "A", "name": "", "data": "203.0.113.10", "ttl": 300,
                 "priority": 0},
                {"id": "a0a0a0a0-0000-4000-8000-000000000002", "type": "CNAME", "name": "www", "data": "example.com",
                 "ttl": 300, "priority": 0},
                {"id": "a0a0a0a0-0000-4000-8000-000000000003", "type": "MX", "name": "", "data": "mail.protonmail.ch",
                 "ttl": 300, "priority": 10},
                {"id": "a0a0a0a0-0000-4000-8000-000000000004", "type": "TXT", "name": "",
                 "data": '"v=spf1 include:_spf.protonmail.ch ~all"', "ttl": 300, "priority": 0},
                {"id": "a0a0a0a0-0000-4000-8000-000000000005", "type": "NS", "name": "", "data": "ns1.vultr.com", "ttl": 300,
                 "priority": 0},
                # the reference's list example gives a name in full: read as relative
                {"id": "a0a0a0a0-0000-4000-8000-000000000006", "type": "A", "name": "home.example.com",
                 "data": "198.51.100.7", "ttl": 120, "priority": 0},
            ],
            "example.net": [
                {"id": "b0b0b0b0-0000-4000-8000-000000000001", "type": "NS", "name": "", "data": "ns1.vultr.com", "ttl": 300,
                 "priority": 0},
            ],
        }
        self.groups = [
            {"id": G_WEB, "description": "web", "date_created": "2026-01-05T10:00:00+00:00",
             "date_modified": "2026-03-01T12:00:00+00:00", "instance_count": 1, "rule_count": 2, "max_rule_count": 50},
            {"id": G_EMPTY, "description": "spare", "date_created": "2026-01-06T10:00:00+00:00",
             "date_modified": "2026-01-06T10:00:00+00:00", "instance_count": 0, "rule_count": 0, "max_rule_count": 50},
            {"id": G_LONE, "description": "db", "date_created": "2026-02-01T08:30:00+00:00",
             "date_modified": "2026-02-01T08:30:00+00:00", "instance_count": 1, "rule_count": 1, "max_rule_count": 50},
        ]
        self.rules = {
            G_WEB: [{"id": 1, "type": "v4", "ip_type": "v4", "action": "accept", "protocol": "tcp", "port": "22",
                     "subnet": "198.51.100.0", "subnet_size": 24, "source": "", "notes": "office ssh"},
                    {"id": 2, "type": "v4", "ip_type": "v4", "action": "accept", "protocol": "tcp", "port": "443",
                     "subnet": "0.0.0.0", "subnet_size": 0, "source": "", "notes": "https"}],
            G_EMPTY: [],
            G_LONE: [{"id": 1, "type": "v4", "ip_type": "v4", "action": "accept", "protocol": "tcp", "port": "5432",
                      "subnet": "203.0.113.10", "subnet_size": 32, "source": "", "notes": "web to db"}],
        }
        self.keys = [{"id": "3b8066a7-b438-455a-9688-44afc9a3597f", "date_created": "2026-01-02T00:00:00+00:00",
                      "name": "laptop", "ssh_key": public_key(1, comment="me@laptop")}]
        self.blocks = [{"id": "e1f2a3b4-0000-4000-8000-0000000000b1", "date_created": "2026-01-05T10:05:00+00:00", "cost": 5,
                        "pending_charges": 1.2, "status": "active", "size_gb": 50, "region": "ewr",
                        "attached_to_instance": WEB, "attached_to_instance_ip": "10.0.0.1",
                        "attached_to_instance_label": "web-1", "label": "data", "mount_id": "ewr-example112233",
                        "block_type": "high_perf"}]
        self.reserved = [{"id": "f0e1d2c3-0000-4000-8000-0000000000c1", "region": "ewr", "ip_type": "v4",
                          "subnet": "192.0.2.123", "subnet_size": 32, "label": "floating", "instance_id": WEB}]
        self.bare_metals = [{"id": "d9b4a6c2-0000-4000-8000-0000000000d1", "label": "metal", "region": "ams",
                             "default_password": BARE_PASSWORD}]
        self.snapshots = [{"id": "s1", "description": "before upgrade", "size": 42949672960},
                          {"id": "s2", "description": "weekly", "size": 10737418240}]
        self.backups = [{"id": "k1"}, {"id": "k2"}, {"id": "k3"}]
        self.vke = [{"id": "c907e832-3080-48a6-a54d-7379e645c0b7", "label": "my-vke"}]
        self.load_balancers: list[dict] = []
        self.databases = [{"id": "999c4ed0-f2e4-4f2a-a951-de358ceb9ab5", "label": "orders"}]

    # -- what the tests read ---------------------------------------------------------------------------------------------
    def writes(self) -> list[tuple[str, str, object]]:
        return [(m, p, b) for m, p, q, b in self.requests if m != "GET"]

    def calls(self) -> list[str]:
        return [f"{m} {p}" for m, p, q, b in self.requests]

    def zone(self, domain: str = "example.com") -> list[tuple[str, str, str]]:
        return [(r["name"], r["type"], r["data"]) for r in self.records[domain]]

    # -- the transport ---------------------------------------------------------------------------------------------------
    def __call__(self, method, url, headers, body, timeout):
        assert url.startswith(BASE + "/"), url
        parts = urlsplit(url)
        path = unquote(parts.path[len("/v2"):])
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        data = json.loads(body) if body else None
        self.requests.append((method, path, query, data))
        if self.gate is not None and self.gate[0](method, path, query):  # held until the test lets it through
            self.gate[1].set()
            self.gate[2].wait(10)
        if self.down:
            raise ConnectionError("no route to host")
        if headers.get("Authorization") != f"Bearer {self.key}":
            return error(401, "Invalid API token.")
        if self.refuse_ip:
            return error(401, f"Unauthorized IP address: {self.refuse_ip}")
        if self.limited:
            self.limited -= 1
            return answer(429, {"error": "Rate limit exceeded", "status": 429}, {"Retry-After": "1"})
        for (m, p), (status, words) in self.fail.items():
            if m == method and p == path:
                return error(status, words)
        return self.route(method, path.strip("/").split("/"), query, data)

    def page(self, items: list, key: str, query: dict):
        size = min(int(query.get("per_page") or 100), self.page_most)
        start = int(base64.b64decode(query["cursor"]).decode().split(":")[1]) if query.get("cursor") else 0
        shown = items[start:start + size]
        more = start + size < len(items)
        nxt = base64.b64encode(f"next:{start + size}".encode()).decode() if more else ""
        return answer(200, {key: shown, "meta": {"total": len(items), "links": {"next": nxt, "prev": ""}}})

    def made_id(self) -> str:
        self.next_id += 1
        return f"0000{self.next_id:04d}-0000-4000-8000-000000000000"

    def route(self, method: str, p: list[str], query: dict, data):
        if method == "GET" and p == ["account"]:
            return answer(200, {"account": self.account})
        if p[0] == "instances":
            return self.instances_route(method, p, query, data)
        if method == "GET" and p == ["plans"]:
            assert query.get("type") == "all", "the plans of every type"
            return self.page(self.plans, "plans", query)
        if method == "GET" and p == ["regions"]:
            return self.page(self.regions, "regions", query)
        if p[0] == "domains":
            return self.dns_route(method, p, query, data)
        if p[0] == "firewalls":
            return self.firewall_route(method, p, query, data)
        if p[0] == "ssh-keys":
            return self.keys_route(method, p, query, data)
        lists = {"blocks": (self.blocks, "blocks"), "reserved-ips": (self.reserved, "reserved_ips"),
                 "bare-metals": (self.bare_metals, "bare_metals"), "snapshots": (self.snapshots, "snapshots"),
                 "backups": (self.backups, "backups"), "load-balancers": (self.load_balancers, "load_balancers")}
        if method == "GET" and len(p) == 1 and p[0] in lists:
            return self.page(*lists[p[0]], query)
        if method == "GET" and p == ["kubernetes", "clusters"]:
            assert "per_page" not in query  # the reference names no per_page for it
            return answer(200, {"vke_clusters": self.vke, "meta": {"total": len(self.vke), "links": {"next": "", "prev": ""}}})
        if method == "GET" and p == ["databases"]:
            assert "per_page" not in query
            return answer(200, {"databases": self.databases, "meta": {"total": len(self.databases)}})
        return error(404, f"Not found: {method} /{'/'.join(p)}")

    def instances_route(self, method, p, query, data):
        if method == "GET" and p == ["instances"]:
            return self.page(self.instances, "instances", query)
        inst = next((i for i in self.instances if len(p) > 1 and i["id"] == p[1]), None)
        if inst is None:
            return error(404, "Invalid instance-id.")
        if method == "GET" and len(p) == 2:
            return answer(200, {"instance": inst})
        if method == "POST" and len(p) == 3 and p[2] in ("start", "reboot", "halt"):
            assert data is None, "a power change takes no body"
            inst["power_status"] = "stopped" if p[2] == "halt" else "running"
            return answer(204)
        return error(404, f"Not found: {method} /{'/'.join(p)}")

    def dns_route(self, method, p, query, data):
        if method == "GET" and p == ["domains"]:
            return self.page(self.domains, "domains", query)
        domain = p[1] if len(p) > 1 else ""
        if domain not in self.records:
            return error(404, "Invalid domain.")
        held = self.records[domain]
        if len(p) == 3 and p[2] == "records":
            if method == "GET":
                found = held
                if "name" in query:
                    found = [r for r in found if relative(r["name"], domain) == query["name"].lower()]
                if query.get("type"):
                    found = [r for r in found if r["type"] == query["type"]]
                return self.page(found, "records", query)
            if method == "POST":
                assert {"name", "type", "data"} <= set(data), "name, type and data are required"
                if data["type"] in ("MX", "SRV"):
                    assert "priority" in data, "MX and SRV need their priority"
                made = {"id": self.made_id(), "type": data["type"], "name": data["name"], "data": data["data"],
                        "ttl": data.get("ttl", 300), "priority": data.get("priority", 0)}
                held.append(made)
                return answer(201, {"record": made})
        if len(p) == 4 and p[2] == "records":
            rec = next((r for r in held if r["id"] == p[3]), None)
            if rec is None:
                return error(404, "Invalid record.")
            if method == "PATCH":
                assert set(data) <= {"name", "data", "ttl", "priority"}, data
                rec.update(data)
                return answer(204)
            if method == "DELETE":
                held.remove(rec)
                return answer(204)
        return error(404, f"Not found: {method} /{'/'.join(p)}")

    def firewall_route(self, method, p, query, data):
        if method == "GET" and p == ["firewalls"]:
            return self.page(self.groups, "firewall_groups", query)
        group = next((g for g in self.groups if len(p) > 1 and g["id"] == p[1]), None)
        if group is None:
            return error(404, "Invalid firewall group.")
        held = self.rules[group["id"]]
        if method == "GET" and len(p) == 2:
            return answer(200, {"firewall_group": group})
        if len(p) == 3 and p[2] == "rules":
            if method == "GET":
                return self.page(held, "firewall_rules", query)
            if method == "POST":
                assert {"ip_type", "protocol", "subnet", "subnet_size"} <= set(data), "the reference's required four"
                made = {"id": max([r["id"] for r in held], default=0) + 1, "type": data["ip_type"], "action": "accept",
                        "source": "", "port": "", "notes": "", **data}
                held.append(made)
                group["rule_count"] = len(held)
                return answer(201, {"firewall_rule": made})
        if len(p) == 4 and p[2] == "rules" and method == "DELETE":
            rule = next((r for r in held if str(r["id"]) == p[3]), None)
            if rule is None:
                return error(404, "Invalid firewall rule.")
            held.remove(rule)
            group["rule_count"] = len(held)
            return answer(204)
        return error(404, f"Not found: {method} /{'/'.join(p)}")

    def keys_route(self, method, p, query, data):
        if method == "GET" and p == ["ssh-keys"]:
            return self.page(self.keys, "ssh_keys", query)
        if method == "POST" and p == ["ssh-keys"]:
            assert set(data) == {"name", "ssh_key"}, data
            made = {"id": self.made_id(), "date_created": "2026-11-11T12:00:00+00:00", **data}
            self.keys.append(made)
            return answer(201, {"ssh_key": made})
        if method == "DELETE" and len(p) == 2:
            key = next((k for k in self.keys if k["id"] == p[1]), None)
            if key is None:
                return error(404, "Invalid SSH key.")
            self.keys.remove(key)
            return answer(204)
        return error(404, f"Not found: {method} /{'/'.join(p)}")


def relative(name: str, domain: str) -> str:
    n = name.lower().rstrip(".")
    return "" if n in ("", domain) else n[: -len(domain) - 1] if n.endswith("." + domain) else n


class Pairs(Login):
    """A login holding pairs by name (the login app's store, as the Login interface asks it)."""

    NAMESPACE = "test"

    def __init__(self, values: dict[str, str]):
        self.pairs = {pair_name(k): v for k, v in values.items()}
        self.asked: list[str] = []

    def user(self) -> dict:
        return {"name": "tester"}

    def vector(self, name: str) -> str:
        self.asked.append(name)
        if name not in self.pairs:
            raise Unauthorized(f"no {name}", 404)
        return self.pairs[name]

    def names(self) -> set[str]:
        return set(self.pairs)


def settings_of(api: bool = True, ddns: bool = False, **more) -> dict[str, str]:
    out = {}
    if api:
        out["VULTR_API_KEY"] = KEY
    if ddns:
        out["VULTR_DDNS_HOSTS"] = "home.example.com"
    out.update(more)
    return out


class App:
    """An app attaching the plugin, by its NAME: the platform ("platform") or another (the charts app run alone)."""

    def __init__(self, name: str = "platform"):
        self.NAME = name


@pytest.fixture(autouse=True)
def _no_vultr_no_network(monkeypatch, tmp_path):
    """No test reaches Vultr, a resolver or this machine's settings: the REST client's HTTPS and nslookup refused, every
    VULTR_ variable cleared, the platform's folder the test's own."""
    def refused(*a, **k):
        raise AssertionError("a test reached for the network")
    monkeypatch.setattr(rest_mod, "_requests_transport", refused)
    monkeypatch.setattr(dns_mod, "query", refused)
    for n in NAMES:
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("LIMINAL_PLATFORM_DIR", str(tmp_path / "platform"))


@pytest.fixture
def env(monkeypatch):
    """Sets the plugin's variables (the EnvironmentLogin's: what the platform reads today)."""
    def put(values: dict[str, str]):
        for k, v in values.items():
            monkeypatch.setenv(k, v)
    return put


@pytest.fixture
def made(tmp_path):
    """A plugin over the stand-ins: (plugin, fake Vultr). `public` is this network's address as the stand-in says it (a
    function giving it, for one that changes); `folder`, Dynamic DNS's state's (the test's own unless given: two plugins
    sharing one stand for a restart)."""
    def make(fake: FakeVultr | None = None, public=HOME, folder=None):
        fake = fake or FakeVultr()
        slept: list[float] = []
        ask = public if callable(public) else (lambda: public)

        def address():
            ip = ask()
            return (ip, "a stand-in") if ip else (None, "no server answered")
        p = VultrPlugin(transport=fake, public=address, sleep=slept.append, gap=0.0,
                        folder=folder if folder is not None else tmp_path / "vultr")
        p.slept = slept
        return p, fake
    return make
