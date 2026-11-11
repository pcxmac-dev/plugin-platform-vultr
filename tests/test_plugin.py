"""The plugin over the stand-ins: its settings read through the Login interface, its status from what was read (no
request made to answer it; no value of a setting in it), valid while its key is set and its last read worked or is
untried, the background reading only while attached, its hooks asked by name, the command line."""
from __future__ import annotations

import json
import time

import pytest

import plugin_platform_vultr.__main__ as cli
from conftest import BARE_PASSWORD, DB, G_WEB, HOME, KEY, WEB, FakeVultr, Pairs, public_key, settings_of
from plugin_platform_vultr import NOT_SET, RETRY_S, STOPPED_BILLS_SAID
from plugin_platform_vultr.settings import read


def wait_until(test, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if test():
            return True
        time.sleep(0.02)
    return False


def table(status: dict, title: str) -> dict:
    return next(t for t in status["tables"] if t["title"] == title)


def test_nothing_set_is_not_valid_and_says_what_to_set_and_where(made):
    p, fake = made()
    st = p.status()
    assert st["present"] is False and st["valid"] is False and st["why"] == NOT_SET and st["summary"] == "not set up"
    assert "VULTR_API_KEY" in st["why"] and "https://console.vultr.com/settings/#settingsapi" in st["why"]
    assert "Access Control" in st["why"] and "View Servers" in st["why"] and "Manage DNS" in st["why"]
    assert st["tables"] == [] and st["actions"] == [] and st["forms"] == [] and not p.present() and fake.requests == []
    with pytest.raises(ValueError, match="the API is not set up"):
        p.refresh()
    with pytest.raises(ValueError, match="Dynamic DNS is not set up"):
        p.ddns_update()


def test_the_hosts_alone_are_not_enough(made, env):
    env({"VULTR_DDNS_HOSTS": "home.example.com"})
    p, fake = made()
    st = p.status()
    assert st["present"] is True and st["valid"] is False
    assert st["why"].startswith("VULTR_API_KEY is not set (Dynamic DNS goes through Vultr's DNS, with the key)")
    assert fake.requests == []


def test_the_settings_are_read_through_the_login_by_their_pairs():
    login = Pairs(settings_of(ddns=True, VULTR_DDNS_MINUTES="15"))
    c = read(login)
    assert (c.api_key, c.hosts, c.minutes) == (KEY, "home.example.com", 15.0) and c.api_ready and c.ddns_ready
    assert "vultr-api-key" in login.asked and "VULTR_API_KEY" not in login.asked  # asked by the pairs' names
    assert KEY not in repr(c)
    c = read(Pairs(settings_of(VULTR_DDNS_MINUTES="often", VULTR_DDNS_HOSTS="a.example.com; b.example.com")))
    assert c.minutes == 5.0 and c.problems == ("VULTR_DDNS_MINUTES is not a number of minutes: 5 is used",)
    assert c.hosts == "a.example.com, b.example.com"
    assert read(Pairs(settings_of(VULTR_DDNS_MINUTES="99999"))).minutes == 1440.0

    class Down(Pairs):
        def names(self):
            raise ConnectionError("the login app is not answering")
    assert read(Down({})).problems == ("the settings could not be read from the login: ConnectionError",)


def test_a_refresh_draws_the_tables_and_the_status_asks_nothing(made, env):
    env(settings_of())
    p, fake = made()
    st = p.status()
    assert st["valid"] is True and st["summary"] == "the account is read once attached" and fake.requests == []
    done = p.refresh()
    assert (done["instances"], done["domains"], done["groups"], done["notRead"]) == (3, 2, 3, [])
    calls = len(fake.requests)
    assert calls == 20  # account, instances, plans, regions, domains + 2 zones, groups + 3 rules, keys, blocks, reserved, 6 counts
    st = p.status()
    assert len(fake.requests) == calls  # the status asks nothing of Vultr
    assert st["valid"] is True and "problem" not in st
    assert st["summary"] == "3 instances (2 running) · 2 domains · balance -$100.55, $60.25 pending"
    assert st["account"] == "Example Account · admin@example.com" and st["balance"] == "-$100.55"
    assert st["pendingCharges"] == "$60.25 this month, not billed yet" and st["lastPayment"] == "-$1.25 on 2026-10-10"
    assert st["keyPermissions"].startswith("every permission (manage_users)")
    assert st["stoppedInstances"] == STOPPED_BILLS_SAID and "does not halt billing" in st["stoppedInstances"]
    assert st["accessControl"].startswith("A Vultr API key answers only from the addresses its Access Control allows")
    assert st["settingsSet"] == "VULTR_API_KEY" and st["apiRequests"] == f"{calls} made"
    assert [t["title"] for t in st["tables"]] == [
        "Instances", "Domains", "example.com records", "example.net records", "Firewall groups", "web rules", "spare rules",
        "db rules", "SSH keys", "Block storage", "Reserved IPs", "The account's other resources"]
    inst = table(st, "Instances")
    assert "still bills" in inst["note"] and "does not halt billing" in inst["note"]
    web, db, new = inst["rows"]
    assert web[0] == {"text": "web-1", "sub": "Debian 12 x64 (bookworm) · web"} and web[1] == "running"
    assert web[2] == {"text": "New Jersey", "sub": "ewr · US"} and web[3] == {"text": "vc2-1c-1gb", "sub": "1 vCPU · 1 GB · 25 GB disk"}
    assert web[4:9] == ["203.0.113.10", "2001:db8::10", "$5.00", "$0.007", "2026-01-05"]
    assert web[9]["form"] == "reboot" and web[10]["form"] == "halt" and web[9]["values"] == {"instance": WEB, "label": "web-1"}
    assert db[1] == {"text": "stopped", "sub": "still billed"} and db[9]["form"] == "start" and db[10] == ""
    assert db[6] == {"text": "$13.00", "sub": "its region's price · backups on: Vultr adds 20%"} and db[7] == "$0.019"
    assert new[0]["text"] == "new-1" and new[1] == {"text": "running", "sub": "pending · installingbooting"}
    assert new[9] == "" and new[10] == ""  # not active yet: no power change offered
    records = table(st, "example.com records")
    assert records["rows"][0][:5] == ["@", "A", "203.0.113.10", "300", ""] and len(records["rows"]) == 6
    assert ["home", "A", "198.51.100.7", "120", ""] in [r[:5] for r in records["rows"]]  # a full name read as relative
    assert ["@", "MX", "mail.protonmail.ch", "300", "10"] in [r[:5] for r in records["rows"]]
    rules = table(st, "web rules")
    assert rules["rows"][0][:5] == ["v4", "TCP", "22", "198.51.100.0/24", "office ssh"]
    assert rules["rows"][1][:4] == ["v4", "TCP", "443", "anywhere (0.0.0.0/0)"] and "linked: web-1" in rules["note"]
    assert table(st, "spare rules")["note"].startswith("not enforced: a group without rules drops nothing")
    groups = table(st, "Firewall groups")
    assert groups["rows"][0] == ["web", "2 of 50", "web-1", "2026-03-01"]
    keys = table(st, "SSH keys")
    assert keys["rows"][0][:2] == ["laptop", "ssh-ed25519"] and keys["rows"][0][2].startswith("SHA256:")
    assert table(st, "Block storage")["rows"][0][2:] == ["50", "high_perf", "web-1", "$5.00"]
    assert table(st, "Reserved IPs")["rows"][0] == ["192.0.2.123/32", "v4", {"text": "New Jersey", "sub": "ewr · US"},
                                                     "floating", "web-1"]
    assert table(st, "The account's other resources")["rows"] == [
        ["Bare metal servers", "1"], ["Snapshots", "2"], ["Backups", "3"], ["Kubernetes clusters", "1"],
        ["Load balancers", "0"], ["Managed databases", "1"]]
    assert [a["hook"] for a in st["actions"]] == ["refresh"]
    text = json.dumps(st)
    assert KEY not in text and BARE_PASSWORD not in text  # a setting's value never; a bare metal's password never


def test_the_plans_and_regions_are_read_again_only_when_old(made, env):
    env(settings_of())
    t = [1_000_000.0]
    p, fake = made()
    p._clock = lambda: t[0]
    p.refresh()
    p.refresh()
    assert fake.calls().count("GET /plans") == 1 and fake.calls().count("GET /regions") == 1
    t[0] += 6 * 3600
    p.refresh()
    assert fake.calls().count("GET /plans") == 2 and fake.calls().count("GET /regions") == 1
    fake.instances[0]["plan"] = "vc2-2c-4gb"  # a plan not in the list: read again for it, at most once an hour
    p.refresh()
    assert fake.calls().count("GET /plans") == 2  # the list was read less than an hour ago
    t[0] += 3600
    p.refresh()
    p.refresh()
    assert fake.calls().count("GET /plans") == 3
    assert table(p.status(), "Instances")["rows"][0][6] == "–"  # still not known: no price said


def test_a_part_refused_is_said_beside_the_rest(made, env):
    env(settings_of())
    p, fake = made()
    fake.fail[("GET", "/blocks")] = (403, "Unauthorized to view this resource")
    fake.fail[("GET", "/snapshots")] = (403, "Unauthorized to view this resource")
    p.refresh()
    st = p.status()
    assert st["valid"] is True and "blocks not read: GET /v2/blocks: HTTP 403" in st["problem"]
    blocks = table(st, "Block storage")
    assert blocks["rows"] == [] and blocks["empty"] == "Not read." and "HTTP 403" in blocks["note"]
    snaps = dict((r[0], r[1]) for r in table(st, "The account's other resources")["rows"])["Snapshots"]
    assert snaps["text"] == "–" and "HTTP 403" in snaps["sub"]


def test_a_key_refused_is_not_valid_and_says_where_its_addresses_are_set(made, env):
    env(settings_of())
    t = [1_000_000.0]
    p, fake = made()
    p._clock = lambda: t[0]
    fake.refuse_ip = HOME
    with pytest.raises(Exception, match="Unauthorized IP address"):
        p.refresh()
    st = p.status()
    assert st["valid"] is False and st["why"].startswith("the API: GET /v2/account: HTTP 401: Unauthorized IP address")
    assert "Access Control" in st["why"] and "https://console.vultr.com/settings/#settingsapi" in st["why"]
    assert st["accessControl"].endswith(f"Vultr refused the address it saw, {HOME}: add it there")
    assert st["forms"] == [] and KEY not in json.dumps(st)
    assert len(fake.requests) == 1  # nothing more asked once the key is refused
    t[0] += RETRY_S
    st = p.status()
    assert st["valid"] is True and st["summary"] == "the account is read once attached"  # the platform attaches it: tried again


def test_a_change_of_the_key_makes_a_failed_read_untried(made, env, monkeypatch):
    env(settings_of())
    p, fake = made()
    fake.key = "SOMEONEELSESKEY"
    with pytest.raises(Exception):
        p.refresh()
    assert p.status()["valid"] is False
    monkeypatch.setenv("VULTR_API_KEY", KEY + "X")
    assert p.config(fresh=True).api_key == KEY + "X" and p.status()["valid"] is True


def test_attached_it_reads_in_the_background_through_the_apps_login_and_detached_nothing_runs(made):
    p, fake = made()
    login = Pairs(settings_of(ddns=True))
    p.attach(object(), login)
    try:
        assert p.working
        assert wait_until(lambda: p.status()["summary"].startswith("3 instances (2 running)")
                          and p.status()["summary"].endswith(f"home.example.com at {HOME}"))
        assert "vultr-api-key" in login.asked
    finally:
        p.detach()
    assert not p.working and p.login is None
    calls = len(fake.requests)
    time.sleep(0.1)
    assert len(fake.requests) == calls


def test_the_hooks_are_asked_by_name_as_the_platform_asks_them(made, env):
    env(settings_of())
    p, fake = made()
    assert p.ask("balance")["email"] == "admin@example.com"
    servers = p.ask("servers")
    assert [s["label"] for s in servers] == ["web-1", "db-1", ""]
    assert servers[0]["price"] == {"monthly": 5, "hourly": 0.007, "regional": False}
    assert servers[1]["price"] == {"monthly": 13, "hourly": 0.019, "regional": True}
    assert [d["domain"] for d in p.ask("domains")] == ["example.com", "example.net"]
    assert {"id": "a0a0a0a0-0000-4000-8000-000000000006", "name": "home", "type": "A", "data": "198.51.100.7", "ttl": 120,
            "priority": 0} in p.ask("records", "example.com")
    walls = p.ask("firewalls")
    assert [len(g["rules"]) for g in walls] == [2, 0, 1] and walls[0]["rules"][0]["port"] == "22"
    keys = p.ask("ssh_keys")
    assert keys[0]["name"] == "laptop" and keys[0]["fingerprint"].startswith("SHA256:")
    rep = p.ask("start", DB, "db-1")
    assert rep["said"] == "db-1 started" and rep["power"] == "running"
    with pytest.raises(LookupError):
        p.ask("destroy", WEB)
    assert not [w for w in fake.writes() if w[0] != "POST" or not w[1].endswith("/start")]


def test_the_command_line(made, env):
    env(settings_of(ddns=True))
    p, fake = made()
    lines, errors, answers = [], [], []

    def run(*argv, say=()):
        lines.clear()
        errors.clear()
        answers[:] = list(say)
        return cli.main(list(argv), plugin=p, out=lines.append, err=errors.append, ask=lambda q: answers.pop(0) if answers else "")
    assert run("account") == 0 and lines[0] == "Example Account (admin@example.com)" and "-$100.55" in lines[1]
    assert run("servers") == 0 and lines[0].startswith("web-1") and "$5.00 a month" in lines[0]
    assert lines[-1] == STOPPED_BILLS_SAID + "."
    assert run("domains") == 0 and lines == [f"{'example.com':<32} DNSSEC disabled", f"{'example.net':<32} DNSSEC enabled"]
    assert run("records", "example.com") == 0 and len(lines) == 6
    assert run("firewalls") == 0 and lines[0] == "web: 2 rules, 1 instances linked"
    assert run("keys") == 0 and lines[0].startswith("laptop")
    assert run("ddns") == 0 and lines[0].startswith("home.example.com") and "set (was 198.51.100.7)" in lines[0]
    assert run("set", "example.com", "blog", "A", "203.0.113.30") == 1 and errors == ["nothing done"]  # not "yes"
    assert ("blog", "A", "203.0.113.30") not in fake.zone()
    assert run("set", "example.com", "blog", "A", "203.0.113.30", say=["yes"]) == 0 and lines[0] == "added blog A 203.0.113.30"
    assert ("blog", "A", "203.0.113.30") in fake.zone()
    assert run("remove", "example.com", "@", "A", say=["yes"]) == 0 and lines[0] == "removed @ A 203.0.113.10"
    assert run("remove", "example.com", "nothing", "TXT", say=["yes"]) == 1 and errors[0].startswith("refused: example.com has no")
    assert run("power", "web-1", "off", say=["yes"]) == 1 and errors == ["nothing done"]  # a halt is asked twice
    assert fake.instances[0]["power_status"] == "running"
    assert run("power", "web-1", "off", say=["yes", "yes"]) == 0 and lines[0] == "web-1 halted"
    assert fake.instances[0]["power_status"] == "stopped"
    assert run("power", "web-1", "on", say=["yes"]) == 0 and lines[0] == "web-1 started"
    assert run("--json", "status") == 0 and json.loads("\n".join(lines))["valid"] is True
    fake.refuse_ip = HOME
    assert run("domains") == 1 and errors[0].startswith("vultr: GET /v2/domains: HTTP 401: Unauthorized IP address")
    with pytest.raises(SystemExit):
        run("nonsense")


def test_the_platform_reads_it_in_its_own_shape(made, env):
    """What the platform's page draws: facts as words, tables of columns and rows, actions it asks by name, forms whose
    hooks it may ask."""
    env(settings_of(ddns=True))
    p, fake = made()
    p.refresh()
    p.ddns_update(force=False)
    st = p.status()
    for t in st["tables"]:
        assert set(t) >= {"title", "columns", "rows"} and all(len(r) == len(t["columns"]) for r in t["rows"]), t["title"]
    hooks = p.interface()["hooks"]
    assert all(a["hook"] in hooks for a in st["actions"]) and all(f["hook"] in hooks for f in st["forms"])
    flat = {k: v for k, v in st.items() if not isinstance(v, (list, dict))}
    assert all(isinstance(v, (str, bool)) for v in flat.values()), flat
    buttons = [c for t in st["tables"] for r in t["rows"] for c in r if isinstance(c, dict) and "form" in c]
    forms = {f["id"] for f in st["forms"]}
    assert buttons and all(b["form"] in forms for b in buttons)
    assert all(a["form"] in forms for t in st["tables"] for a in t.get("actions", []) if "form" in a)


def test_settings_entered_on_the_platforms_page_are_read_at_once(made):
    from liminal_libs.apps import EnvironmentLogin

    p, fake = made()
    kept: dict[str, str] = {}
    p.login = EnvironmentLogin(env=kept)  # as the platform lends its login to a plugin not yet attached
    assert p.status()["valid"] is False and p.status()["why"].startswith("not set up")
    for variable, value in settings_of().items():
        p.login.save(variable, value)  # what the platform's settings route does
    assert p.status()["valid"] is False  # still the settings read a moment ago
    p.settings_changed()
    st = p.status()
    assert st["valid"] is True and "VULTR_API_KEY" in st["settingsSet"] and KEY not in str(st)  # named, never shown


def test_a_key_of_a_limited_user_says_its_permissions(made, env):
    env(settings_of())
    fake = FakeVultr()
    fake.account["acls"] = ["subscriptions_view", "subscriptions", "dns", "firewall"]
    fake.keys.append({"id": "9c0d1e2f-0000-4000-8000-0000000000e1", "date_created": "2026-11-01T00:00:00+00:00",
                      "name": "ci", "ssh_key": public_key(2, comment="ci@runner")})
    p, fake = made(fake)
    p.refresh()
    st = p.status()
    assert st["keyPermissions"] == "subscriptions_view, subscriptions, dns, firewall"
    assert [r[0] for r in table(st, "SSH keys")["rows"]] == ["laptop", "ci"]
    assert G_WEB in {f["id"].split(":", 1)[1] for f in st["forms"] if f["id"].startswith("rule-add:")}
