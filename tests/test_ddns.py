"""Dynamic DNS through Vultr's DNS (liminal-libs 1.49.2's Keeper; 0.1.1, after an audit found a live record pointed at
home within a minute, unasked): it changes only what is its own, a host with no A record (made), one already pointing at
this network or at the address it set last (kept current, after a restart too), and one the user took over on the page.
A host holding another address, or several, is left as it is, its row offering Take over…; several addresses are never
cut to one unasked. Taking a host over is asked twice (0.1.2, the re-verification: it drops what the record holds at
once). A host taken out of the setting is let go, and comes back as not its own. Update DNS now is a confirmed form. A
pass ends once the plugin is detached. Over the stand-ins alone."""
from __future__ import annotations

import json
import threading
import time

import pytest

import plugin_platform_vultr.settings as settings_mod
from conftest import HOME, App, FakeVultr, Pairs, settings_of
from liminal_libs.machines.ddns import TakeOverRefused
from plugin_platform_vultr import DDNS_TTL, PUBLIC_IPV4
from plugin_platform_vultr.records import Refusal

HOME_ID = "a0a0a0a0-0000-4000-8000-000000000006"
NEW_HOME = "93.184.216.99"


def ddns(made, env, fake=None, public=HOME, folder=None, **more):
    env(settings_of(ddns=True, **more))
    return made(fake, public=public, folder=folder)


def ddns_table(status: dict) -> dict:
    return next(t for t in status["tables"] if t["title"] == "Dynamic DNS")


def test_the_public_address_is_asked_of_the_servers_the_plugin_names():
    assert PUBLIC_IPV4 == (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
                           ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))


def test_a_host_holding_another_address_is_left_as_it_is_its_row_offering_take_over(made, env):
    p, fake = ddns(made, env)  # home.example.com holds 198.51.100.7: the user's, not Dynamic DNS's
    out = p.ddns_update(force=False)
    (home,) = out["hosts"]
    assert home["ok"] is False and home["foreign"] is True and home["holds"] == ["198.51.100.7"]
    assert home["result"] == "holds 198.51.100.7, not this network's address: left as it is (Take over… to point it here)"
    assert fake.writes() == [] and fake.calls()[0] == "GET /domains"  # the domains read first: the hosts split against them
    p.ask("ddns_update")  # Update DNS now (force) leaves it as it is too
    assert fake.writes() == []
    st = p.status()
    row = ddns_table(st)["rows"][0]
    assert row[:2] == ["home.example.com", "198.51.100.7"]
    assert row[-1] == {"form": "ddns-take", "title": "Take over…", "label": "Take over home.example.com",
                       "values": {"host": "home.example.com", "holds": "198.51.100.7"}}
    forms = {f["id"]: f for f in st["forms"]}
    assert forms["ddns-take"]["hook"] == "ddns_take_over" and forms["ddns-take"]["confirm"]["danger"] is True
    assert [x["name"] for x in forms["ddns-take"]["fields"]] == ["host", "holds", "accept_take_over"]  # asked twice
    assert "stops answering at {host}" in forms["ddns-take"]["confirm"]["words"]
    assert forms["ddns-now"]["hook"] == "ddns_update" and forms["ddns-now"]["fields"] == []
    assert {"form": "ddns-now", "title": "Update DNS now"} in st["actions"]
    assert not [a for a in st["actions"] if a.get("hook") == "ddns_update"]  # never asked on one click
    assert "Dynamic DNS: home.example.com: holds 198.51.100.7" in st["problem"]


def test_take_over_then_a_pass_sets_it(made, env):
    p, fake = ddns(made, env)
    p.ddns_update(force=False)
    take = ddns_table(p.status())["rows"][0][-1]
    n = len(fake.requests)
    with pytest.raises(Refusal, match="holds 198.51.100.7 now, not 203.0.113.9: nothing taken over"):
        p.ask("ddns_take_over", "home.example.com", "203.0.113.9")  # what the page showed is not what it holds
    with pytest.raises(Refusal, match="none of VULTR_DDNS_HOSTS"):
        p.ask("ddns_take_over", "www.example.com", "")
    assert all(m == "GET" for m, path, q, b in fake.requests[n:])
    with pytest.raises(TakeOverRefused) as refused:  # one yes is not enough: what it holds is dropped at once
        p.ask("ddns_take_over", *take["values"].values())
    assert refused.value.accept == "accept_take_over" and "198.51.100.7" in str(refused.value)
    for not_true in ("true", 1, "yes"):
        with pytest.raises(TakeOverRefused):
            p.ask("ddns_take_over", "home.example.com", "198.51.100.7", not_true)
    assert fake.writes() == [] and not p.keeper().taken("home.example.com") and p.keeper().known() == []
    rep = p.ask("ddns_take_over", *take["values"].values(), True)  # True itself: the page's second confirmation
    assert rep["ok"] and rep["said"] == "home.example.com taken over: set (was 198.51.100.7)"
    assert fake.writes() == [("PATCH", f"/domains/example.com/records/{HOME_ID}", {"data": HOME})]
    kept = json.loads(p.ddns_file().read_text(encoding="utf-8"))
    assert kept == {"own": {"home.example.com": HOME}, "taken": ["home.example.com"]}
    assert p.ddns_update(force=False)["hosts"][0]["result"] == "current" and len(fake.writes()) == 1


def test_a_host_with_several_addresses_is_never_cut_to_one_unasked(made, env):
    fake = FakeVultr()
    fake.records["example.com"].append({"id": "a0a0a0a0-0000-4000-8000-000000000007", "type": "A", "name": "home",
                                        "data": HOME, "ttl": 120, "priority": 0})  # this network's address among two
    p, fake = ddns(made, env, fake)
    for force in (False, True):
        (home,) = p.ddns_update(force=force)["hosts"]
        assert home["result"].startswith(f"holds 2 addresses (198.51.100.7, {HOME}): left as it is")
    assert fake.writes() == []
    rep = p.ask("ddns_take_over", "home.example.com", f"198.51.100.7, {HOME}", True)  # taken over: what it holds dropped
    assert rep["ok"] and fake.writes() == [("PATCH", f"/domains/example.com/records/{HOME_ID}", {"data": HOME}),
                                           ("DELETE", "/domains/example.com/records/a0a0a0a0-0000-4000-8000-000000000007",
                                            None)]
    assert [r for r in fake.zone() if r[1] == "A" and "home" in r[0]] == [("home.example.com", "A", HOME)]


def test_a_host_without_a_record_is_made_and_its_own_kept_current_after_the_address_changes(made, env, tmp_path):
    now, t = [HOME], [1_000_000.0]
    folder = tmp_path / "kept"
    p, fake = ddns(made, env, public=lambda: now[0], folder=folder, VULTR_DDNS_HOSTS="@.example.net")
    p._clock = lambda: t[0]
    (apex,) = p.ddns_update(force=False)["hosts"]
    assert apex["result"] == "made (was none)" and apex["address"] == HOME
    assert ("POST", "/domains/example.net/records", {"name": "", "type": "A", "data": HOME, "ttl": DDNS_TTL}) in fake.writes()
    now[0] = NEW_HOME  # this network's address changed: the record Dynamic DNS set is its own, so it follows
    t[0] += 601  # once the address it keeps is old (the keeper asks it again after ten minutes)
    (apex,) = p.ddns_update(force=False)["hosts"]
    made_id = next(r["id"] for r in fake.records["example.net"] if r["type"] == "A")
    assert apex["result"] == f"set (was {HOME})" and fake.writes()[-1] == (
        "PATCH", f"/domains/example.net/records/{made_id}", {"data": NEW_HOME})
    # a restart (a new plugin, the same folder): its own record still known by its state file
    later, _ = made(fake, public=lambda: "93.184.216.100", folder=folder)
    (apex,) = later.ddns_update(force=False)["hosts"]
    assert apex["result"] == f"set (was {NEW_HOME})" and fake.writes()[-1][2] == {"data": "93.184.216.100"}


def test_update_dns_now_rewrites_only_what_is_its_own(made, env):
    fake = FakeVultr()
    fake.records["example.com"][5]["data"] = HOME  # home already points here: its own from the first look
    p, fake = ddns(made, env, fake)
    out = p.ask("ddns_update")  # the page's Update DNS now, once confirmed (force)
    assert out["said"] == "Dynamic DNS: 1 of 1 host current" and out["ok"] is True
    assert out["hosts"][0]["result"] == "current (nothing to send)" and fake.writes() == []


def test_a_cname_host_and_a_host_in_no_domain_of_the_account_are_said(made, env):
    p, fake = ddns(made, env, VULTR_DDNS_HOSTS="www.example.com, home.elsewhere.org")
    out = p.ddns_update(force=False)
    (www,) = out["hosts"]
    assert www["host"] == "www.example.com" and www["ok"] is False
    assert "is a CNAME: Dynamic DNS keeps an A record" in www["result"] and fake.writes() == []
    assert "not kept: home.elsewhere.org is in none of the account's domains" in out["lines"]
    p.refresh()
    st = p.status()
    assert "home.elsewhere.org is in none of the account's domains" in st["problem"]
    assert "www.example.com: its record could not be read" in st["problem"]
    assert "not kept: home.elsewhere.org is in none of the account's domains" in ddns_table(st)["note"]


def test_no_address_found_means_no_write(made, env):
    p, fake = ddns(made, env, public=None, VULTR_DDNS_HOSTS="@.example.net")
    (apex,) = p.ddns_update(force=True)["hosts"]
    assert apex["ok"] is False and apex["result"].startswith("this network's address was not found")
    assert fake.writes() == []


def test_the_hosts_are_matched_once_the_domains_are_read(made, env):
    p, fake = ddns(made, env)
    st = p.status()  # nothing read yet: no host matched, nothing said wrong
    assert st["valid"] is True and "problem" not in st and ddns_table(st)["rows"] == []
    assert ddns_table(st)["empty"] == "The hosts are matched to the account's domains once they are read."
    assert fake.requests == []


def test_a_host_taken_over_then_out_of_the_setting_is_let_go_and_comes_back_as_not_its_own(made, env, monkeypatch):
    """Settled against the whole setting once the domains are read (Keeper.settle): a host taken out of it is let go by
    the next pass; put back later, holding what is no longer this network's address, it is left as it is, its row
    offering Take over… again. A refresh settles too: with no host set, nothing is held."""
    t = [1_000_000.0]
    now = [HOME]
    p, fake = ddns(made, env, public=lambda: now[0], VULTR_DDNS_HOSTS="@.example.net, home.example.com")
    p._clock = lambda: t[0]
    p.ddns_update(force=False)  # example.net made (its own); home holds another address: left
    p.ask("ddns_take_over", "home.example.com", "198.51.100.7", True)
    assert p.keeper().known() == ["example.net", "home.example.com"] and p.keeper().taken("home.example.com")
    monkeypatch.setenv("VULTR_DDNS_HOSTS", "@.example.net")  # home taken out of the setting
    p.ddns_update(force=False)
    assert p.keeper().known() == ["example.net"] and not p.keeper().taken("home.example.com")
    kept = json.loads(p.ddns_file().read_text(encoding="utf-8"))
    assert kept == {"own": {"example.net": HOME}, "taken": []}
    writes = len(fake.writes())
    now[0], t[0] = NEW_HOME, t[0] + 601  # this network's address changes meanwhile
    monkeypatch.setenv("VULTR_DDNS_HOSTS", "@.example.net, home.example.com")  # home put back
    out = {h["host"]: h for h in p.ddns_update(force=False)["hosts"]}
    assert out["home.example.com"]["foreign"] is True and out["home.example.com"]["result"].startswith(
        f"holds {HOME}, not this network's address: left as it is")  # no longer its own: not followed to the new address
    assert out["example.net"]["result"] == f"set (was {HOME})"  # still its own: followed
    assert [w for w in fake.writes()[writes:] if "example.com" in w[1]] == []
    row = next(r for r in ddns_table(p.status())["rows"] if r[0] == "home.example.com")
    assert row[-1]["form"] == "ddns-take" and row[-1]["values"] == {"host": "home.example.com", "holds": HOME}
    monkeypatch.delenv("VULTR_DDNS_HOSTS")  # no host set at all: the next refresh settles against the whole, empty setting
    p.settings_changed()
    p.refresh()
    assert p.keeper().known() == [] and json.loads(p.ddns_file().read_text(encoding="utf-8")) == {"own": {}, "taken": []}


def test_the_setting_is_settled_only_once_the_domains_are_read(made, env, monkeypatch):
    """Never against an unread list: a refresh whose domains are not read lets nothing go."""
    p, fake = ddns(made, env, VULTR_DDNS_HOSTS="@.example.net")
    p.ddns_update(force=False)
    assert p.keeper().known() == ["example.net"]
    monkeypatch.delenv("VULTR_DDNS_HOSTS")
    p.settings_changed()
    fake.fail[("GET", "/domains")] = (403, "Unauthorized")
    p.refresh()  # the domains not read: nothing settled
    assert p.keeper().known() == ["example.net"]
    del fake.fail[("GET", "/domains")]
    p.refresh()
    assert p.keeper().known() == []


def test_a_pass_under_way_writes_nothing_once_the_plugin_is_detached(made, monkeypatch):
    """Detached while a pass waits on Vultr: the pass writes nothing after it, and the background reads no setting from
    the process's environment (the plugin's login is gone)."""
    reached, release = threading.Event(), threading.Event()
    fake = FakeVultr()
    fake.gate = (lambda m, path, q: (m, path) == ("GET", "/domains/example.net/records") and "name" in q,
                 reached, release)  # the pass's read of the host (by its name), held: the refresh's read is not
    p, fake = made(fake)
    asked_env = []
    real = settings_mod.read

    def read(login=None):
        if login is None and threading.current_thread().name == "vultr":
            asked_env.append(time.monotonic())
        return real(login)
    monkeypatch.setattr(settings_mod, "read", read)
    p.attach(App("platform"), Pairs(settings_of(VULTR_DDNS_HOSTS="@.example.net")))
    detaching = threading.Thread(target=p.detach)
    try:
        assert reached.wait(5)  # the background's first pass reads example.net's records: held there
        detaching.start()
        end = time.monotonic() + 5
        while p._rt.stop is not None and time.monotonic() < end:  # told to stop
            time.sleep(0.01)
    finally:
        release.set()
    detaching.join(10)
    assert not detaching.is_alive() and not p.working and p.login is None
    calls = len(fake.requests)
    time.sleep(0.2)
    assert not [w for w in fake.writes() if w[1].startswith("/domains/example.net")]  # nothing made after the detach
    assert len(fake.requests) == calls and asked_env == []
