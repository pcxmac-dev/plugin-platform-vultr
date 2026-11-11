"""Dynamic DNS through Vultr's DNS (liminal_libs.machines.ddns.Keeper): this network's address asked of the name servers
the plugin names, each host's A record read through the API, set only where it differs (every host with Update DNS now),
made where there is none, the host's other A records removed; a host in none of the account's domains said. Over the
stand-ins alone."""
from __future__ import annotations

from conftest import HOME, FakeVultr, settings_of
from plugin_platform_vultr import DDNS_TTL, PUBLIC_IPV4

HOME_ID = "a0a0a0a0-0000-4000-8000-000000000006"


def ddns(made, env, fake=None, public=HOME, **more):
    env(settings_of(ddns=True, **more))
    return made(fake, public=public)


def test_the_public_address_is_asked_of_the_servers_the_plugin_names():
    assert PUBLIC_IPV4 == (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
                           ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))


def test_a_host_that_differs_is_set_and_one_that_is_current_is_left(made, env):
    p, fake = ddns(made, env)
    out = p.ddns_update(force=False)
    assert out == [{"host": "home.example.com", "address": HOME, "checkedAt": out[0]["checkedAt"],
                    "updatedAt": out[0]["updatedAt"], "result": "set (was 198.51.100.7)", "ok": True}]
    assert fake.writes() == [("PATCH", f"/domains/example.com/records/{HOME_ID}", {"data": HOME})]
    reads = [q for m, path, q, b in fake.requests if path == "/domains/example.com/records"]
    assert reads[0]["name"] == "home" and "type" not in reads[0]  # the host's records by its name (a CNAME there is seen)
    assert fake.calls()[0] == "GET /domains"  # the account's domains read first: the hosts are split against them
    n = len(fake.requests)
    assert p.ddns_update(force=False)[0]["result"] == "current" and len(fake.writes()) == 1
    assert [c for c in fake.calls()[n:]] == ["GET /domains/example.com/records"]
    st = p.status()
    ddns_table = st["tables"][0]
    assert ddns_table["title"] == "Dynamic DNS" and ddns_table["rows"][0][:2] == ["home.example.com", HOME]
    assert f"this network's address: {HOME}" in ddns_table["note"]
    assert [a["hook"] for a in st["actions"]] == ["refresh", "ddns_update"]


def test_update_dns_now_checks_every_host_and_sends_nothing_where_it_is_already_right(made, env):
    p, fake = ddns(made, env)
    fake.records["example.com"][5]["data"] = HOME
    out = p.ask("ddns_update")  # the page's Update DNS now (force)
    assert out[0]["result"] == "current (nothing to send)" and out[0]["ok"] and fake.writes() == []


def test_a_host_without_a_record_is_made_and_the_others_of_its_kind_removed(made, env):
    fake = FakeVultr()
    fake.records["example.com"].append({"id": "a0a0a0a0-0000-4000-8000-000000000007", "type": "A", "name": "home",
                                        "data": "198.51.100.8", "ttl": 120, "priority": 0})
    p, fake = ddns(made, env, fake, VULTR_DDNS_HOSTS="home.example.com, @.example.net")
    out = {h["host"]: h for h in p.ddns_update(force=False)}
    assert out["example.net"]["result"] == "made (was none)" and out["example.net"]["address"] == HOME
    assert ("POST", "/domains/example.net/records", {"name": "", "type": "A", "data": HOME, "ttl": DDNS_TTL}) in fake.writes()
    assert out["home.example.com"]["result"] == "set (its other A records removed: 198.51.100.8) (was 198.51.100.7, 198.51.100.8)"
    assert ("DELETE", "/domains/example.com/records/a0a0a0a0-0000-4000-8000-000000000007", None) in fake.writes()
    assert [r for r in fake.zone() if r[1] == "A" and "home" in r[0]] == [("home.example.com", "A", HOME)]


def test_a_cname_host_and_a_host_in_no_domain_of_the_account_are_said(made, env):
    p, fake = ddns(made, env, VULTR_DDNS_HOSTS="www.example.com, home.elsewhere.org")
    out = p.ddns_update(force=False)
    assert out[0]["host"] == "www.example.com" and out[0]["ok"] is False
    assert "is a CNAME: Dynamic DNS keeps an A record" in out[0]["result"] and fake.writes() == []
    p.refresh()
    st = p.status()
    assert "home.elsewhere.org is in none of the account's domains" in st["problem"]
    assert "www.example.com: its record could not be read" in st["problem"]
    assert "not kept: home.elsewhere.org is in none of the account's domains" in st["tables"][0]["note"]


def test_no_address_found_means_no_write(made, env):
    p, fake = ddns(made, env, public=None)
    out = p.ddns_update(force=True)
    assert out[0]["ok"] is False and out[0]["result"].startswith("this network's address was not found")
    assert fake.writes() == []


def test_the_hosts_are_matched_once_the_domains_are_read(made, env):
    p, fake = ddns(made, env)
    st = p.status()  # nothing read yet: no host matched, nothing said wrong
    assert st["valid"] is True and "problem" not in st and st["tables"][0]["rows"] == []
    assert st["tables"][0]["empty"] == "The hosts are matched to the account's domains once they are read."
    assert fake.requests == []
