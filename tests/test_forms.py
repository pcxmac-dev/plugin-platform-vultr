"""The platform's page changes the account through the plugin's forms (status.forms): each form's fields the hook's
arguments in order, each change confirmed with what it does named, and its hook sending exactly the request the reference
gives (method, path, body), the zone, the group or the keys read before and after it; a reboot, a halt, a set removing
other records and a risky firewall rule change refused until accepted a second time, an acceptance counting only when it
is True itself. Over the stand-ins alone."""
from __future__ import annotations

import inspect

import pytest

from conftest import DB, G_EMPTY, G_LONE, G_WEB, HOME, NEW, WEB, FakeVultr, public_key, settings_of
from plugin_platform_vultr import ACCEPT_HALT, ACCEPT_REBOOT, ACCEPT_REPLACE, ACCEPT_RISK
from plugin_platform_vultr.records import Refusal


def page_args(form: dict, values: dict, accepted=()) -> list:
    """What the platform's page sends for a form (platform.js argsOf): the fields' values in order, a field whose `when` is
    unmet or left empty null (the hook's default), a number as a number, an accept field true only once accepted."""
    now = {**{x["name"]: x.get("value") for x in form["fields"]}, **values}
    out = []
    for x in form["fields"]:
        if x["type"] == "accept":
            out.append(x["name"] in accepted)
            continue
        shown = all(str(now.get(k) or "") in [str(v) for v in vs] for k, vs in (x.get("when") or {}).items())
        v = now.get(x["name"])
        out.append(None if not shown or v in (None, "") else int(v) if x["type"] == "number" else v)
    return out


def ready(made, env, fake=None):
    env(settings_of())
    p, fake = made(fake)
    p.refresh()
    p.keeper().address()  # this network's address known, as after a Dynamic DNS check
    return p, fake, {f["id"]: f for f in p.status()["forms"]}


def button(status: dict, title: str, form: str, **match) -> dict:
    t = next(t for t in status["tables"] if t["title"] == title)
    return next(c for r in t["rows"] for c in r if isinstance(c, dict) and c.get("form") == form
                and all(c["values"].get(k) == v for k, v in match.items()))


def since(fake, n):
    return [(m, p, b) for m, p, q, b in fake.requests[n:]]


def test_every_form_takes_its_hooks_arguments_in_order_and_names_its_change(made, env):
    p, fake, forms = ready(made, env)
    assert sorted(forms) == sorted(["start", "reboot", "halt", "set:example.com", "add:example.com", "remove:example.com",
                                    "set:example.net", "add:example.net", "remove:example.net", f"rule-add:{G_WEB}",
                                    f"rule-remove:{G_WEB}", f"rule-add:{G_EMPTY}", f"rule-remove:{G_EMPTY}",
                                    f"rule-add:{G_LONE}", f"rule-remove:{G_LONE}", "key-add", "key-remove"])
    hooks = p.interface()["hooks"]
    for f in forms.values():
        assert f["hook"] in hooks
        assert [x["name"] for x in f["fields"]] == list(inspect.signature(getattr(p, f["hook"])).parameters), f["id"]
        assert all(x["type"] in ("text", "number", "choice", "fixed", "accept") for x in f["fields"])
        assert f["confirm"]["title"] and f["confirm"]["words"] and f["confirm"]["yes"]
    assert "still bills" in forms["halt"]["confirm"]["words"] and "asked again" in forms["halt"]["confirm"]["words"]
    (accept,) = [x for x in forms["halt"]["fields"] if x["type"] == "accept"]
    assert accept["name"] == ACCEPT_HALT and "may be lost" in accept["words"] and "{label}" in accept["words"]
    assert "hard reboot" in forms["reboot"]["confirm"]["words"] and forms["reboot"]["confirm"]["danger"] is True
    assert "asked again" in forms["reboot"]["confirm"]["words"]
    (again,) = [x for x in forms["reboot"]["fields"] if x["type"] == "accept"]
    assert again["name"] == ACCEPT_REBOOT and "hard restart" in again["words"] and "may be lost" in again["words"]
    assert "{label}" in again["words"] and not [x for x in forms["start"]["fields"] if x["type"] == "accept"]  # start: once
    assert "adds nothing to its charge" in forms["start"]["confirm"]["words"]  # Vultr bills it running or stopped
    assert "running or stopped" in forms["start"]["confirm"]["words"]
    # Set a record… replaces, and says so; Add a record… keeps the rest, and says so (the audit: they disagreed)
    s, a = forms["set:example.com"], forms["add:example.com"]
    assert [c["value"] for c in next(x for x in s["fields"] if x["name"] == "rtype")["choices"]] == ["A", "AAAA", "CNAME"]
    assert [c["value"] for c in next(x for x in a["fields"] if x["name"] == "rtype")["choices"]] == [
        "A", "AAAA", "TXT", "MX", "NS", "SRV", "CAA", "SSHFP"]
    assert "it replaces the host's {rtype} records" in s["confirm"]["words"] and "Every other record" not in s["confirm"]["words"]
    assert [x["name"] for x in s["fields"] if x["type"] == "accept"] == [ACCEPT_REPLACE]
    assert "every other record is kept" in a["confirm"]["words"] and not [x for x in a["fields"] if x["type"] == "accept"]
    assert next(x for x in a["fields"] if x["name"] == "priority")["when"] == {"rtype": ["MX", "SRV"]}
    assert next(x for x in s["fields"] if x["name"] == "data")["placeholder"] == HOME
    add = forms[f"rule-add:{G_WEB}"]
    assert next(x for x in add["fields"] if x["name"] == "port")["when"] == {"protocol": ["tcp", "udp"]}
    assert next(x for x in add["fields"] if x["name"] == "subnet")["note"] == f"this network's address: {HOME}"
    assert [x["name"] for x in add["fields"] if x["type"] == "accept"] == [ACCEPT_RISK]
    assert "the group's first rule while instances are linked" in add["confirm"]["words"]
    assert forms[f"rule-remove:{G_WEB}"]["confirm"]["danger"] is True and forms["key-remove"]["confirm"]["danger"] is True
    assert next(x for x in forms["key-add"]["fields"] if x["name"] == "ssh_key")["secret"] is True
    assert not fake.writes()  # drawn: nothing changed


def test_start_and_reboot_send_the_references_requests(made, env):
    p, fake, forms = ready(made, env)
    st = p.status()
    start = button(st, "Instances", "start", instance=DB)
    n = len(fake.requests)
    rep = p.ask("start", *page_args(forms["start"], start["values"]))
    assert since(fake, n) == [("GET", f"/instances/{DB}", None), ("POST", f"/instances/{DB}/start", None),
                              ("GET", f"/instances/{DB}", None)]
    assert rep["ok"] and rep["said"] == "db-1 started" and rep["lines"][1].startswith("Vultr says now: running")
    reboot = button(p.status(), "Instances", "reboot", instance=WEB)
    n = len(fake.requests)
    with pytest.raises(Refusal, match="rebooted only once that is accepted") as refused:
        p.ask("reboot", *page_args(forms["reboot"], reboot["values"]))  # a hard restart: the first confirmation is not enough
    assert refused.value.accept == ACCEPT_REBOOT and "hard restart" in str(refused.value) and "may be lost" in str(refused.value)
    assert since(fake, n) == [("GET", f"/instances/{WEB}", None)]
    n = len(fake.requests)
    rep = p.ask("reboot", *page_args(forms["reboot"], reboot["values"], accepted={ACCEPT_REBOOT}))
    assert rep["said"] == "web-1 rebooted" and since(fake, n)[1] == ("POST", f"/instances/{WEB}/reboot", None)
    # what the plugin refuses comes back in its words, nothing sent: a server already running, one not active yet, a
    # server renamed since the page showed it, one named by its ID alone
    n = len(fake.requests)
    with pytest.raises(Refusal, match="running already"):
        p.ask("start", WEB, "web-1")
    with pytest.raises(Refusal, match="is pending: a power change waits until it is active"):
        p.ask("reboot", NEW, "new-1")
    with pytest.raises(Refusal, match="is web-1 now, not web-old"):
        p.ask("reboot", WEB, "web-old")
    with pytest.raises(ValueError, match="by its name as the page shows it"):
        p.ask("start", DB)
    assert [m for m, path, b in since(fake, n)] == ["GET", "GET", "GET"]


def test_a_halt_is_made_only_once_it_is_accepted_a_second_time(made, env):
    p, fake, forms = ready(made, env)
    halt = button(p.status(), "Instances", "halt", instance=WEB)
    n = len(fake.requests)
    with pytest.raises(Refusal, match="halted only once that is accepted") as refused:
        p.ask("halt", *page_args(forms["halt"], halt["values"]))  # the first confirmation is not enough
    assert refused.value.accept == ACCEPT_HALT and "still bills" in str(refused.value)
    assert since(fake, n) == [("GET", f"/instances/{WEB}", None)] and fake.instances[0]["power_status"] == "running"
    rep = p.ask("halt", *page_args(forms["halt"], halt["values"], accepted={ACCEPT_HALT}))
    assert ("POST", f"/instances/{WEB}/halt", None) in since(fake, n) and fake.instances[0]["power_status"] == "stopped"
    assert rep["said"] == "web-1 halted" and any("still bills" in line for line in rep["lines"])
    st = p.status()
    row = next(r for r in next(t for t in st["tables"] if t["title"] == "Instances")["rows"] if r[0]["text"] == "web-1")
    assert row[1] == {"text": "stopped", "sub": "still billed · halted at " + row[1]["sub"].rsplit(" ", 1)[-1]}
    assert row[9]["form"] == "start"  # drawn as read after it: Start… now


def test_a_second_confirmation_counts_only_when_it_is_true(made, env):
    """The page sends JSON true; another program's "false", "yes", "0" or 1 is no acceptance (the audit: bool() took
    "false" as yes and halted a server)."""
    fake = FakeVultr()
    fake.records["example.com"].append({"id": "a0a0a0a0-0000-4000-8000-000000000007", "type": "A", "name": "home",
                                        "data": "198.51.100.8", "ttl": 120, "priority": 0})
    p, fake, forms = ready(made, env, fake)
    for no in ("false", "true", "yes", "0", 1, 1.0, [True]):
        with pytest.raises(Refusal, match="accepted a second time"):
            p.ask("halt", WEB, "web-1", no)
        with pytest.raises(Refusal, match="accepted a second time"):
            p.ask("reboot", WEB, "web-1", no)
        with pytest.raises(Refusal, match="risky"):
            p.ask("add_rule", G_WEB, "v4", "tcp", "22", "0.0.0.0", 0, "", no)
        with pytest.raises(Refusal, match="replaces them all"):
            p.ask("set_record", "example.com", "home", "A", HOME, None, no)
    assert fake.writes() == [] and fake.instances[0]["power_status"] == "running"
    assert p.ask("halt", WEB, "web-1", True)["said"] == "web-1 halted"  # True itself


def test_a_record_set_replaces_and_one_added_keeps_the_rest(made, env):
    p, fake, forms = ready(made, env)
    s, a = forms["set:example.com"], forms["add:example.com"]
    before = fake.zone()
    n = len(fake.requests)
    args = page_args(a, {"name": "blog", "rtype": "A", "data": "203.0.113.30", "ttl": "", "priority": "5"})
    assert args == ["example.com", "blog", "A", "203.0.113.30", None, None]  # a priority hidden for an A record: not sent
    rep = p.ask("add_record", *args)
    assert since(fake, n) == [("GET", "/domains/example.com/records", None),
                              ("POST", "/domains/example.com/records", {"name": "blog", "type": "A", "data": "203.0.113.30"}),
                              ("GET", "/domains/example.com/records", None)]
    assert rep["ok"] and rep["said"] == "added blog A 203.0.113.30" and fake.zone() == [*before, ("blog", "A", "203.0.113.30")]
    # the apex's A record set: its one record updated, nothing else touched (asked once: nothing else goes)
    n = len(fake.requests)
    rep = p.ask("set_record", *page_args(s, {"name": "@", "rtype": "A", "data": "203.0.113.11", "ttl": "600"}))
    assert since(fake, n)[1] == ("PATCH", "/domains/example.com/records/a0a0a0a0-0000-4000-8000-000000000001",
                                 {"data": "203.0.113.11", "ttl": 600})
    assert rep["said"] == "set @ A 203.0.113.11: it replaces 203.0.113.10" and rep["ok"]
    # a TXT record is added beside the others, its text in double quotes as Vultr's DNS keeps it
    n = len(fake.requests)
    rep = p.ask("add_record", *page_args(a, {"name": "_dmarc", "rtype": "TXT", "data": "v=DMARC1; p=quarantine"}))
    assert since(fake, n)[1] == ("POST", "/domains/example.com/records",
                                 {"name": "_dmarc", "type": "TXT", "data": '"v=DMARC1; p=quarantine"'})
    rep = p.ask("add_record", "example.com", "@", "TXT", "v=spf1 include:_spf.protonmail.ch ~all", None, None)
    assert rep["changed"] is False and "nothing written" in rep["said"]  # there already (quoted or not)
    n = len(fake.requests)
    rep = p.ask("add_record", *page_args(a, {"name": "@", "rtype": "MX", "data": "mailsec.protonmail.ch", "priority": "20"}))
    assert since(fake, n)[1] == ("POST", "/domains/example.com/records",
                                 {"name": "", "type": "MX", "data": "mailsec.protonmail.ch", "priority": 20})
    assert ("", "MX", "mail.protonmail.ch") in fake.zone() and "beside the host's 1 other MX record, kept" in rep["said"]
    # what the plugin refuses comes back in its words, nothing written
    n = len(fake.requests)
    with pytest.raises(ValueError, match="needs its priority"):
        p.ask("add_record", "example.com", "@", "MX", "mail3.example.org", None, None)
    with pytest.raises(ValueError, match="not an IPv4 address"):
        p.ask("set_record", "example.com", "home", "A", "not-an-ip", None, False)
    with pytest.raises(Refusal, match="cannot stand for the domain itself"):
        p.ask("set_record", "example.com", "@", "CNAME", "other.example.org", None, False)
    with pytest.raises(Refusal, match="www is a CNAME"):
        p.ask("add_record", "example.com", "www", "TXT", "hello", None, None)
    with pytest.raises(ValueError, match="no record type here: A, AAAA, CNAME"):
        p.ask("set_record", "example.com", "@", "TXT", "hello", None, False)  # a TXT is added, never set over others
    with pytest.raises(ValueError, match="no record type here: A, AAAA, TXT"):
        p.ask("add_record", "example.com", "alias", "CNAME", "example.com", None, None)  # a CNAME stands alone: set
    with pytest.raises(Refusal, match="not on this account's Vultr DNS"):
        p.ask("set_record", "example.org", "www", "A", "203.0.113.1", None, False)
    assert [path for m, path, b in since(fake, n)] == ["/domains/example.com/records"] * 6 + ["/domains"]  # reads only


def test_setting_a_hosts_record_over_several_asks_before_the_others_go(made, env):
    """The audit's case: api holds two A records; setting a third address replaces both, so it is asked again, naming
    them; Add a record… keeps them."""
    fake = FakeVultr()
    fake.records["example.com"].append({"id": "a0a0a0a0-0000-4000-8000-000000000007", "type": "A", "name": "home",
                                        "data": "198.51.100.8", "ttl": 120, "priority": 0})
    p, fake, forms = ready(made, env, fake)
    s = forms["set:example.com"]
    n = len(fake.requests)
    with pytest.raises(Refusal, match=r"home holds 2 A records: setting it to 93.184.216.34 replaces them all, so "
                                      r"198.51.100.8 is removed") as refused:
        p.ask("set_record", *page_args(s, {"name": "home", "rtype": "A", "data": HOME}))
    assert refused.value.accept == ACCEPT_REPLACE and since(fake, n) == [("GET", "/domains/example.com/records", None)]
    n = len(fake.requests)
    rep = p.ask("set_record", *page_args(s, {"name": "home", "rtype": "A", "data": HOME}, accepted={ACCEPT_REPLACE}))
    assert since(fake, n)[1:3] == [("PATCH", "/domains/example.com/records/a0a0a0a0-0000-4000-8000-000000000006",
                                    {"data": HOME}),
                                   ("DELETE", "/domains/example.com/records/a0a0a0a0-0000-4000-8000-000000000007", None)]
    assert rep["ok"] and "the host's other A records removed (198.51.100.8)" in rep["said"]
    assert [r for r in fake.zone() if r[1] == "A" and "home" in r[0]] == [("home.example.com", "A", HOME)]
    rep = p.ask("add_record", "example.com", "home", "A", "203.0.113.22", None, None)  # beside: both kept
    assert rep["ok"] and [r[2] for r in fake.zone() if r[1] == "A" and "home" in r[0]] == [HOME, "203.0.113.22"]


def test_a_record_is_removed_by_its_id_once_it_is_the_one_shown(made, env):
    p, fake, forms = ready(made, env)
    rm = forms["remove:example.com"]
    spf = button(p.status(), "example.com records", "remove:example.com", rtype="TXT")
    assert spf["values"] == {"record": "a0a0a0a0-0000-4000-8000-000000000004", "name": "@", "rtype": "TXT",
                             "data": '"v=spf1 include:_spf.protonmail.ch ~all"'}
    n = len(fake.requests)
    rep = p.ask("remove_record", *page_args(rm, spf["values"]))
    assert since(fake, n) == [("GET", "/domains/example.com/records", None),
                              ("DELETE", "/domains/example.com/records/a0a0a0a0-0000-4000-8000-000000000004", None),
                              ("GET", "/domains/example.com/records", None)]
    assert rep["ok"] and rep["said"] == 'removed @ TXT "v=spf1 include:_spf.protonmail.ch ~all"'
    assert ("", "MX", "mail.protonmail.ch") in fake.zone() and len(fake.zone()) == 5
    # one changed since the page showed it is not removed, nor one named by its ID alone
    fake.records["example.com"][0]["data"] = "203.0.113.99"
    apex = {"record": "a0a0a0a0-0000-4000-8000-000000000001", "name": "@", "rtype": "A", "data": "203.0.113.10"}
    n = len(fake.requests)
    with pytest.raises(Refusal, match="not the one shown"):
        p.ask("remove_record", *page_args(rm, apex))
    with pytest.raises(Refusal, match="holds no record"):
        p.ask("remove_record", "example.com", "a0a0a0a0-0000-4000-8000-000000000004", "@", "TXT", "x")
    with pytest.raises(ValueError, match="with its name, type and data as shown"):
        p.ask("remove_record", "example.com", "a0a0a0a0-0000-4000-8000-000000000001")
    assert [m for m, path, b in since(fake, n)] == ["GET", "GET", "GET"] and fake.records["example.com"][0]["data"] == "203.0.113.99"


def test_a_rule_is_added_and_a_risky_one_only_once_accepted(made, env):
    p, fake, forms = ready(made, env)
    add = forms[f"rule-add:{G_WEB}"]
    n = len(fake.requests)
    args = page_args(add, {"ip_type": "v4", "protocol": "tcp", "port": "8000:8999", "subnet": HOME, "subnet_size": "32",
                           "notes": "dev servers"})
    assert args == [G_WEB, "v4", "tcp", "8000:8999", HOME, 32, "dev servers", False]
    rep = p.ask("add_rule", *args)
    assert since(fake, n) == [("GET", f"/firewalls/{G_WEB}", None), ("GET", f"/firewalls/{G_WEB}/rules", None),
                              ("POST", f"/firewalls/{G_WEB}/rules", {"ip_type": "v4", "protocol": "tcp", "subnet": HOME,
                                                                      "subnet_size": 32, "port": "8000:8999",
                                                                      "notes": "dev servers"}),
                              ("GET", f"/firewalls/{G_WEB}/rules", None)]
    assert rep["ok"] and rep["said"] == f"added TCP 8000:8999 from {HOME}/32 (IPv4) to web"
    # SSH open to the whole internet: refused until accepted, nothing sent
    risky = page_args(add, {"ip_type": "v4", "protocol": "tcp", "port": "22", "subnet": "0.0.0.0", "subnet_size": "0"})
    n = len(fake.requests)
    with pytest.raises(Refusal, match=r"lets SSH \(TCP 22\) in from the whole internet") as refused:
        p.ask("add_rule", *risky)
    assert refused.value.accept == ACCEPT_RISK and all(m == "GET" for m, path, b in since(fake, n))
    with pytest.raises(Refusal, match="every UDP port in from the whole internet"):
        p.ask("add_rule", G_WEB, "v6", "udp", "1:65535", "::", 0, "", False)
    with pytest.raises(Refusal, match=r"lets RDP \(TCP 3389\) in from the whole internet"):
        p.ask("add_rule", G_WEB, "v4", "tcp", "3389", "0.0.0.0", 0, "", False)
    with pytest.raises(Refusal, match=r"lets Docker's API \(TCP 2375\), Docker's API over TLS \(TCP 2376\) in"):
        p.ask("add_rule", G_WEB, "v4", "tcp", "2375:2376", "0.0.0.0", 0, "", False)
    rep = p.ask("add_rule", *page_args(add, {"ip_type": "v4", "protocol": "tcp", "port": "22", "subnet": "0.0.0.0",
                                             "subnet_size": "0"}, accepted={ACCEPT_RISK}))
    assert rep["ok"] and any(line.startswith("accepted as risky: it lets SSH") for line in rep["lines"])
    assert fake.writes()[-1][:2] == ("POST", f"/firewalls/{G_WEB}/rules")
    # an ICMP rule takes no port; a rule there already is not added again; a bad one is refused in words
    rep = p.ask("add_rule", *page_args(add, {"ip_type": "v4", "protocol": "icmp", "port": "22", "subnet": "0.0.0.0",
                                             "subnet_size": "0"}))
    assert "port" not in fake.writes()[-1][2] and rep["ok"]
    n = len(fake.requests)
    with pytest.raises(Refusal, match="in the group already"):
        p.ask("add_rule", G_WEB, "v4", "tcp", "443", "0.0.0.0", 0, "", False)
    with pytest.raises(ValueError, match="takes a port or a range"):
        p.ask("add_rule", G_WEB, "v4", "tcp", None, HOME, 32, "", False)
    with pytest.raises(ValueError, match="is not an IPv4 address"):
        p.ask("add_rule", G_WEB, "v4", "tcp", "80", "2001:db8::1", 32, "", False)
    assert all(m == "GET" for m, path, b in since(fake, n))


def test_a_groups_first_rule_is_asked_twice_while_instances_are_linked_to_it(made, env):
    """The audit's case: a group without rules is not enforced; its first rule, even one letting SSH in from one address,
    makes Vultr drop everything else (a website on 80 and 443), so it is asked again."""
    fake = FakeVultr()
    fake.groups[1]["instance_count"] = 2  # the spare group: no rules, two instances linked
    p, fake, forms = ready(made, env, fake)
    add = forms[f"rule-add:{G_EMPTY}"]
    with pytest.raises(Refusal, match="the group's first rule while 2 instances are linked to it: .* dropped \\(a website on "
                                      "80 or 443, any other service, SSH too\\)"):
        p.ask("add_rule", *page_args(add, {"protocol": "tcp", "port": "443", "subnet": "0.0.0.0", "subnet_size": "0"}))
    ssh_only = page_args(add, {"protocol": "tcp", "port": "22", "subnet": HOME, "subnet_size": "32"})
    with pytest.raises(Refusal, match=r"dropped \(a website on 80 or 443, any other service\): only what this rule lets in") \
            as refused:
        p.ask("add_rule", *ssh_only)
    assert refused.value.accept == ACCEPT_RISK and fake.writes() == []
    rep = p.ask("add_rule", *page_args(add, {"protocol": "tcp", "port": "22", "subnet": HOME, "subnet_size": "32"},
                                       accepted={ACCEPT_RISK}))
    assert rep["ok"] and fake.writes() == [("POST", f"/firewalls/{G_EMPTY}/rules",
                                            {"ip_type": "v4", "protocol": "tcp", "subnet": HOME, "subnet_size": 32,
                                             "port": "22"})]
    rep = p.ask("add_rule", G_EMPTY, "v4", "tcp", "443", "0.0.0.0", 0, "https", False)  # its second rule: asked once
    assert rep["ok"]


def test_removing_the_rule_letting_ssh_in_or_a_groups_last_rule_is_asked_twice(made, env):
    p, fake, forms = ready(made, env)
    rm = forms[f"rule-remove:{G_WEB}"]
    ssh = button(p.status(), "web rules", f"rule-remove:{G_WEB}", rule="1")
    assert ssh["values"] == {"rule": "1", "protocol": "TCP", "port": "22", "source": "198.51.100.0/24"}
    n = len(fake.requests)
    with pytest.raises(Refusal, match="the only rule letting SSH in: SSH to its 1 instance is dropped") as refused:
        p.ask("remove_rule", *page_args(rm, ssh["values"]))
    assert refused.value.accept == ACCEPT_RISK and all(m == "GET" for m, path, b in since(fake, n))
    https = button(p.status(), "web rules", f"rule-remove:{G_WEB}", rule="2")
    rep = p.ask("remove_rule", *page_args(rm, https["values"]))  # not risky: SSH still let in
    assert rep["ok"] and fake.writes()[-1] == ("DELETE", f"/firewalls/{G_WEB}/rules/2", None)
    # db's only rule: removing it stops the group being enforced (every port open again)
    lone = button(p.status(), "db rules", f"rule-remove:{G_LONE}", rule="1")
    with pytest.raises(Refusal, match="the group's last rule: a group without rules is not enforced"):
        p.ask("remove_rule", *page_args(forms[f"rule-remove:{G_LONE}"], lone["values"]))
    rep = p.ask("remove_rule", *page_args(forms[f"rule-remove:{G_LONE}"], lone["values"], accepted={ACCEPT_RISK}))
    assert rep["ok"] and fake.rules[G_LONE] == [] and rep["lines"][1].startswith("accepted as risky")
    # a rule changed since it was shown is not removed, nor one named by its ID alone
    with pytest.raises(Refusal, match="not the one shown"):
        p.ask("remove_rule", G_WEB, "1", "TCP", "2222", "198.51.100.0/24", True)
    with pytest.raises(ValueError, match="with its protocol, port and source as shown"):
        p.ask("remove_rule", G_WEB, "1")


def test_ssh_keys_are_added_and_removed(made, env):
    p, fake, forms = ready(made, env)
    key = public_key(7, comment="ci@runner")
    n = len(fake.requests)
    rep = p.ask("add_key", *page_args(forms["key-add"], {"name": "ci", "ssh_key": key}))
    assert since(fake, n) == [("GET", "/ssh-keys", None), ("POST", "/ssh-keys", {"name": "ci", "ssh_key": key}),
                              ("GET", "/ssh-keys", None)]
    assert rep["ok"] and rep["said"].startswith("added the key ci (SHA256:") and "no instance running changes" in rep["lines"][0]
    n = len(fake.requests)
    with pytest.raises(Refusal, match="in the account already, as ci"):
        p.ask("add_key", "ci again", public_key(7, comment="another comment"))
    with pytest.raises(ValueError, match="that is a private key"):
        p.ask("add_key", "oops", "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAA -----END OPENSSH PRIVATE KEY-----")
    with pytest.raises(ValueError, match="not an OpenSSH public key"):
        p.ask("add_key", "bad", "ssh-ed25519 notbase64!!")
    with pytest.raises(ValueError, match="with its name as shown"):
        p.ask("remove_key", "3b8066a7-b438-455a-9688-44afc9a3597f")
    assert [m for m, path, b in since(fake, n)] == ["GET"]
    laptop = button(p.status(), "SSH keys", "key-remove", name="laptop")
    rep = p.ask("remove_key", *page_args(forms["key-remove"], laptop["values"]))
    assert fake.writes()[-1] == ("DELETE", "/ssh-keys/3b8066a7-b438-455a-9688-44afc9a3597f", None)
    assert rep["ok"] and rep["said"] == "removed the key laptop" and [k["name"] for k in fake.keys] == ["ci"]
