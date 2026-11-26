"""Every plugin here conforms to the class contract (plugin API 2.2): liminal_libs.sources.conformance, read from the
plugin alone (nothing runs); its API card is Vultr's API as the client uses it; nothing billable is in the client."""
from __future__ import annotations

import inspect
import os
import re
from pathlib import Path

import pytest

import plugin_platform_vultr as module
import plugin_platform_vultr.api as api
from liminal_libs.sources.apis import API_KINDS, LINK_KINDS, dead_links, problems
from liminal_libs.sources.conformance import assert_module_conforms
from plugin_platform_vultr.card import REF, VULTR_API

PACKAGE = Path(module.__file__).parent


def test_every_plugin_here_conforms_to_the_class_contract():
    found = assert_module_conforms(module)
    assert found and all(p.api == "2.2" and not p.is_record for p in found)
    assert {p.SYSTEM for p in found} == {"platform"} and {p.KIND for p in found} == {"machine"}
    assert {(p.name, p.title, p.order, p.ICON) for p in found} == {("vultr", "Vultr", 762, "vultr")}
    assert module.__version__ == "0.1.6"
    assert 'version = "0.1.6"' in (PACKAGE.parents[1] / "pyproject.toml").read_text(encoding="utf-8")


def test_its_settings_are_pairs_named_by_their_variables():
    p = module.MACHINE
    assert [k.pair for k in p.keys] == ["vultr-api-key", "vultr-ddns-hosts", "vultr-ddns-minutes"]
    assert {k.name for k in p.keys if k.secret} == {"VULTR_API_KEY"}
    assert all(k.hint.startswith("optional") for k in p.keys[1:]) and not p.keys[0].hint.startswith("optional")
    assert "Access Control" in p.keys[0].hint and "Account > API" in p.keys[0].hint  # where the key and its addresses are set
    hooks = p.interface()["hooks"]
    assert {"present", "status", "refresh", "balance", "servers", "domains", "records", "firewalls", "ssh_keys", "start",
            "reboot", "halt", "set_record", "add_record", "remove_record", "add_rule", "remove_rule", "add_key",
            "remove_key", "ddns_update", "ddns_take_over"} <= set(hooks)
    assert "instances" not in p.HOOKS[len(type(p).__mro__[1].HOOKS):]  # Vultr's instances are `servers`: `instances` is Docker's
    assert p.interface()["apis"] == ["Vultr API v2"]


def test_its_icon_is_its_makers_mark_drawn_by_the_library():
    from liminal_libs.ui import STATIC

    drawn = set(re.findall(r"^\s*([a-z]+):\s*'", (STATIC / "icons.js").read_text(encoding="utf-8"), re.M))
    assert module.MACHINE.ICON == "vultr" and "vultr" in drawn


def test_the_card_names_every_call_the_client_makes_and_only_those():
    """The API card's used calls are exactly the client's ENDPOINTS, by the reference's own method and path; its changes
    are the writes, none of them costs; the card's billable calls are none of the client's."""
    made = {f"{m} {p}" for m, p in api.ENDPOINTS.values()}
    used = {c.name for c in VULTR_API.used}
    assert used == made and len(made) == len(api.ENDPOINTS) == 29
    by_name = {c.name: c for c in VULTR_API.calls}
    for name, (m, p) in api.ENDPOINTS.items():
        c = by_name[f"{m} {p}"]
        assert c.writes == (m != "GET") and not c.costs, c
        assert c.docs.startswith(f"{REF}#tag/") and "/operation/" in c.docs
    billable = {c.name for c in VULTR_API.calls if c.costs}
    assert billable and not billable & made
    assert {"POST /instances", "PATCH /instances/{instance-id}", "POST /snapshots", "POST /reserved-ips", "POST /blocks",
            "POST /bare-metals", "POST /kubernetes/clusters", "POST /load-balancers", "POST /databases"} <= billable
    assert api.WRITES == {"start", "reboot", "halt", "record_create", "record_update", "record_delete", "rule_create",
                          "rule_delete", "key_create", "key_delete"}


def test_nothing_billable_is_in_the_clients_source():
    """No call that creates, resizes, restores or destroys a billable thing, nor turns backups on, is in the client: its
    paths are not in api.py, and every request of the package goes through VultrApi.call (ENDPOINTS)."""
    source = (PACKAGE / "api.py").read_text(encoding="utf-8")
    for path in ("/reinstall", "/restore", "/backup-schedule", "/upgrades", "/convert", "/clone", "create-from-url",
                 "/attach", "/detach", "/ipv4", "/ipv6", "/vpcs", "/object-storage", '"enabled"', '"plan":',
                 '"ddos_protection"', '"auto_backups"'):  # no backups turned on, no plan changed, no DDoS protection
        assert path not in source, path
    for m, p in api.ENDPOINTS.values():
        assert (m, p) not in {("POST", "/instances"), ("PATCH", "/instances/{instance-id}"),
                              ("DELETE", "/instances/{instance-id}"), ("POST", "/snapshots"), ("POST", "/reserved-ips"),
                              ("POST", "/blocks"), ("POST", "/bare-metals")}
        assert m == "GET" or not any(x in p for x in ("/bare-metals", "/snapshots", "/backups", "/blocks", "/reserved-ips",
                                                       "/kubernetes", "/load-balancers", "/databases", "/plans"))
    texts = {f.name: f.read_text(encoding="utf-8") for f in PACKAGE.glob("*.py")}
    for name, text in texts.items():
        sends = re.findall(r"\brest\.(request|get|post|put|patch|delete|pages)\(", text)
        assert sends == (["request"] if name == "api.py" else []), (name, sends)  # VultrApi.call's, and no other
        assert "RestClient(" not in text or name == "api.py", name
        assert not re.search(r"^\s*(?:import|from)\s+(?:requests|http\.client|urllib\.request)\b", text, re.M), name


def test_the_card_holds_vultrs_api_as_its_pages_give_it():
    a = VULTR_API
    assert problems(module.MACHINE.apis) == [] and module.MACHINE.apis == (a,)
    assert a.kind == "rest" and a.kind in API_KINDS and a.base == "https://api.vultr.com/v2" and a.verified == "2026-11-11"
    assert a.docs == REF and a.links[0].kind == "reference"
    kinds = {x.kind for x in a.links}
    assert {"reference", "auth", "limits", "pricing", "status", "changelog", "console", "tool", "sdk", "terms"} <= kinds
    assert kinds <= set(LINK_KINDS)
    assert "30 requests a second" in a.limits and "Retry-After" in a.limits and "500" in a.limits
    assert "stopped instance still bills" in a.costs and "672 hours" in a.costs
    assert "Access Control" in a.auth and "Bearer" in a.auth
    names = [x.name for x in a.areas]
    assert len(names) == 43 and names[0] == "Account" and "Instances" in names and "Block Storage clones" in names
    assert all(x.docs.startswith(f"{REF}#tag/") for x in a.areas)
    covered = {x.name for x in a.covered}
    assert covered == {"Account", "Backups", "Bare Metal", "Block Storage", "DNS", "Firewall", "Instances", "Kubernetes",
                       "Load Balancers", "Managed Databases", "Plans", "Reserved IPs", "Regions", "Snapshots", "SSH Keys"}
    assert {c.area for c in a.calls} <= set(names)
    assert all(c.docs.startswith(f"{REF}#tag/") for c in a.calls)
    d = a.as_dict()
    assert d["counts"] == {"areas": 43, "covered": 15, "calls": len(a.calls), "used": 29}


def test_what_it_learned_of_its_api_is_keyed_by_the_cards_name(made, env):
    from conftest import settings_of

    env(settings_of())
    p, fake = made()
    facts = p.api_facts()
    assert list(facts) == ["Vultr API v2"] and facts["Vultr API v2"]["Requests"] == "none yet"
    assert facts["Vultr API v2"]["Account read"] == "not yet"
    p.refresh()
    calls = len(fake.requests)
    facts = p.api_facts()["Vultr API v2"]
    assert len(fake.requests) == calls  # asking nothing to answer it
    assert facts["Requests"] == f"{calls} made" and facts["Last answer"].startswith("HTTP 200")
    assert facts["Account read"] != "not yet" and facts["The key's permissions"].startswith("every permission")


def test_the_hooks_the_forms_ask_take_their_fields_in_order():
    """Each form's fields are the hook's parameters in order (the platform's page sends them so)."""
    p = module.MACHINE
    for hook, fields in (("start", ["instance", "label"]), ("reboot", ["instance", "label", "accept_reboot"]),
                         ("halt", ["instance", "label", "accept_halt"]),
                         ("set_record", ["domain", "name", "rtype", "data", "ttl", "accept_replace"]),
                         ("add_record", ["domain", "name", "rtype", "data", "ttl", "priority"]),
                         ("ddns_take_over", ["host", "holds", "accept_take_over"]), ("ddns_update", ["force"]),
                         ("remove_record", ["domain", "record", "name", "rtype", "data"]),
                         ("add_rule", ["group", "ip_type", "protocol", "port", "subnet", "subnet_size", "notes", "accept_risk"]),
                         ("remove_rule", ["group", "rule", "protocol", "port", "source", "accept_risk"]),
                         ("add_key", ["name", "ssh_key"]), ("remove_key", ["key", "name"])):
        assert list(inspect.signature(getattr(p, hook)).parameters) == fields, hook


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="the vendor's pages are asked only with "
                    "LIMINAL_VENDOR_PAGES=1")
def test_every_address_on_the_card_answers():
    assert dead_links(module.MACHINE.apis) == []
