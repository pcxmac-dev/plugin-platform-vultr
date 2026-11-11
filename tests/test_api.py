"""The client over the stand-in: each request as the reference gives it (the key as a bearer token, a list paged by its
cursor, a count with a page of one), Vultr's errors in words with the key scrubbed, a rate limit waited out, the pace kept."""
from __future__ import annotations

import pytest

from conftest import BASE, KEY, FakeVultr
from plugin_platform_vultr.api import ENDPOINTS, IP_REFUSED, PER_PAGE, VultrApi, path_of
from plugin_platform_vultr.api import RestError


def client(fake, **kw):
    kw.setdefault("sleep", lambda s: None)
    kw.setdefault("gap", 0.0)
    return VultrApi(KEY, transport=fake, **kw)


def test_a_read_bears_the_key_and_asks_a_page_of_the_most():
    seen = []
    fake = FakeVultr()

    def transport(method, url, headers, body, timeout):
        seen.append((method, url, dict(headers), body))
        return fake(method, url, headers, body, timeout)
    api = client(transport)
    assert api.account()["balance"] == -100.55
    method, url, headers, body = seen[0]
    assert (method, url, body) == ("GET", f"{BASE}/account", None)
    assert headers["Authorization"] == f"Bearer {KEY}" and headers["Accept"] == "application/json"
    assert [i["label"] for i in api.instances()] == ["web-1", "db-1", ""]
    assert seen[1][1] == f"{BASE}/instances?per_page={PER_PAGE}"


def test_a_list_is_read_across_its_pages_by_the_cursor():
    fake = FakeVultr()
    fake.page_most = 2  # the stand-in pages by two
    api = client(fake)
    assert [r["id"][-1] for r in api.records("example.com")] == ["1", "2", "3", "4", "5", "6"]
    asked = [q for m, p, q, b in fake.requests if p == "/domains/example.com/records"]
    assert len(asked) == 3 and "cursor" not in asked[0] and asked[1]["cursor"] and asked[2]["cursor"] != asked[1]["cursor"]
    assert all(q["per_page"] == str(PER_PAGE) for q in asked)


def test_a_records_filter_asks_the_name_relative_to_the_domain():
    fake = FakeVultr()
    api = client(fake)
    assert [r["data"] for r in api.records("example.com", name="home", rtype="A")] == ["198.51.100.7"]
    assert [r["data"] for r in api.records("example.com", name="", rtype="A")] == ["203.0.113.10"]  # "" the apex
    assert fake.requests[-1][2] == {"per_page": str(PER_PAGE), "name": "", "type": "A"}


def test_the_other_kinds_are_counted_with_a_page_of_one():
    fake = FakeVultr()
    api = client(fake)
    assert api.count("snapshots", "snapshots") == 2 and fake.requests[-1][2] == {"per_page": "1"}
    assert api.count("kubernetes", "vke_clusters", paged=False) == 1 and fake.requests[-1][2] == {}
    assert api.count("databases", "databases", paged=False) == 1


def test_the_writes_are_the_references_own():
    fake = FakeVultr()
    api = client(fake)
    api.power("halt", "cb676a46-66fd-4dfb-b839-443f2e6c0b60")
    made = api.create_record("example.com", {"name": "blog", "type": "A", "data": "203.0.113.30"})
    api.update_record("example.com", made["id"], {"data": "203.0.113.31"})
    api.delete_record("example.com", made["id"])
    rule = api.create_rule("1e7bb4c2-7dbd-4ad4-a4b6-a6d6b8e0b0a1", {"ip_type": "v4", "protocol": "tcp", "port": "80",
                                                                   "subnet": "0.0.0.0", "subnet_size": 0})
    api.delete_rule("1e7bb4c2-7dbd-4ad4-a4b6-a6d6b8e0b0a1", rule["id"])
    key = api.create_key("ci", "ssh-ed25519 AAAA")
    api.delete_key(key["id"])
    assert fake.writes() == [
        ("POST", "/instances/cb676a46-66fd-4dfb-b839-443f2e6c0b60/halt", None),
        ("POST", "/domains/example.com/records", {"name": "blog", "type": "A", "data": "203.0.113.30"}),
        ("PATCH", f"/domains/example.com/records/{made['id']}", {"data": "203.0.113.31"}),
        ("DELETE", f"/domains/example.com/records/{made['id']}", None),
        ("POST", "/firewalls/1e7bb4c2-7dbd-4ad4-a4b6-a6d6b8e0b0a1/rules",
         {"ip_type": "v4", "protocol": "tcp", "port": "80", "subnet": "0.0.0.0", "subnet_size": 0}),
        ("DELETE", f"/firewalls/1e7bb4c2-7dbd-4ad4-a4b6-a6d6b8e0b0a1/rules/{rule['id']}", None),
        ("POST", "/ssh-keys", {"name": "ci", "ssh_key": "ssh-ed25519 AAAA"}),
        ("DELETE", f"/ssh-keys/{key['id']}", None),
    ]
    with pytest.raises(ValueError, match="no power change"):
        api.power("destroy", "cb676a46-66fd-4dfb-b839-443f2e6c0b60")


def test_a_path_parameter_is_quoted_whole():
    assert path_of("/domains/{dns-domain}/records", {"dns-domain": "a/b"}) == "/domains/a%2Fb/records"
    with pytest.raises(ValueError, match="no dns-domain given"):
        path_of("/domains/{dns-domain}/records", {"dns-domain": " "})
    with pytest.raises(ValueError, match="is not given"):
        path_of(ENDPOINTS["record_delete"][1], {"dns-domain": "example.com"})


def test_vultrs_errors_in_words_with_the_key_scrubbed():
    fake = FakeVultr(key="ANOTHERKEY")
    api = client(fake)
    with pytest.raises(RestError) as refused:
        api.account()
    words = str(refused.value)
    assert refused.value.status == 401 and refused.value.refused and refused.value.code == "401"
    assert words.startswith("GET /v2/account: HTTP 401: Invalid API token. (the API key was refused") and KEY not in words
    fake = FakeVultr()
    fake.refuse_ip = "93.184.216.34"
    with pytest.raises(RestError) as refused:
        client(fake).account()
    assert "Unauthorized IP address: 93.184.216.34" in str(refused.value) and IP_REFUSED in str(refused.value)
    fake = FakeVultr()
    fake.fail[("GET", "/blocks")] = (403, f"Forbidden for {KEY}")  # a key in an answer's words is scrubbed too
    with pytest.raises(RestError) as refused:
        client(fake).blocks()
    assert refused.value.status == 403 and KEY not in str(refused.value) and "permissions" in str(refused.value)


def test_a_rate_limit_is_waited_out_and_a_write_never_sent_twice_on_a_broken_connection():
    fake = FakeVultr()
    fake.limited = 1
    slept = []
    api = client(fake, sleep=slept.append)
    assert api.account()["name"] == "Example Account" and slept == [1.0] and len(fake.requests) == 2
    sent = []

    def broken(method, url, headers, body, timeout):
        sent.append(method)
        raise ConnectionError("reset by peer")
    with pytest.raises(RestError, match="ConnectionError: reset by peer"):
        client(broken).power("reboot", "cb676a46-66fd-4dfb-b839-443f2e6c0b60")
    assert sent == ["POST"]  # a write that may have been done: once


def test_the_pace_keeps_ten_requests_a_second_at_most():
    fake = FakeVultr()
    t = [100.0]
    slept = []

    def sleep(s):
        slept.append(round(s, 3))
        t[0] += s
    api = VultrApi(KEY, transport=fake, sleep=sleep, monotonic=lambda: t[0])
    api.account()
    api.account()
    t[0] += 0.04
    api.account()
    assert slept == [0.1, 0.06]
