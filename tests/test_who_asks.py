"""Who may ask the plugin's changes (0.1.6; the independent review's PLT-H1 and the sweep of the plugins after it,
2026-11-25). Its changes are asked only from its page (PAGE_ONLY_HOOKS, as liminal-libs 1.66.0's apps/asking.py and
liminal-platform 0.34.0 read them): an instance started, rebooted or halted, a record set, added or removed, a firewall
group's rule added or removed, an SSH key added or removed, a Dynamic DNS pass and a host taken over. Another plugin's ask
is refused, and so is an ask that names no one; over HTTP the platform also asks its login whether you are at the page.
Before, any program on this PC asked them of the platform with a header anyone can send, and the API key did the rest:
the web instance halted, PostgreSQL opened to the whole internet and the rule letting SSH in removed (their second
confirmation being only an argument), the domain's address set to another and an MX record added with no second
question at all. Its reads are asked by anyone, as before. Asked through the library's own App (its ask names who asks as
the platform's does), over the stand-in Vultr: nothing reaches Vultr or the network."""
from __future__ import annotations

import pytest

pytest.importorskip("liminal_libs.apps.asking", reason="no hook is asked only from its page before liminal-libs 1.66.0")

from conftest import DB, G_LONE, G_WEB, HOME, WEB, FakeVultr, public_key, settings_of  # noqa: E402 - after the skip, as each
from liminal_libs import internal  # noqa: E402
from liminal_libs.apps import App, EnvironmentLogin, asking  # noqa: E402
from liminal_libs.machines.plugin import MachinePlugin  # noqa: E402
from plugin_platform_vultr import MACHINE  # noqa: E402

CHANGES = ("start", "reboot", "halt", "set_record", "add_record", "remove_record", "add_rule", "remove_rule", "add_key",
           "remove_key", "ddns_update", "ddns_take_over")
READS = ("present", "status", "refresh", "balance", "servers", "domains", "records", "firewalls", "ssh_keys")
HOSTS = "@.example.net, home.example.com"  # Dynamic DNS's: one with no record yet, one holding another address
APEX, SPF, HOME_A = (f"a0a0a0a0-0000-4000-8000-00000000000{n}" for n in (1, 4, 6))  # example.com's records, by their IDs
LAPTOP = FakeVultr().keys[0]["id"]  # the account's one SSH key
ASKED = {  # each change as another program worded it: the hook's arguments, a second confirmation said where it has one
    "start": (DB, "db-1"),
    "reboot": (WEB, "web-1", True),  # a hard restart, "accepted"
    "halt": (WEB, "web-1", True),  # the web instance powered off, "accepted"
    "set_record": ("example.com", "@", "A", "198.51.100.99", None, False),  # the domain's own address, set to another
    "add_record": ("example.com", "@", "MX", "mail.example.org", None, 1),  # the domain's mail, to another server first
    "remove_record": ("example.com", SPF, "@", "TXT", '"v=spf1 include:_spf.protonmail.ch ~all"'),
    "add_rule": (G_LONE, "v4", "tcp", "5432", "0.0.0.0", 0, "", True),  # PostgreSQL, to the whole internet
    "remove_rule": (G_WEB, "1", "TCP", "22", "198.51.100.0/24", True),  # the only rule letting SSH in to web-1
    "add_key": ("another", public_key(2, comment="someone@else")),
    "remove_key": (LAPTOP, "laptop"),
    "ddns_update": (),
    "ddns_take_over": ("home.example.com", None, True),  # a name holding another address pointed at this network
}
SENT = [  # what the same asks send from the page, in CHANGES' order
    ("POST", f"/instances/{DB}/start"), ("POST", f"/instances/{WEB}/reboot"), ("POST", f"/instances/{WEB}/halt"),
    ("PATCH", f"/domains/example.com/records/{APEX}"), ("POST", "/domains/example.com/records"),
    ("DELETE", f"/domains/example.com/records/{SPF}"), ("POST", f"/firewalls/{G_LONE}/rules"),
    ("DELETE", f"/firewalls/{G_WEB}/rules/1"), ("POST", "/ssh-keys"), ("DELETE", f"/ssh-keys/{LAPTOP}"),
    ("POST", "/domains/example.net/records"),  # Update DNS now: example.net made, home.example.com left as it is
    ("PATCH", f"/domains/example.com/records/{HOME_A}"),  # home.example.com taken over
]


class Neighbour(MachinePlugin):
    """Another plugin of the platform, asking Vultr's through its app as any plugin may (a container plugin, or the MCP
    plugin for a local agent)."""

    name, title = "neighbour", "Neighbour"

    def wants(self, hook, *args):
        """Not a hook: one of Vultr's asked through the app."""
        return self.app.ask("vultr", hook, *args)


class Platform(App):
    """The library's App asking as the platform does: from its page's route, the page named in so many words, or from
    its own code, no one named. It holds the plugin as the platform's one-shot commands do (`once`): the plugin's
    background reads and Dynamic DNS passes are not started, so every request the stand-in sees is an ask's."""

    NAME, TITLE, ICON = "platform", "Platform", "chip"
    once = True

    def from_page(self, hook, *args):
        """As the page's route asks a hook."""
        with asking.asking(asking.PAGE):
            return self.ask("vultr", hook, *args)

    def on_its_own(self, hook, *args):
        """As the app's own code asks a hook."""
        return self.ask("vultr", hook, *args)


@pytest.fixture
def attached(made):
    """The plugin over the stand-in Vultr, attached with another plugin to an app whose login holds its settings (the API
    key and two Dynamic DNS hosts); let go after."""
    plugin, fake = made()
    neighbour = Neighbour()
    app = Platform(log=lambda m: None, login=EnvironmentLogin(env=settings_of(VULTR_DDNS_HOSTS=HOSTS)))
    app.attach(plugin)
    app.attach(neighbour)
    yield app, plugin, neighbour, fake
    app.detach(neighbour.name)
    app.detach(plugin.name)


def test_its_changes_are_said_to_be_asked_only_from_its_page_and_its_reads_by_anyone():
    assert set(internal.page_only(MACHINE)) == set(CHANGES)  # what the platform reads
    assert internal.plugin_only(MACHINE) == ()
    assert internal.problems(MACHINE) == []  # each a hook of its own, and someone may ask it
    assert set(CHANGES) | set(READS) == set(MACHINE.interface()["hooks"]) and set(ASKED) == set(CHANGES)
    for hook in CHANGES:
        assert asking.refusal(MACHINE, hook, asking.PAGE) == ""
        assert asking.refusal(MACHINE, hook, "neighbour") == (f"vultr's {hook} is asked only from its page, "
                                                              "never by another plugin: neighbour asked it.")
        assert asking.refusal(MACHINE, hook, None).endswith("This ask names no asker: neither the page nor a plugin.")
    for hook in READS:
        assert {asking.refusal(MACHINE, hook, who) for who in (asking.PAGE, "neighbour", None)} == {""}


def test_another_plugin_or_no_one_asking_a_change_sends_nothing_and_its_page_does(attached):
    app, plugin, neighbour, fake = attached
    for hook in CHANGES:
        for ask in (neighbour.wants, app.on_its_own):
            with pytest.raises(asking.AskRefused, match=f"vultr's {hook} is asked only from its page"):
                ask(hook, *ASKED[hook])
    assert fake.requests == []  # nothing sent, nor read: not the read a change makes first
    assert neighbour.wants("present") is True and neighbour.wants("status")["valid"] is True  # its reads, as before
    assert [x["label"] for x in neighbour.wants("servers")][:2] == ["web-1", "db-1"]
    assert len(neighbour.wants("records", "example.com")) == 6 and app.on_its_own("refresh") is not None
    assert fake.writes() == []
    for hook in CHANGES:  # the same asks from its page: each one sent
        sent = len(fake.writes())
        assert app.from_page(hook, *ASKED[hook]) is not None
        assert len(fake.writes()) == sent + 1, hook
    assert [w[:2] for w in fake.writes()] == SENT
    assert fake.writes()[3][2]["data"] == "198.51.100.99" and fake.writes()[-1][2]["data"] == HOME


def test_its_own_code_asks_nothing_of_the_app_and_runs_as_before(attached):
    """The background's Dynamic DNS pass and the command line call the plugin's code themselves: not an ask, so no asker
    is named and none is needed."""
    app, plugin, neighbour, fake = attached
    assert asking.asker() is None
    net, home = plugin.ddns_update(force=False)["hosts"]
    assert net["ok"] is True and home["foreign"] is True
    assert [w[:2] for w in fake.writes()] == [("POST", "/domains/example.net/records")]
