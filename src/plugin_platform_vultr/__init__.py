"""Vultr for Liminal (the user, 2026-11-11: "lets roll plugins for EC2, vultr, azure and google cloud"; for the clouds,
"Free changes only"): the account through Vultr's API v2 (its balance and the charges pending, the instances with their
plan's price a month and an hour, the domains on Vultr's DNS and their records, the firewall groups and their rules, the
SSH keys, block storage, reserved IPs, and how many bare metal servers, snapshots, backups, Kubernetes clusters, load
balancers and databases it holds), and the changes that cost nothing, each confirmed on the platform's page: an instance
started, or rebooted or halted (each asked twice); a DNS record set (an A, AAAA or CNAME replacing the host's records
of its type, asked again before any other goes), added beside the others, or removed; a firewall rule added or removed (a
risky one asked twice); an SSH key added or removed. Dynamic DNS keeps hosts at this network's public IPv4 address
through Vultr's DNS, changing only what is its own: a host it made, one already pointing here, one you took over on the
page (liminal-libs 1.49.2's Keeper; 0.1.1, after an audit). Nothing that starts a charge: no instance, volume,
snapshot, backup or reserved IP is made, nothing resized, restored or destroyed. A stopped instance still bills: Vultr's
docs say stopping an instance does not halt billing, only destroying it does.

Its settings are pairs asked of the login of the app it is attached to (settings.py: VULTR_API_KEY, VULTR_DDNS_HOSTS,
VULTR_DDNS_MINUTES), never a file of its own. A Vultr API key answers only from the addresses its Access Control allows
(Vultr's console: Account > API > Access Control). While attached to the platform app, and set up, it reads the account
every quarter of an hour and checks the Dynamic DNS hosts every few minutes, in a thread of its own; attached by any other
app (the charts app run alone), not set up, or detached, nothing of it runs. Its
status is what was read last (no request is made to answer it): the platform's page draws its tables, its actions
(Refresh, Update DNS now) and its forms.

    python -m plugin_platform_vultr status | account | servers | domains | records DOMAIN | firewalls | keys | ddns [--now]
        | power NAME on|off|reboot | set DOMAIN NAME TYPE DATA [--ttl N] | add DOMAIN NAME TYPE DATA [--ttl N] [--priority N]
        | remove DOMAIN NAME TYPE [DATA]
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

from liminal_libs.machines import ddns as keeping
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.machines.rest import RestError

from . import records as zones
from . import rules as walls
from . import settings as settings_mod
from . import sshkeys
from .api import COUNTED, RATE, VultrApi
from .card import APIS, VULTR_API
from .records import TYPES, Refusal
from .settings import ACCESS_CONTROL, API_KEY, CONSOLE_API, DDNS_HOSTS, KEYS, NAMES, WHERE_KEY, Config

__version__ = "0.1.1"
REFRESH_S = 900.0  # the account read again at most this often while attached (or by Refresh)
CONFIG_S = 30.0  # the settings asked of the login again after this long
RETRY_S = 900.0  # a read that failed is taken as untried after this long while detached: attached again, it is tried again
PLANS_KEEP_S = 6 * 3600.0  # the plans (the prices) read again after this long
REGIONS_KEEP_S = 86400.0  # the regions read again after this long
UNKNOWN_RETRY_S = 3600.0  # a plan or a region not in the list read again for it at most this often
ZONES_MAX = 25  # the domains whose records a refresh reads (the rest: `records DOMAIN`)
GROUPS_MAX = 25  # the firewall groups whose rules a refresh reads
DDNS_TTL = 300  # the TTL of an A record Dynamic DNS makes (the reference's examples' 300 s)
ACCEPT_HALT = "accept_halt"  # the halt's argument accepting it (Refusal's accept): the page's second confirmation
ACCEPT_REBOOT = "accept_reboot"  # the reboot's (a hard reboot: asked twice, as a halt is)
ACCEPT_RISK = walls.ACCEPT  # a risky firewall rule change's
ACCEPT_REPLACE = "accept_replace"  # a record set removing the host's other records of its type
DIR_VAR = "LIMINAL_PLATFORM_DIR"  # the platform's own folder: Dynamic DNS's state goes under it
TRANSIENT_RETRY_S = 120.0  # a read that did not get through (no answer, a 429, a 5xx) tried again after this long
HIDDEN = ("kvm", "default_password")  # never handed on: an instance's console link (a token in it), a password
PUBLIC_IPV4 = (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),  # this network's address, asked of these servers
               ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))
STOPPED_BILLS = ("a stopped (halted) instance still bills: Vultr's docs say stopping an instance does not halt billing; "
                 "only destroying it ends the charges")
STOPPED_BILLS_SAID = STOPPED_BILLS[0].upper() + STOPPED_BILLS[1:]
PERMISSIONS = ("Safest: the key of a Vultr user limited to what the plugin does (Vultr's console: Users; its permissions): "
               "View Servers for the reads, Manage Servers to start, reboot and halt (Vultr's permission also lets a key "
               "destroy servers: the plugin never asks it), Manage DNS for the records and Dynamic DNS, Manage Firewall "
               "for the rules; not Deploy New Servers, Upgrade Existing Servers nor Manage Users. Vultr scopes a key by "
               "its user's permissions and by address, never by product.")
NOT_SET = (f"not set up: {API_KEY} is not set. Make the key in {WHERE_KEY}, Enable API ({CONSOLE_API}), and enter it in "
           f"the plugin's Settings…; {ACCESS_CONTROL}, so add this network's address there. {PERMISSIONS}")
HALT_WORDS = ("Halting powers {label} off at once. Vultr's API has no other way to power an instance off, and Vultr's docs "
              "differ on how cleanly a halt stops its system (a VX1 guide calls a stop a graceful shutdown; the CLI calls "
              "a bare metal halt a forced power-off): anything not saved on it may be lost, so shut the system down from "
              "inside it first to be sure. It still bills while it is off: only destroying it ends the charges.")
REBOOT_WORDS = ("Vultr's docs call a restart a hard reboot: its running processes are stopped, not shut down, so unsaved "
                "work in them is lost; files on disk stay.")
REBOOT_ACCEPT_WORDS = ("Rebooting restarts {label} at once, and it is a hard restart: Vultr's docs call a restart a hard "
                       "reboot, its running processes stopped, not shut down, so anything not saved on it may be lost (its "
                       "files on disk stay). Save the work, or restart the system from inside it, to be sure.")
START_WORDS = ("Starting it adds nothing to its charge: Vultr bills an instance hourly from its deployment until it is "
               "destroyed, running or stopped.")
ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
REFUSED_IP = re.compile(r"Unauthorized IP address: ([0-9A-Fa-f:.]+)")  # Vultr's refusal names the address it saw


def when(t: float | None) -> str:
    return "–" if not t else time.strftime("%b %d %H:%M", time.localtime(t))


def plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def cell(text, sub: str | None = None):
    return {"text": text, "sub": sub} if sub else text


def money(value, hourly: bool = False) -> str:
    """Dollars as Vultr gives them (its prices are US dollars): $5.00, -$100.55, an hour's to the tenth of a cent."""
    try:
        x = float(value)
    except (TypeError, ValueError):
        return "–"
    if hourly:
        s = f"{abs(x):,.4f}".rstrip("0")
        s = s if len(s.split(".")[1]) >= 2 else f"{abs(x):,.2f}"
    else:
        s = f"{abs(x):,.2f}"
    return ("-$" if x < 0 else "$") + s


def day(text) -> str:
    """An ISO time as its day (2020-10-10)."""
    t = str(text or "").strip()
    return t[:10] if re.match(r"^\d{4}-\d{2}-\d{2}", t) else (t or "–")


def name_of(inst: dict) -> str:
    """What the page calls an instance: its label, else its hostname, else its ID."""
    return str(inst.get("label") or inst.get("hostname") or inst.get("id") or "")


def an_id(value, what: str) -> str:
    t = str(value if value is not None else "").strip()
    if not ID.match(t):
        raise ValueError(f"{t!r} is not {what}'s ID")
    return t


def platform_dir() -> Path:
    """The platform's own folder (LIMINAL_PLATFORM_DIR, else the data folder's platform/)."""
    named = (os.environ.get(DIR_VAR) or "").strip()
    if named:
        return Path(named).expanduser()
    from liminal_libs import layout

    return layout.data_dir() / "platform"


def public_view(inst: dict) -> dict:
    """An instance as the plugin hands it on: without its console link (a token in its query) nor a password."""
    return {k: v for k, v in inst.items() if k not in HIDDEN}


def transient(e: Exception) -> bool:
    """A trouble that is no refusal: no answer came back, Vultr's rate limit, Vultr's own failure (tried again soon; the
    plugin stays valid)."""
    status = getattr(e, "status", None)
    return isinstance(status, int) and (status == 0 or status == 429 or status >= 500)


class _Runtime:
    """What the plugin read and holds, shared by its copies (the registry's with_ makes them)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.config: tuple[float, Config] | None = None
        self.api: tuple[str, VultrApi] | None = None
        self.read: dict[str, object] = {}  # account, instances, domains, groups, keys, blocks, reserved: as read
        self.why: dict[str, str] = {}  # a part not read, and why
        self.zones: dict[str, tuple | str] = {}  # by domain: its records as read, or why not
        self.rules: dict[str, tuple | str] = {}  # by firewall group ID: its rules as read, or why not
        self.counts: dict[str, int | str] = {}  # the other kinds: how many, or why not
        self.plans: dict[str, dict] = {}
        self.plans_at: float | None = None
        self.plans_tried: float | None = None
        self.regions: dict[str, dict] = {}
        self.regions_at: float | None = None
        self.regions_tried: float | None = None
        self.notes: dict[str, str] = {}  # by instance ID: a power change asked, in words
        self.refreshed_at: float | None = None
        self.api_ok: bool | None = None  # the last refresh's outcome (None: none yet)
        self.api_error = ""
        self.api_error_at: float | None = None
        self.api_print = ""  # the settings that outcome is of
        self.trouble = ""  # the last read that did not get through (no refusal: tried again soon), and when
        self.trouble_at: float | None = None
        self.ctx = threading.local()  # the worker thread's: its stop event (config() and client() refuse once it is set)
        self.keeper: keeping.Keeper | None = None
        self.ddns_print = ""
        self.ddns_at: float | None = None
        self.worker: threading.Thread | None = None
        self.stop: threading.Event | None = None
        self.wake = threading.Event()
        self.refreshing = threading.Lock()


class VultrPlugin(MachinePlugin):
    """Vultr: the account's parts through its API and the free changes; reading in the background while attached."""

    name = "vultr"
    title = "Vultr"
    about = ("Your Vultr account through Vultr's API: its balance and charges, instances with their prices, domains and "
             "records, firewall groups and rules, SSH keys, block storage, reserved IPs; free changes only, each confirmed; "
             "Dynamic DNS through Vultr's DNS")
    api = "2.2"
    order = 762
    ICON = "vultr"  # Vultr's V (liminal-libs 1.49.0's icons.js)
    HOOKS = (*MachinePlugin.HOOKS, "refresh", "balance", "servers", "domains", "records", "firewalls", "ssh_keys",
             "start", "reboot", "halt", "set_record", "add_record", "remove_record", "add_rule", "remove_rule", "add_key",
             "remove_key", "ddns_update", "ddns_take_over")
    keys = KEYS
    signup = CONSOLE_API
    limits = f"Vultr's API: {RATE} (429 and Retry-After beyond); the plugin keeps to ten a second"
    apis = APIS

    def __init__(self, transport=None, public=None, clock=None, sleep=None, gap: float | None = None,
                 folder: Path | None = None):
        self._transport = transport  # RestClient's (method, url, headers, body, timeout) -> (status, headers, body): a test's
        self._public = public  # () -> (address, whose): a test's; else this network's address asked of PUBLIC_IPV4
        self._folder = Path(folder) if folder is not None else None  # its own folder (a test's): Dynamic DNS's state
        self._clock = clock or time.time
        self._sleep = sleep or time.sleep
        self._gap = gap
        self._rt = _Runtime()

    # -- the settings, the API, the keeper -----------------------------------------------------------------------------------
    def config(self, fresh: bool = False) -> Config:
        """The settings, asked of the login (the attached app's, else the environment's); kept CONFIG_S. In the
        background's thread once it was told to stop (the plugin detached): refused, nothing read."""
        stop = getattr(self._rt.ctx, "stop", None)
        if stop is not None and stop.is_set():
            raise RuntimeError("the plugin was detached: nothing more is read or sent")
        now = time.monotonic()
        with self._rt.lock:
            kept = self._rt.config
        if kept is not None and not fresh and now - kept[0] < CONFIG_S:
            return kept[1]
        cfg = settings_mod.read(self.login)
        with self._rt.lock:
            self._rt.config = (now, cfg)
        return cfg

    def settings_changed(self) -> None:
        """Its settings were just entered (the platform's Settings…, kept through its login): read anew at once; the
        background started now if the platform holds it and it is set up now, or woken."""
        with self._rt.lock:
            self._rt.config = None
        self._maybe_start()
        self._rt.wake.set()

    def client(self) -> VultrApi:
        """The API with the key as it is set (ValueError when it is not)."""
        cfg = self.config()
        if not cfg.api_ready:
            raise ValueError(f"the API is not set up: {API_KEY} is not set")
        with self._rt.lock:
            held = self._rt.api
        if held is not None and held[0] == cfg.api_print:
            return held[1]
        made = VultrApi(cfg.api_key, transport=self._transport, clock=self._clock, sleep=self._sleep,
                        **({"gap": self._gap} if self._gap is not None else {}))
        with self._rt.lock:
            self._rt.api = (cfg.api_print, made)
        return made

    def ddns_file(self) -> Path:
        """Where Dynamic DNS keeps what is its own and what it was let take over: the platform's folder's vultr/ddns.json."""
        return (self._folder if self._folder is not None else platform_dir() / self.name) / "ddns.json"

    def keeper(self) -> keeping.Keeper:
        """Dynamic DNS's keeper: a host's A record read and set through Vultr's DNS, only where it is its own."""
        with self._rt.lock:
            if self._rt.keeper is None:
                self._rt.keeper = keeping.Keeper(read=self._ddns_read, write=self._ddns_write, servers=PUBLIC_IPV4,
                                                 public=self._public, clock=self._clock, state=self.ddns_file())
            return self._rt.keeper

    def known(self) -> list[str]:
        """The account's domains on Vultr's DNS, as last read."""
        with self._rt.lock:
            return [str(d.get("domain")) for d in (self._rt.read.get("domains") or []) if d.get("domain")]

    # -- the hooks: reading ----------------------------------------------------------------------------------------------------
    def present(self) -> bool:
        """Whether anything of it is set."""
        return bool(self.config().present)

    def refresh(self) -> dict:
        """The account read again now (what the status shows until the next)."""
        cfg = self.config(fresh=True)
        if not cfg.api_ready:
            raise ValueError(f"the API is not set up: {API_KEY} is not set")
        if not self._rt.refreshing.acquire(timeout=120):
            raise RuntimeError("a refresh is under way")
        try:
            return self._refresh(cfg)
        finally:
            self._rt.refreshing.release()

    def _refresh(self, cfg: Config, api: VultrApi | None = None) -> dict:
        now = self._clock()
        got: dict[str, object] = {}
        why: dict[str, str] = {}

        def stopped() -> None:
            if self._stopping():  # the background's refresh, the plugin detached meanwhile: nothing more read
                raise RuntimeError("the plugin was detached: the refresh ends here")

        def part(name, read):
            stopped()
            try:
                got[name] = read()
            except RestError as e:
                if e.status == 401 or (e.status == 0 and not got):  # the key refused, or Vultr not reached at all
                    raise
                why[name] = str(e)

        def each(found, key, read, most, words):
            out: dict[str, tuple | str] = {}
            for i, item in enumerate(found or []):
                stopped()
                k = str(item.get(key) or "")
                if not k:
                    continue
                if i >= most:
                    out[k] = words(k)
                    continue
                try:
                    out[k] = read(k)
                except RestError as e:
                    if e.status == 401:
                        raise
                    out[k] = str(e)
            return out

        try:
            api = api or self.client()
            part("account", api.account)
            part("instances", api.instances)
            self._prices(api, got.get("instances") or [], now)
            part("domains", api.domains)
            read_zones = each(got.get("domains"), "domain", lambda d: zones.records_of(api.records(d), d), ZONES_MAX,
                              lambda d: f"not read with the rest (more than {ZONES_MAX} domains): records {d}")
            part("groups", api.firewalls)
            read_rules = each(got.get("groups"), "id", lambda g: walls.rules_of(api.rules(g)), GROUPS_MAX,
                              lambda g: f"not read with the rest (more than {GROUPS_MAX} groups)")
            part("keys", api.ssh_keys)
            part("blocks", api.blocks)
            part("reserved", api.reserved_ips)
            counts: dict[str, int | str] = {}
            for name, items, title, paged in COUNTED:
                stopped()
                try:
                    counts[title] = api.count(name, items, paged)
                except RestError as e:
                    if e.status == 401:
                        raise
                    counts[title] = str(e)
            if not got:
                raise RestError("every part was refused: " + "; ".join(f"{k}: {v}" for k, v in why.items()))
        except (RestError, ValueError) as e:
            with self._rt.lock:
                if transient(e):  # no answer, the rate limit, Vultr's own failure: no refusal of the key (tried again soon)
                    self._rt.trouble, self._rt.trouble_at = str(e), now
                else:
                    self._rt.api_ok, self._rt.api_error, self._rt.api_error_at, self._rt.api_print = False, str(e), now, cfg.api_print
            raise
        with self._rt.lock:
            rt = self._rt
            rt.read, rt.why, rt.zones, rt.rules, rt.counts, rt.refreshed_at = got, why, read_zones, read_rules, counts, now
            rt.notes = {}
            rt.api_ok, rt.api_error, rt.api_error_at, rt.api_print = True, "", None, cfg.api_print
            rt.trouble, rt.trouble_at = "", None
        return {"instances": len(got.get("instances") or []), "domains": len(got.get("domains") or []),
                "groups": len(got.get("groups") or []), "notRead": sorted(why), "refreshedAt": when(now)}

    def _prices(self, api: VultrApi, instances: list, now: float) -> None:
        """The plans (each instance's price) and the regions (their cities), read again when old, or when an instance
        names one not among them (at most once an hour); a failure keeps what was read before."""
        with self._rt.lock:
            rt = self._rt
            plans_old = rt.plans_at is None or now - rt.plans_at >= PLANS_KEEP_S
            regions_old = rt.regions_at is None or now - rt.regions_at >= REGIONS_KEEP_S
            plan_new = any(i.get("plan") and i.get("plan") not in rt.plans for i in instances) and \
                (rt.plans_tried is None or now - rt.plans_tried >= UNKNOWN_RETRY_S)
            region_new = any(i.get("region") and i.get("region") not in rt.regions for i in instances) and \
                (rt.regions_tried is None or now - rt.regions_tried >= UNKNOWN_RETRY_S)
        if plans_old or plan_new:
            try:
                plans = {str(p.get("id")): p for p in api.plans() if p.get("id")}
                with self._rt.lock:
                    self._rt.plans, self._rt.plans_at, self._rt.plans_tried = plans, now, now
            except RestError as e:
                if e.status == 401:
                    raise
                with self._rt.lock:
                    self._rt.plans_tried = now
        if regions_old or region_new:
            try:
                regions = {str(r.get("id")): r for r in api.regions() if r.get("id")}
                with self._rt.lock:
                    self._rt.regions, self._rt.regions_at, self._rt.regions_tried = regions, now, now
            except RestError as e:
                if e.status == 401:
                    raise
                with self._rt.lock:
                    self._rt.regions_tried = now

    def balance(self) -> dict:
        """The account, read now: its name, email, the key's permissions, its balance and the charges pending (the
        contract's `account` is another thing: the plugin whose account its requests count against)."""
        found = self.client().account()
        with self._rt.lock:
            self._rt.read["account"] = found
        return found

    def servers(self) -> list[dict]:
        """The instances, read now, each with its plan's price."""
        api = self.client()
        found = api.instances()
        self._prices(api, found, self._clock())
        with self._rt.lock:
            self._rt.read["instances"] = found
        return [{**public_view(i), "price": self._price(i)} for i in found]

    def domains(self) -> list[dict]:
        """The domains on Vultr's DNS, read now."""
        found = self.client().domains()
        with self._rt.lock:
            self._rt.read["domains"] = found
        return found

    def records(self, domain: str) -> list[dict]:
        """A domain's records, read now."""
        d = zones.valid_domain(domain)
        found = zones.records_of(self.client().records(d), d)
        self._keep_zone(d, found)
        return [r.as_dict() for r in found]

    def firewalls(self) -> list[dict]:
        """The firewall groups and their rules, read now."""
        api = self.client()
        groups = api.firewalls()
        out, read = [], {}
        for g in groups:
            gid = str(g.get("id") or "")
            rules = walls.rules_of(api.rules(gid)) if gid else ()
            read[gid] = rules
            out.append({**g, "rules": [r.as_dict() for r in rules]})
        with self._rt.lock:
            self._rt.read["groups"] = groups
            self._rt.rules.update(read)
        return out

    def ssh_keys(self) -> list[dict]:
        """The account's SSH keys, read now, each with its fingerprint."""
        found = self.client().ssh_keys()
        with self._rt.lock:
            self._rt.read["keys"] = found
        return [{**k, "fingerprint": sshkeys.fingerprint(k.get("ssh_key") or "")} for k in found]

    def _keep_zone(self, domain: str, records) -> None:
        with self._rt.lock:
            self._rt.zones[domain] = tuple(records)

    # -- the hooks: the free changes ----------------------------------------------------------------------------------------------
    def start(self, instance: str, label: str = "") -> dict:
        """An instance started (it was stopped)."""
        return self._power("start", instance, label)

    def reboot(self, instance: str, label: str = "", accept_reboot: bool = False) -> dict:
        """An instance rebooted (it was running): a hard reboot, Vultr's docs say, so refused until accepted a second time
        (accept_reboot), as a halt is."""
        return self._power("reboot", instance, label, accept_reboot is True)

    def halt(self, instance: str, label: str = "", accept_halt: bool = False) -> dict:
        """An instance halted (powered off; still billed): refused until accepted a second time (accept_halt)."""
        return self._power("halt", instance, label, accept_halt is True)

    def _power(self, action: str, instance: str, label: str = "", accepted: bool = False) -> dict:
        """A power change, once the instance read afresh is the one shown (`label`, needed), active and in the state the
        change is for; a reboot and a halt only once accepted a second time (`accepted`: True itself)."""
        iid = an_id(instance, "an instance")
        if not str(label or "").strip():
            raise ValueError("an instance is named by its ID and by its name as the page shows it (its label)")
        api = self.client()
        now = api.instance(iid)
        if not now:
            raise Refusal(f"this account has no instance {iid}")
        shown = name_of(now)
        if label != shown:
            raise Refusal(f"instance {iid} is {shown} now, not {label}: nothing asked (the page shows it as read now)")
        power, status = str(now.get("power_status") or ""), str(now.get("status") or "")
        if status != "active":
            raise Refusal(f"{shown} is {status or 'not active'}: a power change waits until it is active")
        if action == "start" and power == "running":
            raise Refusal(f"{shown} is running already")
        if action in ("reboot", "halt") and power != "running":
            raise Refusal(f"{shown} is {power or 'not running'}: there is nothing to {action}")
        if action == "halt" and accepted is not True:
            raise Refusal(f"{shown} is halted only once that is accepted a second time ({ACCEPT_HALT}). "
                          + HALT_WORDS.format(label=shown), accept=ACCEPT_HALT)
        if action == "reboot" and accepted is not True:
            raise Refusal(f"{shown} is rebooted only once that is accepted a second time ({ACCEPT_REBOOT}). "
                          + REBOOT_ACCEPT_WORDS.format(label=shown), accept=ACCEPT_REBOOT)
        api.power(action, iid)
        said = {"start": "started", "reboot": "rebooted", "halt": "halted"}[action]
        lines = [f"asked of Vultr at {time.strftime('%H:%M:%S', time.localtime(self._clock()))}: POST /instances/{iid}/{action}"]
        try:
            after = api.instance(iid)
        except RestError as e:
            after = {}
            lines.append(f"its state could not be read after it: {e}")
        if after:
            lines.append(f"Vultr says now: {after.get('power_status') or '–'} ({after.get('status') or '–'}, "
                         f"{after.get('server_status') or '–'}); the next refresh shows how it ends")
            self._keep_instance(after)
        if action == "halt":
            lines.append(STOPPED_BILLS_SAID)
        with self._rt.lock:
            self._rt.notes[iid] = f"{said} at {time.strftime('%H:%M', time.localtime(self._clock()))}"
        return {"said": f"{shown} {said}", "ok": True, "instance": iid, "lines": lines,
                "power": str((after or now).get("power_status") or "")}

    def _keep_instance(self, inst: dict) -> None:
        with self._rt.lock:
            found = list(self._rt.read.get("instances") or [])
            for i, x in enumerate(found):
                if x.get("id") == inst.get("id"):
                    found[i] = inst
                    self._rt.read["instances"] = found
                    return

    def _known_domain(self, domain: str) -> str:
        """`domain` when it is on the account's DNS (the domains as read, else read now); Refusal otherwise."""
        d = zones.valid_domain(domain)
        if d not in self.known():
            self.domains()
        if d not in self.known():
            raise Refusal(f"{d} is not on this account's Vultr DNS")
        return d

    def set_record(self, domain: str, name: str, rtype: str, data: str, ttl=None, accept_replace: bool = False) -> dict:
        """A record set in `domain` (records.plan_set: an A, AAAA or CNAME), replacing the host's records of its type: one
        updated, any others removed only once that is accepted a second time (accept_replace, True itself); every other
        record of the domain kept; the zone read before and after."""
        d = self._known_domain(domain)
        api = self.client()
        held = zones.records_of(api.records(d), d)
        plan = zones.plan_set(held, d, name, rtype, data, ttl=ttl)
        if plan.removes and accept_replace is not True:
            host = zones.relative(name, d) or "@"
            raise Refusal(f"{host} holds {len(plan.removes) + 1} {str(rtype).strip().upper()} records: setting it to "
                          f"{data} replaces them all, so {', '.join(r.data for r in plan.removes)} "
                          f"{'is' if len(plan.removes) == 1 else 'are'} removed. Nothing was sent: it is done only once "
                          f"that is accepted ({ACCEPT_REPLACE}); to keep them, Add a record… adds one beside them",
                          accept=ACCEPT_REPLACE)
        return self._applied(d, plan, held, name, rtype, api)

    def add_record(self, domain: str, name: str, rtype: str, data: str, ttl=None, priority=None) -> dict:
        """A record added to `domain` beside the host's others (records.plan_add: every type but CNAME), every other
        record kept; the zone read before and after."""
        d = self._known_domain(domain)
        api = self.client()
        held = zones.records_of(api.records(d), d)
        plan = zones.plan_add(held, d, name, rtype, data, ttl=ttl, priority=priority)
        return self._applied(d, plan, held, name, rtype, api)

    def _applied(self, d: str, plan, held, name: str, rtype: str, api: VultrApi) -> dict:
        report, after = zones.apply(api, plan)
        self._keep_zone(d, after if after is not None else held)
        host = zones.relative(name, d)
        if plan.ops and str(rtype).strip().upper() == "A" and self._ddns_host(d, host):
            report["lines"].append(f"{host or '@'}.{d} is one of {DDNS_HOSTS}: Dynamic DNS keeps it only while it points "
                                   "at this network's address alone, or once you take it over")
        return report

    def remove_record(self, domain: str, record: str, name: str = "", rtype: str = "", data: str = "") -> dict:
        """A record removed from `domain` by its ID, once it is checked to be the one shown (`name`, `rtype` and `data`,
        all three needed)."""
        d = self._known_domain(domain)
        api = self.client()
        held = zones.records_of(api.records(d), d)
        plan = zones.plan_remove(held, d, record, name, rtype, data)
        report, after = zones.apply(api, plan)
        self._keep_zone(d, after if after is not None else tuple(r for r in held if r.id != str(record)))
        return report

    def _group(self, api: VultrApi, group: str) -> tuple[str, dict, tuple, int]:
        """A firewall group read afresh: its ID, itself, its rules, how many instances are linked to it."""
        gid = an_id(group, "a firewall group")
        g = api.firewall(gid)
        if not g:
            raise Refusal(f"this account has no firewall group {gid}")
        held = walls.rules_of(api.rules(gid))
        with self._rt.lock:
            linked = sum(1 for i in (self._rt.read.get("instances") or []) if str(i.get("firewall_group_id") or "") == gid)
        try:
            linked = max(linked, int(g.get("instance_count") or 0))
        except (TypeError, ValueError):
            pass
        return gid, g, held, linked

    def add_rule(self, group: str, ip_type: str, protocol: str, port, subnet: str, subnet_size, notes: str = "",
                 accept_risk: bool = False) -> dict:
        """A rule added to a firewall group; a risky one (rules.py) refused until accepted a second time (accept_risk)."""
        api = self.client()
        body = walls.checked(ip_type, protocol, port, subnet, subnet_size, notes)
        gid, g, held, linked = self._group(api, group)
        new = walls.as_rule(body)
        there = next((r for r in held if walls.same_rule(new, r)), None)
        if there is not None:
            raise Refusal(f"{there.said()} is in the group already (rule {there.id}): nothing added")
        most = g.get("max_rule_count")
        if isinstance(most, int) and most and len(held) >= most:
            raise Refusal(f"the group holds {len(held)} rules, its most ({most}): remove one first")
        risk = walls.risk_of_adding(new, held, linked)
        walls.refuse_risky(risk, accept_risk)
        made = api.create_rule(gid, body)
        title = str(g.get("description") or gid)
        lines = [f"sent: POST /firewalls/{gid}/rules " + ", ".join(f"{k} {v}" for k, v in body.items())]
        if risk:
            lines.append(f"accepted as risky: {risk}")
        report = {"said": f"added {new.said()} to {title}", "group": gid, "rule": str(made.get("id") or ""), "lines": lines}
        try:
            after = walls.rules_of(api.rules(gid))
        except RestError as e:
            report.update(ok=None)
            report["lines"].append(f"the group could not be read back to check it: {e}")
            return report
        with self._rt.lock:
            self._rt.rules[gid] = after
        report["ok"] = any(walls.same_rule(new, r) for r in after)
        report["lines"].append(f"read back: {'the rule is there' if report['ok'] else 'the rule is not there'} "
                               f"({plural(len(after), 'rule')})")
        return report

    def remove_rule(self, group: str, rule: str, protocol: str = "", port: str = "", source: str = "",
                    accept_risk: bool = False) -> dict:
        """A rule removed from a firewall group by its ID, once it is checked to be the one shown; a risky one (rules.py)
        refused until accepted a second time (accept_risk)."""
        api = self.client()
        gid, g, held, linked = self._group(api, group)
        rid = str(rule if rule is not None else "").strip()
        found = next((r for r in held if r.id == rid), None)
        if found is None:
            raise Refusal(f"the group holds no rule {rid} any more: nothing removed (the page shows it as read now)")
        if any(x in (None, "") for x in (protocol, port, source)):
            raise ValueError("a rule is removed by its ID with its protocol, port and source as shown (all three)")
        differs = [w for w, given, now in (("protocol", protocol, found.protocol.upper()), ("port", port, found.port_words()),
                                           ("from", source, found.from_words()))
                   if str(given).strip().lower() != now.lower()]
        if differs:
            raise Refusal(f"rule {rid} is {found.said()} now, not the one shown ({', '.join(differs)} differ): nothing removed")
        risk = walls.risk_of_removing(found, held, linked)
        walls.refuse_risky(risk, accept_risk)
        api.delete_rule(gid, found.id)
        title = str(g.get("description") or gid)
        report = {"said": f"removed {found.said()} from {title}", "group": gid, "rule": found.id,
                  "lines": [f"sent: DELETE /firewalls/{gid}/rules/{found.id}"] + ([f"accepted as risky: {risk}"] if risk else [])}
        try:
            after = walls.rules_of(api.rules(gid))
        except RestError as e:
            report.update(ok=None)
            report["lines"].append(f"the group could not be read back to check it: {e}")
            return report
        with self._rt.lock:
            self._rt.rules[gid] = after
        report["ok"] = all(r.id != found.id for r in after)
        report["lines"].append(f"read back: {'it is gone' if report['ok'] else 'it is still there'} ({plural(len(after), 'rule')})")
        return report

    def add_key(self, name: str, ssh_key: str) -> dict:
        """An SSH key added to the account (for instances deployed from now on: running ones keep theirs)."""
        n, key = sshkeys.checked(name, ssh_key)
        api = self.client()
        held = api.ssh_keys()
        there = next((k for k in held if sshkeys.same_key(k.get("ssh_key") or "", key)), None)
        if there is not None:
            raise Refusal(f"this key is in the account already, as {there.get('name') or there.get('id')}: nothing added")
        made = api.create_key(n, key)
        report = {"said": f"added the key {n} ({sshkeys.fingerprint(key)})", "key": str(made.get("id") or ""),
                  "lines": ["Vultr copies a key to an instance when it is deployed: no instance running changes"]}
        return self._keys_after(api, report, lambda found: any(sshkeys.same_key(k.get("ssh_key") or "", key) for k in found))

    def remove_key(self, key: str, name: str = "") -> dict:
        """An SSH key removed from the account by its ID, once it is checked to be the one shown (`name`, needed)."""
        kid = an_id(key, "an SSH key")
        if not str(name or "").strip():
            raise ValueError("an SSH key is removed by its ID with its name as shown")
        api = self.client()
        held = api.ssh_keys()
        found = next((k for k in held if str(k.get("id")) == kid), None)
        if found is None:
            raise Refusal(f"the account holds no SSH key {kid} any more: nothing removed")
        if name != str(found.get("name") or ""):
            raise Refusal(f"SSH key {kid} is named {found.get('name')} now, not {name}: nothing removed")
        api.delete_key(kid)
        report = {"said": f"removed the key {found.get('name') or kid}", "key": kid,
                  "lines": ["the instances deployed with it keep it: Vultr copied it to them then"]}
        return self._keys_after(api, report, lambda after: all(str(k.get("id")) != kid for k in after))

    def _keys_after(self, api: VultrApi, report: dict, check) -> dict:
        try:
            after = api.ssh_keys()
        except RestError as e:
            report.update(ok=None)
            report["lines"].append(f"the keys could not be read back to check it: {e}")
            return report
        with self._rt.lock:
            self._rt.read["keys"] = after
        report["ok"] = bool(check(after))
        report["lines"].append(f"read back: {'as asked' if report['ok'] else 'not as asked'} ({plural(len(after), 'key')})")
        return report

    # -- Dynamic DNS, through Vultr's DNS ------------------------------------------------------------------------------------
    def _ddns_host(self, domain: str, host: str) -> bool:
        cfg = self.config()
        if not cfg.ddns_ready:
            return False
        hosts, _ = keeping.hosts_of(cfg.hosts, self.known())
        return any(h.zone == domain and (h.name if h.name != "@" else "") == host for h in hosts)

    @staticmethod
    def _at(h: keeping.Host) -> str:
        return "" if h.name == "@" else h.name

    def _held(self, h: keeping.Host, api: VultrApi | None = None) -> list:
        """The host's records as Vultr's DNS holds them now (a CNAME there refused: an A record cannot stand beside it)."""
        rel = self._at(h)
        api = api or self.client()
        found = [r for r in zones.records_of(api.records(h.zone, name=rel), h.zone) if r.name == rel]
        if any(r.type == "CNAME" for r in found):
            raise ValueError(f"{h.fqdn} is a CNAME: Dynamic DNS keeps an A record, which cannot stand beside it")
        return [r for r in found if r.type == "A"]

    def _ddns_read(self, h: keeping.Host) -> list[str]:
        return [r.data for r in self._held(h)]

    def _stopping(self) -> bool:
        stop = getattr(self._rt.ctx, "stop", None)
        return stop is not None and stop.is_set()

    def _ddns_write(self, h: keeping.Host, ip: str) -> str:
        """The host's A record set to exactly `ip` (the keeper asks it only of a host that is its own or taken over): made
        where there is none, else its first updated and, for a host taken over that held several, the others removed
        (its confirmation said what it holds is dropped). The background's stop is heeded before each request."""
        api = self.client()
        held = self._held(h, api)
        if self._stopping():
            raise RuntimeError("the plugin was detached: nothing written")
        if not held:
            api.create_record(h.zone, {"name": self._at(h), "type": "A", "data": ip, "ttl": DDNS_TTL})
            return "made"
        first, rest = held[0], held[1:]
        if first.data == ip and not rest:
            return "current (nothing to send)"  # Update DNS now over a record that is right: nothing asked of Vultr
        if first.data != ip:
            api.update_record(h.zone, first.id, {"data": ip})
        for r in rest:
            if self._stopping():
                raise RuntimeError("the plugin was detached: the rest not written")
            api.delete_record(h.zone, r.id)
        return "set" + (f" (the other addresses it held dropped: {', '.join(r.data for r in rest)})" if rest else "")

    def ddns_hosts(self, cfg: Config | None = None, fetch: bool = False) -> tuple[list, list[str]]:
        """The Dynamic DNS hosts set, split against the account's domains (read now when none is known and `fetch`), and
        the entries in none of them, in words."""
        cfg = cfg or self.config()
        if fetch and cfg.api_ready and not self.known():
            try:
                self.domains()
            except RestError:
                pass  # said by each host as it is checked
        return keeping.hosts_of(cfg.hosts, self.known())

    def _let_go_removed(self, cfg: Config) -> list[str]:
        """The hosts the keeper holds (in this run, or in its state file) that are no longer in the settings, let go of:
        neither its own nor taken over any more. Their names, in order."""
        wanted = set()
        for part in cfg.hosts.replace(";", ",").replace(" ", ",").split(","):
            n = part.strip().rstrip(".").lower()
            if n:
                wanted.add(n[2:] if n.startswith("@.") else n)
        keeper = self.keeper()
        held = {s.fqdn for s in keeper.states()}
        try:
            data = json.loads(self.ddns_file().read_text(encoding="utf-8"))
            held |= {str(k).lower() for k in (data.get("own") or {})} | {str(k).lower() for k in (data.get("taken") or [])}
        except (OSError, ValueError, AttributeError):
            pass
        gone = sorted(h for h in held if h not in wanted)
        for fqdn in gone:
            keeper.let_go(fqdn)
        return gone

    def _ddns_pass(self, cfg: Config, hosts: list, force: bool = False, wait: float = 120.0, stop=None) -> list[dict]:
        self._let_go_removed(cfg)
        out = self.keeper().run_pass(hosts, force=bool(force), wait=wait, stop=stop)
        with self._rt.lock:
            self._rt.ddns_print, self._rt.ddns_at = cfg.ddns_print, self._clock()
        return out

    def ddns_update(self, force: bool = True) -> dict:
        """A Dynamic DNS pass now (the page's confirmed Update DNS now: `force`, each host that is its own set whether it
        differs or not; the command line's `ddns` without --now sets only where it differs). A host holding another
        address is left as it is (Take over… on the page). Its answer: said, lines and each host's state (`hosts`)."""
        cfg = self.config(fresh=True)
        if not cfg.ddns_ready:
            raise ValueError("Dynamic DNS is not set up: " + ("; ".join(cfg.incomplete) or f"{DDNS_HOSTS} is not set"))
        hosts, wrong = self.ddns_hosts(cfg, fetch=True)
        if not hosts:
            raise ValueError(f"no host of {DDNS_HOSTS} is in this account's Vultr DNS: " + ("; ".join(wrong) or "none set"))
        out = self._ddns_pass(cfg, hosts, force=force)
        current = sum(1 for h in out if h.get("ok"))
        return {"said": f"Dynamic DNS: {current} of {plural(len(out), 'host')} current", "ok": current == len(out),
                "lines": [f"{h['host']}: {h['result']}" for h in out] + [f"not kept: {w}" for w in wrong], "hosts": out}

    def ddns_take_over(self, host: str, holds=None) -> dict:
        """A host let be taken over (the page's Take over…, once confirmed: its confirmation named what the record holds
        and that it will point here), then a pass for it: its A record set to this network's address alone. Refused when
        it is none of the hosts set, or holds now what the page did not show (`holds`)."""
        cfg = self.config(fresh=True)
        if not cfg.ddns_ready:
            raise ValueError("Dynamic DNS is not set up: " + ("; ".join(cfg.incomplete) or f"{DDNS_HOSTS} is not set"))
        hosts, _ = self.ddns_hosts(cfg, fetch=True)
        name = str(host or "").strip().rstrip(".").lower()
        h = next((x for x in hosts if x.fqdn == name), None)
        if h is None:
            raise Refusal(f"{host} is none of {DDNS_HOSTS} in this account's Vultr DNS: nothing taken over")
        now = self._ddns_read(h)
        if holds is not None:
            shown = sorted(a.strip() for a in str(holds).split(",") if a.strip())
            if shown != sorted(now):
                raise Refusal(f"{h.fqdn} holds {', '.join(now) or 'no A record'} now, not {holds}: nothing taken over (the "
                              "page shows it as read now)")
        keeper = self.keeper()
        keeper.take_over(h.fqdn)
        out = self._ddns_pass(cfg, [h], force=False)
        st = out[0] if out else {"result": "not checked", "ok": None}
        return {"said": f"{h.fqdn} taken over: {st['result']}", "ok": st.get("ok"), "host": h.fqdn,
                "lines": [f"it held {', '.join(now) or 'no A record'}; Dynamic DNS keeps it at this network's address from "
                          "now on"]}

    # -- attached: the reading in the background ---------------------------------------------------------------------------
    def attach(self, app, login=None) -> dict:
        """Attached: its settings asked of the app's login from now on. Attached by the platform, and set up: the account
        read and the Dynamic DNS hosts checked in the background (attached by any other app, the charts app run alone,
        nothing of it runs)."""
        interface = super().attach(app, login)
        with self._rt.lock:
            self._rt.config = None
        self._maybe_start()
        return interface

    def detach(self) -> None:
        """Detached (the platform ending, the plugin disabled or not valid): the background reading ends, and a pass
        under way writes nothing more."""
        self._stop()
        super().detach()
        with self._rt.lock:
            self._rt.config = None

    @property
    def working(self) -> bool:
        with self._rt.lock:
            t = self._rt.worker
        return t is not None and t.is_alive()

    def _maybe_start(self) -> None:
        """The background started when the platform holds the plugin (its app's NAME) and it is set up."""
        if getattr(self.app, "NAME", "") != "platform" or getattr(self.app, "once", False):  # nor a one-shot command's
            return
        try:
            ready = self.config().api_ready
        except Exception:  # noqa: BLE001 - its settings not to be read: nothing started
            return
        if ready:
            self._start()

    def _start(self) -> None:
        with self._rt.lock:
            if self._rt.worker is not None and self._rt.worker.is_alive():
                return
            stop = threading.Event()
            t = threading.Thread(target=self._work, args=(stop,), name="vultr", daemon=True)
            self._rt.worker, self._rt.stop = t, stop
            self._rt.wake.clear()
        t.start()

    def _stop(self) -> None:
        with self._rt.lock:
            t, stop = self._rt.worker, self._rt.stop
            self._rt.worker = self._rt.stop = None
        if stop is not None:
            stop.set()
            self._rt.wake.set()
        if t is not None and t is not threading.current_thread():
            t.join(timeout=10)

    def _work(self, stop: threading.Event) -> None:
        """The background: the account read every REFRESH_S (a read that did not get through, again after
        TRANSIENT_RETRY_S), the Dynamic DNS hosts checked every VULTR_DDNS_MINUTES. It ends once stopped (nothing read or
        written after that: config() refuses in this thread) or once the key is no longer set."""
        self._rt.ctx.stop = stop
        next_api = next_ddns = 0.0
        while not stop.is_set():
            now = time.monotonic()
            cfg = None
            try:
                cfg = self.config()
                if not cfg.api_ready:
                    break  # not set up any more: nothing runs (settings_changed starts it again)
                if now >= next_api:
                    next_api = now + REFRESH_S
                    if self._rt.refreshing.acquire(blocking=False):  # Refresh asked meanwhile: that one is enough
                        try:
                            self._refresh(cfg)
                        except Exception as e:  # noqa: BLE001 - kept as its outcome, shown by the status
                            if transient(e):
                                next_api = now + TRANSIENT_RETRY_S
                        finally:
                            self._rt.refreshing.release()
                if cfg.ddns_ready and now >= next_ddns and not stop.is_set():
                    next_ddns = now + cfg.minutes * 60.0
                    try:
                        hosts, _ = self.ddns_hosts(cfg)
                        if hosts:
                            self._ddns_pass(cfg, hosts, force=False, wait=0.5, stop=stop)
                    except Exception:  # noqa: BLE001 - a pass under way (Update DNS now), or its trouble kept by the hosts
                        pass
            except Exception:  # noqa: BLE001 - the background never ends on a trouble; the status says it
                pass
            due = [t for t, on in ((next_api, cfg is not None and cfg.api_ready),
                                   (next_ddns, cfg is not None and cfg.ddns_ready)) if on]
            wait = min([60.0, *(t - time.monotonic() for t in due)])
            self._rt.wake.wait(max(1.0, wait))
            self._rt.wake.clear()

    # -- what it learned of its API (plugin API 2.2) ---------------------------------------------------------------------------
    def api_facts(self) -> dict:
        """What the client's answers said of Vultr's API (RestClient.facts: the requests made, the last answer, a wait
        asked) and when the account was read: from what is held, asking nothing."""
        with self._rt.lock:
            held, at, ok, error = self._rt.api, self._rt.refreshed_at, self._rt.api_ok, self._rt.api_error
            account = dict(self._rt.read.get("account") or {})
        facts = dict(held[1].rest.facts()) if held is not None else {"Requests": "none yet"}
        if "retry-after" in facts:
            facts["Last asked to wait (s)"] = facts.pop("retry-after")
        facts["Account read"] = when(at) if at else "not yet"
        if ok is False and error:
            facts["Last read failed"] = error[:200]
        if account.get("acls") is not None:
            facts["The key's permissions"] = acl_words(account.get("acls"))
        return {VULTR_API.name: facts}

    # -- what the platform's page shows --------------------------------------------------------------------------------------
    def _price(self, inst: dict) -> dict:
        """An instance's price as its plan gives it: a month and an hour, its region's where Vultr prices it apart, the
        preemptible price for a preemptible instance ({} when its plan is not known)."""
        with self._rt.lock:
            plan = self._rt.plans.get(str(inst.get("plan") or ""))
        if not plan:
            return {}
        cost = (plan.get("location_cost") or {}).get(str(inst.get("region") or "")) or plan
        tail = "_preemptible" if inst.get("preemptible") else ""
        return {"monthly": cost.get(f"monthly_cost{tail}", cost.get("monthly_cost")),
                "hourly": cost.get(f"hourly_cost{tail}", cost.get("hourly_cost")),
                "regional": cost is not plan}

    def status(self) -> dict:
        """What was read last, asking nothing of Vultr: the settings set (by name), the summary, valid (the key set and
        its last read working or untried) and why not, the facts, the tables, the actions and the forms."""
        cfg = self.config()
        if not cfg.present:
            return {"present": False, "valid": False, "why": NOT_SET, "summary": "not set up",
                    "settingsNotSet": ", ".join(NAMES), "tables": [], "actions": [], "forms": []}
        rt, now, attached = self._rt, self._clock(), self.app is not None
        with rt.lock:
            read, why = dict(rt.read), dict(rt.why)
            read_zones, read_rules, counts, notes = dict(rt.zones), dict(rt.rules), dict(rt.counts), dict(rt.notes)
            regions = dict(rt.regions)
            refreshed_at, api_ok, api_error, api_error_at = rt.refreshed_at, rt.api_ok, rt.api_error, rt.api_error_at
            trouble, trouble_at = rt.trouble, rt.trouble_at
            api_print, ddns_print, keeper = rt.api_print, rt.ddns_print, rt.keeper
        works = None
        if cfg.api_ready:
            works = api_ok if api_print == cfg.api_print else None
            if works is False and not attached and api_error_at is not None and now - api_error_at >= RETRY_S:
                works = None  # tried again once the platform attaches it
        hosts, wrong = keeping.hosts_of(cfg.hosts, self.known()) if cfg.ddns_ready else ([], [])
        if cfg.ddns_ready and not self.known():
            wrong = []  # the domains are not read yet: the hosts are split once they are
        states = {s.fqdn: s for s in (keeper.states() if keeper is not None else [])}
        failing = [f"{s.fqdn}: {s.result}" for h in hosts for s in [states.get(h.fqdn)] if s is not None and s.ok is False
                   and ddns_print == cfg.ddns_print]
        notes_words = [*([f"the last read did not get through ({when(trouble_at)}): {trouble}; tried again in a few minutes"]
                         if trouble and works is not False else []),
                       *cfg.incomplete, *cfg.problems, *wrong, *(f"Dynamic DNS: {f}" for f in failing),
                       *(f"{k} not read: {v}" for k, v in sorted(why.items()))]
        valid = cfg.api_ready and works is not False
        out: dict = {"present": True, "valid": valid,
                     "summary": self._summary(cfg, works, api_error, read, hosts, states, attached)}
        if not valid:
            if works is False:
                out["why"] = (f"the API: {api_error}. The key is made in {WHERE_KEY} ({CONSOLE_API}); {ACCESS_CONTROL}. "
                              + PERMISSIONS)
            else:
                out["why"] = ("; ".join(cfg.incomplete) + ". " if cfg.incomplete else "") + NOT_SET
        elif notes_words:
            out["problem"] = "; ".join(notes_words)
        account = read.get("account") or {}
        if account:
            out["account"] = " · ".join(str(x) for x in (account.get("name"), account.get("email")) if x)
            out["balance"] = money(account.get("balance"))
            out["pendingCharges"] = f"{money(account.get('pending_charges'))} this month, not billed yet"
            if account.get("last_payment_date"):
                out["lastPayment"] = f"{money(account.get('last_payment_amount'))} on {day(account.get('last_payment_date'))}"
            if account.get("acls") is not None:
                out["keyPermissions"] = acl_words(account.get("acls"))
        public = keeper.public if keeper is not None else None
        refused = REFUSED_IP.search(api_error or "") if works is False else None
        out["accessControl"] = ACCESS_CONTROL[0].upper() + ACCESS_CONTROL[1:] + (
            f"; this network's address: {public}" if public else "") + (
            f"; Vultr refused the address it saw, {refused.group(1)}: add it there" if refused else "")
        out["stoppedInstances"] = STOPPED_BILLS_SAID
        out["settingsSet"] = ", ".join(n for n in NAMES if n in cfg.present)
        missing = [n for n in NAMES if n not in cfg.present]
        if missing:
            out["settingsNotSet"] = ", ".join(missing)
        if refreshed_at:
            out["readAt"] = when(refreshed_at)
        with rt.lock:
            held = rt.api
        if held is not None and held[0] == cfg.api_print:
            seen = held[1].rest.seen
            out["apiRequests"] = f"{seen.requests:,} made" + (f", {seen.failed:,} failed" if seen.failed else "")
        if cfg.ddns_ready:
            out["ddnsEvery"] = f"every {cfg.minutes:g} min" + ("" if attached else ", once attached")
        out["tables"] = self._tables(cfg, read, why, read_zones, read_rules, counts, notes, regions, hosts, wrong, public)
        out["forms"] = self._forms(cfg, read, read_zones, read_rules, public) if cfg.api_ready and works is not False else []
        if cfg.ddns_ready and works is not False:
            out["forms"] += [self.keeper().take_form(), self.keeper().now_form()]
        out["actions"] = ([{"hook": "refresh", "args": [], "title": "Refresh",
                            "note": "the account read again now (a few dozen requests at most)"}] if cfg.api_ready else []) + \
                         ([{"form": keeping.NOW_FORM, "title": "Update DNS now"}] if cfg.ddns_ready and works is not False else [])
        return out

    def _summary(self, cfg, works, api_error, read, hosts, states, attached) -> str:
        bits = []
        if cfg.api_ready:
            if works is True:
                inst = read.get("instances") or []
                running = sum(1 for i in inst if i.get("power_status") == "running")
                account = read.get("account") or {}
                bits.append("the instances not read" if read.get("instances") is None else
                            f"{plural(len(inst), 'instance')} ({running:,} running)" if inst else "no instances")
                bits.append(plural(len(read.get("domains") or []), "domain"))
                if account:
                    bits.append(f"balance {money(account.get('balance'))}, {money(account.get('pending_charges'))} pending")
            elif works is None:
                bits.append("reading the account…" if attached else "the account is read once attached")
            else:
                bits.append(f"the API: {shorten(api_error or 'failed', 100)}")
        else:
            bits.append(f"{API_KEY} is not set")
        if cfg.ddns_ready:
            mine = [states[h.fqdn] for h in hosts if h.fqdn in states]
            if len(hosts) == 1 and mine and mine[0].ok:
                bits.append(f"{mine[0].fqdn} at {mine[0].address}")
            elif any(s.ok is not None for s in mine):
                bits.append(f"Dynamic DNS: {sum(1 for s in mine if s.ok)} of {plural(len(hosts), 'host')} current")
            else:
                bits.append("Dynamic DNS: the first check is under way" if attached else "Dynamic DNS: checked once attached")
        return " · ".join(bits)

    def _tables(self, cfg, read, why, read_zones, read_rules, counts, notes, regions, hosts, wrong, public) -> list[dict]:
        out = []
        if cfg.ddns_ready:
            t = self.keeper().table(hosts, cfg.minutes, attached=self.app is not None, when=when, take=True,
                                    empty=None if self.known() else "The hosts are matched to the account's domains once "
                                                                    "they are read.")
            if wrong:
                t["note"] += " · not kept: " + "; ".join(wrong)
            out.append(t)
        if not cfg.api_ready:
            return out
        instances = read.get("instances")
        if instances is not None or "instances" in why:
            out.append(self._instances_table(instances or [], why.get("instances"), notes, regions))
        out += self._dns_tables(read.get("domains"), why.get("domains"), read_zones, hosts)
        out += self._firewall_tables(read.get("groups"), why.get("groups"), read_rules, instances or [])
        keys = read.get("keys")
        if keys is not None or "keys" in why:
            out.append({"title": "SSH keys", "note": why.get("keys") or (
                "copied to an instance when it is deployed: a key added or removed here changes no instance running"),
                        "columns": [{"title": "Name"}, {"title": "Type"}, {"title": "Fingerprint"}, {"title": "Added"},
                                    {"title": ""}],
                        "rows": [[str(k.get("name") or "–"), sshkeys.kind_of(k.get("ssh_key") or "") or "–",
                                  sshkeys.fingerprint(k.get("ssh_key") or "") or "–", day(k.get("date_created")),
                                  {"form": "key-remove", "title": "Remove…", "label": f"Remove the key {k.get('name')}",
                                   "values": {"key": str(k.get("id")), "name": str(k.get("name") or "")}}]
                                 for k in (keys or [])],
                        "empty": "No SSH keys in this account." if keys is not None else "Not read.",
                        "actions": [{"form": "key-add", "title": "Add a key…"}] if keys is not None else []})
        blocks = read.get("blocks")
        if blocks is not None or "blocks" in why:
            out.append({"title": "Block storage", "note": why.get("blocks") or "volumes, each billed by the month as Vultr gives it",
                        "columns": [{"title": "Volume"}, {"title": "Region"}, {"title": "Size (GB)", "num": True},
                                    {"title": "Type"}, {"title": "Attached to"}, {"title": "Per month", "num": True}],
                        "rows": [[cell(str(b.get("label") or b.get("id")), str(b.get("status") or "") or None),
                                  self._region(regions, b.get("region")), str(b.get("size_gb") or "–"),
                                  str(b.get("block_type") or "–"),
                                  str(b.get("attached_to_instance_label") or b.get("attached_to_instance") or "–"),
                                  money(b.get("cost"))] for b in (blocks or [])],
                        "empty": "No block storage in this account." if blocks is not None else "Not read."})
        reserved = read.get("reserved")
        if reserved is not None or "reserved" in why:
            labels = {str(i.get("id")): name_of(i) for i in (instances or [])}
            out.append({"title": "Reserved IPs", "note": why.get("reserved") or "addresses kept apart from any instance",
                        "columns": [{"title": "Address"}, {"title": "Type"}, {"title": "Region"}, {"title": "Label"},
                                    {"title": "On"}],
                        "rows": [[f"{r.get('subnet')}/{r.get('subnet_size')}", str(r.get("ip_type") or "–"),
                                  self._region(regions, r.get("region")), str(r.get("label") or "–"),
                                  labels.get(str(r.get("instance_id") or ""), str(r.get("instance_id") or "") or "–")]
                                 for r in (reserved or [])],
                        "empty": "No reserved IPs in this account." if reserved is not None else "Not read."})
        if counts:
            out.append({"title": "The account's other resources",
                        "note": "counted, one list each (bare metal, snapshots, backups, Kubernetes, load balancers, "
                                "databases): nothing of them is changed here",
                        "columns": [{"title": "Kind"}, {"title": "Count", "num": True}],
                        "rows": [[title, f"{n:,}" if isinstance(n, int) else cell("–", f"not read: {shorten(n, 120)}")]
                                 for title, n in counts.items()],
                        "empty": "None counted."})
        return out

    @staticmethod
    def _region(regions: dict, rid) -> object:
        r = regions.get(str(rid or ""))
        if not r:
            return str(rid or "–")
        return cell(str(r.get("city") or rid), " · ".join(str(x) for x in (rid, r.get("country")) if x))

    def _instances_table(self, instances: list, why: str | None, notes: dict, regions: dict) -> dict:
        rows = []
        for i in instances:
            iid, label = str(i.get("id") or ""), name_of(i)
            power, status, server = (str(i.get(k) or "") for k in ("power_status", "status", "server_status"))
            sub = " · ".join(x for x in (str(i.get("os") or ""), str(i.get("hostname") or "") if i.get("hostname") != label
                                          else "", ", ".join(i.get("tags") or [])) if x)
            state_sub = " · ".join(x for x in ("still billed" if power == "stopped" else "",
                                                status if status != "active" else "", server if server not in ("ok", "") else "",
                                                notes.get(iid, "")) if x)
            price = self._price(i)
            features = set(i.get("features") or [])
            month_sub = " · ".join(x for x in ("its region's price" if price.get("regional") else "",
                                                "preemptible" if i.get("preemptible") else "",
                                                "backups on: Vultr adds 20%" if "auto_backups" in features else "") if x)
            size = " · ".join(x for x in (f"{i.get('vcpu_count')} vCPU" if i.get("vcpu_count") else "",
                                           f"{(i.get('ram') or 0) / 1024:g} GB" if i.get("ram") else "",
                                           f"{i.get('disk')} GB disk" if i.get("disk") else "") if x)
            active = status == "active"
            first = second = ""
            values = {"instance": iid, "label": label}
            if active and power == "running":
                first = {"form": "reboot", "title": "Reboot…", "label": f"Reboot {label}", "values": values}
                second = {"form": "halt", "title": "Halt…", "label": f"Halt {label}", "values": values}
            elif active and power == "stopped":
                first = {"form": "start", "title": "Start…", "label": f"Start {label}", "values": values}
            rows.append([cell(label, sub or None), cell(power or status or "–", state_sub or None),
                         self._region(regions, i.get("region")), cell(str(i.get("plan") or "–"), size or None),
                         str(i.get("main_ip") or "–"), str(i.get("v6_main_ip") or "–"),
                         cell(money(price.get("monthly")), month_sub or None) if price else "–",
                         money(price.get("hourly"), hourly=True) if price and price.get("hourly") is not None else "–",
                         day(i.get("date_created")), first, second])
        return {"title": "Instances",
                "note": why or (STOPPED_BILLS_SAID + " · prices: the plan's, a month and an hour "
                                "(Vultr bills hourly, capped at 672 hours a month); started, rebooted and halted here, "
                                "each confirmed (a reboot and a halt asked twice)"),
                "columns": [{"title": "Instance"}, {"title": "Power"}, {"title": "Region"}, {"title": "Plan"},
                            {"title": "IPv4"}, {"title": "IPv6"}, {"title": "Per month", "num": True},
                            {"title": "Per hour", "num": True}, {"title": "Created"}, {"title": ""}, {"title": ""}],
                "rows": rows, "empty": "No instances in this account." if why is None else "Not read."}

    def _dns_tables(self, domains, why, read_zones, hosts) -> list[dict]:
        if domains is None and why is None:
            return []
        def held(d) -> str:
            z = read_zones.get(str(d.get("domain")))
            return f"{len(z):,}" if isinstance(z, tuple) else "–"

        out = [{"title": "Domains", "note": why or "on Vultr's DNS (free hosting); each domain's records below",
                "columns": [{"title": "Domain"}, {"title": "Added"}, {"title": "DNSSEC"}, {"title": "Records", "num": True}],
                "rows": [[str(d.get("domain")), day(d.get("date_created")), str(d.get("dns_sec") or "–"), held(d)]
                         for d in (domains or [])],
                "empty": "No domains on Vultr's DNS." if why is None else "Not read."}]
        for d in (domains or []):
            name = str(d.get("domain") or "")
            z = read_zones.get(name)
            if not isinstance(z, tuple):
                out.append({"title": f"{name} records", "note": str(z or "not read yet"), "columns": [{"title": "Name"}],
                            "rows": [], "empty": "Not read."})
                continue
            kept = [h.name for h in hosts if h.zone == name]
            rows = []
            for r in sorted(z, key=lambda r: (r.name != "", r.name, r.type, r.data)):
                short = r.data if len(r.data) <= 64 else r.data[:63] + "…"
                rows.append([r.host, r.type, short, str(r.ttl) if r.ttl else "–",
                             str(r.priority) if r.type in zones.PRIORITY else "",
                             {"form": f"remove:{name}", "title": "Remove…", "label": f"Remove {r.host} {r.type} {short}",
                              "values": {"record": r.id, "name": r.host, "rtype": r.type, "data": r.data}}])
            note = ("Set a record… replaces the host's A, AAAA or CNAME records (asked again before any other goes); "
                    "Add a record… adds one beside the others, all kept; Remove… takes one away. The zone is read before "
                    "and after each change (the command line too: python -m plugin_platform_vultr set | add | remove)")
            if kept:
                note += f" · Dynamic DNS keeps {', '.join(kept)} at this network's address"
            out.append({"title": f"{name} records", "note": note,
                        "columns": [{"title": "Name"}, {"title": "Type"}, {"title": "Data"}, {"title": "TTL", "num": True},
                                    {"title": "Priority", "num": True}, {"title": ""}],
                        "rows": rows, "empty": "No records.",
                        "actions": [{"form": f"set:{name}", "title": "Set a record…"},
                                    {"form": f"add:{name}", "title": "Add a record…"}]})
        return out

    def _firewall_tables(self, groups, why, read_rules, instances) -> list[dict]:
        if groups is None and why is None:
            return []
        linked: dict[str, list[str]] = {}
        for i in instances:
            gid = str(i.get("firewall_group_id") or "")
            if gid:
                linked.setdefault(gid, []).append(name_of(i))
        out = [{"title": "Firewall groups",
                "note": why or ("inbound rules on Vultr's network edge, each letting traffic in; Vultr enforces a group "
                                "once it holds a rule, and then drops everything no rule lets in"),
                "columns": [{"title": "Group"}, {"title": "Rules", "num": True}, {"title": "Instances linked"},
                            {"title": "Changed"}],
                "rows": [[str(g.get("description") or g.get("id")), f"{g.get('rule_count', 0)} of {g.get('max_rule_count', '–')}",
                          ", ".join(linked.get(str(g.get("id")), [])) or (f"{g.get('instance_count')}" if g.get("instance_count")
                                                                           else "none"),
                          day(g.get("date_modified"))] for g in (groups or [])],
                "empty": "No firewall groups in this account." if why is None else "Not read."}]
        for g in (groups or []):
            gid = str(g.get("id") or "")
            title = f"{g.get('description') or gid} rules"
            held = read_rules.get(gid)
            if not isinstance(held, tuple):
                out.append({"title": title, "note": str(held or "not read yet"), "columns": [{"title": "Rule"}], "rows": [],
                            "empty": "Not read."})
                continue
            on = linked.get(gid, [])
            rows = [[r.ip_type, r.protocol.upper(), r.port_words(), r.from_words(), r.notes or "–",
                     {"form": f"rule-remove:{gid}", "title": "Remove…", "label": f"Remove {r.said()}",
                      "values": {"rule": r.id, "protocol": r.protocol.upper(), "port": r.port_words(), "source": r.from_words()}}]
                    for r in held]
            enforced = "enforced: everything no rule lets in is dropped" if held else \
                "not enforced: a group without rules drops nothing"
            out.append({"title": title,
                        "note": f"{enforced} · linked: {', '.join(on) if on else 'no instance'} · rules added and removed "
                                "here, each confirmed (a risky one asked twice)",
                        "columns": [{"title": "IP"}, {"title": "Protocol"}, {"title": "Port"}, {"title": "From"},
                                    {"title": "Notes"}, {"title": ""}],
                        "rows": rows, "empty": "No rules: the group drops nothing.",
                        "actions": [{"form": f"rule-add:{gid}", "title": "Add a rule…"}]})
        return out

    def _forms(self, cfg, read, read_zones, read_rules, public) -> list[dict]:
        """The forms the platform's page draws (status.forms), their fields the hooks' arguments in order; each asked once
        the user has confirmed the change it names; a halt and a risky rule change only once that is accepted too (the
        refusal names its accept field: the page's second confirmation)."""
        out = []
        if read.get("instances"):
            instance = {"name": "instance", "label": "Instance", "type": "fixed"}
            label = {"name": "label", "label": "Server", "type": "fixed"}
            out += [
                {"id": "start", "hook": "start", "title": "Start an instance", "fields": [instance, label],
                 "confirm": {"title": "Start {label}?", "words": "{label} is started now. " + START_WORDS, "yes": "Start it"}},
                {"id": "reboot", "hook": "reboot", "title": "Reboot an instance",
                 "fields": [instance, label,
                            {"name": ACCEPT_REBOOT, "type": "accept", "title": "Reboot it anyway?", "yes": "Reboot it",
                             "words": REBOOT_ACCEPT_WORDS}],
                 "confirm": {"title": "Reboot {label}?", "words": "{label} is rebooted now. " + REBOOT_WORDS
                                      + " You are asked again before it goes.",
                             "yes": "Go on", "danger": True}},
                {"id": "halt", "hook": "halt", "title": "Halt an instance",
                 "fields": [instance, label,
                            {"name": ACCEPT_HALT, "type": "accept", "title": "Halt it anyway?", "yes": "Halt it",
                             "words": HALT_WORDS}],
                 "confirm": {"title": "Halt {label}?",
                             "words": "{label} is powered off now (a halt). " + STOPPED_BILLS_SAID
                                      + ". You are asked again before it goes.",
                             "yes": "Go on", "danger": True}},
            ]
        for name in sorted(read_zones):
            if not isinstance(read_zones[name], tuple):
                continue
            domain = {"name": "domain", "label": "Domain", "type": "fixed", "value": name}
            ttl = {"name": "ttl", "label": "TTL (seconds)", "type": "number", "min": zones.TTL_MIN, "placeholder": "300",
                   "empty": "the record's own, else Vultr's"}
            host = {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "@, www, home",
                    "note": f"@ is {name} itself; home is home.{name}"}
            out += [
                {"id": f"set:{name}", "hook": "set_record", "title": f"Set a record in {name}",
                 "note": "Sets the host's A, AAAA or CNAME record: it replaces the host's records of that type. To add an "
                         "address beside the ones there, Add a record….",
                 "fields": [domain, host,
                            {"name": "rtype", "label": "Type", "type": "choice", "value": "A",
                             "choices": [{"value": t, "title": t, "note": n} for t, n in zones.SET_TYPES.items()]},
                            {"name": "data", "label": "Data", "type": "text", "required": True,
                             "placeholder": public or "an address, or a host name for a CNAME"},
                            ttl,
                            {"name": ACCEPT_REPLACE, "type": "accept", "title": "Replace them?", "yes": "Replace them",
                             "words": ("Setting {name} {rtype} to {data} removes the host's other {rtype} records the "
                                       "refusal above names: they stop answering for {name}. Add a record… would add one "
                                       "beside them instead.")}],
                 "submit": "Review the change",
                 "confirm": {"title": f"Set this record in {name}?",
                             "words": "{name} {rtype} is set to {data} in {domain}: it replaces the host's {rtype} records "
                                      "(one updated to {data}; you are asked again before any other is removed). Every "
                                      "record of another host or another type is kept.",
                             "yes": "Set the record"}},
                {"id": f"add:{name}", "hook": "add_record", "title": f"Add a record to {name}",
                 "note": "Adds a record beside the host's others: every other record is kept.",
                 "fields": [domain, host,
                            {"name": "rtype", "label": "Type", "type": "choice", "value": "TXT",
                             "choices": [{"value": t, "title": t, "note": n} for t, n in zones.ADD_TYPES.items()]},
                            {"name": "data", "label": "Data", "type": "text", "required": True,
                             "placeholder": "an address, a host name or text, as its type says",
                             "note": "TXT text is sent in double quotes, as Vultr's DNS keeps it"},
                            ttl,
                            {"name": "priority", "label": "Priority", "type": "number", "min": 0, "max": 65535,
                             "placeholder": "10", "required": True, "when": {"rtype": sorted(zones.PRIORITY)}}],
                 "submit": "Review the change",
                 "confirm": {"title": f"Add this record to {name}?",
                             "words": "{name} {rtype} {data} is added to {domain}, beside the host's others: every other "
                                      "record is kept.",
                             "yes": "Add the record"}},
                {"id": f"remove:{name}", "hook": "remove_record", "title": f"Remove a record from {name}",
                 "fields": [domain, {"name": "record", "label": "Record", "type": "fixed"},
                            {"name": "name", "label": "Name", "type": "fixed"}, {"name": "rtype", "label": "Type", "type": "fixed"},
                            {"name": "data", "label": "Data", "type": "fixed"}],
                 "confirm": {"title": f"Remove this record from {name}?", "words": "{name} {rtype} {data} is removed from "
                             "{domain}. Every other record is kept.", "yes": "Remove the record", "danger": True}},
            ]
        groups = {str(g.get("id")): g for g in (read.get("groups") or [])}
        for gid in sorted(read_rules):
            if not isinstance(read_rules[gid], tuple) or gid not in groups:
                continue
            title = str(groups[gid].get("description") or gid)
            group = {"name": "group", "label": "Firewall group", "type": "fixed", "value": gid}
            accept = {"name": ACCEPT_RISK, "type": "accept", "title": "Make this risky change?", "yes": "Make it anyway",
                      "words": ("This change may open the instances linked to the group to the whole internet, or shut "
                                "you out of them over SSH (the refusal above says which). Make it anyway?")}
            out += [
                {"id": f"rule-add:{gid}", "hook": "add_rule", "title": f"Add a rule to {title}",
                 "note": "An inbound rule letting traffic in; Vultr enforces a group once it holds a rule, and then drops "
                         "everything no rule lets in.",
                 "fields": [group,
                            {"name": "ip_type", "label": "IP", "type": "choice", "value": "v4",
                             "choices": [{"value": "v4", "title": "IPv4"}, {"value": "v6", "title": "IPv6"}]},
                            {"name": "protocol", "label": "Protocol", "type": "choice", "value": "tcp",
                             "choices": [{"value": p, "title": p.upper(), "note": n} for p, n in walls.PROTOCOLS.items()]},
                            {"name": "port", "label": "Port or range", "type": "text", "required": True,
                             "placeholder": "22, 443, 8000:8999", "when": {"protocol": sorted(walls.PORTED)}},
                            {"name": "subnet", "label": "From (an address or a network's)", "type": "text", "required": True,
                             "placeholder": public or "203.0.113.7",
                             "note": f"this network's address: {public}" if public else "0.0.0.0 with size 0: the whole internet"},
                            {"name": "subnet_size", "label": "Subnet size (bits)", "type": "number", "min": 0, "max": 128,
                             "value": 32, "required": True, "note": "32: one IPv4 address; 128: one IPv6; 0: everyone"},
                            {"name": "notes", "label": "Notes", "type": "text", "placeholder": "what it is for"},
                            accept],
                 "submit": "Review the rule",
                 "confirm": {"title": f"Add this rule to {title}?",
                             "words": "{protocol} {port} from {subnet}/{subnet_size} ({ip_type}) is let in to the instances "
                                      f"linked to {title}. Asked again when risky: every port, SSH, RDP, VNC or Docker's "
                                      "API open to everyone, or the group's first rule while instances are linked to it "
                                      "(from then on everything else is dropped).",
                             "yes": "Add the rule"}},
                {"id": f"rule-remove:{gid}", "hook": "remove_rule", "title": f"Remove a rule from {title}",
                 "fields": [group, {"name": "rule", "label": "Rule", "type": "fixed"},
                            {"name": "protocol", "label": "Protocol", "type": "fixed"},
                            {"name": "port", "label": "Port", "type": "fixed"},
                            {"name": "source", "label": "From", "type": "fixed"}, accept],
                 "confirm": {"title": f"Remove this rule from {title}?",
                             "words": "{protocol} {port} from {source} is no longer let in. Removing a group's last rule "
                                      "or the only rule letting SSH in is asked again.",
                             "yes": "Remove the rule", "danger": True}},
            ]
        if read.get("keys") is not None:
            out += [
                {"id": "key-add", "hook": "add_key", "title": "Add an SSH key",
                 "note": "Copied to the instances deployed from now on; no instance running changes.",
                 "fields": [{"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "laptop"},
                            {"name": "ssh_key", "label": "Public key", "type": "text", "required": True, "secret": True,
                             "placeholder": "ssh-ed25519 AAAA... you@host", "note": "the .pub file's one line; never a private key"}],
                 "confirm": {"title": "Add this SSH key?", "words": "{name} is added to the account's SSH keys, for the "
                             "instances deployed from now on.", "yes": "Add the key"}},
                {"id": "key-remove", "hook": "remove_key", "title": "Remove an SSH key",
                 "fields": [{"name": "key", "label": "Key", "type": "fixed"}, {"name": "name", "label": "Name", "type": "fixed"}],
                 "confirm": {"title": "Remove this SSH key?", "words": "{name} is removed from the account's SSH keys. The "
                             "instances deployed with it keep it.", "yes": "Remove the key", "danger": True}},
            ]
        return out


def acl_words(acls) -> str:
    """The key's user's permissions in words (the account's acls)."""
    found = [str(a) for a in (acls or [])]
    if not found:
        return "none said"
    if "manage_users" in found:
        return "every permission (manage_users): a key of a user limited to what the plugin does is safer"
    return ", ".join(found)


def shorten(text: str, most: int = 200) -> str:
    t = " ".join(str(text).split())
    return t if len(t) <= most else t[: most - 1] + "…"


MACHINE = VultrPlugin()
