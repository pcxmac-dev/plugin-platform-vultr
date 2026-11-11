"""The plugin's settings, read through the library's Login interface and nothing else (the user, 2026-11-08: "again, all
the settings are stored on a login-app db"). Each setting is a pair named by its variable (VULTR_API_KEY is the pair
`vultr-api-key`: apps.authorization.pair_name), asked of the login of the app the plugin is attached to: the platform's
EnvironmentLogin today, the login app's pairs once the platform binds it. Not attached (the command line), an
EnvironmentLogin of its own. The plugin keeps no settings file: a value is never written anywhere, never shown, and only
the names of the settings set are said."""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from liminal_libs.apps import EnvironmentLogin, Login
from liminal_libs.machines.ddns import MINUTES
from liminal_libs.sources.keys import KeyVar

API_KEY = "VULTR_API_KEY"
DDNS_HOSTS = "VULTR_DDNS_HOSTS"
DDNS_MINUTES = "VULTR_DDNS_MINUTES"
CONSOLE_API = "https://console.vultr.com/settings/#settingsapi"  # the console's API page (the reference names it)
WHERE_KEY = "Vultr's console: Account > API (under Other)"
ACCESS_CONTROL = ("a Vultr API key answers only from the addresses its Access Control allows: set them on the same page, "
                  "Account > API > Access Control (an organization user's own key: Manage Organization > Users > the user > "
                  "API Access > Access Control List)")

# what the login app's "Pairs your plugins ask for" lists, once it lists the platform's plugins
KEYS = (
    KeyVar(API_KEY, label="API key",
           hint=f"{WHERE_KEY}: Enable API, then copy the Personal Access Token; {ACCESS_CONTROL}"),
    KeyVar(DDNS_HOSTS, label="Dynamic DNS hosts", secret=False,
           hint="optional: the hosts kept at this network's address, comma separated, in domains on Vultr's DNS: "
                "home.example.com, @.example.com (the domain itself). A host with no A record is made; one holding "
                "another address, or several, is left as it is until you take it over on the plugin's page"),
    KeyVar(DDNS_MINUTES, label="Dynamic DNS minutes", secret=False,
           hint="optional: minutes between Dynamic DNS checks, 1 to 1440 (5 unless set)"),
)
NAMES = tuple(k.name for k in KEYS)


@dataclass(frozen=True)
class Config:
    """The settings as read (`present`: the names of those set; `problems`: what was set but could not be taken, in words
    that never hold a secret)."""

    api_key: str = field(default="", repr=False)
    hosts: str = ""  # the Dynamic DNS hosts as typed (split against the account's domains once they are known)
    minutes: float = MINUTES[2]
    present: frozenset = frozenset()
    problems: tuple[str, ...] = ()

    @property
    def api_ready(self) -> bool:
        return bool(self.api_key)

    @property
    def ddns_ready(self) -> bool:
        """Dynamic DNS goes through Vultr's DNS: the key and the hosts both."""
        return bool(self.api_key and self.hosts.strip())

    @property
    def incomplete(self) -> tuple[str, ...]:
        """What a part set halfway lacks, in words."""
        if self.hosts.strip() and not self.api_key:
            return (f"{API_KEY} is not set (Dynamic DNS goes through Vultr's DNS, with the key)",)
        return ()

    @property
    def secrets(self) -> tuple[str, ...]:
        """The values scrubbed from every message the plugin gives."""
        return (self.api_key,) if self.api_key else ()

    def print_of(self, *names: str) -> str:
        """A fingerprint of these settings' values (kept in memory to notice a change; never shown nor written)."""
        values = {API_KEY: self.api_key, DDNS_HOSTS: self.hosts, DDNS_MINUTES: str(self.minutes)}
        return hashlib.sha256("\0".join(f"{n}={values[n]}" for n in names).encode("utf-8")).hexdigest()

    @property
    def api_print(self) -> str:
        return self.print_of(API_KEY)

    @property
    def ddns_print(self) -> str:
        return self.print_of(API_KEY, DDNS_HOSTS)


def parse(values: Mapping[str, str]) -> Config:
    """The settings from their values by variable (those not set left out or empty)."""
    v = {n: str(values.get(n) or "").strip() for n in NAMES}
    present = frozenset(n for n in NAMES if v[n])
    problems: list[str] = []
    least, most, default = MINUTES
    minutes = default
    if v[DDNS_MINUTES]:
        try:
            minutes = min(max(float(v[DDNS_MINUTES]), least), most)
        except ValueError:
            problems.append(f"{DDNS_MINUTES} is not a number of minutes: {default:g} is used")
    hosts = ", ".join(h for h in re.split(r"[,;\s]+", v[DDNS_HOSTS]) if h)
    return Config(api_key=v[API_KEY], hosts=hosts, minutes=minutes, present=present, problems=tuple(problems))


def read(login: Login | None = None) -> Config:
    """The settings as `login` furnishes them (the login of the app the plugin is attached to), else an EnvironmentLogin's:
    the variables set, by their pairs' names; a login that cannot be asked furnishes none, and says so."""
    asked = login if login is not None else EnvironmentLogin()
    try:
        values = asked.variables(NAMES)
    except Exception as e:  # noqa: BLE001 - a login that cannot be asked: nothing set, and why
        return Config(problems=(f"the settings could not be read from the login: {type(e).__name__}",))
    return parse(values)
