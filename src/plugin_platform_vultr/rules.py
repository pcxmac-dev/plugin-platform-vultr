"""A Vultr firewall group's rules (Vultr Firewall: inbound rules on the network's edge, each one letting traffic in; a group
filters the instances linked to it). The reference's rule: `id`, `ip_type` (v4, v6), `action` (accept), `protocol` (ICMP,
TCP, UDP, GRE, ESP, AH), `port` (TCP/UDP only: a port or a colon separated range), `subnet` and `subnet_size`, `source`
("" the subnet; "cloudflare" Cloudflare's addresses; a load balancer's ID its addresses), `notes`. Vultr's FAQ: a group
"must contain at least one rule before it is enforced"; until then it drops nothing, and once it holds one, everything
no rule lets in is dropped.

So a change is risky, and asked twice (`ACCEPT`), when it:
- lets every port in from the whole internet (a subnet of size 0), or a way to control a server from afar (REMOTE: SSH,
  RDP, VNC, Docker's API);
- is a group's first rule while instances are linked to it, whatever it lets in (0.1.1: an audit found one letting SSH in
  asked once): from then on everything else is dropped, a website on 80 or 443 too;
- removes a group's last rule while instances are linked to it: the group is no longer enforced, every port open again;
- removes the only rule letting SSH in to the instances linked to the group.
A TCP or UDP rule without a port is taken as letting every port in (Vultr's docs do not say what one admits): the page
asks a port or a range for each one it adds."""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .records import Refusal

ACCEPT = "accept_risk"  # the hooks' argument accepting a risky rule change (Refusal's accept)
PROTOCOLS = {  # what the page's form adds, in the order offered, with what each lets in
    "tcp": "TCP: a port or a range (22, 443, 8000:8999)",
    "udp": "UDP: a port or a range (53, 51820, 60000:61000)",
    "icmp": "ICMP: ping and the network's own messages (no port)",
    "gre": "GRE tunnels (no port)",
    "esp": "IPsec ESP (no port)",
    "ah": "IPsec AH (no port)",
}
PORTED = frozenset({"tcp", "udp"})
SSH = 22
REMOTE = {22: "SSH", 3389: "RDP", 5900: "VNC", 2375: "Docker's API", 2376: "Docker's API over TLS"}  # TCP ports controlling a server
NOTES_MAX = 255  # the CLI's reference: notes "up to 255 characters"


@dataclass(frozen=True)
class Rule:
    """A rule as Vultr gives it."""

    id: str
    ip_type: str
    protocol: str
    port: str
    subnet: str
    size: int
    source: str = ""
    notes: str = ""

    @property
    def ports(self) -> tuple[int, int] | None:
        """The ports it lets in (lowest, highest); None for a protocol without ports. A TCP or UDP rule without a port is
        taken as every port."""
        if self.protocol not in PORTED:
            return None
        return port_range(self.port) or (1, 65535)

    @property
    def everyone(self) -> bool:
        """Whether it lets the whole internet in (a subnet of size 0, no other source)."""
        return not self.source and self.size == 0

    def admits(self, port: int, protocol: str = "tcp") -> bool:
        p = self.ports
        return self.protocol == protocol and p is not None and p[0] <= port <= p[1]

    @property
    def every_port(self) -> bool:
        p = self.ports
        return p is not None and p[0] <= 1 and p[1] >= 65535

    def from_words(self) -> str:
        """Where it lets traffic in from, in words."""
        if self.source == "cloudflare":
            return "Cloudflare's addresses"
        if self.source:
            return f"load balancer {self.source}"
        if self.everyone:
            return f"anywhere ({self.subnet}/{self.size})"
        return f"{self.subnet}/{self.size}"

    def port_words(self) -> str:
        if self.protocol not in PORTED:
            return "–"
        return self.port or "every port (none given)"

    def said(self) -> str:
        what = self.protocol.upper() + (f" {self.port_words()}" if self.protocol in PORTED else "")
        return f"{what} from {self.from_words()} ({'IPv4' if self.ip_type == 'v4' else 'IPv6'})"

    def as_dict(self) -> dict:
        return {"id": self.id, "ipType": self.ip_type, "protocol": self.protocol, "port": self.port, "subnet": self.subnet,
                "size": self.size, "source": self.source, "notes": self.notes}


def rule_of(d: Mapping) -> Rule:
    size = d.get("subnet_size")
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = -1
    return Rule(id=str(d.get("id") if d.get("id") is not None else ""), ip_type=str(d.get("ip_type") or d.get("type") or ""),
                protocol=str(d.get("protocol") or "").lower(), port=str(d.get("port") or "").strip(),
                subnet=str(d.get("subnet") or ""), size=size, source=str(d.get("source") or ""),
                notes=str(d.get("notes") or ""))


def rules_of(found: Sequence[Mapping]) -> tuple[Rule, ...]:
    return tuple(rule_of(d) for d in found)


def port_range(text: str) -> tuple[int, int] | None:
    """A rule's port as (lowest, highest): 22 is (22, 22), 8000:8999 its range; None when it is none."""
    t = str(text or "").strip().replace("-", ":")
    if not t:
        return None
    lo, sep, hi = t.partition(":")
    try:
        a, b = int(lo), int(hi) if sep else int(lo)
    except ValueError:
        return None
    if not (1 <= a <= b <= 65535):
        return None
    return a, b


def checked(ip_type: str, protocol: str, port, subnet: str, subnet_size, notes: str = "") -> dict:
    """A rule to add, as the reference's body (ip_type, protocol, port, subnet, subnet_size, notes); ValueError when a
    part is none. The subnet is taken as its network's address (203.0.113.7/24 is 203.0.113.0/24)."""
    t = str(ip_type or "").strip().lower()
    if t not in ("v4", "v6"):
        raise ValueError("the IP type is v4 or v6")
    proto = str(protocol or "").strip().lower()
    if proto not in PROTOCOLS:
        raise ValueError(f"{protocol!r} is no protocol here: {', '.join(PROTOCOLS)}")
    text = str(port if port is not None else "").strip()
    if proto in PORTED:
        found = port_range(text)
        if found is None:
            raise ValueError(f"a {proto.upper()} rule takes a port or a range, 1 to 65535 (22, 8000:8999)")
        text = str(found[0]) if found[0] == found[1] else f"{found[0]}:{found[1]}"
    elif text:
        raise ValueError(f"an {proto.upper()} rule takes no port")
    try:
        size = int(subnet_size)
    except (TypeError, ValueError):
        raise ValueError("the subnet size is a number of bits (32 for one IPv4 address, 128 for one IPv6)") from None
    most = 32 if t == "v4" else 128
    if not 0 <= size <= most:
        raise ValueError(f"an {'IPv4' if t == 'v4' else 'IPv6'} subnet's size is 0 to {most}")
    try:
        net = ipaddress.ip_network(f"{str(subnet or '').strip()}/{size}", strict=False)
    except ValueError:
        raise ValueError(f"{str(subnet).strip()!r} is not an {'IPv4' if t == 'v4' else 'IPv6'} address") from None
    if net.version != (4 if t == "v4" else 6):
        raise ValueError(f"{str(subnet).strip()!r} is not an {'IPv4' if t == 'v4' else 'IPv6'} address (the IP type is {t})")
    note = " ".join(str(notes or "").split())
    if len(note) > NOTES_MAX:
        raise ValueError(f"the notes are at most {NOTES_MAX} characters")
    body = {"ip_type": t, "protocol": proto, "subnet": str(net.network_address), "subnet_size": size}
    if proto in PORTED:
        body["port"] = text
    if note:
        body["notes"] = note
    return body


def as_rule(body: Mapping) -> Rule:
    return Rule("", body["ip_type"], body["protocol"], str(body.get("port") or ""), body["subnet"], int(body["subnet_size"]),
                "", str(body.get("notes") or ""))


def plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def risk_of_adding(new: Rule, rules: Sequence[Rule], linked: int) -> str:
    """Why adding `new` to a group holding `rules`, with `linked` instances, is risky ("" when it is not)."""
    why = []
    if new.everyone and new.every_port:
        why.append(f"it lets every {new.protocol.upper()} port in from the whole internet"
                   + (" (SSH, RDP and every other service)" if new.protocol == "tcp" else ""))
    elif new.everyone:
        opened = [f"{what} (TCP {port})" for port, what in REMOTE.items() if new.admits(port)]
        if opened:
            why.append(f"it lets {', '.join(opened)} in from the whole internet")
    if not rules and linked:
        them = plural(linked, "instance")
        why.append(f"it is the group's first rule while {them} {'is' if linked == 1 else 'are'} linked to it: Vultr enforces "
                   "a group once it holds a rule, so from then on every other inbound connection to them is dropped (a "
                   "website on 80 or 443, any other service" + ("" if new.admits(SSH) else ", SSH too")
                   + "): only what this rule lets in still reaches them")
    return "; ".join(why)


def risk_of_removing(rule: Rule, rules: Sequence[Rule], linked: int) -> str:
    """Why removing `rule` from a group holding `rules`, with `linked` instances, is risky ("" when it is not)."""
    if not linked:
        return ""
    rest = [r for r in rules if r.id != rule.id]
    if not rest:
        return (f"it is the group's last rule: a group without rules is not enforced, so every port of its "
                f"{plural(linked, 'instance')} is open to the whole internet once it goes")
    if rule.admits(SSH) and not any(r.admits(SSH) for r in rest):
        return f"it is the only rule letting SSH in: SSH to its {plural(linked, 'instance')} is dropped once it goes"
    return ""


def same_rule(a: Rule, b: Rule) -> bool:
    return (a.ip_type, a.protocol, a.ports, a.subnet, a.size, a.source) == (b.ip_type, b.protocol, b.ports, b.subnet, b.size,
                                                                          b.source)


def refuse_risky(why: str, accepted) -> None:
    """Refusal naming ACCEPT when a change is risky and that was not accepted: `accepted` counts only when it is True
    itself (the page sends JSON true; a string such as "false", or a 1, from another program is no acceptance)."""
    if why and accepted is not True:
        raise Refusal(f"risky: {why}. Nothing was sent: it is made only once that is accepted ({ACCEPT}: the platform's page "
                      "asks again; the command line asks twice)", accept=ACCEPT)
