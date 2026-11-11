"""A domain's records on Vultr's DNS, changed one at a time (Vultr's API creates, updates and deletes a record by its ID:
every other record stays as it is). The reference's record: `id`, `type` (A, AAAA, CNAME, NS, MX, SRV, TXT, CAA, SSHFP),
`name` (relative to the domain: "" is the domain itself, the apex), `data`, `ttl`, `priority` (MX and SRV only).

Two changes, each planned against the zone as read just before, and each said as it is (0.1.1: an audit found the
set's confirmation saying every other record was kept while it deleted the host's others of its type):
- a record **set** (`plan_set`, A, AAAA or CNAME): it *replaces* the host's records of its type, one of them updated and
  any others deleted (`Plan.removes`: the plugin asks a second time before those go); a CNAME stands alone, never at the
  domain itself;
- a record **added** (`plan_add`, every type but CNAME): beside the host's others, which are all kept (the same record
  there already: its TTL or priority changed when given, else nothing written).
A record removed is named by its ID and by what the page showed (`plan_remove`: its name, type and data, all of them):
one changed since is not removed. After the writes the zone is read again and the change checked (`apply`)."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

TYPES = {  # every record type the page writes, with what it holds
    "A": "an IPv4 address",
    "AAAA": "an IPv6 address",
    "CNAME": "a host name this host stands for (it holds nothing else; the domain itself takes none)",
    "TXT": "text (SPF, DKIM, DMARC, a verification)",
    "MX": "a mail server, with its priority",
    "NS": "a subdomain's name server",
    "SRV": "a service: its weight, port and target (5 5060 sip.example.com), with its priority",
    "CAA": "who may issue certificates: flag, tag and value (0 issue \"letsencrypt.org\")",
    "SSHFP": "an SSH host key's fingerprint: algorithm, type and hex (4 2 123abc...)",
}
SINGLE = frozenset({"A", "AAAA", "CNAME"})  # what Set a record… sets: the host's records of the type replaced
SET_TYPES = {t: f"{TYPES[t]}; replaces the host's {t} records" for t in ("A", "AAAA", "CNAME")}
ADD_TYPES = {t: f"{TYPES[t]}; added beside the host's others" for t in TYPES if t != "CNAME"}
PRIORITY = frozenset({"MX", "SRV"})  # the reference: priority "Only required for MX and SRV"
NAMED = frozenset({"CNAME", "NS", "MX"})  # data that is a host name
MAX_TEXT = 2048
LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
DOMAIN = re.compile(r"^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
TTL_MIN, TTL_MAX = 1, 2_147_483_647  # RFC 2181's (Vultr's reference sets no bounds; it refuses what it will not take)


class Refusal(ValueError):
    """A change not made, and why: nothing was sent to Vultr. `accept`: the argument that, set, makes it anyway (the
    platform's page asks it as a second, explicit confirmation); None when nothing can be accepted."""

    def __init__(self, message: str, accept: str | None = None):
        super().__init__(message)
        self.accept = accept


@dataclass(frozen=True)
class Record:
    """A record as Vultr gives it, its name relative to the domain ("" the apex)."""

    id: str
    name: str
    type: str
    data: str
    ttl: int = 0
    priority: int = 0

    @property
    def host(self) -> str:
        """Its name as the page shows it: @ for the domain itself."""
        return self.name or "@"

    def key(self) -> tuple[str, str, str]:
        """What makes it the same record: its name, its type, its data (compared as written)."""
        return (self.name, self.type, norm(self.type, self.data))

    def said(self) -> str:
        short = self.data if len(self.data) <= 60 else self.data[:59] + "…"
        return f"{self.host} {self.type} {short}" + (f" (priority {self.priority})" if self.type in PRIORITY else "")

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.host, "type": self.type, "data": self.data, "ttl": self.ttl,
                "priority": self.priority}


def valid_domain(name: str) -> str:
    """A domain's name, lowercase without a trailing dot; ValueError when it is none."""
    d = str(name or "").strip().lower().rstrip(".")
    if not DOMAIN.match(d):
        raise ValueError(f"{str(name).strip()!r} is not a domain name")
    return d


def relative(name: str, domain: str) -> str:
    """A record's name relative to its domain, as Vultr takes it ("" the apex): the domain's own name given in full
    (www.example.com) or @ is taken off; ValueError when it is no host name."""
    n = str(name if name is not None else "").strip().lower().rstrip(".")
    d = domain.lower().rstrip(".")
    if n in ("", "@", d):
        return ""
    if n.endswith("." + d):
        n = n[: -len(d) - 1]
    labels = n.split(".")
    if len(n) > 253 or not all(LABEL.match(x) or (i == 0 and x == "*") for i, x in enumerate(labels)):
        raise ValueError(f"{str(name).strip()!r} is not a host: @, www, home, *, _dmarc")
    return n


def record_of(d: Mapping, domain: str) -> Record:
    """A record of the list's answer (its name made relative: the reference's example gives one in full)."""
    raw = str(d.get("name") or "")
    try:
        name = relative(raw, domain)
    except ValueError:
        name = raw.strip().lower().rstrip(".")
    return Record(id=str(d.get("id") or ""), name=name, type=str(d.get("type") or "").upper(), data=str(d.get("data") or ""),
                  ttl=number(d.get("ttl"), 0), priority=number(d.get("priority"), 0))


def records_of(found: Iterable[Mapping], domain: str) -> tuple[Record, ...]:
    return tuple(record_of(d, domain) for d in found)


def number(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def unquoted(text: str) -> str:
    """TXT data without the double quotes Vultr's DNS keeps it in."""
    t = str(text or "").strip()
    if len(t) >= 2 and t[0] == t[-1] == '"':
        return t[1:-1].replace('\\"', '"')
    return t


def norm(rtype: str, data: str) -> str:
    """Data as compared: addresses in their short form, host names lowercase without the trailing dot, TXT unquoted."""
    a = str(data or "").strip()
    if rtype in ("A", "AAAA"):
        try:
            return str(ipaddress.ip_address(a))
        except ValueError:
            return a
    if rtype in NAMED:
        return a.lower().rstrip(".")
    if rtype == "TXT":
        return unquoted(a)
    if rtype == "SRV":
        parts = a.split()
        return " ".join(parts[:-1] + [parts[-1].lower().rstrip(".")]) if parts else a
    return " ".join(a.split())


def host_name(value: str, rtype: str) -> str:
    n = str(value or "").strip().lower().rstrip(".")
    labels = n.split(".")
    if len(n) > 253 or len(labels) < 2 or not all(LABEL.match(x) for x in labels):
        raise ValueError(f"{str(value).strip()!r} is not a host name (a {rtype} record's)")
    return n


def data_for(rtype: str, data: str) -> str:
    """The data of a record of `rtype` as sent; ValueError when it is none. TXT text is sent in double quotes, as Vultr's
    DNS keeps TXT data (text already in them is sent as it is)."""
    a = str(data or "").strip()
    if not a:
        raise ValueError("no data given")
    if any(ord(c) < 32 or ord(c) == 127 for c in a) or len(a) > MAX_TEXT:
        raise ValueError(f"a record's data is one line of at most {MAX_TEXT} characters")
    if rtype == "A":
        try:
            return str(ipaddress.IPv4Address(a))
        except ValueError:
            raise ValueError(f"{a!r} is not an IPv4 address (an A record's)") from None
    if rtype == "AAAA":
        try:
            return str(ipaddress.IPv6Address(a))
        except ValueError:
            raise ValueError(f"{a!r} is not an IPv6 address (an AAAA record's)") from None
    if rtype in NAMED:
        return host_name(a, rtype)
    if rtype == "TXT":
        if len(a) >= 2 and a[0] == a[-1] == '"':
            return a
        return '"' + a.replace('"', '\\"') + '"'
    if rtype == "SRV":
        parts = a.split()
        if len(parts) != 3 or not all(p.isdigit() and int(p) <= 65535 for p in parts[:2]):
            raise ValueError(f"{a!r} is not an SRV record's data: its weight, port and target (5 5060 sip.example.com)")
        target = "." if parts[2] == "." else host_name(parts[2], rtype)
        return f"{int(parts[0])} {int(parts[1])} {target}"
    if rtype == "CAA":
        m = re.match(r'^(\d{1,3})\s+([A-Za-z0-9]+)\s+(".*"|\S+)$', a)
        if not m or int(m.group(1)) > 255:
            raise ValueError(f"{a!r} is not a CAA record's data: flag, tag and value (0 issue \"letsencrypt.org\")")
        value = m.group(3) if m.group(3).startswith('"') else f'"{m.group(3)}"'
        return f"{int(m.group(1))} {m.group(2).lower()} {value}"
    if rtype == "SSHFP":
        m = re.match(r"^(\d{1,3})\s+(\d{1,3})\s+([0-9A-Fa-f]+)$", a)
        if not m or int(m.group(1)) > 255 or int(m.group(2)) > 255:
            raise ValueError(f"{a!r} is not an SSHFP record's data: algorithm, type and hex fingerprint")
        return f"{int(m.group(1))} {int(m.group(2))} {m.group(3).lower()}"
    raise ValueError(f"{rtype!r} is no record type here: {', '.join(TYPES)}")


def record_type(value: str, among=TYPES) -> str:
    t = str(value or "").strip().upper()
    if t not in among:
        raise ValueError(f"{value!r} is no record type here: {', '.join(among)}")
    return t


def ttl_of(value) -> int:
    try:
        t = int(value)
    except (TypeError, ValueError):
        raise ValueError("a TTL is a number of seconds") from None
    if not TTL_MIN <= t <= TTL_MAX:
        raise ValueError(f"a TTL is {TTL_MIN} to {TTL_MAX:,} seconds")
    return t


def priority_of(value) -> int:
    try:
        p = int(value)
    except (TypeError, ValueError):
        raise ValueError("a priority is a number, 0 to 65535") from None
    if not 0 <= p <= 65535:
        raise ValueError("a priority is 0 to 65535")
    return p


# -- a change planned ------------------------------------------------------------------------------------------------------
@dataclass
class Plan:
    """The writes a change takes, in order (("create", body) | ("update", record, body) | ("delete", record)), what it does
    in words, what the zone holds after it (`want`: the record's key there; `gone`: the records' IDs no longer), and the
    records a set removes besides the one it updates (`removes`: asked about a second time)."""

    domain: str
    words: str
    ops: list = field(default_factory=list)
    want: tuple[str, str, str] | None = None
    gone: tuple[str, ...] = ()
    removes: tuple[Record, ...] = ()


def _cname_rules(here: Sequence[Record], host: str, t: str, domain: str) -> None:
    shown = host or "@"
    if t == "CNAME" and host == "":
        raise Refusal(f"a CNAME cannot stand for the domain itself ({domain}): its other records would be lost to it")
    if t == "CNAME" and any(r.type != "CNAME" for r in here):
        raise Refusal(f"{shown} holds other records ({', '.join(sorted({r.type for r in here}))}): a CNAME stands alone")
    if t != "CNAME" and any(r.type == "CNAME" for r in here):
        raise Refusal(f"{shown} is a CNAME: it holds no {t} record beside it")


def plan_set(records: Sequence[Record], domain: str, name: str, rtype: str, data: str, ttl=None) -> Plan:
    """The writes that set a record of the host, replacing its records of the type (A, AAAA or CNAME): the one holding
    the data already, else its first, updated; any others deleted (`removes`)."""
    t = record_type(rtype, SET_TYPES)
    host = relative(name, domain)
    value = data_for(t, data)
    ttl = ttl_of(ttl) if ttl is not None else None
    here = [r for r in records if r.name == host]
    _cname_rules(here, host, t, domain)
    want = (host, t, norm(t, value))
    new = Record("", host, t, value, ttl or 0, 0)
    mine = [r for r in here if r.type == t]
    if not mine:
        body = {"name": host, "type": t, "data": value, **({"ttl": ttl} if ttl else {})}
        return Plan(domain, f"set {new.said()} (the host had no {t} record: one made)", [("create", body)], want)
    first = next((r for r in mine if r.key() == want), mine[0])
    rest = tuple(r for r in mine if r is not first)
    change = {k: v for k, v in (("data", value), ("ttl", ttl)) if v is not None and
              (k != "data" or first.key() != want) and (k != "ttl" or v != first.ttl)}
    ops = ([("update", first, change)] if change else []) + [("delete", r) for r in rest]
    if not ops:
        return Plan(domain, f"{first.said()} is set already: nothing written", [], want)
    if first.key() == want:
        words = f"{first.said()} is set already" + (f"; TTL {ttl}" if "ttl" in change else "")
    else:
        words = f"set {new.said()}: it replaces {first.data}"
    if rest:
        words += f"; the host's other {t} records removed ({', '.join(r.data for r in rest)})"
    return Plan(domain, words, ops, want, tuple(r.id for r in rest), rest)


def plan_add(records: Sequence[Record], domain: str, name: str, rtype: str, data: str, ttl=None, priority=None) -> Plan:
    """The write that adds a record beside the host's others, every other record kept (every type but CNAME, which
    stands alone: Set a record… replaces one); the same record there already: its TTL or priority changed when given and
    different, else nothing written."""
    t = record_type(rtype, ADD_TYPES)
    host = relative(name, domain)
    value = data_for(t, data)
    if priority is not None and t not in PRIORITY:
        raise ValueError("a priority is an MX or SRV record's alone")
    if t in PRIORITY and priority is None:
        raise ValueError(f"an {t} record needs its priority (0 to 65535)")
    ttl = ttl_of(ttl) if ttl is not None else None
    prio = priority_of(priority) if priority is not None else None
    here = [r for r in records if r.name == host]
    _cname_rules(here, host, t, domain)
    want = (host, t, norm(t, value))
    same = next((r for r in here if r.key() == want), None)
    if same is not None:
        change = {k: v for k, v in (("ttl", ttl), ("priority", prio)) if v is not None and v != getattr(same, k)}
        if not change:
            return Plan(domain, f"{same.said()} is there already: nothing written", [], want)
        return Plan(domain, f"{same.said()} is there already; " + ", ".join(f"{k} {v}" for k, v in change.items()),
                    [("update", same, change)], want)
    body = {"name": host, "type": t, "data": value, **({"ttl": ttl} if ttl else {}),
            **({"priority": prio} if prio is not None else {})}
    others = [r for r in here if r.type == t]
    words = f"added {Record('', host, t, value, 0, prio or 0).said()}" + (
        f" beside the host's {len(others)} other {t} record{'' if len(others) == 1 else 's'}, kept" if others else "")
    return Plan(domain, words, [("create", body)], want)


def plan_remove(records: Sequence[Record], domain: str, record_id: str, name: str = "", rtype: str = "", data: str = "") -> Plan:
    """The write that removes a record by its ID, once it is checked to be the one the page showed: its name, its type
    and its data, all three given (a record named by its ID alone is not removed)."""
    rid = str(record_id or "").strip()
    if not rid:
        raise ValueError("no record named (its ID)")
    if any(x in (None, "") for x in (name, rtype, data)):
        raise ValueError("a record is removed by its ID with its name, type and data as shown (all three)")
    found = next((r for r in records if r.id == rid), None)
    if found is None:
        raise Refusal(f"{domain} holds no record {rid} any more: nothing removed (the page shows the zone as read now)")
    shown = []
    if relative(name, domain) != found.name:
        shown.append(f"named {name}")
    if str(rtype).strip().upper() != found.type:
        shown.append(f"of type {rtype}")
    if norm(found.type, data) != norm(found.type, found.data):
        shown.append(f"holding {data}")
    if shown:
        raise Refusal(f"record {rid} of {domain} is {found.said()} now, not the one shown ({', '.join(shown)}): nothing "
                      "removed")
    return Plan(domain, f"removed {found.said()}", [("delete", found)], None, (found.id,))


# -- the writes, and the check after them ------------------------------------------------------------------------------------
def apply(api, plan: Plan, stop=None) -> tuple[dict, tuple[Record, ...] | None]:
    """A plan's writes sent (the creates and updates before the deletes: a failure halfway never leaves the host with
    less than it had), the zone read again and checked. (The report, the zone read after; None when it could not be.)
    `stop` set (the plugin detached) ends it before its next write."""
    sent: list[str] = []
    if not plan.ops:
        return {"domain": plan.domain, "changed": False, "said": plan.words, "ok": True, "lines": []}, None
    ordered = [op for op in plan.ops if op[0] != "delete"] + [op for op in plan.ops if op[0] == "delete"]
    for op in ordered:
        if stop is not None and stop.is_set():
            return {"domain": plan.domain, "changed": bool(sent), "said": plan.words, "ok": None, "sent": sent,
                    "lines": [*sent, "stopped before the rest: the plugin was detached"]}, None
        if op[0] == "create":
            made = api.create_record(plan.domain, op[1])
            sent.append(f"created {op[1].get('type')} {op[1].get('name') or '@'}" + (f" ({made.get('id')})" if made.get("id") else ""))
        elif op[0] == "update":
            api.update_record(plan.domain, op[1].id, op[2])
            sent.append(f"updated {op[1].id}: " + ", ".join(f"{k} {v}" for k, v in op[2].items()))
        else:
            api.delete_record(plan.domain, op[1].id)
            sent.append(f"deleted {op[1].id} ({op[1].said()})")
    try:
        after = records_of(api.records(plan.domain), plan.domain)
    except Exception as e:  # noqa: BLE001 - the writes are done: what could not be checked is said
        return {"domain": plan.domain, "changed": True, "said": plan.words, "ok": None, "sent": sent,
                "lines": [*sent, f"the zone could not be read back to check it: {e}"]}, None
    keys = {r.key() for r in after}
    ids = {r.id for r in after}
    missing = plan.want is not None and plan.want not in keys
    still = [i for i in plan.gone if i in ids]
    ok = not missing and not still
    lines = [*sent, f"read back: {'the change is there' if ok else 'the change is not all there'} ({len(after)} records)"]
    if missing:
        lines.append(f"not found after the write: {plan.want[0] or '@'} {plan.want[1]} {plan.want[2]}")
    lines += [f"still there after the write: {i}" for i in still]
    return {"domain": plan.domain, "changed": True, "said": plan.words, "ok": ok, "sent": sent, "lines": lines,
            "records": len(after)}, after
