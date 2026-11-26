"""`python -m plugin_platform_vultr ...`: the plugin from the command line, its settings read from the environment (an
EnvironmentLogin: the variables as this shell has them).

    status                                   the account read, then the plugin's status (JSON)
    account                                  the account: its balance, the charges pending, the key's permissions
    servers                                  the instances, each with its plan's price
    domains                                  the domains on Vultr's DNS
    records DOMAIN                           a domain's records
    firewalls                                the firewall groups and their rules
    keys                                     the account's SSH keys
    ddns [--now]                             a Dynamic DNS pass: a host of its own set where it differs (--now: every one);
                                             a host holding another address left as it is (Take over… on the page)
    power NAME on|off|reboot                 an instance started, or halted or rebooted (each asked twice): NAME its
                                             label or ID
    set DOMAIN NAME TYPE DATA [--ttl N]      an A, AAAA or CNAME set: it replaces the host's records of that type (asked
                                             a second time before any other is removed); every other record kept
    add DOMAIN NAME TYPE DATA [--ttl N] [--priority N]
                                             a record added beside the host's others, every other record kept
    remove DOMAIN NAME TYPE [DATA]           a record removed, the rest kept

Each change asks "yes" on the terminal first (a halt, a reboot and a set replacing others twice); --json prints the
answer as JSON. The firewall rules and the SSH keys are changed from the platform's page. The platform asks the plugin's
changes only from its page (PAGE_ONLY_HOOKS, 0.1.6); this command line asks the platform nothing: it calls the same code
in its own process, with this shell's settings, as before."""
from __future__ import annotations

import argparse
import json
import sys

from . import (HALT_WORDS, MACHINE, REBOOT_ACCEPT_WORDS, REBOOT_WORDS, START_WORDS, STOPPED_BILLS_SAID, money, name_of,
               when)
from . import ACCEPT_REPLACE
from . import records as zones
from .api import RestError


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m plugin_platform_vultr",
                                description="Vultr for Liminal: the account, instances, DNS, firewalls, keys, Dynamic DNS")
    p.add_argument("--json", action="store_true", help="print the answer as JSON")
    sub = p.add_subparsers(dest="what")
    sub.add_parser("status", help="the account read, then the plugin's status")
    sub.add_parser("account", help="the account: balance, pending charges, the key's permissions")
    sub.add_parser("servers", help="the instances, each with its plan's price")
    sub.add_parser("domains", help="the domains on Vultr's DNS")
    r = sub.add_parser("records", help="a domain's records")
    r.add_argument("domain")
    sub.add_parser("firewalls", help="the firewall groups and their rules")
    sub.add_parser("keys", help="the account's SSH keys")
    d = sub.add_parser("ddns", help="a Dynamic DNS pass")
    d.add_argument("--now", action="store_true", help="each host's record set, whether it differs or not")
    w = sub.add_parser("power", help="an instance started, halted or rebooted")
    w.add_argument("name", help="its label, hostname or ID")
    w.add_argument("action", choices=("on", "off", "reboot"))
    s = sub.add_parser("set", help="an A, AAAA or CNAME set: it replaces the host's records of that type")
    for a in ("domain", "name", "type", "data"):
        s.add_argument(a)
    s.add_argument("--ttl", type=int)
    a_ = sub.add_parser("add", help="a record added beside the host's others, every other record kept")
    for a in ("domain", "name", "type", "data"):
        a_.add_argument(a)
    a_.add_argument("--ttl", type=int)
    a_.add_argument("--priority", type=int, help="an MX or SRV record's priority")
    m = sub.add_parser("remove", help="a record removed, the rest kept")
    for a in ("domain", "name", "type"):
        m.add_argument(a)
    m.add_argument("data", nargs="?")
    return p


def confirmed(ask, words: str) -> bool:
    """Whether the terminal answers yes to `words`."""
    try:
        return str(ask(f"{words} Type yes to go on: ") or "").strip().lower() == "yes"
    except EOFError:
        return False


def report_lines(rep: dict) -> list[str]:
    return [str(rep.get("said") or ""), *(f"  {line}" for line in rep.get("lines") or [])]


def main(argv: list[str] | None = None, plugin=None, out=None, err=None, ask=None) -> int:
    p = plugin if plugin is not None else MACHINE
    say = out or (lambda s: print(s))
    tell = err or (lambda s: print(s, file=sys.stderr))
    ask = ask or input
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    what = args.what or "status"
    try:
        if what == "status":
            if p.config().api_ready:
                try:
                    p.refresh()
                except (RestError, ValueError, RuntimeError):
                    pass  # the status says it
            say(json.dumps(p.status(), indent=1))
            return 0
        if what == "account":
            answer = p.balance()
            lines = [f"{answer.get('name') or '–'} ({answer.get('email') or '–'})",
                     f"balance {money(answer.get('balance'))}; pending this month, not billed yet: "
                     f"{money(answer.get('pending_charges'))}",
                     f"the key's permissions: {', '.join(answer.get('acls') or []) or 'none said'}"]
        elif what == "servers":
            answer = p.servers()
            lines = [f"{name_of(i):<24} {i.get('power_status') or i.get('status') or '–':<8} {i.get('region') or '–':<5} "
                     f"{i.get('plan') or '–':<16} {i.get('main_ip') or '–':<16} "
                     f"{money(i['price'].get('monthly')) + ' a month' if i.get('price') else 'price not known'}"
                     for i in answer] or ["no instances in this account"]
            lines.append(STOPPED_BILLS_SAID + ".")
        elif what == "domains":
            answer = p.domains()
            lines = [f"{d.get('domain'):<32} DNSSEC {d.get('dns_sec') or '–'}" for d in answer] or ["no domains on Vultr's DNS"]
        elif what == "records":
            answer = p.records(args.domain)
            lines = [f"{r['name']:<24} {r['type']:<6} {r['data']}  ttl {r['ttl']}" + (f"  priority {r['priority']}" if
                     r["type"] in zones.PRIORITY else "") for r in answer] or ["no records"]
        elif what == "firewalls":
            answer = p.firewalls()
            lines = []
            for g in answer:
                lines.append(f"{g.get('description') or g.get('id')}: {len(g['rules'])} rules, {g.get('instance_count', 0)} "
                             "instances linked")
                lines += [f"  {r['id']:>4} {r['ipType']} {r['protocol'].upper():<5} {r['port'] or '–':<12} from "
                          f"{r['source'] or str(r['subnet']) + '/' + str(r['size'])}  {r['notes']}" for r in g["rules"]]
            lines = lines or ["no firewall groups in this account"]
        elif what == "keys":
            answer = p.ssh_keys()
            lines = [f"{k.get('name') or '–':<24} {k['fingerprint'] or '–'}  added {str(k.get('date_created') or '')[:10]}"
                     for k in answer] or ["no SSH keys in this account"]
        elif what == "ddns":
            answer = p.ddns_update(force=args.now)
            lines = [f"{h['host']:<32} {h['address'] or '–':<16} {h['result']} (checked {when(h['checkedAt'])})"
                     for h in answer["hosts"]] + [line for line in answer["lines"] if line.startswith("not kept:")]
        elif what == "power":
            found = [i for i in p.servers() if args.name in (i.get("label"), i.get("hostname"), i.get("id"))]
            if len(found) != 1:
                tell(f"refused: {'no' if not found else len(found)} instances named {args.name}")
                return 1
            inst, action = found[0], {"on": "start", "off": "halt", "reboot": "reboot"}[args.action]
            label = name_of(inst)
            words = {"start": f"{label} is started. {START_WORDS}", "reboot": f"{label} is rebooted. {REBOOT_WORDS}",
                     "halt": f"{label} is halted (powered off). {STOPPED_BILLS_SAID}."}[action]
            if not confirmed(ask, words):
                tell("nothing done")
                return 1
            second = {"halt": HALT_WORDS, "reboot": REBOOT_ACCEPT_WORDS}.get(action)
            if second and not confirmed(ask, second.format(label=label) + " Asked a second time:"):
                tell("nothing done")
                return 1
            answer = getattr(p, action)(str(inst.get("id")), label, *([True] if second else []))
            lines = report_lines(answer)
        elif what == "set":
            kind = args.type.strip().upper()
            if kind not in zones.SET_TYPES:
                tell(f"refused: set sets an A, AAAA or CNAME record (it replaces the host's records of that type); "
                     f"a {kind} record is added: add {args.domain} {args.name} {kind} ...")
                return 1
            if not confirmed(ask, f"{args.name} {kind} is set to {args.data} in {args.domain}: it replaces the host's "
                                  f"{kind} records (you are asked again before any other is removed); every record of "
                                  "another host or type is kept."):
                tell("nothing done")
                return 1
            try:
                answer = p.set_record(args.domain, args.name, kind, args.data, ttl=args.ttl)
            except zones.Refusal as e:
                if e.accept != ACCEPT_REPLACE or not confirmed(ask, f"{e} Asked a second time:"):
                    raise
                answer = p.set_record(args.domain, args.name, kind, args.data, ttl=args.ttl, accept_replace=True)
            lines = report_lines(answer)
        elif what == "add":
            if not confirmed(ask, f"{args.name} {args.type.upper()} {args.data} is added to {args.domain}, beside the "
                                  "host's others: every other record is kept."):
                tell("nothing done")
                return 1
            answer = p.add_record(args.domain, args.name, args.type, args.data, ttl=args.ttl, priority=args.priority)
            lines = report_lines(answer)
        else:  # remove
            domain = zones.valid_domain(args.domain)
            held = [r for r in p.records(domain) if zones.relative(r["name"], domain) == zones.relative(args.name, domain)
                    and r["type"] == args.type.strip().upper()
                    and (args.data is None or zones.norm(r["type"], r["data"]) == zones.norm(r["type"], args.data))]
            if len(held) != 1:
                tell(f"refused: {domain} has {len(held) or 'no'} {args.type.upper()} records at {args.name}"
                     + (" matching that data" if args.data else "") + ("" if not held else ": name the one by its data"))
                return 1
            r = held[0]
            if not confirmed(ask, f"{r['name']} {r['type']} {r['data']} is removed from {domain}; the rest is kept."):
                tell("nothing done")
                return 1
            answer = p.remove_record(domain, r["id"], r["name"], r["type"], r["data"])
            lines = report_lines(answer)
    except RestError as e:
        tell(f"vultr: {e}")
        return 1
    except (ValueError, LookupError, RuntimeError) as e:  # a refusal (records.Refusal), a setting not set, a pass under way
        tell(f"refused: {e}")
        return 1
    if args.json:
        say(json.dumps(answer, indent=1))
    else:
        for line in lines:
            say(line)
    if what in ("set", "add", "remove", "power") and answer.get("ok") is False:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
