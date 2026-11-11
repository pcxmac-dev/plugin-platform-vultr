# plugin-platform-vultr

Vultr for Liminal's platform: your Vultr account through Vultr's API v2, the changes that cost nothing (each one
confirmed), and Dynamic DNS through Vultr's DNS.

The user's words (2026-11-11): "lets roll plugins for EC2, vultr, azure and google cloud"; for the clouds, "Free changes
only"; and for every plugin, "each plugin should reflect the the API its attached to, and present links that provide
documentation".

## What it does

A machine plugin of the platform (`liminal_libs.machines.MachinePlugin`, plugin API 2.2, its icon Vultr's V):

- **It shows** the account (its name, the key's permissions, the balance, the charges pending this month and the last
  payment); the instances, each with its power, region, plan, public IPv4 and IPv6 addresses, its plan's price a month
  and an hour (its region's price where Vultr prices it apart) and when it was made; the domains on Vultr's DNS and each
  one's records; the firewall groups, the instances linked to each and each group's rules; the SSH keys with their
  fingerprints; the block storage volumes; the reserved IPs; and how many bare metal servers, snapshots, backups,
  Kubernetes clusters, load balancers and managed databases the account holds.
- **It changes only what costs nothing**, each change through a form the page confirms first:
  - an instance **started** or **rebooted**, or **halted** (asked twice: a halt powers the instance off at once);
  - a DNS record **set** (created, or its own record updated) or **removed**, every other record kept;
  - a firewall rule **added** or **removed** (a risky one asked twice: below);
  - an SSH key **added** or **removed**.
- **Dynamic DNS**: hosts kept at this network's public IPv4 address, through Vultr's DNS.
- **It never** makes an instance, a volume, a snapshot, a backup or a reserved IP, never resizes, restores, reinstalls
  or destroys anything, and never turns backups or DDoS protection on: the client holds none of those calls (its tests
  check its source for them).

**A stopped instance still bills.** Vultr's docs: "Stopping an instance does not halt billing"; Vultr bills a server
hourly (capped at 672 hours a month, 730 for GPUs) until it is destroyed. The page says so beside the instances, in
the halt's confirmation and in its facts.

While it is attached to the platform app, it reads the account every quarter of an hour and checks the Dynamic DNS
hosts every `VULTR_DDNS_MINUTES` (5), in a thread of its own. Detached (the platform ending, the plugin disabled or not
valid), nothing of it runs. Its status is what it read last: no request is made to draw the page.

## From the platform's page

The tables: Dynamic DNS (when hosts are set), Instances, Domains, each domain's records, Firewall groups, each group's
rules, SSH keys, Block storage, Reserved IPs, and The account's other resources. The actions: **Refresh** and **Update
DNS now**. The forms:

- **Start…** on a stopped instance, **Reboot…** and **Halt…** on a running one. Vultr's docs call a restart a hard
  reboot: its confirmation says so. A halt is asked a second time ("Halt it anyway?"): Vultr's API has no other way to
  power an instance off, and its docs differ on how cleanly a halt stops the system, so anything not saved may be lost.
- **Set a record…** under each domain's records (the name, the type, the data, the TTL, and for MX and SRV the
  priority), and **Remove…** on each record. An A, AAAA or CNAME replaces the host's records of its type (the first one
  updated, any others removed); the other types are added beside the host's others. A CNAME stands alone, never at the
  domain itself. TXT text is sent in double quotes, as Vultr's DNS keeps it. The zone is read before each change and
  again after it; a record changed since the page showed it is not removed.
- **Add a rule…** under each group's rules (IPv4 or IPv6, the protocol, the port or range for TCP and UDP, the
  address and its subnet size, notes), and **Remove…** on each rule. Asked a second time when the change is risky:
  a rule letting SSH (TCP 22) or every port in from the whole internet; a group's first rule while instances are linked
  to it (Vultr enforces a group once it holds a rule, so everything else, SSH too, is dropped), unless it lets SSH in;
  removing a group's last rule while instances are linked to it (a group without rules is not enforced: every port open
  again); removing the only rule letting SSH in.
- **Add a key…** (a public key's one line; a private key is refused) and **Remove…** on each key. Vultr copies a key to
  an instance when it is deployed: no instance running changes.

## Setting it up

1. **Make the API key**: Vultr's console, **Account > API** (under Other), **Enable API**; the Personal Access Token
   shown there is the key (https://console.vultr.com/settings/#settingsapi).
2. **Allow this network's address**: a Vultr API key answers only from the addresses its **Access Control** allows,
   set on the same page (Account > API > Access Control; for an organization user's own key: Manage Organization >
   Users > the user > API Access > Access Control List). Add this network's public IPv4 address, or its subnet
   (Vultr's refusal names the address it saw: "Unauthorized IP address: …"; the plugin's page shows this network's
   address once Dynamic DNS has checked it). Vultr advises against allowing every address.
3. **Safest: a key of a limited user.** Vultr's keys are not scoped to products (one key reaches every resource its user
   may), but each user has a key of its own with that user's permissions (Vultr's console: Users). For this plugin:
   **View Servers** (the reads), **Manage Servers** (start, reboot, halt; Vultr's permission also lets a key destroy a
   server: the plugin never asks it), **Manage DNS** (the records and Dynamic DNS), **Manage Firewall** (the rules); not
   Deploy New Servers, Upgrade Existing Servers nor Manage Users. A part the key's user may not read is said beside the
   rest (that table "not read", the reason in its note).
4. **Enter the settings**: on the platform's page, the plugin's **Settings…** asks for each one below, the key typed
   hidden; no value is ever shown back. They are pairs the plugin asks of the login of the app it is attached to, each
   named by its variable (VULTR_API_KEY is the pair `vultr-api-key`): today the platform's login keeps them as your user
   environment variables, and the plugin reads them at once. Setting the variables yourself works too.

| Variable | | |
|---|---|---|
| `VULTR_API_KEY` | needed (secret) | the key of step 1 |
| `VULTR_DDNS_HOSTS` | optional | the hosts kept at this network's address, comma separated, in domains on Vultr's DNS: `home.example.com`, `@.example.com` (the domain itself) |
| `VULTR_DDNS_MINUTES` | optional | minutes between Dynamic DNS checks, 1 to 1440 (5 unless set) |

The plugin keeps no settings file and never shows a value: its status names the settings that are set.

## Dynamic DNS

This network's public IPv4 address is asked of name servers that answer with the asker's own (`myip.opendns.com` of
OpenDNS's 208.67.222.222, else Google's `o-o.myaddr.l.google.com` of 216.239.32.10), through the library's
`machines.ddns.Keeper`. Each host's records are read through the API (`GET /domains/{domain}/records?name=…`), and its
A record set only when it differs (Update DNS now checks every host, and sends nothing where it is already right): its
own record updated, any other A record at the host removed, or one made (TTL 300 s) where there is none. A host that is
a CNAME, or in no domain on the account's Vultr DNS, is said, not touched. Dynamic DNS goes through the API, so it
needs the key too.

## Valid, and the platform

The plugin is valid while its key is set and its last read worked, or has not been tried yet: the platform disables a
plugin that is not valid. A key refused (wrong, rotated, or this network's address not in its Access Control) makes it
not valid, its `why` saying so and where to set it; a read that failed is taken as untried a quarter of an hour later
(the platform attaches it again and it is tried again), or at once when the key changes. A part the key may not read
(an HTTP 403) leaves the plugin valid and is said as its `problem`.

## Its hooks

`present`, `status` (the summary, the facts, `tables`, `actions`, `forms`), `refresh()`, `balance()`, `servers()`,
`domains()`, `records(domain)`, `firewalls()`, `ssh_keys()`, `start(instance, label="")`, `reboot(instance, label="")`,
`halt(instance, label="", accept_halt=False)`, `set_record(domain, name, rtype, data, ttl=None, priority=None)`,
`remove_record(domain, record, name="", rtype="", data="")`,
`add_rule(group, ip_type, protocol, port, subnet, subnet_size, notes="", accept_risk=False)`,
`remove_rule(group, rule, protocol="", port="", source="", accept_risk=False)`, `add_key(name, ssh_key)`,
`remove_key(key, name="")`, `ddns_update(force=True)`. A refusal is a `ValueError` (`records.Refusal`), its `accept`
naming the argument that accepts it (`accept_halt`, `accept_risk`): the page's second confirmation. A change's answer:
`said`, `lines` (what was sent and the check after it), `ok`.

## From the command line

Its settings read from the environment (as this shell has them):

```
python -m plugin_platform_vultr status
python -m plugin_platform_vultr account
python -m plugin_platform_vultr servers
python -m plugin_platform_vultr domains
python -m plugin_platform_vultr records example.com
python -m plugin_platform_vultr firewalls
python -m plugin_platform_vultr keys
python -m plugin_platform_vultr ddns [--now]
python -m plugin_platform_vultr power web-1 on|off|reboot
python -m plugin_platform_vultr set example.com home A 203.0.113.7 --ttl 300
python -m plugin_platform_vultr remove example.com home A
```

Each change asks `yes` on the terminal first (a halt twice). `--json` before the command prints the answer as JSON. The
firewall rules and the SSH keys are changed from the platform's page.

## Its API

It attaches to **Vultr's API v2** (`https://api.vultr.com/v2`): a REST API over HTTPS doing what Vultr's customer portal
does, JSON both ways, every request bearing the key (`Authorization: Bearer`), a list paged by a cursor (`per_page`, at
most 500; `cursor` from `meta.links.next`), a 4xx answered with an `error`. Its reference is one OpenAPI 3.0 document
(the reference page's Download button gives the file). The plugin's page draws its card (`card.py`): every one of the
reference's 43 sections, what the plugin does with each, the 29 calls it makes and the notable ones it never makes
(those that start a charge marked so), and the facts it learned (the requests made, the last answer, when the account
was read).

- Reference: https://www.vultr.com/api/
- API access, keys and access control: https://docs.vultr.com/platform/other/api
- Access control: https://docs.vultr.com/platform/other/api/manage-api-access-control
- Permissions a user can be given: https://docs.vultr.com/support/platform/users/what-permissions-can-be-granted-to-users
- Pricing: https://www.vultr.com/pricing/; billing: https://docs.vultr.com/support/platform/billing/how-am-i-billed-for-my-servers
- Stopped instances are still billed: https://docs.vultr.com/support/platform/billing/are-stopped-instances-still-billed-on-vultr
- Status: https://status.vultr.com/; changes: https://docs.vultr.com/platform/api-opensource-changelog
- vultr-cli: https://github.com/vultr/vultr-cli; GoVultr: https://github.com/vultr/govultr

**Limits**: more than 30 requests a second from one address may be answered 429, with a `Retry-After` (the reference's
introduction). The plugin keeps to ten a second and waits out a 429 (the library's `RestClient`); a refresh is about
fifteen requests and one more per domain and per firewall group (at most 25 of each), every quarter of an hour; Dynamic
DNS one request per host every few minutes, one or two more when a record changes.

## Install

```
pip install "plugin-platform-vultr @ git+https://github.com/pcxmac-dev/plugin-platform-vultr@main"
```

or, for the platform's preview, a checkout in the plugin directory (`LIMINAL_PLUGINS`). Its tests use stand-ins for
Vultr and DNS alone (`python -m pytest`): none reaches Vultr or the network. `LIMINAL_VENDOR_PAGES=1` adds one that asks
each address on its card once.
