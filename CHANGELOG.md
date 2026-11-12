# Changelog

## 0.1.2 (2026-11-11)

What the re-verification of the audit's fixes found in Dynamic DNS (FIX2-clouds.md), fixed with liminal-libs 1.49.7
(needed now):
- **Take over… is asked twice.** It points the record at this network's address at once and drops every address it
  held, so one yes is not enough: `ddns_take_over(host, holds, accept_take_over)` hands the second confirmation on to
  the keeper (`Keeper.take_over(accept=...)`), which refuses it (`TakeOverRefused`, naming `accept_take_over`: the
  page's second confirmation, "Drop what it holds?") unless it is True itself. The plugin's own checks come first (the
  host is in the setting, the record still holds what the page showed).
- **A host taken out of the setting is let go, while the plugin ran or not**: the keeper's `settle` with the plugin's
  whole setting, once the account's domains are read (never a partial or unread list), in each Dynamic DNS pass and each
  refresh. Put back later, a host that holds another address is left as it is, its row offering Take over… again.
  `settle` replaces the plugin's own letting go.
- The third round (FIX3-clouds.md), with liminal-libs 1.49.8 (needed now): a take-over is single-use, its consent used
  up once its write lands (the host is the keeper's own from then on); and only the serving platform settles: the
  plugin's own command line, a one-shot platform command or an unattached plugin never does, since a shell's setting may
  lack VULTR_DDNS_HOSTS and would empty the shared ddns.json.

## 0.1.1 (2026-11-11)

What an audit of the cloud plugins found before any key went in (session 87405e6a: eight reviewers, a skeptic per
finding; FIX-clouds.md), fixed. Needs liminal-libs>=1.49.2.

- **Dynamic DNS changes only what is its own** (the library's 1.49.2 Keeper): a host with no A record (made), one already
  pointing at this network or at the address it set last (kept current, after a restart too: its state in the platform's
  folder, `vultr/ddns.json`), and one you take over on the page. A host holding another address, or several, is left as
  it is, its row offering **Take over…** (confirmed, naming what it holds and that what answers there stops answering);
  several addresses are never cut to one unasked. **Update DNS now** is a confirmed form, no longer one click. The
  address is asked again just before a write. A host taken out of the settings is let go. (The audit: saving a host had
  its live record pointed at home, and its other addresses deleted, within a minute.)
- **Set a record… and Add a record…, each saying what it does**: Set (A, AAAA, CNAME) replaces the host's records of its
  type, its confirmation says so, and it asks a second time, naming them, before any other record of that type goes
  (`accept_replace`); Add (every type but CNAME) adds beside the host's others, all kept. The command line has `set` and
  `add` alike. (The audit: the set's confirmation said every other record was kept while it deleted the host's others.)
- **A group's first firewall rule is asked twice** while instances are linked to it, whatever it lets in: from then on
  Vultr drops everything else (a website on 80 and 443 too). Opening a remote-control port to everyone (SSH, RDP, VNC,
  Docker's API) or every port is asked twice too. (The audit: a first rule letting SSH in was asked once, its dialog
  promising a second ask.)
- **A second confirmation counts only when it is True itself**: a string such as "false" or "yes", or a 1, from another
  program is refused like a missing one (accept_reboot, accept_halt, accept_risk, accept_replace).
- **A change is named by what the page showed**: a power change needs the instance's label, a record removed its name,
  type and data, a rule removed its protocol, port and source, a key removed its name (none by its ID alone).
- **The background runs only under the platform, and only set up**: attached by the charts app run alone, or with no key
  set, no thread starts; the key entered on the page starts it. Once detached, a refresh or a pass under way reads and
  writes nothing more, and no setting is read from the process's environment.
- **A read that does not get through** (no answer, a 429, a 5xx) leaves the plugin valid, said as its problem and tried
  again two minutes later (the audit: one dropped connection turned it grey for a quarter of an hour).
- **An instance's console link** (Vultr's `kvm`, a token in its query) is never handed on by `servers` or the command line.
- The key field of Add a key… is marked `secret` (for the platform, which logs a hook's arguments: the audit's blocker
  there is the platform's to fix).

The platform's one-shot commands (status, machine: `PlatformApp.once`, liminal-platform 0.20.1) start none of its background work.

## 0.1.0 (2026-11-11)

The first release (the user: "lets roll plugins for EC2, vultr, azure and google cloud"; for the clouds, "Free changes
only"; and "each plugin should reflect the the API its attached to, and present links that provide documentation, the
plugin interface should more or less contain what it already has, BUT, it should also expose more of what the API is
about"). Plugin API 2.2; needs liminal-libs>=1.49.0.

- Its settings read through the library's Login interface alone, as pairs named by their variables (`vultr-api-key`
  for VULTR_API_KEY, `vultr-ddns-hosts`, `vultr-ddns-minutes`); no settings file; the status names the settings set,
  never a value. The page, the README and the key's hint say that a Vultr API key answers only from the addresses its
  Access Control allows, and where that is set (Vultr's console: Account > API > Access Control).
- The account through Vultr's API v2 (the library's `RestClient`: the key as a bearer token, a 429 waited out, a read
  tried again, a write never sent twice, the key scrubbed from every word; at most ten requests a second, a third of
  Vultr's 30): the account (balance, pending charges, the key's permissions), the instances with their plan's price a
  month and an hour (the plans and regions read again every six hours and every day), the domains on Vultr's DNS and
  their records, the firewall groups and their rules, the SSH keys, block storage, reserved IPs, and the counts of bare
  metal servers, snapshots, backups, Kubernetes clusters, load balancers and managed databases (a page of one each).
  A part the key may not read is said beside the rest.
- The free changes, each through a form the platform's page confirms: an instance started; rebooted (asked twice: a
  hard restart, Vultr's docs call it a hard reboot, so unsaved data may be lost) or halted (asked twice; a halted
  instance still bills: Vultr's docs say stopping does not halt billing); a DNS record set (created, or its own record updated; an A, AAAA or CNAME replacing the host's others of
  its type) or removed by its ID once it is the one shown, every other record kept, the zone read before and after; a
  firewall rule added or removed, a risky one asked twice (SSH or every port open to the whole internet, a group's
  first rule while instances are linked, its last rule, the only rule letting SSH in); an SSH key added or removed.
  Nothing that starts a charge: the client holds no call that creates, resizes, restores or destroys anything billed,
  nor turns backups on (a test checks its source).
- Dynamic DNS through Vultr's DNS (the library's `Keeper`): this network's address asked of OpenDNS's and Google's name
  servers, a host's A record set only where it differs (Update DNS now: every host checked), made where there is none,
  its other A records removed; a CNAME host or one in no domain of the account said.
- Its API on its page (`apis`, `card.py`): Vultr's API v2 with its reference, access-control, permissions, pricing,
  billing, status, changelog, console, CLI and SDK pages; all 43 sections of the reference, what the plugin does with
  each; the 29 calls it makes and the notable others (those that start a charge marked); verified 2026-11-11. Its
  `api_facts()`: the requests made, the last answer, a wait asked, when the account was read, the key's permissions.
- While attached to the platform app: the account read every quarter of an hour and the Dynamic DNS hosts checked every
  VULTR_DDNS_MINUTES (5) in a thread of its own; detached, nothing runs. Valid while the key is set and its last read
  worked or is untried.
- `python -m plugin_platform_vultr status | account | servers | domains | records | firewalls | keys | ddns | power | set
  | remove` (each change asking `yes` first, a reboot and a halt twice).
