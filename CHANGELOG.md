# Changelog

## 0.1.7 (2026-11-26)

Its reads made with the account's key are asked only from the page too. The user, 2026-11-26: "Yes, closed by
default" (liminal-libs 1.107.0: a hook a plugin declares for no one is its page's alone), and of these reads:
"Page-only".

- **What only the page asks now, beside its changes**: `refresh`, `balance`, `servers`, `domains`, `records`, `firewalls`, `ssh_keys`.
  Each sends requests to the provider as you and returns what the account holds. Until now any plugin, and any program
  on this machine through the platform, could ask them. Another plugin's ask and an ask that names no one are refused
  (403) in words, and liminal-platform asks its login whether you are at the page (401 otherwise).
- `present` and `status` stay reads anyone here may ask: the status is what was read last, and no request is made to
  answer it. The background's reads and the command line call the code themselves: those are not asks.
- Every hook now says who may ask it, so the library's `conformance.warnings` is empty.

Tests: "its reads by anyone" became "its reads by the page alone": each read refused to another plugin and to no one,
nothing sent for it, and answered for the page; a test that no hook is left undeclared. They fail when a read is taken
out of `PAGE_ONLY_HOOKS`, on liminal-libs 1.106.0 and on 1.107.0 alike. No new requirement: the word is liminal-libs
1.66.0's.

## 0.1.6 (2026-11-25)

Its changes are asked only from the page (`PAGE_ONLY_HOOKS`, liminal-libs 1.66.0's word): the independent review's
finding PLT-H1, and the sweep of every plugin's hooks that followed it. The user, 2026-11-25, chose "Plugin releases":
each plugin says which of its hooks only its page asks.

- **What only the page asks**: `start`, `reboot`, `halt`, `set_record`, `add_record`, `remove_record`, `add_rule`,
  `remove_rule`, `add_key`, `remove_key`, `ddns_update` and `ddns_take_over`. Another plugin's ask of one is refused
  (403), and so is an ask that names no asker; liminal-platform 0.34.0 refuses one over HTTP (401) unless its login
  shows that you are at the page. A platform that holds no login asks them as before. The 401 rests on the login's
  word that your browser is signed in, and a local login signs `secret` and `default` in with no password, so a
  program on this PC can sign itself in and ask them still: a proof that a program cannot make is the login's and the
  platform's to give, not this plugin's.
- **Before**, the platform handed an ask of any program on this PC (`POST /api/machines/vultr/ask`, with a header
  anyone can send and a Host the client chooses, no sign-in) straight to the hook it named, and the hook used your
  API key. The page's dialogs were the only confirmation, and a second confirmation is an argument the asker sets:
  `halt` with `[id, label, true]` powered an instance off; `add_rule` with `accept_risk` true opened PostgreSQL or
  SSH to the whole internet, and `remove_rule` took out the only rule letting SSH in; `ddns_take_over` with
  `[host, null, true]` pointed a Dynamic DNS host holding another address at this network. `set_record` set the
  domain's own address to another and `add_record` added an MX record beside yours, neither asked twice.
- **As before**: its reads (`present`, `status`, `refresh` and the lists) are asked by anyone. The background (the
  account read every quarter of an hour, the Dynamic DNS checks) and the command line call the plugin's code
  themselves, not through an ask. The library floor stays 1.49.9: a library before 1.66.0 does not read the word, and
  asks the hooks as it did.
- Tests: `tests/test_who_asks.py`, through the library's own App over the stand-in Vultr: each of the twelve refused
  to another plugin and to no one, no request made; the same twelve asked from the page, each sent; the reads answered
  to a plugin; a Dynamic DNS pass run by the plugin's own code. A hook taken out of `PAGE_ONLY_HOOKS` fails it.
  Skipped on a library before 1.66.0.

## 0.1.5 (2026-11-24)

Removing a host's other records bound to the ones the refusal showed (the review of 2026-11-21, item 26). `set_record`
over a host with several records of its type is refused once, naming the ones it removes; with `accept_replace` it
then removed whatever the host held by the time the confirmation came. The page sends the same arguments again with
its second confirmation, so the refusal now keeps the records it named (IDs and data, by the change asked, for 15
minutes, 32 at most), and the accepted call is refused, nothing sent, when the host's records of the type are any
others now, or when no refusal showed them lately: set again, the new refusal names what it holds now. Binding as
liminal-libs 1.49.9's take-over binds `holds`. Test: an accept never shown, then one whose records changed after its
refusal, both refused with nothing written; asked again, replaced.

## 0.1.4 (2026-11-14)

Drawn under the platform's Cloud plugins section, in the list on the left (the user: "classify the cloud plugins under the 'cloud plugins' section which should be on the far left"): `SECTION = "cloud"`. That is liminal-libs
1.51.0's machine-plugin attribute; liminal-platform 0.25.0 draws it, and an older platform keeps the plugin under Machine
plugins. Nothing else changes.

## 0.1.3 (2026-11-11)

The third round (FIX3-clouds.md), with liminal-libs 1.49.8 (needed now): a take-over is single-use, its consent used
up once its write lands (the host is the keeper's own from then on); and only the serving platform settles: the
plugin's own command line, a one-shot platform command or an unattached plugin never does, since a shell's setting may
lack VULTR_DDNS_HOSTS and would empty the shared ddns.json.

Needs liminal-libs>=1.49.9: a take-over's consent is bound to the addresses it drops (a record changed after
a failed write is asked about again); the state file keeps each take-over's addresses.

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
