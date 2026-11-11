# Changelog

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
