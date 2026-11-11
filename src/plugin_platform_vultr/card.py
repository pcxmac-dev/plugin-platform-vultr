"""What the plugin attaches to (plugin API 2.2, liminal_libs.sources.apis): Vultr's API v2, as Vultr's own pages give it,
read 2026-11-11: the reference (https://www.vultr.com/api/, one OpenAPI 3.0 document, "Vultr API" 2.0, 43 sections and
612 operations), Vultr Docs (API access and its access control, user permissions, billing, the firewall's FAQ, restart and
stop), the pricing page and the status page. Every part of the reference is an Area (what the plugin does with it, or
nothing); every call the client makes (api.ENDPOINTS) is a Call it uses, beside the notable ones it never makes (those that
create, resize, restore or destroy what is billed among them). Each address was read that day; LIMINAL_VENDOR_PAGES=1 runs
the page check (tests/test_contract.py)."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

REF = "https://www.vultr.com/api/"
VERIFIED = "2026-11-11"


def tag(section: str) -> str:
    """A section of the reference (its Redoc anchor)."""
    return f"{REF}#tag/{section}"


def op(section: str, operation: str) -> str:
    """An operation of the reference (its Redoc anchor)."""
    return f"{REF}#tag/{section}/operation/{operation}"


# the reference's sections in its own order: (anchor, name, what it is, what the plugin does with it)
SECTIONS = (
    ("account", "Account", "your user account: name, email, permissions, balance, pending charges, bandwidth, BGP",
     "the account's facts: its name, the key's permissions, the balance and the charges pending this month"),
    ("application", "Applications", "the One-Click and Marketplace applications an instance can be deployed with", ""),
    ("api-keys", "API Keys", "the signed-in user's own API keys: listed, made, deleted", ""),
    ("backup", "Backups", "an instance's automatic, scheduled images", "counted among the other resources"),
    ("baremetal", "Bare Metal", "single-tenant physical servers: deployed, powered, reinstalled, destroyed",
     "counted among the other resources"),
    ("billing", "Billing", "read-only billing: its history, invoices and their items, the pending charges", ""),
    ("block", "Block Storage", "SSD volumes of 10 GB to 40,000 GB, attached to an instance and moved between them",
     "the Block storage table"),
    ("CDNs", "CDNs", "pull and push zones of Vultr's content delivery network", ""),
    ("clusters", "Clusters", "groups of GPU or bare metal instances deployed and managed together", ""),
    ("Container-Registry", "Container Registry", "public and private container image registries", ""),
    ("dns", "DNS", "Vultr's free DNS hosting: domains, their records, SOA and DNSSEC",
     "the Domains table; each domain's records, set and removed; Dynamic DNS"),
    ("firewall", "Firewall", "firewall groups of inbound rules, linked to instances",
     "the Firewall groups table; each group's rules, added and removed"),
    ("iam", "IAM", "policies, roles, groups and invitations controlling who may do what", ""),
    ("instances", "Instances", "cloud compute instances: deployed, powered, reinstalled, resized, restored, destroyed",
     "the Instances table; an instance started, rebooted or halted"),
    ("instance-templates", "Instance Templates", "reusable deployment settings for instances and clusters", ""),
    ("iso", "ISO", "ISO images uploaded or from the public library, to boot an instance from", ""),
    ("kubernetes", "Kubernetes", "Vultr Kubernetes Engine clusters and their node pools", "counted among the other resources"),
    ("load-balancer", "Load Balancers", "load balancers in front of instances: their rules, firewall and certificates",
     "counted among the other resources"),
    ("logs", "Logs", "the account's activity: logins, the portal's and the API's requests", ""),
    ("managed-databases", "Managed Databases", "managed MySQL, PostgreSQL, Valkey and Kafka",
     "counted among the other resources"),
    ("marketplace", "Marketplace", "the vendors' applications published on Vultr", ""),
    ("oauth", "OAuth Apps", "OAuth 2.0 apps that act for Vultr users who authorize them", ""),
    ("oidc", "OIDC", "OpenID Connect providers and issuers for federated sign-in", ""),
    ("organizations", "Organizations", "the organization's settings", ""),
    ("scim", "SCIM (Pre-Release)", "users and groups provisioned by an identity provider", ""),
    ("s3", "Object Storage", "S3-compatible object storage: subscriptions, clusters, tiers and keys", ""),
    ("os", "Operating Systems", "the operating systems an instance can be deployed with", ""),
    ("plans", "Plans", "the instance plans (vCPUs, RAM, disk, bandwidth) and their prices, by region",
     "each instance's price a month and an hour, its region's where Vultr prices it apart"),
    ("private-Networks", "Private Networks", "the older private networks (deprecated: VPCs instead)", ""),
    ("serverless-inference", "Serverless Inference", "GenAI models served without servers of your own", ""),
    ("software-licenses", "Software Licenses", "the software licenses attached to instances", ""),
    ("tickets", "Tickets", "the account's support tickets", ""),
    ("VPCs", "VPCs", "isolated networks within a region, attached to instances", ""),
    ("reserved-ip", "Reserved IPs", "addresses reserved and moved between instances (floating IPs)", "the Reserved IPs table"),
    ("region", "Regions", "Vultr's locations and what each offers", "the instances' cities"),
    ("snapshot", "Snapshots", "an instance's images taken by hand", "counted among the other resources"),
    ("subaccount", "Sub-Accounts", "accounts linked to this one for billing and administration", ""),
    ("ssh", "SSH Keys", "the public keys copied to new instances when they are deployed",
     "the SSH keys table; a key added or removed"),
    ("startup", "Startup Scripts", "boot and PXE scripts run on new deployments", ""),
    ("storage-gateways", "Storage Gateways", "NFS access to Vultr File System", ""),
    ("users", "Users", "the account's users, their permissions, API keys and API access control lists", ""),
    ("VFS", "VFS", "Vultr File System, shared file storage for instances and pods", ""),
    ("blocks", "Block Storage clones", "a block storage volume cloned, and the clone's progress", ""),
)
AREA = {anchor: name for anchor, name, _, _ in SECTIONS}


def call(section: str, operation: str, name: str, about: str, used: str = "", writes: bool = False,
         costs: bool = False) -> Call:
    return Call(name, about, AREA[section], used, op(section, operation), writes, costs)


CALLS = (
    # -- the calls the plugin makes (api.ENDPOINTS) -------------------------------------------------------------------------
    call("account", "get-account", "GET /account", "the account: name, email, permissions (acls), balance, pending charges",
         "the account's facts, every refresh"),
    call("instances", "list-instances", "GET /instances", "every instance, its plan, region, addresses and power",
         "the Instances table"),
    call("instances", "get-instance", "GET /instances/{instance-id}", "one instance",
         "an instance read afresh before and after a power change"),
    call("plans", "list-plans", "GET /plans", "every plan and its price a month and an hour (type=all)",
         "each instance's price (read again every six hours)"),
    call("region", "list-regions", "GET /regions", "every region: its city, country and continent",
         "the instances' cities (read again every day)"),
    call("dns", "list-dns-domains", "GET /domains", "the domains on Vultr's DNS", "the Domains table"),
    call("dns", "list-dns-domain-records", "GET /domains/{dns-domain}/records",
         "a domain's records (name: relative to the domain, empty for the apex; type)",
         "each domain's records; a zone read afresh before a change and after it; Dynamic DNS reading a host's A record"),
    call("firewall", "list-firewall-groups", "GET /firewalls", "the firewall groups: rules, instances linked",
         "the Firewall groups table"),
    call("firewall", "get-firewall-group", "GET /firewalls/{firewall-group-id}", "one group: its rules and instances linked",
         "a group read afresh before a rule changes"),
    call("firewall", "list-firewall-group-rules", "GET /firewalls/{firewall-group-id}/rules", "a group's rules",
         "each group's rules; read afresh before and after a change"),
    call("ssh", "list-ssh-keys", "GET /ssh-keys", "the account's SSH keys", "the SSH keys table"),
    call("block", "list-blocks", "GET /blocks", "the block storage volumes, their size, cost and instance",
         "the Block storage table"),
    call("reserved-ip", "list-reserved-ips", "GET /reserved-ips", "the reserved IPs and the instances they are on",
         "the Reserved IPs table"),
    call("baremetal", "list-baremetals", "GET /bare-metals", "the bare metal servers",
         "their count (a page of one: meta.total)"),
    call("snapshot", "list-snapshots", "GET /snapshots", "the snapshots", "their count (a page of one: meta.total)"),
    call("backup", "list-backups", "GET /backups", "the automatic backups", "their count (a page of one: meta.total)"),
    call("kubernetes", "list-kubernetes-clusters", "GET /kubernetes/clusters", "the Kubernetes clusters", "their count"),
    call("load-balancer", "list-load-balancers", "GET /load-balancers", "the load balancers",
         "their count (a page of one: meta.total)"),
    call("managed-databases", "list-databases", "GET /databases", "the managed databases", "their count"),
    call("instances", "start-instance", "POST /instances/{instance-id}/start", "an instance started (204)",
         "Start… (confirmed)", writes=True),
    call("instances", "reboot-instance", "POST /instances/{instance-id}/reboot",
         "an instance rebooted (204; Vultr's docs call a restart a hard reboot)",
         "Reboot… (confirmed, then asked again: a hard restart)", writes=True),
    call("instances", "halt-instance", "POST /instances/{instance-id}/halt",
         "an instance halted: powered off, still billed (204)", "Halt… (confirmed, then asked again)", writes=True),
    call("dns", "create-dns-domain-record", "POST /domains/{dns-domain}/records",
         "a record created: name, type, data, ttl, priority (MX and SRV)",
         "Set a record… where the host has none of its kind; Dynamic DNS's first record", writes=True),
    call("dns", "update-dns-domain-record", "PATCH /domains/{dns-domain}/records/{record-id}",
         "a record's name, data, ttl or priority changed, the rest kept (204)",
         "Set a record… over the host's own; Dynamic DNS", writes=True),
    call("dns", "delete-dns-domain-record", "DELETE /domains/{dns-domain}/records/{record-id}", "a record deleted (204)",
         "Remove…; Set a record… replacing the host's others of its type", writes=True),
    call("firewall", "post-firewalls-firewall-group-id-rules", "POST /firewalls/{firewall-group-id}/rules",
         "a rule added: ip_type, protocol, port, subnet, subnet_size, source, notes",
         "Add a rule… (a risky one asked twice)", writes=True),
    call("firewall", "delete-firewall-group-rule", "DELETE /firewalls/{firewall-group-id}/rules/{firewall-rule-id}",
         "a rule deleted (204)", "Remove… (a risky one asked twice)", writes=True),
    call("ssh", "create-ssh-key", "POST /ssh-keys", "a key added for new deployments (running instances keep theirs)",
         "Add a key…", writes=True),
    call("ssh", "delete-ssh-key", "DELETE /ssh-keys/{ssh-key-id}", "a key deleted (204)", "Remove…", writes=True),
    # -- the API's other notable calls, never made here ------------------------------------------------------------------
    call("instances", "create-instance", "POST /instances", "an instance deployed: billed hourly from then on",
         writes=True, costs=True),
    call("instances", "update-instance", "PATCH /instances/{instance-id}",
         "an instance changed: a larger plan, backups or DDoS protection raise its charge", writes=True, costs=True),
    call("instances", "delete-instance", "DELETE /instances/{instance-id}",
         "an instance destroyed, its data with it (what ends its billing)", writes=True),
    call("instances", "reinstall-instance", "POST /instances/{instance-id}/reinstall", "an instance reinstalled: its data erased",
         writes=True),
    call("instances", "restore-instance", "POST /instances/{instance-id}/restore",
         "an instance restored from a backup or a snapshot", writes=True),
    call("instances", "create-instance-backup-schedule", "POST /instances/{instance-id}/backup-schedule",
         "the schedule of an instance's automatic backups (backups add 20% to its fee)", writes=True),
    call("instances", "get-instance-upgrades", "GET /instances/{instance-id}/upgrades",
         "the plans, applications and systems an instance can be changed to"),
    call("instances", "get-instance-bandwidth", "GET /instances/{instance-id}/bandwidth", "an instance's bandwidth by day"),
    call("instances", "halt-instances", "POST /instances/halt", "several instances halted at once", writes=True),
    call("instances", "start-instances", "POST /instances/start", "several instances started at once", writes=True),
    call("instances", "reboot-instances", "POST /instances/reboot", "several instances rebooted at once", writes=True),
    call("billing", "pending-charges", "GET /billing/pending-charges", "this month's pending charges, item by item"),
    call("billing", "list-billing-history", "GET /billing/history", "the account's billing history"),
    call("billing", "list-invoices", "GET /billing/invoices", "the account's invoices"),
    call("account", "get-account-bandwidth", "GET /account/bandwidth", "the account's bandwidth this month and the last"),
    call("snapshot", "create-snapshot", "POST /snapshots", "a snapshot taken: $0.05 per GB a month", writes=True, costs=True),
    call("snapshot", "delete-snapshot", "DELETE /snapshots/{snapshot-id}", "a snapshot deleted", writes=True),
    call("reserved-ip", "create-reserved-ip", "POST /reserved-ips", "an address reserved: billed", writes=True, costs=True),
    call("reserved-ip", "attach-reserved-ip", "POST /reserved-ips/{reserved-ip}/attach", "a reserved IP put on an instance",
         writes=True),
    call("block", "create-block", "POST /blocks", "a block storage volume made: billed", writes=True, costs=True),
    call("block", "attach-block", "POST /blocks/{block-id}/attach", "a volume attached to an instance", writes=True),
    call("blocks", "create-block-storage-clone", "POST /blocks/clone", "a volume cloned: another billed volume",
         writes=True, costs=True),
    call("baremetal", "create-baremetal", "POST /bare-metals", "a bare metal server deployed: billed",
         writes=True, costs=True),
    call("baremetal", "halt-baremetal", "POST /bare-metals/{baremetal-id}/halt",
         "a bare metal server halted (the CLI's docs: a forced power-off)", writes=True),
    call("kubernetes", "create-kubernetes-cluster", "POST /kubernetes/clusters", "a Kubernetes cluster made: its nodes billed",
         writes=True, costs=True),
    call("load-balancer", "create-load-balancer", "POST /load-balancers", "a load balancer made: billed",
         writes=True, costs=True),
    call("managed-databases", "create-database", "POST /databases", "a managed database made: billed",
         writes=True, costs=True),
    call("s3", "create-object-storage", "POST /object-storage", "an object storage subscription made: billed",
         writes=True, costs=True),
    call("dns", "create-dns-domain", "POST /domains", "a domain added to Vultr's DNS", writes=True),
    call("dns", "delete-dns-domain", "DELETE /domains/{dns-domain}", "a domain and its records taken off Vultr's DNS",
         writes=True),
    call("dns", "get-dns-domain-dnssec", "GET /domains/{dns-domain}/dnssec", "a domain's DNSSEC records"),
    call("dns", "update-dns-domain-soa", "PATCH /domains/{dns-domain}/soa", "a domain's SOA changed", writes=True),
    call("firewall", "create-firewall-group", "POST /firewalls", "a firewall group made", writes=True),
    call("users", "list-users", "GET /users", "the account's users and their permissions"),
    call("users", "list-user-ip-whitelist", "GET /users/{user-id}/ip-whitelist", "a user's API access control list"),
    call("users", "add-user-ip-whitelist", "POST /users/{user-id}/ip-whitelist",
         "an address allowed to use a user's API key", writes=True),
    call("api-keys", "list-api-keys", "GET /apikeys", "the signed-in user's API keys"),
    call("os", "list-os", "GET /os", "the operating systems offered"),
)

VULTR_API = Api(
    name="Vultr API v2",
    maker="Vultr",
    about=("Vultr's REST API does what its customer portal does: compute instances and bare metal, Kubernetes, managed "
           "databases, block and object storage, networking (DNS, firewalls, VPCs, reserved IPs, load balancers) and the "
           "account's billing, users and keys. JSON over HTTPS, its lists paged by a cursor; its reference is one OpenAPI "
           "3.0 document (the reference page's Download gives the file). The plugin reads the account and its parts, and "
           "makes only the changes that cost nothing."),
    kind="rest",
    base="https://api.vultr.com/v2",
    version="v2 (the reference's OpenAPI document: \"Vultr API\" 2.0, read 2026-11-11)",
    auth=("an API key (Personal Access Token) as `Authorization: Bearer`, made in Vultr's console: Account > API, Enable "
          "API. Each user has a key of its own, with that user's permissions (one key reaches every resource the user "
          "may: keys are not scoped to products); a key answers only from the addresses its Access Control allows, set "
          "on the same page"),
    limits=("more than 30 requests a second from one address may be answered 429 with a Retry-After in seconds (the "
            "reference's introduction); a page of a list holds at most 500 (per_page, 100 unless set). The plugin keeps "
            "to ten a second: a refresh is about fifteen requests and one more per domain and per firewall group, every "
            "quarter of an hour; Dynamic DNS one per host every few minutes"),
    costs=("the API costs nothing; what it creates is billed hourly, capped at 672 hours a month (730 for GPUs): "
           "instances, bare metal, block storage, snapshots ($0.05 per GB a month), reserved IPs, load balancers, "
           "Kubernetes, databases, object storage; automatic backups add 20% to an instance's fee, DDoS protection $10 a "
           "month. A stopped instance still bills: Vultr's docs say stopping does not halt billing, only destroying it "
           "does. DNS hosting is free"),
    links=(
        Link("API v2 reference (one OpenAPI 3.0 document: its Download button gives the file)", REF, "reference"),
        Link("API access, keys and access control", "https://docs.vultr.com/platform/other/api", "auth"),
        Link("Enable API access", "https://docs.vultr.com/platform/other/api/enable-user-api-access", "auth"),
        Link("Manage API access control (the addresses a key answers from)",
             "https://docs.vultr.com/platform/other/api/manage-api-access-control", "auth"),
        Link("Can API keys be scoped to products? (no: one key reaches every resource; limit it by address)",
             "https://docs.vultr.com/support/platform/api/can-i-scope-api-keys-to-specific-products", "auth"),
        Link("The permissions a user can be given",
             "https://docs.vultr.com/support/platform/users/what-permissions-can-be-granted-to-users", "guide"),
        Link("Rate limit and paging (the reference's introduction)", f"{REF}#section/Introduction", "limits"),
        Link("Pricing", "https://www.vultr.com/pricing/", "pricing"),
        Link("How servers are billed (hourly, capped each month)",
             "https://docs.vultr.com/support/platform/billing/how-am-i-billed-for-my-servers", "pricing"),
        Link("Stopped instances are still billed until destroyed",
             "https://docs.vultr.com/support/platform/billing/are-stopped-instances-still-billed-on-vultr", "pricing"),
        Link("Server status", "https://status.vultr.com/", "status"),
        Link("API and open source tooling changelog", "https://docs.vultr.com/platform/api-opensource-changelog", "changelog"),
        Link("Console: the API key and its access control", "https://console.vultr.com/settings/#settingsapi", "console"),
        Link("vultr-cli, the official command line tool", "https://github.com/vultr/vultr-cli", "tool"),
        Link("GoVultr, the official Go client", "https://github.com/vultr/govultr", "sdk"),
        Link("Vultr's Terraform provider", "https://github.com/vultr/terraform-provider-vultr", "sdk"),
        Link("Vultr on GitHub", "https://github.com/vultr/", "source"),
        Link("Restart an instance: a hard reboot",
             "https://docs.vultr.com/products/compute/instances/cloud-compute/management/restart-instance", "guide"),
        Link("Stop an instance: billing continues",
             "https://docs.vultr.com/products/compute/instances/cloud-compute/management/stop-instance", "guide"),
        Link("Firewall groups FAQ (a group is enforced once it holds a rule)",
             "https://docs.vultr.com/products/network/firewall-groups/faq", "guide"),
        Link("Vultr DNS: provisioning, name servers, management", "https://docs.vultr.com/products/network/dns", "guide"),
        Link("Terms of Service", "https://www.vultr.com/legal/tos/", "terms"),
    ),
    areas=tuple(Area(name, about, tag(anchor), covered) for anchor, name, about, covered in SECTIONS),
    calls=CALLS,
    verified=VERIFIED,
)

APIS = (VULTR_API,)
