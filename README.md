# Multi-vendor vulnerability and upgrade tracker (DEMO)

Personal learning project. Hostnames, sites and installed versions are made up.
Advisories are real public data (CISA KEV catalog + CVE records), refreshed daily by a GitHub Action.

- `index.html` the dashboard (needs the `data/` folder next to it; open via GitHub Pages)
- `data/advisories.json` refreshed daily by `feed/refresh.py`
- `data/devices.json` made-up inventory
- `data/playbooks.json` upgrade steps per vendor (illustrative times)
- `data/remediation.json` made-up history

Prototype only: the matcher is rule-based, ranges the vendor writes as free text are marked "Needs review",
and which device setting an advisory depends on is mapped by hand for a few CVEs.
