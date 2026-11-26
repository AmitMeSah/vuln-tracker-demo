#!/usr/bin/env python3
"""Refresh data/advisories.json from public sources. Standard library only.

Sources:
  * CISA Known Exploited Vulnerabilities (KEV) catalog, via CISA's official GitHub mirror
  * CVE records (CVE Program, cvelistV5 on GitHub): vendor-supplied affected version ranges
  * FIRST EPSS API: exploit-likelihood score (optional; left empty if unreachable)

Version ranges are parsed per vendor. Anything that cannot be parsed is kept with an
empty range list so the dashboard sends it to a person instead of guessing.
"""
import json, re, sys, urllib.request, datetime, os

OUT = os.path.join(os.path.dirname(__file__), "..", "data", "advisories.json")
KEV_URLS = [
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
]
CVE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{y}/{d}xxx/{cid}.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={ids}"
SINCE = "2023-01-01"  # only KEV entries added on or after this date

# A person decides which device setting an advisory depends on. This is NOT from the feed.
CURATED_FEATURE = {
    "CVE-2023-36844": "jweb_enabled", "CVE-2023-36845": "jweb_enabled",
    "CVE-2023-36846": "jweb_enabled", "CVE-2023-36847": "jweb_enabled",
    "CVE-2024-53704": "sslvpn_enabled",
    "CVE-2023-3519": "gateway_enabled", "CVE-2023-4966": "gateway_enabled",
    "CVE-2025-5777": "gateway_enabled", "CVE-2025-6543": "gateway_enabled",
    "CVE-2023-6548": "admin_portal_exposed", "CVE-2023-6549": "gateway_enabled",
}

def get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-tracker-demo"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))

def nums(v):
    return [int(x) for x in re.findall(r"[0-9]+", str(v))]

def canon(v):
    a, p = v["vendorProject"], v["product"]
    if a == "Juniper" and p == "Junos OS": return ("Juniper", "Junos OS")
    if a == "SonicWall" and p.startswith("SonicOS"): return ("SonicWall", "SonicOS")
    if a == "Ivanti" and "Connect Secure" in p and "Pulse" not in p: return ("Ivanti", "Connect Secure")
    if a == "Citrix" and "NetScaler" in p and "SD-WAN" not in p: return ("Citrix", "NetScaler ADC")
    if a == "Arista" and p == "Extensible Operating System": return ("Arista", "EOS")
    return None

def rng(mn, mx, inc, fixed, tier):
    return {"min": mn, "max": mx, "inc": inc, "fixed": fixed, "tier": tier}

def parse(vendor, affected):
    """Return list of ranges parsed from the CNA 'affected' block."""
    out = []
    def add(r):
        if r not in out: out.append(r)
    if vendor == "Juniper":
        for a in affected:
            if a.get("product") != "Junos OS": continue
            for v in a.get("versions", []):
                lt = (v.get("lessThan") or "").split(",")[0].strip()
                if v.get("status") != "affected" or not lt or "*" in lt: continue
                mn = v.get("version", "0")
                add(rng("0" if mn in ("0", "unspecified") else mn, lt, False, lt, "Auto-matched"))
    elif vendor == "Citrix":
        for a in affected:
            if a.get("product") not in ("ADC", "Gateway", "NetScaler ADC", "NetScaler Gateway"): continue
            for v in a.get("versions", []):
                ver, lt, le = v.get("version", ""), v.get("lessThan"), v.get("lessThanOrEqual")
                txt = " ".join(str(x) for x in (ver, lt, le))
                if v.get("status") != "affected" or "FIPS" in txt or "NDcPP" in txt: continue
                if ver == "0" and lt and "-" in lt:
                    train = ".".join(str(n) for n in nums(lt)[:2])
                    add(rng(train + "-0", lt, False, lt, "Auto-matched"))
                elif lt and re.fullmatch(r"[0-9]+\.[0-9]+", ver):
                    add(rng(ver + "-0", ver + "-" + lt, False, ver + "-" + lt, "Auto-matched"))
                elif le and re.fullmatch(r"[0-9]+\.[0-9]+", ver):
                    add(rng(ver + "-0", ver + "-" + le, True, "a later release than " + ver + "-" + le, "Auto-matched"))
    elif vendor == "Ivanti":
        un = [v["version"] for a in affected if a.get("product") in ("Connect Secure", "ICS")
              for v in a.get("versions", []) if v.get("status") == "unaffected"]
        for a in affected:
            if a.get("product") not in ("Connect Secure", "ICS"): continue
            for v in a.get("versions", []):
                if v.get("status") != "affected": continue
                le, ver = v.get("lessThanOrEqual"), v.get("version")
                mx = le or ver
                later = sorted([u for u in un if nums(u) > nums(mx)], key=nums)
                add(rng(ver, mx, True, later[0] if later else "a later release than " + mx, "Auto-matched"))
    elif vendor == "SonicWall":
        for a in affected:
            if a.get("product") != "SonicOS": continue
            for v in a.get("versions", []):
                t = v.get("version", "")
                m = re.search(r"[0-9]+(?:\.[0-9]+)+(?:-[0-9A-Za-z]+)*", t)
                if not m: continue
                tok = m.group(0)
                if re.search(r"older|earlier", t, re.I):
                    add(rng(str(nums(tok)[0]) + ".0", tok, True, "a later release than " + tok, "Needs review"))
                else:
                    add(rng(tok, tok, True, "a later release than " + tok, "Needs review"))
    elif vendor == "Arista":
        for a in affected:
            if a.get("product") != "EOS": continue
            for v in a.get("versions", []):
                if v.get("status") != "affected": continue
                ver, le = v.get("version"), v.get("lessThanOrEqual")
                add(rng("0" if ver == "*" else ver, le or ver, True, "a fixed release listed in the vendor advisory", "Auto-matched"))
    return out

def cvss(rec):
    best = None
    conts = [rec["containers"]["cna"]] + rec["containers"].get("adp", [])
    for c in conts:
        for m in c.get("metrics", []):
            for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                if k in m and "baseScore" in m[k]:
                    best = best if best is not None else m[k]["baseScore"]
    return best

def main():
    kev = None
    for u in KEV_URLS:
        try:
            kev = get(u, 60); break
        except Exception as e:
            print("KEV source failed:", u, e, file=sys.stderr)
    if not kev: sys.exit("No KEV source reachable; keeping previous data.")
    rows = []
    for v in kev["vulnerabilities"]:
        c = canon(v)
        if not c or v["dateAdded"] < SINCE: continue
        cid = v["cveID"]; y = cid.split("-")[1]; n = int(cid.split("-")[2])
        ranges, score, note = [], None, ""
        try:
            rec = get(CVE_URL.format(y=y, d=n // 1000, cid=cid))
            ranges = parse(c[0], rec["containers"]["cna"].get("affected", []))
            score = cvss(rec)
        except Exception as e:
            note = "CVE record not readable: %s" % e
        if not ranges and not note:
            note = "The record lists no affected range this tool can read"
        tiers = [r["tier"] for r in ranges]
        rows.append({
            "advisory_id": cid, "cve": cid, "vendor": c[0], "product": c[1],
            "title": v["vulnerabilityName"], "required_action": v["requiredAction"],
            "kev": True, "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "published": v["dateAdded"], "cvss": score, "epss": None,
            "condition_feature": CURATED_FEATURE.get(cid, ""),
            "match_tier": "Needs review" if (not ranges or "Needs review" in tiers) else "Auto-matched",
            "ranges": ranges, "note": note,
            "source_type": "CISA KEV and CVE record",
        })
    # EPSS (optional)
    try:
        ids = [r["cve"] for r in rows]
        for i in range(0, len(ids), 50):
            d = get(EPSS_URL.format(ids=",".join(ids[i:i + 50])), 30)
            m = {x["cve"]: float(x["epss"]) for x in d.get("data", [])}
            for r in rows:
                if r["cve"] in m: r["epss"] = m[r["cve"]]
    except Exception as e:
        print("EPSS unavailable, left empty:", e, file=sys.stderr)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for r in rows: r["last_checked"] = now
    rows.sort(key=lambda r: (r["vendor"], r["published"]), reverse=False)
    json.dump({"generated_at": now, "kev_version": kev.get("catalogVersion"), "advisories": rows},
              open(OUT, "w"), indent=1)
    print("wrote", len(rows), "advisories;", sum(1 for r in rows if not r["ranges"]), "without readable ranges")

if __name__ == "__main__":
    main()
