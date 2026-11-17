"""Build ``vulndb.json`` from CISA ICS advisories (CSAF 2.0) and the CISA KEV catalog.

Run on an Internet-connected machine, then copy the output to the sensor (or upload it from the
dashboard). Archives are read in memory and never extracted to disk.

    python tools/vulndb_build.py --fetch -o data/vulndb.json
    python tools/vulndb_build.py --csaf-tar CSAF-develop.tar.gz --kev kev.json -o data/vulndb.json

Standard library only: no third-party packages are needed on the build machine.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

CSAF_TARBALL = "https://codeload.github.com/cisagov/CSAF/tar.gz/refs/heads/develop"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CSAF_PATH_MARKER = "/csaf_files/OT/white/"
MODEL_IN_NAME = re.compile(r"\(([0-9A-Z][0-9A-Z\-/ ]{4,}[0-9A-Z])\)")
SIEMENS_MLFB = re.compile(r"\b6(?:ES7|AG1|GK1|ES5)\s?\d{3}-\w{5}-\w{4}\b", re.I)
VERSION_LIKE = re.compile(r"^\s*(?:vers:|[<>=!]|all\b|\*|(?:v(?:ersion)?\s*)?\d)", re.I)


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "neteye-vulndb-builder"})
    with urllib.request.urlopen(request, timeout=300) as response:
        return response.read()


def iter_csaf_tar(data: bytes) -> Iterator[dict[str, Any]]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            if member.isfile() and CSAF_PATH_MARKER in member.name and member.name.endswith(".json"):
                handle = archive.extractfile(member)
                if handle is not None:
                    try:
                        yield json.load(handle)
                    except json.JSONDecodeError:
                        continue


def iter_csaf_dir(path: Path) -> Iterator[dict[str, Any]]:
    for file in sorted(path.rglob("*.json")):
        try:
            yield json.loads(file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue


def _leaves(branches: list[dict], path: dict[str, str]) -> Iterator[tuple[dict[str, str], dict]]:
    for branch in branches or []:
        here = {**path, branch.get("category", ""): branch.get("name", "")}
        if branch.get("branches"):
            yield from _leaves(branch["branches"], here)
        elif branch.get("product"):
            yield here, branch["product"]


def _max_score(vuln: dict) -> tuple[float | None, set[str]]:
    best, products = None, set()
    for score in vuln.get("scores", []):
        for key in ("cvss_v3", "cvss_v4", "cvss_v2"):
            base = (score.get(key) or {}).get("baseScore")
            if base is not None:
                best = max(best or 0.0, float(base))
                break
        products.update(score.get("products", []))
    return best, products


def convert(doc: dict[str, Any], kev: set[str]) -> dict[str, Any] | None:
    document = doc.get("document", {})
    tracking = document.get("tracking", {})
    advisory_id = tracking.get("id")
    if not advisory_id:
        return None
    url = next((r.get("url") for r in document.get("references", []) if r.get("category") == "self"), "")
    url = next((r.get("url") for r in document.get("references", [])
                if "cisa.gov" in (r.get("url") or "") and "/ics-" in (r.get("url") or "")), url)

    # product_id -> affecting CVEs / max CVSS / first vendor fix
    affected: dict[str, dict[str, Any]] = {}
    all_cves: list[str] = []
    for vuln in doc.get("vulnerabilities", []):
        cve = vuln.get("cve")
        if cve:
            all_cves.append(cve)
        score, scored_products = _max_score(vuln)
        status = vuln.get("product_status", {})
        ids = set(status.get("known_affected", [])) | set(status.get("first_affected", [])) | \
            set(status.get("last_affected", [])) | scored_products
        fixes = {}
        for rem in vuln.get("remediations", []):
            if rem.get("category") in ("vendor_fix", "mitigation") and rem.get("details"):
                for pid in rem.get("product_ids", []):
                    fixes.setdefault(pid, rem["details"].strip())
        for pid in ids:
            entry = affected.setdefault(pid, {"cves": [], "cvss": None, "remediation": ""})
            if cve and cve not in entry["cves"]:
                entry["cves"].append(cve)
            if score is not None:
                entry["cvss"] = max(entry["cvss"] or 0.0, score)
            if not entry["remediation"] and pid in fixes:
                entry["remediation"] = fixes[pid]

    products = []
    for path, product in _leaves(doc.get("product_tree", {}).get("branches", []), {}):
        pid = product.get("product_id")
        if affected and pid not in affected:
            continue
        name = path.get("product_name") or path.get("product_family") or product.get("name", "")
        version = path.get("product_version_range") or path.get("product_version") or ""
        models = list((product.get("product_identification_helper") or {}).get("model_numbers", []))
        models += MODEL_IN_NAME.findall(name)
        models += SIEMENS_MLFB.findall(name)
        if version and not VERSION_LIKE.match(version):
            models.append(version)  # e.g. Schneider lists order numbers as "versions"
            version = "*"
        info = affected.get(pid, {})
        item = {"vendor": path.get("vendor", ""), "product": name, "versions": version or "*"}
        if models:
            item["models"] = sorted(set(m.strip() for m in models if m.strip()))
        for key in ("cves", "cvss", "remediation"):
            if info.get(key):
                item[key] = info[key][:400] if key == "remediation" else info[key]
        products.append(item)
    if not products:
        return None

    scores = [p["cvss"] for p in products if p.get("cvss")]
    result = {
        "id": advisory_id,
        "title": document.get("title", ""),
        "published": tracking.get("initial_release_date", "")[:10],
        "url": url,
        "cves": sorted(set(all_cves)),
        "cvss": max(scores) if scores else None,
        "products": products,
    }
    kev_hits = sorted(set(all_cves) & kev)
    if kev_hits:
        result["kev_cves"] = kev_hits
    return result


def build(documents: Iterable[dict[str, Any]], kev_catalog: dict[str, Any]) -> dict[str, Any]:
    kev = {v["cveID"] for v in kev_catalog.get("vulnerabilities", [])}
    advisories: dict[str, dict] = {}
    for doc in documents:
        adv = convert(doc, kev)
        if adv is None:
            continue
        previous = advisories.get(adv["id"])
        if previous is None or adv["published"] >= previous["published"]:
            advisories[adv["id"]] = adv
    ordered = sorted(advisories.values(), key=lambda a: (a["published"], a["id"]), reverse=True)
    return {
        "format": "neteye-vulndb/1",
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {"csaf": "CISA ICS advisories (CSAF)", "kev_catalog_version": kev_catalog.get("catalogVersion")},
        "kev_advisories": sum(1 for a in ordered if a.get("kev_cves")),
        "advisories": ordered,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fetch", action="store_true", help="download CSAF archive and KEV from CISA/GitHub")
    parser.add_argument("--csaf-tar", type=Path, help="local CSAF repository tarball (.tar.gz)")
    parser.add_argument("--csaf-dir", type=Path, help="local directory of CSAF JSON files")
    parser.add_argument("--kev", type=Path, help="local known_exploited_vulnerabilities.json")
    parser.add_argument("-o", "--output", type=Path, default=Path("data/vulndb.json"))
    args = parser.parse_args(argv)

    if args.csaf_dir:
        documents: Iterable[dict] = iter_csaf_dir(args.csaf_dir)
    elif args.csaf_tar:
        documents = iter_csaf_tar(args.csaf_tar.read_bytes())
    elif args.fetch:
        print("downloading CISA CSAF archive...", file=sys.stderr)
        documents = iter_csaf_tar(_fetch(CSAF_TARBALL))
    else:
        parser.error("one of --fetch, --csaf-tar or --csaf-dir is required")

    if args.kev:
        kev_catalog = json.loads(args.kev.read_text(encoding="utf-8"))
    elif args.fetch:
        print("downloading CISA KEV catalog...", file=sys.stderr)
        kev_catalog = json.loads(_fetch(KEV_URL))
    else:
        kev_catalog = {}
        print("warning: no KEV catalog given; known-exploited flags will be empty", file=sys.stderr)

    db = build(documents, kev_catalog)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(db, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"{len(db['advisories'])} advisories ({db['kev_advisories']} with KEV CVEs) -> {args.output}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
