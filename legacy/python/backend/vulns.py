"""Offline vulnerability matching of observed assets against a normalized ICS advisory database.

The database (``vulndb.json``) is produced by ``backend.vulndb_build`` from CISA ICS advisories
(CSAF) and the CISA KEV catalog on an Internet-connected machine, then copied to the sensor.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

CONFIRMED, LIKELY, POSSIBLE = "confirmed", "likely", "possible"
LEVEL_WEIGHT = {CONFIRMED: 1.0, LIKELY: 0.8, POSSIBLE: 0.5}
LEVEL_LABEL = {CONFIRMED: "확정", LIKELY: "유력", POSSIBLE: "가능"}


def norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def vendor_key(vendor: str) -> str:
    """'Rockwell Automation/Allen-Bradley' -> 'rockwell', 'Schneider Electric Software, LLC' -> 'schneider'."""
    words = re.findall(r"[a-z0-9]+", (vendor or "").lower())
    if not words:
        return ""
    return {"allen": "rockwell", "ab": "rockwell", "ge": "ge"}.get(words[0], words[0])


# Model / station-type -> product-family patterns, matched on word boundaries of advisory product
# names (so "ET 200S" does not match "ET 200SP"). Communication modules are matched by model only.
S7 = {n: rf"\bs7 ?{n}\b" for n in ("300", "400", "1200", "1500")}
FAMILY_RULES: list[tuple[str, str, tuple[str, ...]]] = [
    ("siemens", r"^(6es731|6ag131|s7300$)", (S7["300"],)),
    ("siemens", r"^(6es741|6ag141|s7400$)", (S7["400"],)),
    ("siemens", r"^(6es721|6ag121|s71200$)", (S7["1200"],)),
    ("siemens", r"^(6es751|6ag151|s71500$)", (S7["1500"],)),
    ("siemens", r"^(6es71518|6ag11518)", (r"\bet ?200 ?s\b(?! ?p)", S7["300"])),
    ("rockwell", r"^1756l6", (r"\bcontrollogix ?5560\b", r"\b1756 ?l6")),
    ("rockwell", r"^1756l7", (r"\bcontrollogix ?5570\b", r"\b1756 ?l7")),
    ("rockwell", r"^1756l8", (r"\bcontrollogix ?5580\b", r"\b1756 ?l8")),
    ("rockwell", r"^1769l3", (r"\bcompactlogix ?5370\b", r"\b1769 ?l3")),
    ("rockwell", r"^5069l3", (r"\bcompactlogix ?5380\b", r"\b5069 ?l3")),
    ("schneider", r"^bmxp34", (r"\bm340\b",)),
    ("schneider", r"^(bmep58|bmeh58)", (r"\bm580\b",)),
    ("schneider", r"^140cpu", (r"\bquantum\b",)),
    ("schneider", r"^tm221", (r"\bm221\b",)),
    ("schneider", r"^tm241", (r"\bm241\b",)),
    ("schneider", r"^tm251", (r"\bm251\b",)),
    ("mitsubishi", r"^r\d+(en)?cpu", (r"\biq ?r\b",)),
    ("mitsubishi", r"^fx5", (r"\biq ?f\b", r"\bfx5")),
    ("mitsubishi", r"^q\d+\w*cpu", (r"\bmelsec ?q\b", r"\bq ?series\b")),
    ("mitsubishi", r"^l\d+\w*cpu", (r"\bmelsec ?l\b", r"\bl ?series\b")),
]
# Family-level matches only consider advisory products that describe the controller itself.
ORDER_NUMBER = re.compile(
    r"\b(?:6(?:ES7|AG1|GK1|ES5)\s?\d{3}-\w{5}-\w{4}|17\d\d-\w+|5069-\w+|BM[XE]\w{4,}|140CPU\w+|TM2\d\d\w+)\b", re.I)
CONTROLLER_WORDS = re.compile(r"\b(cpu|cpus|family|controllers?|plcs?|series|firmware)\b")


def spaced(text: str) -> str:
    return " " + " ".join(re.findall(r"[a-z0-9]+", (text or "").lower())) + " "


def families(vkey: str, model: str) -> list[str]:
    m = norm(model)
    found: list[str] = []
    for vendor, pattern, keys in FAMILY_RULES:
        if vendor == vkey and m and re.search(pattern, m):
            found.extend(keys)
    return list(dict.fromkeys(found))


# ------------------------------------------------------------------ versions
def parse_version(text: str, wildcard_from: list[int] | None = None) -> list[int] | None:
    """'V3.2.16' -> [3, 2, 16]; '4.003' -> [4, 3]; 'V16 Update 5' -> [16, 5]; 'V3.X.14' uses wildcard_from."""
    text = (text or "").strip()
    if not text or not re.search(r"\d", text):
        return None
    parts = re.split(r"[.\s_\-]+|update|sp", text.lower().lstrip("v"))
    out: list[int] = []
    for i, part in enumerate(p for p in parts if p):
        part = part.lstrip("v")
        if part in ("x", "*"):
            if wildcard_from is None or i >= len(wildcard_from):
                return None
            out.append(wildcard_from[i])
            continue
        digits = re.match(r"\d+", part)
        if not digits:
            break
        out.append(int(digits.group()))
    return out or None


def _cmp(a: list[int], b: list[int]) -> int:
    width = max(len(a), len(b))
    a, b = a + [0] * (width - len(a)), b + [0] * (width - len(b))
    return (a > b) - (a < b)


_OPS = {"<": lambda c: c < 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0, ">=": lambda c: c >= 0,
        "=": lambda c: c == 0, "!=": lambda c: c != 0}


def version_affected(spec: str, firmware: str) -> bool | None:
    """True/False if decidable, None when the spec or the firmware cannot be interpreted."""
    spec = (spec or "").strip()
    lowered = spec.lower()
    if not spec or lowered in ("*", "vers:all/*", "all versions", "all") or lowered.endswith("/*") \
            or lowered.startswith("all versions"):
        return True
    fw = parse_version(firmware)
    if fw is None:
        return None
    if lowered.startswith("vers:"):
        spec = spec.split("/", 1)[1] if "/" in spec else ""
    constraints = [c.strip() for c in re.split(r"\||,|\band\b", spec) if c.strip()]
    if len(constraints) == 1 and re.fullmatch(r"\S+\s*-\s*\S+", constraints[0]) and "<" not in spec:
        low, high = [s.strip() for s in constraints[0].split("-", 1)]
        constraints = [f">={low}", f"<={high}"]
    decided = False
    for constraint in constraints:
        match = re.match(r"(<=|>=|!=|<|>|=)?\s*(.+)", constraint)
        op, value = match.group(1), match.group(2)
        ref = parse_version(value, wildcard_from=fw)
        if ref is None:
            return None
        if op is None:  # bare version: that release line (prefix match)
            if fw[:len(ref)] != ref:
                return False
        elif not _OPS[op](_cmp(fw, ref)):
            return False
        decided = True
    return True if decided else None


# ----------------------------------------------------------------- database
class VulnDB:
    def __init__(self, data: dict[str, Any]) -> None:
        if data.get("format") != "neteye-vulndb/1":
            raise ValueError("not a NetEye vulnerability database (format neteye-vulndb/1)")
        self.meta = {k: v for k, v in data.items() if k != "advisories"}
        self.advisories: list[dict] = data["advisories"]
        self.by_vendor: dict[str, list[tuple[dict, dict]]] = {}
        self.by_model: dict[str, list[tuple[dict, dict]]] = {}
        for adv in self.advisories:
            for product in adv["products"]:
                product["_norm"] = norm(product["product"])
                product["_spaced"] = spaced(product["product"])
                product["_has_specific_model"] = bool(product.get("models")) or bool(
                    ORDER_NUMBER.search(product["product"]))
                self.by_vendor.setdefault(vendor_key(product["vendor"]), []).append((adv, product))
                for model in product.get("models", []):
                    self.by_model.setdefault(norm(model), []).append((adv, product))

    @classmethod
    def load(cls, path: str | Path) -> "VulnDB":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def info(self) -> dict[str, Any]:
        return {**self.meta, "advisory_count": len(self.advisories)}

    def match(self, asset: dict[str, Any]) -> list[dict[str, Any]]:
        vkey = vendor_key(asset.get("vendor", ""))
        model = asset.get("model", "") or ""
        model_n = norm(model)
        firmware = asset.get("firmware", "") or ""
        fams = families(vkey, model)
        if not (vkey or model_n):
            return []

        candidates: list[tuple[dict, dict, str]] = []
        for adv, product in self.by_model.get(model_n, []) if model_n else []:
            candidates.append((adv, product, "model"))
        for adv, product in self.by_vendor.get(vkey, []) if vkey else []:
            pn = product["_norm"]
            # Specific order/catalog numbers only (>= 8 chars); "S7-1500" etc. are families.
            if len(model_n) >= 8 and (model_n in pn or (len(pn) >= 6 and model_n.startswith(pn)
                                                         and re.search(r"\d", pn))):
                candidates.append((adv, product, "model"))
            elif (fams and not product["_has_specific_model"]
                  and CONTROLLER_WORDS.search(product["_spaced"])
                  and any(re.search(f, product["_spaced"]) for f in fams)):
                candidates.append((adv, product, "family"))

        results: dict[str, dict[str, Any]] = {}
        for adv, product, how in candidates:
            affected = version_affected(product.get("versions", ""), firmware)
            if affected is False:
                continue
            if affected is None or (how == "family" and not firmware):
                level = POSSIBLE  # undecidable version, or family match on an unknown firmware
            else:
                level = CONFIRMED if how == "model" else LIKELY
            current = results.get(adv["id"])
            if current and LEVEL_WEIGHT[current["level"]] >= LEVEL_WEIGHT[level]:
                continue
            cvss = product.get("cvss") or adv.get("cvss")
            kev = bool(set(product.get("cves") or adv.get("cves", [])) & set(adv.get("kev_cves", [])))
            results[adv["id"]] = {
                "id": adv["id"], "title": adv["title"], "url": adv.get("url", ""),
                "published": adv.get("published", ""),
                "cves": product.get("cves") or adv.get("cves", []),
                "cvss": cvss, "kev": kev, "level": level, "level_label": LEVEL_LABEL[level],
                "product": product["product"], "versions": product.get("versions", ""),
                "remediation": product.get("remediation", ""),
                "score": round(min(10.0, (cvss or 5.0) * LEVEL_WEIGHT[level] + (1.5 if kev else 0)), 1),
            }
        return sorted(results.values(), key=lambda v: (-v["score"], v["id"]))


def risk_level(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "none"
