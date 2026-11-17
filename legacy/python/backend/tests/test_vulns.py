import struct
import unittest

from backend.engine import Engine
from backend.tests.test_protocols import HMI_MAC, PLC_MAC, tcp, tpkt_cotp
from backend.vulndb_build import build, convert
from backend.vulns import VulnDB, parse_version, version_affected


def csaf(advisory_id: str, vendor: str, product: str, version: str, cve: str, score: float,
         models: list[str] | None = None, fix: str = "Update to V3.2.16 or later") -> dict:
    leaf = {"product_id": "P1", "name": f"{product} {version}"}
    if models:
        leaf["product_identification_helper"] = {"model_numbers": models}
    return {
        "document": {"title": f"{vendor} {product}", "tracking": {"id": advisory_id, "initial_release_date": "2024-01-02T00:00:00Z"},
                     "references": [{"category": "self", "url": f"https://example.invalid/{advisory_id}.json"}]},
        "product_tree": {"branches": [{"category": "vendor", "name": vendor, "branches": [
            {"category": "product_name", "name": product, "branches": [
                {"category": "product_version_range", "name": version, "product": leaf}]}]}]},
        "vulnerabilities": [{"cve": cve, "product_status": {"known_affected": ["P1"]},
                             "scores": [{"cvss_v3": {"baseScore": score}, "products": ["P1"]}],
                             "remediations": [{"category": "vendor_fix", "details": fix, "product_ids": ["P1"]}]}],
    }


DOCS = [
    csaf("ICSA-T-01", "Siemens", "SIMATIC ET 200S IM151-8 PN/DP CPU (6ES7151-8AB01-0AB0)",
         "vers:all/<V3.2.16", "CVE-2000-0001", 7.5, models=["6ES7151-8AB01-0AB0"]),
    csaf("ICSA-T-02", "Siemens", "SIMATIC S7-300 CPU family", "vers:all/*", "CVE-2000-0002", 9.8),
    csaf("ICSA-T-03", "Siemens", "SIMATIC ET 200SP Open Controller CPU", "vers:all/*", "CVE-2000-0003", 9.6),
    csaf("ICSA-T-04", "Rockwell Automation", "1756-ENBT", "<=4.003", "CVE-2000-0004", 10.0),
]
KEV = {"vulnerabilities": [{"cveID": "CVE-2000-0002"}]}


class VersionTests(unittest.TestCase):
    def test_parse_formats(self):
        self.assertEqual(parse_version("V3.2.16"), [3, 2, 16])
        self.assertEqual(parse_version("4.003"), [4, 3])
        self.assertEqual(parse_version("V16 Update 5"), [16, 5])
        self.assertEqual(parse_version("V3.X.14", wildcard_from=[3, 3, 9]), [3, 3, 14])
        self.assertIsNone(parse_version("unknown"))

    def test_ranges(self):
        cases = [
            ("vers:intdot/<3.2.17", "V3.2.6", True), ("vers:intdot/<3.2.17", "V3.2.17", False),
            ("<V3.2.16", "V3.2.6", True), ("<= 3.2.12", "3.2.12", True), ("<= 3.2.12", "3.2.13", False),
            ("vers:intdot/>=2.0|<3.0", "2.5", True), ("vers:intdot/>=2.0|<3.0", "3.1", False),
            ("<V3.X.14", "V3.3.9", True), ("<V3.X.14", "V3.3.14", False),
            ("20-33", "20.011", True), ("20-33", "34.1", False),
            ("3.2", "V3.2.6", True), ("3.2", "V3.3.0", False),
            ("vers:all/*", "", True), ("All versions", "1.0", True),
            ("<V2.0", "", None), ("<=first five digits of serial", "1.0", None),
        ]
        for spec, firmware, expected in cases:
            with self.subTest(spec=spec, firmware=firmware):
                self.assertEqual(version_affected(spec, firmware), expected)


class BuilderTests(unittest.TestCase):
    def test_convert_extracts_products_cves_and_fix(self):
        adv = convert(DOCS[0], kev=set())
        product = adv["products"][0]
        self.assertEqual(adv["id"], "ICSA-T-01")
        self.assertEqual(product["versions"], "vers:all/<V3.2.16")
        self.assertEqual(product["models"], ["6ES7151-8AB01-0AB0"])
        self.assertEqual(product["cves"], ["CVE-2000-0001"])
        self.assertEqual(product["cvss"], 7.5)
        self.assertIn("V3.2.16", product["remediation"])

    def test_order_numbers_listed_as_versions_become_models(self):
        doc = csaf("ICSA-T-05", "Schneider Electric", "Modicon M340 PLC", "BMXP342020", "CVE-2000-0005", 7.5)
        product = convert(doc, kev=set())["products"][0]
        self.assertEqual((product["versions"], product["models"]), ("*", ["BMXP342020"]))

    def test_build_marks_kev(self):
        db = build(DOCS, KEV)
        self.assertEqual(db["format"], "neteye-vulndb/1")
        self.assertEqual(db["kev_advisories"], 1)


class MatchTests(unittest.TestCase):
    db = VulnDB(build(DOCS, KEV))

    def ids(self, asset):
        return {v["id"]: v for v in self.db.match(asset)}

    def test_order_number_match_respects_version(self):
        old = self.ids({"vendor": "Siemens", "model": "6ES7 151-8AB01-0AB0", "firmware": "V3.2.6"})
        new = self.ids({"vendor": "Siemens", "model": "6ES7 151-8AB01-0AB0", "firmware": "V3.2.17"})
        self.assertEqual(old["ICSA-T-01"]["level"], "confirmed")
        self.assertNotIn("ICSA-T-01", new)

    def test_family_match_and_kev(self):
        result = self.ids({"vendor": "Siemens", "model": "6ES7 151-8AB01-0AB0", "firmware": "V3.2.6"})
        self.assertEqual(result["ICSA-T-02"]["level"], "likely")
        self.assertTrue(result["ICSA-T-02"]["kev"])

    def test_family_does_not_bleed_into_similar_names(self):
        result = self.ids({"vendor": "Siemens", "model": "6ES7 151-8AB01-0AB0", "firmware": "V3.2.6"})
        self.assertNotIn("ICSA-T-03", result)  # ET 200SP is not ET 200S

    def test_unknown_firmware_is_only_possible(self):
        result = self.ids({"vendor": "Siemens", "model": "6ES7 315-2EH14-0AB0", "firmware": ""})
        self.assertEqual(result["ICSA-T-02"]["level"], "possible")

    def test_catalog_number_prefix_and_vendor_alias(self):
        result = self.ids({"vendor": "Rockwell Automation/Allen-Bradley", "model": "1756-ENBT/A", "firmware": "4.003"})
        self.assertEqual(result["ICSA-T-04"]["level"], "confirmed")
        self.assertEqual(result["ICSA-T-04"]["score"], 10.0)

    def test_other_vendor_does_not_match(self):
        self.assertEqual(self.db.match({"vendor": "Omron", "model": "1756-ENBT", "firmware": "1.0"}), [])


def szl_response(model: str, firmware: tuple[int, int, int]) -> bytes:
    params = b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\x00\x00"
    rec1 = struct.pack("!H", 1) + model.ljust(20).encode() + struct.pack("!HHH", 0xC0, 4, 1)
    major, minor, patch = firmware
    rec2 = struct.pack("!H", 7) + b" " * 20 + struct.pack("!HHH", 0xC0, 0x5600 | major, (minor << 8) | patch)
    data = b"\xff\x09" + struct.pack("!HHHHH", 8 + 56, 0x0011, 0, 28, 2) + rec1 + rec2
    s7 = struct.pack("!BBHHHH", 0x32, 7, 0, 1, len(params), len(data)) + params + data
    return tcp("10.0.0.11", "10.0.0.40", 102, 50100, tpkt_cotp(s7), src_mac=PLC_MAC, dst_mac=HMI_MAC)


class EngineVulnTests(unittest.TestCase):
    def test_identity_from_traffic_is_matched_and_kev_alerted(self):
        engine = Engine(vulndb=VulnDB(build(DOCS, KEV)))
        engine.process_raw(szl_response("6ES7 151-8AB01-0AB0", (3, 2, 6)), 1_700_000_000)
        snap = engine.snapshot()
        plc = next(a for a in snap["assets"] if a["id"] == "10.0.0.11")
        self.assertEqual({v["id"] for v in plc["vulns"]}, {"ICSA-T-01", "ICSA-T-02"})
        self.assertEqual(plc["risk_level"], "critical")
        self.assertEqual(snap["stats"]["kev_assets"], 1)
        self.assertEqual([a["title"] for a in snap["alerts"]], ["악용 중인 취약점(KEV) 보유 자산"])

    def test_loading_db_later_rematches_existing_assets(self):
        engine = Engine()
        engine.process_raw(szl_response("6ES7 151-8AB01-0AB0", (3, 2, 6)), 1_700_000_000)
        self.assertEqual(engine.snapshot()["stats"]["vulnerable_assets"], 0)
        engine.set_vulndb(VulnDB(build(DOCS, KEV)))
        self.assertEqual(engine.snapshot()["stats"]["vulnerable_assets"], 1)

    def test_firmware_upgrade_clears_fixed_advisory(self):
        engine = Engine(vulndb=VulnDB(build(DOCS, KEV)))
        engine.process_raw(szl_response("6ES7 151-8AB01-0AB0", (3, 2, 6)), 1_700_000_000)
        engine.process_raw(szl_response("6ES7 151-8AB01-0AB0", (3, 2, 17)), 1_700_000_100)
        plc = next(a for a in engine.snapshot()["assets"] if a["id"] == "10.0.0.11")
        self.assertNotIn("ICSA-T-01", {v["id"] for v in plc["vulns"]})


if __name__ == "__main__":
    unittest.main()
