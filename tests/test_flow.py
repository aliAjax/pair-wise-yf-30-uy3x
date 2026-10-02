import sys
import tempfile
import unittest
from pathlib import Path
from datetime import timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, PharmacovigilanceService, iso, utcnow


class PharmacovigilanceFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.svc = PharmacovigilanceService(Path(self.tmp.name) / "test.db")

    def tearDown(self):
        self.tmp.cleanup()

    def create(self, dedupe="intake-1"):
        return self.svc.create_case(
            "reporter-a", "reporter", "CN",
            {"patient_ref": "P-1", "region": "CN", "product": "DrugA", "event_term": "肝损伤",
             "source": "email", "dedupe_key": dedupe, "received_at": iso(utcnow()), "serious": False},
        )["case"]

    def test_full_case_and_deduplication_flow(self):
        case = self.create()
        self.assertEqual(case["revision"], 1)
        followed = self.svc.add_followup(
            case["id"], "reporter-a", "reporter", "CN",
            {"content": "住院并出现死亡转归", "source": "phone", "expected_revision": 1,
             "received_at": iso(utcnow())},
        )
        self.assertEqual(followed["revision"], 2)
        reviewed = self.svc.medical_review(
            case["id"], "reviewer-1", "medical_reviewer",
            {"expected_revision": 2, "serious": True, "fatal": True, "causality": "possibly_related",
             "rationale": "住院记录和死亡证明已核验", "received_at": iso(utcnow())},
        )
        self.assertEqual(reviewed["case"]["revision"], 3)
        report = self.svc.create_report(case["id"], "lead-cn", "regional_lead", "CN", {"country": "CN"})
        submitted = self.svc.submit_report(report["id"], "lead-cn", "regional_lead", "CN", {})
        self.assertEqual(submitted["report"]["status"], "submitted")
        duplicate = self.svc.create_case(
            "reporter-b", "reporter", "CN",
            {"patient_ref": "P-1", "region": "CN", "product": "DrugA", "event_term": "肝损伤",
             "source": "fax", "dedupe_key": "intake-1", "received_at": iso(utcnow())},
        )
        self.assertTrue(duplicate["deduplicated"])
        detail = self.svc.get_case(case["id"], "global_admin", "")
        self.assertEqual(len(detail["intakes"]), 1)
        self.assertGreaterEqual(len(detail["audit"]), 5)
        self.assertEqual(submitted["report"]["late"], 0)

    def test_permissions_and_stale_revision(self):
        case = self.create("intake-2")
        with self.assertRaises(ApiError) as ctx:
            self.svc.get_case(case["id"], "reporter", "US")
        self.assertEqual(ctx.exception.status, 403)
        self.svc.add_followup(case["id"], "reporter-a", "reporter", "CN",
                              {"content": "第一次更新", "source": "email", "expected_revision": 1})
        with self.assertRaises(ApiError) as ctx:
            self.svc.add_followup(case["id"], "reporter-a", "reporter", "CN",
                                  {"content": "过期修改", "source": "email", "expected_revision": 1})
        self.assertEqual(ctx.exception.code, "revision_conflict")
        with self.assertRaises(ApiError) as ctx:
            self.svc.medical_review(case["id"], "lead-cn", "regional_lead",
                                    {"expected_revision": 2, "serious": True, "fatal": False,
                                     "causality": "related", "rationale": "x", "received_at": iso(utcnow())})
        self.assertEqual(ctx.exception.status, 403)


if __name__ == "__main__":
    unittest.main()
