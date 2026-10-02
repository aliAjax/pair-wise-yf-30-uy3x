import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, GENESIS_HASH, PharmacovigilanceService, iso, record_digest


class AuditChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.svc = PharmacovigilanceService(Path(self.tmp.name) / "test.db")

    def tearDown(self):
        self.tmp.cleanup()

    def create(self, dedupe="intake-1"):
        return self.svc.create_case(
            "reporter-a", "reporter", "CN",
            {"patient_ref": "P-1", "region": "CN", "product": "DrugA", "event_term": "肝损伤",
             "source": "email", "dedupe_key": dedupe, "received_at": iso(), "serious": False},
        )["case"]

    def tail(self, case_id):
        return self.svc.verify_chain(case_id)["tail_hash"]

    def raw_audit(self, case_id):
        return self.svc.repo.conn.execute(
            "SELECT * FROM audit_log WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall()

    # ---- 正常挂链 -------------------------------------------------

    def test_chain_linked_on_append(self):
        case = self.create()
        case_id = case["id"]
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "随访一", "source": "phone", "expected_revision": 1})
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "随访二", "source": "email", "expected_revision": 2})
        rows = self.raw_audit(case_id)
        self.assertEqual([r["seq"] for r in rows], [1, 2, 3])
        self.assertEqual(rows[0]["prev_hash"], GENESIS_HASH)
        for i in range(1, 3):
            self.assertEqual(rows[i]["prev_hash"], rows[i - 1]["record_hash"])
        result = self.svc.verify_chain(case_id)
        self.assertTrue(result["valid"])
        self.assertEqual(result["records_checked"], 3)
        self.assertEqual(result["tail_hash"], rows[-1]["record_hash"])
        self.assertEqual(result["audit_status"], "verified")

    # ---- 篡改 -----------------------------------------------------

    def test_tamper_detail_breaks_chain_and_marks_pending(self):
        case = self.create()
        case_id = case["id"]
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "原始内容", "source": "phone", "expected_revision": 1})
        rows = self.raw_audit(case_id)
        target = rows[1]
        self.svc.repo.conn.execute(
            "UPDATE audit_log SET detail_json=? WHERE id=?",
            ('{"revision": 2, "source": "tampered"}', target["id"]),
        )
        result = self.svc.verify_chain(case_id)
        self.assertFalse(result["valid"])
        self.assertEqual(result["earliest_break"]["reason"], "digest_mismatch")
        self.assertEqual(result["earliest_break"]["record_id"], target["id"])
        # 发现即冻结
        checked = self.svc.check_audit_chain(case_id, "global-admin", "global_admin", "")
        self.assertEqual(checked["audit_status"], "pending_verification")
        with self.assertRaises(ApiError) as ctx:
            self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                                  {"content": "冻结期间追加", "source": "email", "expected_revision": 2})
        self.assertEqual(ctx.exception.code, "case_pending_verification")

    # ---- 抹去记录 -------------------------------------------------

    def test_erased_record_breaks_chain(self):
        case = self.create()
        case_id = case["id"]
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "随访一", "source": "phone", "expected_revision": 1})
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "随访二", "source": "email", "expected_revision": 2})
        rows = self.raw_audit(case_id)
        # 抹去中间一条记录
        self.svc.repo.conn.execute("DELETE FROM audit_log WHERE id=?", (rows[1]["id"],))
        result = self.svc.verify_chain(case_id)
        self.assertFalse(result["valid"])
        self.assertIn(result["earliest_break"]["reason"], {"gap", "link_mismatch"})
        self.assertEqual(result["earliest_break"]["record_id"], rows[2]["id"])

    # ---- 补插记录 -------------------------------------------------

    def test_inserted_record_breaks_chain(self):
        case = self.create()
        case_id = case["id"]
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "随访一", "source": "phone", "expected_revision": 1})
        rows = self.raw_audit(case_id)
        # 伪造一条记录，摘要按规则重算但 prev_hash 接在创世之后（补插）
        detail_json = json.dumps({"source": "fake"}, sort_keys=True)
        created_at = iso()
        digest = record_digest(seq=2, prev_hash=GENESIS_HASH, case_id=case_id, actor="intruder",
                               role="reporter", action="followup_added",
                               detail_json=detail_json, created_at=created_at)
        self.svc.repo.conn.execute(
            "INSERT INTO audit_log(case_id,actor,role,action,detail_json,created_at,seq,prev_hash,record_hash) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (case_id, "intruder", "reporter", "followup_added", detail_json, created_at,
             2, GENESIS_HASH, digest),
        )
        result = self.svc.verify_chain(case_id)
        self.assertFalse(result["valid"])
        self.assertIsNotNone(result["earliest_break"])

    # ---- 分叉 -----------------------------------------------------

    def test_fork_detected(self):
        case = self.create()
        case_id = case["id"]
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "随访一", "source": "phone", "expected_revision": 1})
        rows = self.raw_audit(case_id)
        tail = rows[-1]
        # 两条记录指向同一条前条摘要（并发补插），序号连续
        for i, action in enumerate(("fork_a", "fork_b")):
            detail_json = json.dumps({"i": i}, sort_keys=True)
            created_at = iso()
            digest = record_digest(seq=tail["seq"] + 1 + i, prev_hash=tail["record_hash"],
                                   case_id=case_id, actor="x", role="reporter", action=action,
                                   detail_json=detail_json, created_at=created_at)
            self.svc.repo.conn.execute(
                "INSERT INTO audit_log(case_id,actor,role,action,detail_json,created_at,seq,prev_hash,record_hash) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (case_id, "x", "reporter", action, detail_json, created_at,
                 tail["seq"] + 1 + i, tail["record_hash"], digest),
            )
        result = self.svc.verify_chain(case_id)
        self.assertFalse(result["valid"])
        self.assertEqual(result["earliest_break"]["reason"], "fork")
        self.assertEqual(len(result["forks"]), 1)
        self.assertEqual(result["forks"][0]["prev_hash"], tail["record_hash"])

    # ---- 修复 -----------------------------------------------------

    def test_repair_requires_admin_and_reason(self):
        case = self.create()
        case_id = case["id"]
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "随访一", "source": "phone", "expected_revision": 1})
        rows = self.raw_audit(case_id)
        self.svc.repo.conn.execute(
            "UPDATE audit_log SET detail_json=? WHERE id=?",
            ('{"revision": 2, "source": "tampered"}', rows[1]["id"]),
        )
        for actor, role in (("reporter-a", "reporter"), ("lead-cn", "regional_lead"),
                            ("reviewer-1", "medical_reviewer")):
            with self.assertRaises(ApiError) as ctx:
                self.svc.repair_chain(case_id, actor, role, {"reason": "核查后重挂"})
            self.assertEqual(ctx.exception.code, "repair_forbidden")
        with self.assertRaises(ApiError) as ctx:
            self.svc.repair_chain(case_id, "global-admin", "global_admin", {})
        self.assertEqual(ctx.exception.code, "reason_required")
        result = self.svc.repair_chain(case_id, "global-admin", "global_admin",
                                       {"reason": "监管核查后重新挂链，断点记录已核实"})
        self.assertEqual(result["audit_status"], "verified")
        self.assertTrue(self.svc.verify_chain(case_id)["valid"])
        # 修复动作本身在链上留痕
        rows = self.raw_audit(case_id)
        self.assertEqual(rows[-1]["action"], "audit_chain_repaired")
        self.assertEqual(json.loads(rows[-1]["detail_json"])["reason"], "监管核查后重新挂链，断点记录已核实")

    def test_repair_relinks_erased_chain(self):
        case = self.create()
        case_id = case["id"]
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "随访一", "source": "phone", "expected_revision": 1})
        self.svc.add_followup(case_id, "reporter-a", "reporter", "CN",
                              {"content": "随访二", "source": "email", "expected_revision": 2})
        rows = self.raw_audit(case_id)
        self.svc.repo.conn.execute("DELETE FROM audit_log WHERE id=?", (rows[1]["id"],))
        self.assertFalse(self.svc.verify_chain(case_id)["valid"])
        result = self.svc.repair_chain(case_id, "global-admin", "global_admin",
                                       {"reason": "抹去记录已无法恢复，按现存记录重新挂链"})
        self.assertGreater(result["relinked"], 0)
        self.assertTrue(self.svc.verify_chain(case_id)["valid"])

    # ---- 旧数据升级 -----------------------------------------------

    def test_legacy_data_upgraded_on_startup(self):
        db_path = Path(self.tmp.name) / "legacy.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(
            """
            CREATE TABLE cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_no TEXT NOT NULL UNIQUE,
                patient_ref TEXT NOT NULL, region TEXT NOT NULL, product TEXT NOT NULL,
                event_term TEXT NOT NULL, onset_at TEXT, received_at TEXT NOT NULL,
                serious INTEGER NOT NULL DEFAULT 0, fatal INTEGER NOT NULL DEFAULT 0,
                causality TEXT, report_due_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
                revision INTEGER NOT NULL DEFAULT 1, merged_into INTEGER REFERENCES cases(id),
                created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, actor TEXT NOT NULL,
                role TEXT NOT NULL, action TEXT NOT NULL, detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        now = iso()
        conn.execute(
            "INSERT INTO cases(case_no,patient_ref,region,product,event_term,received_at,report_due_at,"
            "created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("PV-LEGACY-1", "P-1", "CN", "DrugA", "肝损伤", now, now, "reporter-a", now, now),
        )
        conn.execute(
            "INSERT INTO audit_log(case_id,actor,role,action,detail_json,created_at) VALUES(?,?,?,?,?,?)",
            (1, "reporter-a", "reporter", "case_created", '{"source": "email"}', now),
        )
        conn.execute(
            "INSERT INTO audit_log(case_id,actor,role,action,detail_json,created_at) VALUES(?,?,?,?,?,?)",
            (1, "reporter-a", "reporter", "followup_added", '{"revision": 2}', now),
        )
        conn.commit()
        conn.close()

        # 以新版本服务打开旧库：自动补列、补链
        svc = PharmacovigilanceService(db_path)
        result = svc.verify_chain(1)
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["records_checked"], 2)
        rows = svc.repo.conn.execute("SELECT seq,prev_hash,record_hash FROM audit_log ORDER BY id").fetchall()
        self.assertEqual([r["seq"] for r in rows], [1, 2])
        self.assertEqual(rows[0]["prev_hash"], GENESIS_HASH)
        self.assertEqual(rows[1]["prev_hash"], rows[0]["record_hash"])

    # ---- 并发追加 -------------------------------------------------

    def test_concurrent_append_tail_conflict_then_retry(self):
        case = self.create()
        case_id = case["id"]
        tail_v0 = self.tail(case_id)
        # A、B 同时读到链尾 v0
        first = self.svc.add_followup(
            case_id, "reporter-a", "reporter", "CN",
            {"content": "A 的追加", "source": "phone", "expected_revision": 1,
             "expected_tail_hash": tail_v0},
        )
        self.assertEqual(first["audit_tail"]["prev_hash"], tail_v0)
        # B 仍按旧链尾追加 → 失败
        with self.assertRaises(ApiError) as ctx:
            self.svc.add_followup(
                case_id, "reporter-b", "reporter", "CN",
                {"content": "B 的追加", "source": "email", "expected_revision": 1,
                 "expected_tail_hash": tail_v0},
            )
        self.assertEqual(ctx.exception.code, "chain_conflict")
        self.assertEqual(ctx.exception.extra["current_tail_hash"], first["audit_tail"]["record_hash"])
        # B 按最新链尾重试成功
        latest = self.tail(case_id)
        self.assertEqual(latest, first["audit_tail"]["record_hash"])
        retry = self.svc.add_followup(
            case_id, "reporter-b", "reporter", "CN",
            {"content": "B 的追加", "source": "email", "expected_revision": 2,
             "expected_tail_hash": latest},
        )
        self.assertTrue(self.svc.verify_chain(case_id)["valid"])
        self.assertEqual(retry["audit_tail"]["prev_hash"], latest)


if __name__ == "__main__":
    unittest.main()
