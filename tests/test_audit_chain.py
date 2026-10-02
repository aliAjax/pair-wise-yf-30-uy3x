import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import (
    ApiError, GENESIS_HASH, CHAIN_INVESTIGATING, CHAIN_REPAIRED,
    PharmacovigilanceService, canonical_detail, entry_hash, iso, utcnow,
)


class AuditChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        self.svc = PharmacovigilanceService(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def create_case(self, dedupe="chain-1"):
        return self.svc.create_case(
            "reporter-a", "reporter", "CN",
            {"patient_ref": "P-1", "region": "CN", "product": "DrugA", "event_term": "肝损伤",
             "source": "email", "dedupe_key": dedupe, "received_at": iso(utcnow()), "serious": False},
        )["case"]

    def raw_conn(self):
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        return conn

    def active_entries(self, conn, case_id):
        return conn.execute(
            "SELECT * FROM audit_chain WHERE case_id=? AND superseded=0 ORDER BY seq", (case_id,)
        ).fetchall()

    def verify(self, case_id):
        return self.svc.verify_case(case_id, "global_admin", "")

    def add_followup_ok(self, case_id, revision, content="随访"):
        return self.svc.add_followup(
            case_id, "reporter-a", "reporter", "CN",
            {"content": content, "source": "phone", "expected_revision": revision,
             "received_at": iso(utcnow())},
        )

    # 1. 正常追加：每条带前一条摘要，全链可校验。
    def test_each_entry_carries_previous_hash_and_verifies(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1, "第一次随访")
        self.add_followup_ok(case["id"], 2, "第二次随访")
        report = self.verify(case["id"])
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["checked"], 3)
        with self.raw_conn() as conn:
            entries = self.active_entries(conn, case["id"])
            self.assertEqual(entries[0]["prev_hash"], GENESIS_HASH)
            self.assertEqual(entries[1]["prev_hash"], entries[0]["entry_hash"])
            self.assertEqual(entries[2]["prev_hash"], entries[1]["entry_hash"])
            for r in entries:
                self.assertEqual(
                    r["entry_hash"],
                    entry_hash(r["seq"], r["case_id"], r["actor"], r["role"], r["action"],
                               r["detail_json"], r["created_at"], r["prev_hash"]),
                )
            head = conn.execute(
                "SELECT audit_tail_seq,audit_tail_hash FROM cases WHERE id=?", (case["id"],)
            ).fetchone()
            self.assertEqual(head["audit_tail_seq"], 3)
            self.assertEqual(head["audit_tail_hash"], entries[-1]["entry_hash"])

    # 2. 抹去一条记录 => seq_gap，指出最早断点。
    def test_deleted_entry_detected_as_seq_gap(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        self.add_followup_ok(case["id"], 2)
        with self.raw_conn() as conn:
            conn.execute("DELETE FROM audit_chain WHERE case_id=? AND seq=2", (case["id"],))
        report = self.verify(case["id"])
        self.assertFalse(report["valid"])
        self.assertEqual(report["earliest_break"]["kind"], "seq_gap")
        self.assertEqual(report["earliest_break"]["seq"], 2)

    # 3. 篡改详情内容 => hash_mismatch，定位到被改的那条。
    def test_tampered_detail_detected_as_hash_mismatch(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        self.add_followup_ok(case["id"], 2)
        with self.raw_conn() as conn:
            conn.execute("UPDATE audit_chain SET detail_json=? WHERE case_id=? AND seq=1",
                         (canonical_detail({"forged": True}), case["id"]))
        report = self.verify(case["id"])
        self.assertFalse(report["valid"])
        self.assertEqual(report["earliest_break"]["kind"], "hash_mismatch")
        self.assertEqual(report["earliest_break"]["seq"], 1)

    # 4. 抹去原记录并补插一条伪造记录、不重算后续 => prev_hash_mismatch，最早断点是插入点的下一条。
    def test_inserted_without_rechaining_detected(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        self.add_followup_ok(case["id"], 2)
        with self.raw_conn() as conn:
            rows = self.active_entries(conn, case["id"])
            seq1 = rows[0]
            original_seq2 = conn.execute(
                "SELECT * FROM audit_chain WHERE case_id=? AND seq=2", (case["id"],)
            ).fetchone()
            forged_hash = entry_hash(2, case["id"], "mallory", "global_admin", "backdoor",
                                     canonical_detail({"x": 1}), iso(), seq1["entry_hash"])
            conn.execute("DELETE FROM audit_chain WHERE id=?", (original_seq2["id"],))
            conn.execute(
                """INSERT INTO audit_chain(case_id,seq,actor,role,action,detail_json,created_at,prev_hash,entry_hash)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (case["id"], 2, "mallory", "global_admin", "backdoor",
                 canonical_detail({"x": 1}), iso(), seq1["entry_hash"], forged_hash),
            )
        report = self.verify(case["id"])
        self.assertFalse(report["valid"])
        self.assertEqual(report["earliest_break"]["kind"], "prev_hash_mismatch")
        self.assertEqual(report["earliest_break"]["seq"], 3)

    # 5. 同一前驱两条后继 => chain_fork。
    def test_fork_detected(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        self.add_followup_ok(case["id"], 2)
        with self.raw_conn() as conn:
            head = conn.execute(
                "SELECT * FROM audit_chain WHERE case_id=? AND seq=1", (case["id"],)
            ).fetchone()
            seq3 = conn.execute(
                "SELECT * FROM audit_chain WHERE case_id=? AND seq=3", (case["id"],)
            ).fetchone()
            # 真分叉：保留 seq1->seq2 支，同时把 seq3 的 prev_hash 也改成 seq1 的摘要，
            # seq1 于是有 seq2、seq3 两个后继。seq3 的自身摘要按新前驱重算，
            # 这样断点不在内容而在结构（同一前驱出现两个后继）。
            new_hash = entry_hash(3, case["id"], seq3["actor"], seq3["role"], seq3["action"],
                                  seq3["detail_json"], seq3["created_at"], head["entry_hash"])
            conn.execute(
                "UPDATE audit_chain SET prev_hash=?, entry_hash=? WHERE id=?",
                (head["entry_hash"], new_hash, seq3["id"]),
            )
        report = self.verify(case["id"])
        self.assertFalse(report["valid"])
        self.assertEqual(report["earliest_break"]["kind"], "chain_fork")
        self.assertEqual(report["earliest_break"]["seq"], 3)

    # 6. 案例登记的链尾与实际不一致 => tail_pointer_mismatch。
    def test_tail_pointer_rewrite_detected(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        with self.raw_conn() as conn:
            conn.execute("DELETE FROM audit_chain WHERE case_id=? AND seq=2", (case["id"],))
            conn.execute("UPDATE cases SET audit_tail_seq=1 WHERE id=?", (case["id"],))
        report = self.verify(case["id"])
        self.assertFalse(report["valid"])
        self.assertEqual(report["earliest_break"]["kind"], "tail_pointer_mismatch")

    # 7. 发现断链 => 整案进入待核查，后续业务追加全部被拒绝。
    def test_broken_chain_marks_case_pending_and_blocks_writes(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        with self.raw_conn() as conn:
            conn.execute("DELETE FROM audit_chain WHERE case_id=? AND seq=2", (case["id"],))
        report = self.svc.get_case(case["id"], "reporter", "CN")["audit_chain"]
        self.assertFalse(report["valid"])
        self.assertEqual(report["chain_state"], CHAIN_INVESTIGATING)
        with self.assertRaises(ApiError) as ctx:
            self.add_followup_ok(case["id"], 2)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, "case_pending_investigation")
        self.assertIn("earliest_break", ctx.exception.details)
        with self.raw_conn() as conn:
            state = conn.execute("SELECT chain_state FROM cases WHERE id=?", (case["id"],)).fetchone()
            self.assertEqual(state["chain_state"], CHAIN_INVESTIGATING)

    # 8. 两人并发追加同一案例：只有一条接上，另一条失败后按最新链尾重试成功。
    def test_concurrent_appends_only_one_chains_then_retry(self):
        case = self.create_case()
        results: list[dict] = []
        errors: list[ApiError] = []
        barrier = threading.Barrier(2)

        def append(actor, content):
            barrier.wait()
            try:
                res = self.svc.add_followup(
                    case["id"], actor, "reporter", "CN",
                    {"content": content, "source": "phone", "expected_revision": 1,
                     "received_at": iso(utcnow())},
                )
                results.append(res)
            except ApiError as exc:
                errors.append(exc)

        t1 = threading.Thread(target=append, args=("reporter-a", "并发追加 A"))
        t2 = threading.Thread(target=append, args=("reporter-b", "并发追加 B"))
        t1.start(); t2.start(); t1.join(); t2.join()

        self.assertEqual(len(results), 1, "恰好一条追加成功")
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, "revision_conflict")
        loser = errors[0]
        # 失败响应带回最新链尾，败者按最新链尾重试：
        current = self.svc.get_case(case["id"], "reporter", "CN")["case"]
        retry = self.svc.add_followup(
            case["id"], "reporter-b", "reporter", "CN",
            {"content": "并发追加 B（重试）", "source": "phone",
             "expected_revision": current["revision"],
             "expected_audit_seq": loser.details["audit_tail"]["seq"],
             "received_at": iso(utcnow())},
        )
        report = self.verify(case["id"])
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["checked"], 3)
        self.assertEqual(retry["case"]["revision"], current["revision"] + 1)

    # 9. expected_audit_seq 过期：链尾 CAS 失败并返回最新链尾。
    def test_stale_expected_audit_seq_rejected_with_latest_tail(self):
        case = self.create_case()  # 链尾 seq=1
        self.add_followup_ok(case["id"], 1)  # 链尾 seq=2
        self.svc.medical_review(
            case["id"], "reviewer-1", "medical_reviewer",
            {"expected_revision": 2, "serious": True, "fatal": False, "causality": "related",
             "rationale": "x", "received_at": iso(utcnow())},
        )  # revision=3, 链尾 seq=3
        with self.assertRaises(ApiError) as ctx:
            self.svc.add_followup(
                case["id"], "reporter-a", "reporter", "CN",
                {"content": "旧链尾追加", "source": "phone", "expected_revision": 3,
                 "expected_audit_seq": 1, "received_at": iso(utcnow())},
            )
        self.assertEqual(ctx.exception.code, "chain_tail_conflict")
        self.assertEqual(ctx.exception.details["expected_seq"], 1)
        self.assertEqual(ctx.exception.details["latest_tail"]["seq"], 3)
        with self.assertRaises(ApiError) as ctx2:
            self.svc.add_followup(
                case["id"], "reporter-a", "reporter", "CN",
                {"content": "按最新链尾重试", "source": "phone", "expected_revision": 2,
                 "expected_audit_seq": 3, "received_at": iso(utcnow())},
            )
        self.assertEqual(ctx2.exception.code, "revision_conflict")
        # 两个版本号都按最新的来 => 追加成功，成为 seq=4。
        ok = self.svc.add_followup(
            case["id"], "reporter-a", "reporter", "CN",
            {"content": "按最新链尾重试", "source": "phone", "expected_revision": 3,
             "expected_audit_seq": 3, "received_at": iso(utcnow())},
        )
        self.assertEqual(ok["audit_entry"]["seq"], 4)
        self.assertTrue(self.verify(case["id"])["valid"])

    # 10. 越权修复被拒绝；管理员不写原因也被拒绝。
    def test_unauthorized_and_reasonless_repair_rejected(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        with self.raw_conn() as conn:
            conn.execute("DELETE FROM audit_chain WHERE case_id=? AND seq=2", (case["id"],))
        self.verify(case["id"])
        with self.assertRaises(ApiError) as ctx:
            self.svc.repair_chain(case["id"], "lead-cn", "regional_lead", {"reason": "我要修复"})
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(ctx.exception.code, "repair_forbidden")
        with self.assertRaises(ApiError) as ctx:
            self.svc.repair_chain(case["id"], "reviewer-1", "medical_reviewer", {"reason": "我要修复"})
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(ApiError) as ctx:
            self.svc.repair_chain(case["id"], "global-admin", "global_admin", {"reason": "   "})
        self.assertEqual(ctx.exception.code, "reason_required")

    # 11. 管理员写明原因修复删链：重排链接上，校验通过，修复记录永久留痕，状态=repaired。
    def test_admin_reasoned_repair_restores_chain_and_is_recorded(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        self.add_followup_ok(case["id"], 2)
        with self.raw_conn() as conn:
            conn.execute("DELETE FROM audit_chain WHERE case_id=? AND seq=2", (case["id"],))
        before = self.verify(case["id"])
        self.assertEqual(before["earliest_break"]["kind"], "seq_gap")
        result = self.svc.repair_chain(
            case["id"], "global-admin", "global_admin",
            {"reason": "核查确认 seq=2 为 DBA 误删，按保留记录重排链尾"},
        )
        self.assertTrue(result["report_after"]["valid"], result)
        self.assertEqual(result["repair_entry"]["seq"], 3)
        after = self.verify(case["id"])
        self.assertTrue(after["valid"])
        self.assertEqual(after["chain_state"], CHAIN_REPAIRED)
        with self.raw_conn() as conn:
            entries = self.active_entries(conn, case["id"])
            actions = [r["action"] for r in entries]
            self.assertIn("chain_repaired", actions)
            repair = entries[-1]
            detail = json.loads(repair["detail_json"])
            self.assertEqual(detail["reason"], "核查确认 seq=2 为 DBA 误删，按保留记录重排链尾")
            self.assertEqual(detail["earliest_break"]["kind"], "seq_gap")
            self.assertEqual(repair["prev_hash"], entries[-2]["entry_hash"])
            logged = conn.execute("SELECT * FROM chain_repairs WHERE case_id=?", (case["id"],)).fetchall()
            self.assertEqual(len(logged), 1)
            self.assertEqual(logged[0]["admin"], "global-admin")
            self.assertEqual(logged[0]["entry_seq"], repair["seq"])

    # 12. 修复分叉：败选支重接回主链，链重新连续可校验，分叉事实写入修复明细。
    def test_admin_repair_fork_restores_linear_chain(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        self.add_followup_ok(case["id"], 2)
        with self.raw_conn() as conn:
            head = conn.execute("SELECT * FROM audit_chain WHERE case_id=? AND seq=1", (case["id"],)).fetchone()
            seq3 = conn.execute("SELECT * FROM audit_chain WHERE case_id=? AND seq=3", (case["id"],)).fetchone()
            forged = entry_hash(3, case["id"], seq3["actor"], seq3["role"], seq3["action"],
                                seq3["detail_json"], seq3["created_at"], head["entry_hash"])
            conn.execute("UPDATE audit_chain SET prev_hash=?, entry_hash=? WHERE id=?",
                         (head["entry_hash"], forged, seq3["id"]))
        self.assertEqual(self.verify(case["id"])["earliest_break"]["kind"], "chain_fork")
        result = self.svc.repair_chain(
            case["id"], "global-admin", "global_admin", {"reason": "核查分叉来源，保留先写入支"},
        )
        self.assertTrue(result["report_after"]["valid"], result)
        with self.raw_conn() as conn:
            entries = self.active_entries(conn, case["id"])
            self.assertEqual(entries[2]["prev_hash"], entries[1]["entry_hash"])
            detail = json.loads(entries[-1]["detail_json"])
            self.assertEqual(detail["earliest_break"]["kind"], "chain_fork")
            self.assertEqual(detail["reason"], "核查分叉来源，保留先写入支")
        # 修复后业务可以继续追加，且接在最新链尾后。
        current = self.svc.get_case(case["id"], "global_admin", "")["case"]
        self.svc.add_followup(
            case["id"], "reporter-a", "reporter", "CN",
            {"content": "修复后新随访", "source": "phone", "expected_revision": current["revision"],
             "received_at": iso(utcnow())},
        )
        self.assertTrue(self.verify(case["id"])["valid"])

    # 13. 旧数据升级：老库 audit_log 在迁移后补齐哈希链，旧记录也能通过校验。
    def test_legacy_audit_log_backfilled_and_verifies(self):
        legacy_db = Path(self.tmp.name) / "legacy.db"
        conn = sqlite3.connect(legacy_db)
        conn.executescript(
            """
            CREATE TABLE cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_no TEXT NOT NULL UNIQUE,
                patient_ref TEXT NOT NULL, region TEXT NOT NULL, product TEXT NOT NULL,
                event_term TEXT NOT NULL, onset_at TEXT, received_at TEXT NOT NULL,
                serious INTEGER NOT NULL DEFAULT 0, fatal INTEGER NOT NULL DEFAULT 0,
                causality TEXT, report_due_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
                revision INTEGER NOT NULL DEFAULT 1, merged_into INTEGER,
                created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE intakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, source TEXT NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, received_at TEXT NOT NULL,
                created_by TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE followups (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, content TEXT NOT NULL,
                source TEXT NOT NULL, received_at TEXT NOT NULL, revision INTEGER NOT NULL,
                created_by TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(case_id, revision)
            );
            CREATE TABLE reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, country TEXT NOT NULL,
                due_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', submitted_at TEXT,
                submitted_by TEXT, late INTEGER NOT NULL DEFAULT 0, UNIQUE(case_id, country)
            );
            CREATE TABLE medical_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, case_revision INTEGER NOT NULL,
                serious INTEGER NOT NULL, fatal INTEGER NOT NULL, causality TEXT NOT NULL,
                rationale TEXT NOT NULL, reviewer TEXT NOT NULL, created_at TEXT NOT NULL,
                UNIQUE(case_id, case_revision)
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, actor TEXT NOT NULL,
                role TEXT NOT NULL, action TEXT NOT NULL, detail_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """
        )
        now = iso(utcnow() - timedelta(days=3))
        conn.execute(
            """INSERT INTO cases(case_no,patient_ref,region,product,event_term,received_at,
               report_due_at,status,revision,created_by,created_at,updated_at)
               VALUES('PV-OLD-1','P-9','US','DrugB','皮疹',?,?, 'open',1,'r1',?,?)""",
            (now, now, now, now),
        )
        old_logs = [
            (1, "r1", "reporter", "case_created", {"case_no": "PV-OLD-1"}),
            (1, "r1", "reporter", "followup_added", {"revision": 2, "source": "fax"}),
        ]
        for cid, actor, role, action, detail in old_logs:
            conn.execute(
                "INSERT INTO audit_log(case_id,actor,role,action,detail_json,created_at) VALUES(?,?,?,?,?,?)",
                (cid, actor, role, action, canonical_detail(detail), now),
            )
        conn.commit()
        conn.close()

        # 在旧库之上启动服务 => 触发一次性迁移。
        migrated = PharmacovigilanceService(legacy_db)
        report = migrated.verify_case(1, "global_admin", "")
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["checked"], 2)
        with sqlite3.connect(legacy_db) as check:
            check.row_factory = sqlite3.Row
            entries = check.execute("SELECT * FROM audit_chain WHERE case_id=1 ORDER BY seq").fetchall()
            self.assertEqual(entries[0]["prev_hash"], GENESIS_HASH)
            self.assertEqual(entries[1]["prev_hash"], entries[0]["entry_hash"])
            head = check.execute("SELECT audit_tail_seq,audit_tail_hash FROM cases WHERE id=1").fetchone()
            self.assertEqual(head["audit_tail_seq"], 2)
            self.assertEqual(head["audit_tail_hash"], entries[-1]["entry_hash"])
        # 迁移后新追加接在旧链尾之后。
        followed = migrated.add_followup(
            1, "r1", "reporter", "US",
            {"content": "迁移后随访", "source": "email", "expected_revision": 1,
             "received_at": iso(utcnow())},
        )
        self.assertEqual(followed["revision"], 2)
        self.assertTrue(migrated.verify_case(1, "global_admin", "")["valid"])
        # 再次启动不重复迁移。
        PharmacovigilanceService(legacy_db)
        with sqlite3.connect(legacy_db) as check:
            count = check.execute("SELECT COUNT(*) FROM audit_chain WHERE case_id=1").fetchone()[0]
            self.assertEqual(count, 3)

    # 14. 区域角色能看到链状态与断点，但看不到链上明细。
    def test_region_roles_see_status_but_not_entries(self):
        case = self.create_case()
        self.add_followup_ok(case["id"], 1)
        self.add_followup_ok(case["id"], 2)
        detail = self.svc.get_case(case["id"], "reporter", "CN")
        self.assertEqual(detail["audit_chain"]["chain_state"], "ok")
        self.assertNotIn("entries", detail["audit_chain"])
        self.assertEqual(detail["audit"], [])
        with self.raw_conn() as conn:
            conn.execute("DELETE FROM audit_chain WHERE case_id=? AND seq=2", (case["id"],))
        report = self.svc.verify_case(case["id"], "reporter", "CN")
        self.assertFalse(report["valid"])
        self.assertEqual(report["earliest_break"]["kind"], "seq_gap")
        self.assertNotIn("entries", report)


if __name__ == "__main__":
    unittest.main()
