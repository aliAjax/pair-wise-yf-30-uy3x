#!/usr/bin/env python3
"""Pharmacovigilance case intake service using only the Python standard library."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse

PORT = 8201
ROLES = {"reporter", "regional_lead", "medical_reviewer", "global_admin"}

# 每案审计链的创世前摘要是固定值：第 1 条记录 prev_hash 指向它。
GENESIS_HASH = "0" * 64
# 链状态：ok 正常；investigating 发现断链/分叉，整案待核查；repaired 已由管理员写明原因修复。
CHAIN_OK = "ok"
CHAIN_INVESTIGATING = "investigating"
CHAIN_REPAIRED = "repaired"


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        # 冲突时把最新链尾等信息带回，供调用方按最新链尾重试。
        self.details = details


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    current = value or utcnow()
    return current.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None, default: datetime | None = None) -> datetime:
    if not value:
        if default is None:
            raise ApiError(400, "missing_time", "必须提供 ISO 8601 时间")
        return default
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiError(400, "invalid_time", f"时间格式错误: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def report_deadline(received_at: datetime, serious: bool, fatal: bool) -> datetime:
    if serious:
        return received_at + timedelta(days=7 if fatal else 15)
    return received_at + timedelta(days=90)


def canonical_detail(detail: dict[str, Any]) -> str:
    return json.dumps(detail, ensure_ascii=False, sort_keys=True)


def entry_hash(seq: int, case_id: int, actor: str, role: str, action: str,
               detail_json: str, created_at: str, prev_hash: str) -> str:
    """计算一条审计记录的摘要：覆盖业务字段与前一条摘要，任何字节改动都会失效。"""
    payload = {
        "seq": seq,
        "case_id": case_id,
        "actor": actor,
        "role": role,
        "action": action,
        "detail_json": detail_json,
        "created_at": created_at,
        "prev_hash": prev_hash,
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class Repository:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        # 初始化（建表/迁移）用独立连接；业务读写每次取新连接，
        # 否则 ThreadingHTTPServer 下多线程共享同一连接会让事务互相串台。
        init_conn = self._connect()
        try:
            self.init_schema(init_conn)
        finally:
            init_conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        # 并发 BEGIN IMMEDIATE 时后到者等待持锁事务，而不是立刻 database is locked。
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def init_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_no TEXT NOT NULL UNIQUE,
                patient_ref TEXT NOT NULL,
                region TEXT NOT NULL,
                product TEXT NOT NULL,
                event_term TEXT NOT NULL,
                onset_at TEXT,
                received_at TEXT NOT NULL,
                serious INTEGER NOT NULL DEFAULT 0,
                fatal INTEGER NOT NULL DEFAULT 0,
                causality TEXT,
                report_due_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                revision INTEGER NOT NULL DEFAULT 1,
                merged_into INTEGER REFERENCES cases(id),
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS intakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER REFERENCES cases(id),
                source TEXT NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                received_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS followups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id),
                content TEXT NOT NULL,
                source TEXT NOT NULL,
                received_at TEXT NOT NULL,
                revision INTEGER NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(case_id, revision)
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id),
                country TEXT NOT NULL,
                due_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                submitted_at TEXT,
                submitted_by TEXT,
                late INTEGER NOT NULL DEFAULT 0,
                UNIQUE(case_id, country)
            );
            CREATE TABLE IF NOT EXISTS medical_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id),
                case_revision INTEGER NOT NULL,
                serious INTEGER NOT NULL,
                fatal INTEGER NOT NULL,
                causality TEXT NOT NULL,
                rationale TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(case_id, case_revision)
            );
            -- 旧版仅按时间追加的审计表，保留为历史归档；新记录一律写入 audit_chain。
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            -- 连续可校验的逐案例哈希链。
            CREATE TABLE IF NOT EXISTS audit_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id),
                seq INTEGER NOT NULL,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                superseded INTEGER NOT NULL DEFAULT 0
            );
            -- 同一案例的有效记录序号唯一（分叉修复时败选支保留为 superseded 证据）。
            CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_active_seq
                ON audit_chain(case_id, seq) WHERE superseded=0;
            CREATE INDEX IF NOT EXISTS idx_audit_chain_case ON audit_chain(case_id, seq);
            -- 管理员修复必须写明原因，单独留表供监管核查。
            CREATE TABLE IF NOT EXISTS chain_repairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id),
                entry_seq INTEGER NOT NULL,
                admin TEXT NOT NULL,
                reason TEXT NOT NULL,
                break_json TEXT,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        self._add_column(conn, "cases", "audit_tail_seq", "INTEGER NOT NULL DEFAULT 0")
        self._add_column(conn, "cases", "audit_tail_hash", "TEXT")
        self._add_column(conn, "cases", "chain_state", f"TEXT NOT NULL DEFAULT '{CHAIN_OK}'")
        self._migrate_legacy_audit(conn)

    @staticmethod
    def _add_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc):
                raise

    @staticmethod
    def _migrate_legacy_audit(conn: sqlite3.Connection) -> None:
        """把旧版 audit_log 按 (案例, 原始 id 顺序) 重排并重算摘要，补齐哈希链。"""
        done = conn.execute("SELECT 1 FROM schema_meta WHERE key='audit_chain_v1'").fetchone()
        if done:
            return
        legacy = conn.execute(
            "SELECT * FROM audit_log WHERE case_id IS NOT NULL ORDER BY case_id, id"
        ).fetchall()
        tails: dict[int, tuple[int, str]] = {}
        for row in legacy:
            case_id = row["case_id"]
            seq, prev_hash = tails.get(case_id, (0, GENESIS_HASH))
            seq += 1
            digest = entry_hash(seq, case_id, row["actor"], row["role"], row["action"],
                                row["detail_json"], row["created_at"], prev_hash)
            conn.execute(
                """INSERT INTO audit_chain(case_id,seq,actor,role,action,detail_json,created_at,prev_hash,entry_hash)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (case_id, seq, row["actor"], row["role"], row["action"],
                 row["detail_json"], row["created_at"], prev_hash, digest),
            )
            tails[case_id] = (seq, digest)
        for case_id, (seq, digest) in tails.items():
            conn.execute(
                "UPDATE cases SET audit_tail_seq=?, audit_tail_hash=? WHERE id=?",
                (seq, digest, case_id),
            )
        conn.execute(
            "INSERT INTO schema_meta(key,value) VALUES('audit_chain_v1',?)", (iso(),)
        )

    @staticmethod
    def _entry_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "seq": row["seq"],
            "actor": row["actor"],
            "role": row["role"],
            "action": row["action"],
            "detail_json": row["detail_json"],
            "created_at": row["created_at"],
            "prev_hash": row["prev_hash"],
            "entry_hash": row["entry_hash"],
            "superseded": bool(row["superseded"]),
        }

    @staticmethod
    def verify_chain(conn: sqlite3.Connection, case_id: int) -> dict[str, Any]:
        """
        逐记录重算摘要并核对前链，返回校验报告；发现问题时给出最早断点。
        kind 取值：
          hash_mismatch       记录内容被抹去/篡改，自身摘要对不上
          seq_gap             有记录被删除，序号出现缺口
          prev_hash_mismatch  有人补插/替换记录，前链接不上
          chain_fork          同一前驱出现两个后继（分叉），或同序号出现两条有效记录
          genesis_mismatch    首条记录未接创世摘要
          tail_pointer_mismatch 案例登记的链尾与实际链尾不一致
        """
        rows = conn.execute(
            "SELECT * FROM audit_chain WHERE case_id=? ORDER BY seq, id", (case_id,)
        ).fetchall()
        active = [r for r in rows if not r["superseded"]]
        superseded = [Repository._entry_dict(r) for r in rows if r["superseded"]]

        earliest: dict[str, Any] | None = None

        def record_break(found: dict[str, Any] | None) -> None:
            nonlocal earliest
            if found is not None and earliest is None:
                earliest = found

        # 同一有效序号出现两条记录 => 分叉。
        seen_seq: dict[int, int] = {}
        for r in active:
            if r["seq"] in seen_seq:
                record_break({"seq": r["seq"], "kind": "chain_fork",
                              "expected": f"seq {r['seq']} 唯一",
                              "actual": f"出现 id={seen_seq[r['seq']]} 与 id={r['id']} 两条有效记录"})
            seen_seq[r["seq"]] = r["id"]

        # 同一前驱出现两个后继 => 分叉。
        children: dict[str, list[int]] = {}
        for r in active:
            children.setdefault(r["prev_hash"], []).append(r["seq"])

        prev_hash = GENESIS_HASH
        expected_seq = 1
        tail: dict[str, Any] | None = None
        for r in active:
            digest = entry_hash(r["seq"], case_id, r["actor"], r["role"], r["action"],
                                r["detail_json"], r["created_at"], r["prev_hash"])
            if r["seq"] != expected_seq:
                if r["seq"] > expected_seq:
                    record_break({"seq": expected_seq, "kind": "seq_gap",
                                  "expected": expected_seq, "actual": None,
                                  "message": f"缺少 seq={expected_seq}，记录可能被删除"})
                # seq 小于期望值的重复情形已在上面的 chain_fork 中记录。
            if expected_seq == 1 and r["seq"] == 1 and r["prev_hash"] != GENESIS_HASH:
                record_break({"seq": 1, "kind": "genesis_mismatch",
                              "expected": GENESIS_HASH, "actual": r["prev_hash"]})
            if digest != r["entry_hash"]:
                record_break({"seq": r["seq"], "kind": "hash_mismatch",
                              "expected": digest, "actual": r["entry_hash"],
                              "message": "记录内容与其摘要不一致（疑似被抹去或篡改）"})
            if r["prev_hash"] != prev_hash and r["seq"] != 1:
                # 分叉：这条记录自己的前驱还挂着另一条后继。
                forks = children.get(r["prev_hash"], [])
                kind = "chain_fork" if len(forks) > 1 else "prev_hash_mismatch"
                record_break({"seq": r["seq"], "kind": kind,
                              "expected": prev_hash, "actual": r["prev_hash"],
                              "message": "前一条摘要接不上（疑似补插或替换记录）"})
            prev_hash = r["entry_hash"]
            expected_seq = r["seq"] + 1
            tail = {"seq": r["seq"], "entry_hash": r["entry_hash"]}

        case = conn.execute(
            "SELECT audit_tail_seq, audit_tail_hash, chain_state FROM cases WHERE id=?", (case_id,)
        ).fetchone()
        if earliest is None and case is not None:
            if tail is None:
                if case["audit_tail_seq"] != 0:
                    earliest = {"seq": case["audit_tail_seq"], "kind": "tail_pointer_mismatch",
                                "expected": "空链", "actual": f"登记链尾 seq={case['audit_tail_seq']}"}
            elif case["audit_tail_seq"] != tail["seq"] or case["audit_tail_hash"] != tail["entry_hash"]:
                earliest = {"seq": tail["seq"], "kind": "tail_pointer_mismatch",
                            "expected": {"seq": tail["seq"], "entry_hash": tail["entry_hash"]},
                            "actual": {"seq": case["audit_tail_seq"], "entry_hash": case["audit_tail_hash"]}}

        return {
            "valid": earliest is None,
            "earliest_break": earliest,
            "checked": len(active),
            "tail": tail,
            "chain_state": case["chain_state"] if case is not None else None,
            "entries": [Repository._entry_dict(r) for r in active],
            "superseded_entries": superseded,
        }

    @staticmethod
    def _insert_entry(conn: sqlite3.Connection, case_id: int, seq: int, actor: str, role: str,
                      action: str, detail: dict[str, Any], created_at: str,
                      prev_hash: str) -> dict[str, Any]:
        detail_json = canonical_detail(detail)
        digest = entry_hash(seq, case_id, actor, role, action, detail_json, created_at, prev_hash)
        cur = conn.execute(
            """INSERT INTO audit_chain(case_id,seq,actor,role,action,detail_json,created_at,prev_hash,entry_hash)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (case_id, seq, actor, role, action, detail_json, created_at, prev_hash, digest),
        )
        conn.execute(
            "UPDATE cases SET audit_tail_seq=?, audit_tail_hash=? WHERE id=?",
            (seq, digest, case_id),
        )
        row = conn.execute("SELECT * FROM audit_chain WHERE id=?", (cur.lastrowid,)).fetchone()
        return Repository._entry_dict(row)

    @staticmethod
    def append_audit(conn: sqlite3.Connection, case_id: int, actor: str, role: str,
                     action: str, detail: dict[str, Any], expected_seq: int | None = None,
                     at: datetime | None = None) -> dict[str, Any]:
        """
        在写事务内追加一条审计记录：先校验链完整、再按当前链尾 CAS 接上。
        - 链已断/分叉 => 整案标记待核查并拒绝追加；
        - expected_seq 与最新链尾不一致 => 409 chain_tail_conflict，带回最新链尾供重试。
        必须在 BEGIN IMMEDIATE 事务中调用：并发追加由写锁串行化，只会一条接一条。
        """
        state_row = conn.execute("SELECT chain_state FROM cases WHERE id=?", (case_id,)).fetchone()
        if state_row is None:
            raise ApiError(404, "case_not_found", "案例不存在")
        report = Repository.verify_chain(conn, case_id)
        if state_row["chain_state"] == CHAIN_INVESTIGATING:
            raise ApiError(409, "case_pending_investigation",
                           "审计链存在断点/分叉，整案待核查，禁止继续追加记录",
                           details={"case_id": case_id, "chain_state": CHAIN_INVESTIGATING,
                                    "earliest_break": report["earliest_break"]})
        if not report["valid"]:
            conn.execute(
                "UPDATE cases SET chain_state=? WHERE id=?", (CHAIN_INVESTIGATING, case_id)
            )
            raise ApiError(409, "case_pending_investigation",
                           "追加前校验发现审计链断点，案例已转入待核查",
                           details={"earliest_break": report["earliest_break"]})
        tail = report["tail"]
        tail_seq = tail["seq"] if tail else 0
        if expected_seq is not None and expected_seq != tail_seq:
            raise ApiError(409, "chain_tail_conflict",
                           "审计链尾已被其他追加接上，请按最新链尾重试",
                           details={"expected_seq": expected_seq, "latest_tail": tail})
        prev_hash = tail["entry_hash"] if tail else GENESIS_HASH
        return Repository._insert_entry(conn, case_id, tail_seq + 1, actor, role, action,
                                        detail, iso(at), prev_hash)


class PharmacovigilanceService:
    def __init__(self, db_path: str | Path):
        self.repo = Repository(db_path)

    @staticmethod
    def identity(headers: Any) -> tuple[str, str, str]:
        actor = headers.get("X-User-Id", "").strip()
        role = headers.get("X-Role", "").strip()
        region = headers.get("X-Region", "").strip()
        if not actor or role not in ROLES:
            raise ApiError(401, "unauthorized", "需要 X-User-Id 和有效的 X-Role")
        if role in {"reporter", "regional_lead"} and not region:
            raise ApiError(401, "region_required", "该角色必须提供 X-Region")
        return actor, role, region

    @staticmethod
    def can_access(case: dict[str, Any], role: str, region: str) -> bool:
        return role in {"medical_reviewer", "global_admin"} or case["region"] == region

    def _case(self, conn: sqlite3.Connection, case_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise ApiError(404, "case_not_found", "案例不存在")
        return row

    def _chain_summary(self, conn: sqlite3.Connection, case_id: int, include_entries: bool) -> dict[str, Any]:
        report = Repository.verify_chain(conn, case_id)
        summary = {k: v for k, v in report.items() if k != "entries"}
        if include_entries:
            summary["entries"] = report["entries"]
        return summary

    def _flag_if_broken(self, case_id: int, report: dict[str, Any]) -> dict[str, Any]:
        if report["valid"] or report["chain_state"] == CHAIN_INVESTIGATING:
            return report
        with self.repo.tx() as conn:
            conn.execute(
                "UPDATE cases SET chain_state=? WHERE id=? AND chain_state!=?",
                (CHAIN_INVESTIGATING, case_id, CHAIN_INVESTIGATING),
            )
        report["chain_state"] = CHAIN_INVESTIGATING
        return report

    def create_case(self, actor: str, role: str, region: str, body: dict[str, Any]) -> dict[str, Any]:
        required = ("patient_ref", "region", "product", "event_term", "source", "dedupe_key")
        missing = [key for key in required if not str(body.get(key, "")).strip()]
        if missing:
            raise ApiError(400, "missing_fields", f"缺少字段: {', '.join(missing)}")
        if role == "reporter" and body["region"] != region:
            raise ApiError(403, "region_forbidden", "只能录入本区域案例")
        if role == "medical_reviewer" and body["region"] not in {"", region}:
            raise ApiError(403, "reviewer_region_forbidden", "医学审核员不能代表区域录入案例")
        received = parse_time(body.get("received_at"), utcnow())
        serious = bool(body.get("serious", False))
        fatal = bool(body.get("fatal", False))
        due = report_deadline(received, serious, fatal)
        now = iso()
        with self.repo.tx() as conn:
            duplicate = conn.execute("SELECT * FROM intakes WHERE dedupe_key=?", (body["dedupe_key"],)).fetchone()
            if duplicate:
                case = self._case(conn, duplicate["case_id"])
                Repository.append_audit(conn, case["id"], actor, role, "intake_deduplicated",
                                        {"dedupe_key": body["dedupe_key"], "source": body["source"]})
                return {"deduplicated": True, "case": dict(self._case(conn, case["id"])), "intake_id": duplicate["id"]}
            count = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] + 1
            case_no = body.get("case_no") or f"PV-{received.year}-{count:06d}"
            try:
                cursor = conn.execute(
                    """INSERT INTO cases(case_no,patient_ref,region,product,event_term,onset_at,received_at,
                       serious,fatal,causality,report_due_at,status,revision,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (case_no, body["patient_ref"], body["region"], body["product"], body["event_term"],
                     body.get("onset_at"), iso(received), int(serious), int(fatal), body.get("causality"),
                     iso(due), "open", 1, actor, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ApiError(409, "case_number_conflict", "案例编号已存在") from exc
            case_id = cursor.lastrowid
            conn.execute(
                "INSERT INTO intakes(case_id,source,dedupe_key,payload_json,received_at,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (case_id, body["source"], body["dedupe_key"], json.dumps(body, ensure_ascii=False, sort_keys=True), iso(received), actor, now),
            )
            entry = Repository.append_audit(conn, case_id, actor, role, "case_created",
                                            {"case_no": case_no, "source": body["source"]})
            case = dict(self._case(conn, case_id))
            return {"deduplicated": False, "case": case, "audit_entry": {"seq": entry["seq"], "entry_hash": entry["entry_hash"]}}

    def get_case(self, case_id: int, role: str, region: str) -> dict[str, Any]:
        with self.repo.read() as conn:
            case = self._case(conn, case_id)
            if not self.can_access(case, role, region):
                raise ApiError(403, "case_forbidden", "无权查看该区域案例")
            can_view_audit = role in {"medical_reviewer", "global_admin"}
            intakes = [dict(r) for r in conn.execute(
                "SELECT id,source,dedupe_key,received_at,created_by,created_at FROM intakes WHERE case_id=? ORDER BY id", (case_id,))]
            followups = [dict(r) for r in conn.execute("SELECT * FROM followups WHERE case_id=? ORDER BY revision", (case_id,))]
            reports = [dict(r) for r in conn.execute("SELECT * FROM reports WHERE case_id=? ORDER BY country", (case_id,))]
            reviews = [dict(r) for r in conn.execute("SELECT * FROM medical_reviews WHERE case_id=? ORDER BY id", (case_id,))]
            chain = self._chain_summary(conn, case_id, can_view_audit)
            audit = chain["entries"] if can_view_audit else []
        # 读详情即校验：一旦发现断链/分叉，整案转入待核查。
        self._flag_if_broken(case_id, chain)
        return {
            "case": dict(case),
            "intakes": intakes,
            "followups": followups,
            "reports": reports,
            "reviews": reviews,
            "audit": audit,
            "audit_chain": chain,
        }

    def list_cases(self, role: str, region: str, query: dict[str, list[str]]) -> list[dict[str, Any]]:
        sql = "SELECT * FROM cases WHERE status!='merged'"
        args: list[Any] = []
        if role not in {"medical_reviewer", "global_admin"}:
            sql += " AND region=?"
            args.append(region)
        if query.get("status"):
            sql += " AND status=?"
            args.append(query["status"][0])
        if query.get("chain_state"):
            sql += " AND chain_state=?"
            args.append(query["chain_state"][0])
        sql += " ORDER BY received_at DESC,id DESC"
        with self.repo.read() as conn:
            return [dict(r) for r in conn.execute(sql, args)]

    def add_followup(self, case_id: int, actor: str, role: str, region: str, body: dict[str, Any]) -> dict[str, Any]:
        content = str(body.get("content", "")).strip()
        source = str(body.get("source", "")).strip()
        if not content or not source:
            raise ApiError(400, "missing_fields", "content 和 source 必填")
        expected = body.get("expected_revision")
        if not isinstance(expected, int):
            raise ApiError(400, "revision_required", "expected_revision 必须是整数")
        expected_audit_seq = body.get("expected_audit_seq")
        if expected_audit_seq is not None and not isinstance(expected_audit_seq, int):
            raise ApiError(400, "invalid_audit_seq", "expected_audit_seq 必须是整数")
        with self.repo.tx() as conn:
            case = self._case(conn, case_id)
            if not self.can_access(case, role, region) or role in {"medical_reviewer"}:
                raise ApiError(403, "followup_forbidden", "当前角色不能提交随访")
            if case["status"] == "merged":
                raise ApiError(409, "case_merged", "已合并案例不能再更新")
            if case["revision"] != expected:
                tail = conn.execute(
                    "SELECT audit_tail_seq, audit_tail_hash FROM cases WHERE id=?", (case_id,)
                ).fetchone()
                raise ApiError(409, "revision_conflict", "案例已被其他人员更新，请重新读取后按最新版本与链尾重试",
                               details={"current_revision": case["revision"],
                                        "audit_tail": {"seq": tail["audit_tail_seq"],
                                                       "entry_hash": tail["audit_tail_hash"]}})
            revision = case["revision"] + 1
            received = parse_time(body.get("received_at"), utcnow())
            due = report_deadline(received, bool(case["serious"]), bool(case["fatal"]))
            conn.execute(
                "INSERT INTO followups(case_id,content,source,received_at,revision,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (case_id, content, source, iso(received), revision, actor, iso()),
            )
            conn.execute(
                "UPDATE cases SET revision=?,received_at=?,report_due_at=?,updated_at=? WHERE id=?",
                (revision, iso(received), iso(due), iso(), case_id),
            )
            entry = Repository.append_audit(conn, case_id, actor, role, "followup_added",
                                            {"revision": revision, "source": source},
                                            expected_seq=expected_audit_seq)
            return {"case": dict(self._case(conn, case_id)), "revision": revision,
                    "audit_entry": {"seq": entry["seq"], "entry_hash": entry["entry_hash"]}}

    def medical_review(self, case_id: int, actor: str, role: str, body: dict[str, Any]) -> dict[str, Any]:
        if role != "medical_reviewer":
            raise ApiError(403, "medical_reviewer_required", "只有医学审核员可以裁定严重性")
        expected = body.get("expected_revision")
        if not isinstance(expected, int):
            raise ApiError(400, "revision_required", "expected_revision 必须是整数")
        serious = body.get("serious")
        fatal = body.get("fatal")
        causality = str(body.get("causality", "")).strip()
        rationale = str(body.get("rationale", "")).strip()
        if not isinstance(serious, bool) or not isinstance(fatal, bool) or not causality or not rationale:
            raise ApiError(400, "invalid_review", "serious/fatal 必须是布尔值，causality 和 rationale 必填")
        if fatal and not serious:
            raise ApiError(400, "invalid_severity", "死亡案例必须标记为严重")
        received = parse_time(body.get("received_at"))
        due = report_deadline(received, serious, fatal)
        with self.repo.tx() as conn:
            case = self._case(conn, case_id)
            if case["status"] == "merged":
                raise ApiError(409, "case_merged", "已合并案例不能审核")
            if case["revision"] != expected:
                tail = conn.execute(
                    "SELECT audit_tail_seq, audit_tail_hash FROM cases WHERE id=?", (case_id,)
                ).fetchone()
                raise ApiError(409, "revision_conflict", "案例版本已变化，请重新读取后重试",
                               details={"current_revision": case["revision"],
                                        "audit_tail": {"seq": tail["audit_tail_seq"],
                                                       "entry_hash": tail["audit_tail_hash"]}})
            revision = expected + 1
            conn.execute(
                """UPDATE cases SET serious=?,fatal=?,causality=?,report_due_at=?,revision=?,updated_at=? WHERE id=?""",
                (int(serious), int(fatal), causality, iso(due), revision, iso(), case_id),
            )
            conn.execute(
                """INSERT INTO medical_reviews(case_id,case_revision,serious,fatal,causality,rationale,reviewer,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (case_id, expected, int(serious), int(fatal), causality, rationale, actor, iso()),
            )
            Repository.append_audit(conn, case_id, actor, role, "medical_reviewed",
                                    {"from_revision": expected, "serious": serious, "fatal": fatal, "causality": causality})
            return {"case": dict(self._case(conn, case_id)), "reviewed_revision": expected}

    def create_report(self, case_id: int, actor: str, role: str, region: str, body: dict[str, Any]) -> dict[str, Any]:
        if role not in {"regional_lead", "global_admin"}:
            raise ApiError(403, "report_forbidden", "只有区域负责人或全局管理员可以生成报告")
        country = str(body.get("country", "")).strip().upper()
        if not country:
            raise ApiError(400, "country_required", "country 必填")
        with self.repo.tx() as conn:
            case = self._case(conn, case_id)
            if not self.can_access(case, role, region):
                raise ApiError(403, "region_forbidden", "不能为本区域之外案例生成报告")
            due = report_deadline(parse_time(case["received_at"]), bool(case["serious"]), bool(case["fatal"]))
            try:
                cur = conn.execute("INSERT INTO reports(case_id,country,due_at,status) VALUES(?,?,?,?)", (case_id, country, iso(due), "pending"))
            except sqlite3.IntegrityError as exc:
                raise ApiError(409, "report_exists", "该国家报告已经存在") from exc
            entry = Repository.append_audit(conn, case_id, actor, role, "report_created",
                                            {"report_id": cur.lastrowid, "country": country})
            result = dict(conn.execute("SELECT * FROM reports WHERE id=?", (cur.lastrowid,)).fetchone())
            result["audit_entry"] = {"seq": entry["seq"], "entry_hash": entry["entry_hash"]}
            return result

    def submit_report(self, report_id: int, actor: str, role: str, region: str, body: dict[str, Any]) -> dict[str, Any]:
        if role not in {"regional_lead", "global_admin"}:
            raise ApiError(403, "submit_forbidden", "当前角色不能提交监管报告")
        with self.repo.tx() as conn:
            row = conn.execute("SELECT r.*,c.region FROM reports r JOIN cases c ON c.id=r.case_id WHERE r.id=?", (report_id,)).fetchone()
            if not row:
                raise ApiError(404, "report_not_found", "报告不存在")
            if not self.can_access(dict(row), role, region):
                raise ApiError(403, "region_forbidden", "无权提交其他区域报告")
            if row["status"] == "submitted":
                return {"report": dict(row), "idempotent": True}
            now = parse_time(body.get("submitted_at"), utcnow())
            late = int(now > parse_time(row["due_at"]))
            conn.execute("UPDATE reports SET status='submitted',submitted_at=?,submitted_by=?,late=? WHERE id=?", (iso(now), actor, late, report_id))
            Repository.append_audit(conn, row["case_id"], actor, role, "report_submitted",
                                    {"report_id": report_id, "country": row["country"], "late": bool(late)})
            return {"report": dict(conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()), "idempotent": False}

    def merge_cases(self, source_id: int, actor: str, role: str, body: dict[str, Any]) -> dict[str, Any]:
        if role != "global_admin":
            raise ApiError(403, "merge_forbidden", "只有全局管理员可以合并案例")
        target_id = body.get("target_case_id")
        if not isinstance(target_id, int) or source_id == target_id:
            raise ApiError(400, "invalid_target", "target_case_id 必须指向不同案例")
        with self.repo.tx() as conn:
            source = self._case(conn, source_id)
            target = self._case(conn, target_id)
            if source["status"] == "merged":
                return {"case": dict(source), "idempotent": True}
            if target["status"] == "merged" or source["product"].casefold() != target["product"].casefold():
                raise ApiError(409, "merge_conflict", "目标案例不可用，或产品与来源案例不一致")
            conn.execute("UPDATE cases SET status='merged',merged_into=?,revision=revision+1,updated_at=? WHERE id=?", (target_id, iso(), source_id))
            conn.execute("UPDATE intakes SET case_id=? WHERE case_id=?", (target_id, source_id))
            Repository.append_audit(conn, target_id, actor, role, "case_merged_in", {"source_case_id": source_id})
            Repository.append_audit(conn, source_id, actor, role, "case_merged_into", {"target_case_id": target_id})
            return {"case": dict(self._case(conn, source_id)), "idempotent": False}

    def overdue(self, role: str, region: str) -> list[dict[str, Any]]:
        sql = "SELECT r.*,c.chain_state FROM reports r JOIN cases c ON c.id=r.case_id WHERE r.status!='submitted' AND r.due_at < ?"
        args: list[Any] = [iso()]
        if role not in {"medical_reviewer", "global_admin"}:
            sql += " AND c.region=?"
            args.append(region)
        with self.repo.read() as conn:
            return [dict(r) for r in conn.execute(sql, args)]

    def escalate_overdue(self, actor: str, role: str, region: str) -> dict[str, Any]:
        if role not in {"regional_lead", "global_admin"}:
            raise ApiError(403, "escalation_forbidden", "当前角色不能执行逾期升级")
        sql = """SELECT r.* FROM reports r JOIN cases c ON c.id=r.case_id
                 WHERE r.status='pending' AND r.due_at < ? AND c.chain_state!=?"""
        args: list[Any] = [iso(), CHAIN_INVESTIGATING]
        if role not in {"medical_reviewer", "global_admin"}:
            sql += " AND c.region=?"
            args.append(region)
        blocked: list[dict[str, Any]] = []
        with self.repo.tx() as conn:
            rows = [dict(r) for r in conn.execute(sql, args)]
            for row in rows:
                conn.execute("UPDATE reports SET status='overdue' WHERE id=?", (row["id"],))
                Repository.append_audit(conn, row["case_id"], actor, role, "report_overdue_escalated",
                                        {"report_id": row["id"], "country": row["country"]})
            blocked_rows = conn.execute(
                """SELECT r.id AS report_id, r.case_id, r.country FROM reports r JOIN cases c ON c.id=r.case_id
                   WHERE r.status='pending' AND r.due_at < ? AND c.chain_state=?""" +
                (" AND c.region=?" if role not in {"medical_reviewer", "global_admin"} else ""),
                [iso(), CHAIN_INVESTIGATING] + ([region] if role not in {"medical_reviewer", "global_admin"} else []),
            ).fetchall()
            blocked = [dict(r) for r in blocked_rows]
        return {"escalated": len(rows), "blocked_pending_investigation": blocked}

    def verify_case(self, case_id: int, role: str, region: str) -> dict[str, Any]:
        """显式校验：返回链报告；发现断链/分叉时把整案置为待核查。"""
        with self.repo.tx() as conn:
            case = self._case(conn, case_id)
            if not self.can_access(case, role, region):
                raise ApiError(403, "case_forbidden", "无权查看该区域案例")
            report = Repository.verify_chain(conn, case_id)
            if not report["valid"]:
                conn.execute(
                    "UPDATE cases SET chain_state=? WHERE id=? AND chain_state=?",
                    (CHAIN_INVESTIGATING, case_id, CHAIN_OK),
                )
                report["chain_state"] = CHAIN_INVESTIGATING
            if role not in {"medical_reviewer", "global_admin"}:
                report.pop("entries", None)
                report.pop("superseded_entries", None)
            return report

    def repair_chain(self, case_id: int, actor: str, role: str, body: dict[str, Any]) -> dict[str, Any]:
        """
        越权修复一律拒绝；仅全局管理员可执行，且必须写明原因。
        修复从最早断点起重排/重算链尾，并把原因、断点、改动清单作为 chain_repaired
        记录永久挂在链上，同时登记 chain_repairs 供监管核查。
        """
        if role != "global_admin":
            raise ApiError(403, "repair_forbidden", "只有全局管理员可以修复审计链")
        reason = str(body.get("reason", "")).strip()
        if not reason:
            raise ApiError(400, "reason_required", "修复审计链必须写明原因")
        with self.repo.tx() as conn:
            self._case(conn, case_id)
            report = Repository.verify_chain(conn, case_id)
            earliest = report["earliest_break"]
            renumbered: list[dict[str, int]] = []
            superseded_ids: list[int] = []

            if earliest is not None:
                break_seq = earliest["seq"]
                if earliest["kind"] == "tail_pointer_mismatch":
                    # 链本身完整，只需把案例登记的链尾对齐（最后由 _insert_entry 统一写回）。
                    next_seq = report["tail"]["seq"] + 1 if report["tail"] else 1
                    prev = report["tail"]["entry_hash"] if report["tail"] else GENESIS_HASH
                else:
                    prefix = conn.execute(
                        "SELECT entry_hash FROM audit_chain WHERE case_id=? AND superseded=0 AND seq<=? ORDER BY seq",
                        (case_id, break_seq - 1),
                    ).fetchall()
                    # 分叉时同一序号只保留最早写入的一条，其余保留为 superseded 证据。
                    damaged_rows = conn.execute(
                        "SELECT * FROM audit_chain WHERE case_id=? AND superseded=0 AND seq>=? ORDER BY seq, id",
                        (case_id, break_seq),
                    ).fetchall()
                    kept_seq: set[int] = set()
                    chosen: list[sqlite3.Row] = []
                    for r in damaged_rows:
                        if r["seq"] in kept_seq:
                            conn.execute("UPDATE audit_chain SET superseded=1 WHERE id=?", (r["id"],))
                            superseded_ids.append(r["id"])
                            continue
                        kept_seq.add(r["seq"])
                        chosen.append(r)
                    prev = prefix[-1]["entry_hash"] if prefix else GENESIS_HASH
                    next_seq = break_seq
                    for r in chosen:
                        old_seq = r["seq"]
                        detail_json = canonical_detail(json.loads(r["detail_json"]))
                        digest = entry_hash(next_seq, case_id, r["actor"], r["role"], r["action"],
                                           detail_json, r["created_at"], prev)
                        conn.execute(
                            "UPDATE audit_chain SET seq=?,prev_hash=?,entry_hash=? WHERE id=?",
                            (next_seq, prev, digest, r["id"]),
                        )
                        renumbered.append({"id": r["id"], "old_seq": old_seq, "new_seq": next_seq})
                        prev = digest
                        next_seq += 1

                repair_detail = {
                    "reason": reason,
                    "earliest_break": earliest,
                    "renumbered_entries": renumbered,
                    "superseded_entry_ids": superseded_ids,
                }
            else:
                repair_detail = {"reason": reason, "earliest_break": None, "renumbered_entries": [],
                                 "superseded_entry_ids": [], "note": "校验通过，仅登记管理员复核"}

            # 修复事件本身必须链接入链，不允许“无痕修复”。
            if earliest is not None:
                entry = Repository._insert_entry(
                    conn, case_id, next_seq, actor, role, "chain_repaired", repair_detail,
                    iso(), prev,
                )
            else:
                entry = Repository.append_audit(
                    conn, case_id, actor, role, "chain_repaired", repair_detail,
                )
            conn.execute(
                """INSERT INTO chain_repairs(case_id,entry_seq,admin,reason,break_json,detail_json,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (case_id, entry["seq"], actor, reason,
                 json.dumps(earliest, ensure_ascii=False, sort_keys=True),
                 canonical_detail(repair_detail), entry["created_at"]),
            )
            conn.execute(
                "UPDATE cases SET chain_state=? WHERE id=?", (CHAIN_REPAIRED, case_id)
            )
            final_report = Repository.verify_chain(conn, case_id)
            return {"repaired": earliest is not None, "repair_entry": {"seq": entry["seq"], "entry_hash": entry["entry_hash"]},
                    "reason": reason, "report_before": report, "report_after": final_report}

    def state(self, role: str, region: str) -> dict[str, Any]:
        cases = self.list_cases(role, region, {})
        return {"cases": cases, "overdue": self.overdue(role, region), "server_time": iso()}


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: Any) -> None:
    raw = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


class Handler(BaseHTTPRequestHandler):
    service: PharmacovigilanceService
    web_root: Path

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        try:
            result = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ApiError(400, "invalid_json", "请求体不是有效 JSON") from exc
        if not isinstance(result, dict):
            raise ApiError(400, "invalid_json", "请求体必须是 JSON 对象")
        return result

    def _dispatch_get(self, path: str, query: dict[str, list[str]]) -> Any:
        if path == "/health":
            return 200, {"status": "ok", "service": "pharmacovigilance"}
        actor, role, region = self.service.identity(self.headers)
        if path == "/api/state":
            return 200, self.service.state(role, region)
        if path == "/api/cases":
            return 200, {"cases": self.service.list_cases(role, region, query)}
        if path == "/api/overdue":
            return 200, {"reports": self.service.overdue(role, region)}
        parts = [part for part in path.split("/") if part]
        if len(parts) == 3 and parts[:2] == ["api", "cases"] and parts[2].isdigit():
            return 200, self.service.get_case(int(parts[2]), role, region)
        if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[2].isdigit() and parts[3] == "audit-verify":
            return 200, self.service.verify_case(int(parts[2]), role, region)
        raise ApiError(404, "not_found", "接口不存在")

    def _dispatch_post(self, path: str, body: dict[str, Any]) -> Any:
        actor, role, region = self.service.identity(self.headers)
        if path == "/api/cases":
            return 201, self.service.create_case(actor, role, region, body)
        if path == "/api/escalate-overdue":
            return 200, self.service.escalate_overdue(actor, role, region)
        parts = [part for part in path.split("/") if part]
        if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[2].isdigit():
            case_id, action = int(parts[2]), parts[3]
            if action == "followups":
                return 201, self.service.add_followup(case_id, actor, role, region, body)
            if action == "medical-review":
                return 200, self.service.medical_review(case_id, actor, role, body)
            if action == "reports":
                return 201, self.service.create_report(case_id, actor, role, region, body)
            if action == "merge":
                return 200, self.service.merge_cases(case_id, actor, role, body)
            if action == "audit-repair":
                return 200, self.service.repair_chain(case_id, actor, role, body)
        if len(parts) == 4 and parts[:2] == ["api", "reports"] and parts[2].isdigit() and parts[3] == "submit":
            return 200, self.service.submit_report(int(parts[2]), actor, role, region, body)
        raise ApiError(404, "not_found", "接口不存在")

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        try:
            if method == "GET" and parsed.path == "/":
                page = (self.web_root / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return
            if method == "GET":
                status, payload = self._dispatch_get(parsed.path, parse_qs(parsed.query))
            else:
                status, payload = self._dispatch_post(parsed.path, self._body())
            json_response(self, status, payload)
        except ApiError as exc:
            error = {"error": exc.code, "message": exc.message}
            if exc.details:
                error["details"] = exc.details
            json_response(self, exc.status, error)
        except Exception as exc:
            print(f"unhandled error: {exc!r}")
            json_response(self, 500, {"error": "internal_error", "message": str(exc)})

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")


def create_server(db_path: str | Path, host: str = "127.0.0.1", port: int = PORT) -> ThreadingHTTPServer:
    service = PharmacovigilanceService(db_path)
    web_root = Path(__file__).resolve().parent / "static"
    handler = type("PharmacovigilanceHandler", (Handler,), {"service": service, "web_root": web_root})
    return ThreadingHTTPServer((host, port), handler)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--db", default=os.environ.get("PV_DB", "pharmacovigilance.db"))
    args = parser.parse_args()
    server = create_server(args.db, args.host, args.port)
    print(f"pharmacovigilance listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
