#!/usr/bin/env python3
"""Pharmacovigilance case intake service using only the Python standard library."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

PORT = 8201
ROLES = {"reporter", "regional_lead", "medical_reviewer", "global_admin"}

# 审计链创世记录的前一条摘要（64 个 0）
GENESIS_HASH = "0" * 64


def record_digest(*, seq: int, prev_hash: str, case_id: int | None, actor: str,
                  role: str, action: str, detail_json: str, created_at: str) -> str:
    """按规范字段重算审计记录摘要，用于挂链与校验。"""
    material = json.dumps(
        {
            "seq": seq,
            "case_id": case_id,
            "actor": actor,
            "role": role,
            "action": action,
            "detail": json.loads(detail_json),
            "created_at": created_at,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra


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


class Repository:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    @contextmanager
    def tx(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def init_schema(self) -> None:
        self.conn.executescript(
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
                audit_status TEXT NOT NULL DEFAULT 'verified',
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
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                seq INTEGER NOT NULL DEFAULT 0,
                prev_hash TEXT NOT NULL DEFAULT '',
                record_hash TEXT NOT NULL DEFAULT ''
            );
            """
        )
        self._migrate_legacy_schema()
        self.upgrade_audit_chains()

    def _migrate_legacy_schema(self) -> None:
        """为旧版本库补齐审计链所需列（SQLite 不支持 ADD COLUMN IF NOT EXISTS）。"""
        existing = {row["name"] for row in self.conn.execute("PRAGMA table_info(audit_log)")}
        for column, ddl in (
            ("seq", "ALTER TABLE audit_log ADD COLUMN seq INTEGER NOT NULL DEFAULT 0"),
            ("prev_hash", "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"),
            ("record_hash", "ALTER TABLE audit_log ADD COLUMN record_hash TEXT NOT NULL DEFAULT ''"),
        ):
            if column not in existing:
                self.conn.execute(ddl)
        case_columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(cases)")}
        if "audit_status" not in case_columns:
            self.conn.execute("ALTER TABLE cases ADD COLUMN audit_status TEXT NOT NULL DEFAULT 'verified'")

    def upgrade_audit_chains(self) -> dict[str, int]:
        """补齐旧数据的审计链：为从未挂链的记录按序补 seq/prev_hash/record_hash。

        幂等，可在每次启动时执行。已有哈希的记录（可能被篡改）保持原样，
        交由校验发现，绝不在升级时静默重算。返回补链的案例数与记录数。
        """
        upgraded_cases = 0
        upgraded_records = 0
        case_ids = [row["id"] for row in self.conn.execute("SELECT id FROM cases ORDER BY id")]
        for case_id in case_ids:
            rows = self.conn.execute(
                "SELECT * FROM audit_log WHERE case_id=? ORDER BY id", (case_id,)
            ).fetchall()
            prev_hash = GENESIS_HASH
            seq = 0
            changed = False
            for row in rows:
                seq += 1
                if not row["record_hash"]:
                    digest = record_digest(
                        seq=seq,
                        prev_hash=prev_hash,
                        case_id=row["case_id"],
                        actor=row["actor"],
                        role=row["role"],
                        action=row["action"],
                        detail_json=row["detail_json"],
                        created_at=row["created_at"],
                    )
                    self.conn.execute(
                        "UPDATE audit_log SET seq=?, prev_hash=?, record_hash=? WHERE id=?",
                        (seq, prev_hash, digest, row["id"]),
                    )
                    prev_hash = digest
                    changed = True
                    upgraded_records += 1
                else:
                    prev_hash = row["record_hash"]
            if changed:
                upgraded_cases += 1
        return {"cases": upgraded_cases, "records": upgraded_records}

    @staticmethod
    def chain_tail(conn: sqlite3.Connection, case_id: int | None) -> tuple[str, int]:
        """返回案例当前链尾摘要与序号；无记录时返回创世摘要与 0。"""
        row = conn.execute(
            "SELECT record_hash, seq FROM audit_log WHERE case_id IS ? ORDER BY id DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        if not row or not row["record_hash"]:
            return GENESIS_HASH, 0
        return row["record_hash"], row["seq"]

    @staticmethod
    def audit(conn: sqlite3.Connection, case_id: int | None, actor: str, role: str,
              action: str, detail: dict[str, Any], expected_tail_hash: str | None = None) -> dict[str, Any]:
        """向案例审计链追加一条记录，自动链接前一条摘要。

        调用方可传入上次读到的 expected_tail_hash 做乐观并发控制：
        若链尾已被其他追加更新则抛出 409 chain_conflict 并附带当前链尾，
        调用方应按最新链尾重试。
        """
        tail_hash, tail_seq = Repository.chain_tail(conn, case_id)
        if expected_tail_hash is not None and not hmac.compare_digest(str(expected_tail_hash), tail_hash):
            raise ApiError(409, "chain_conflict", "审计链尾已被其他追加更新，请按最新链尾重试",
                           current_tail_hash=tail_hash)
        seq = tail_seq + 1
        detail_json = json.dumps(detail, ensure_ascii=False, sort_keys=True)
        created_at = iso()
        digest = record_digest(
            seq=seq,
            prev_hash=tail_hash,
            case_id=case_id,
            actor=actor,
            role=role,
            action=action,
            detail_json=detail_json,
            created_at=created_at,
        )
        conn.execute(
            """INSERT INTO audit_log(case_id,actor,role,action,detail_json,created_at,seq,prev_hash,record_hash)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (case_id, actor, role, action, detail_json, created_at, seq, tail_hash, digest),
        )
        return {"seq": seq, "prev_hash": tail_hash, "record_hash": digest}

    @staticmethod
    def row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None


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

    @staticmethod
    def _require_auditable(case: sqlite3.Row) -> None:
        """断链/分叉待核查期间冻结案例的一切变更。"""
        if case["audit_status"] == "pending_verification":
            raise ApiError(409, "case_pending_verification",
                          "案例审计链存在断链或分叉，整案待核查，期间禁止变更；仅全局管理员写明原因后可修复")

    def verify_chain(self, case_id: int, role: str | None = None, region: str | None = None) -> dict[str, Any]:
        """逐条重算审计链摘要，返回校验结果与最早断点。

        校验项：记录是否从未挂链、序号是否连续（抹去）、前向链接是否吻合
        （抹去/补插）、本条摘要是否被篡改、是否存在分叉（多条记录指向同一前条）。
        """
        conn = self.repo.conn
        case = self._case(conn, case_id)
        if role is not None and not self.can_access(case, role, region or ""):
            raise ApiError(403, "case_forbidden", "无权查看该区域案例审计链")
        rows = conn.execute("SELECT * FROM audit_log WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        expected_prev = GENESIS_HASH
        expected_seq = 1
        earliest_break: dict[str, Any] | None = None
        for row in rows:
            if not row["record_hash"]:
                earliest_break = {
                    "record_id": row["id"], "seq": row["seq"], "reason": "unhashed_record",
                    "message": "记录未挂链，疑似旧数据升级未完成",
                }
                break
            if row["seq"] != expected_seq:
                earliest_break = {
                    "record_id": row["id"], "seq": row["seq"], "reason": "gap",
                    "expected_seq": expected_seq, "actual_seq": row["seq"],
                    "message": "序号不连续，疑似有记录被抹去",
                }
                break
            if not hmac.compare_digest(row["prev_hash"], expected_prev):
                earliest_break = {
                    "record_id": row["id"], "seq": row["seq"], "reason": "link_mismatch",
                    "expected_prev_hash": expected_prev, "actual_prev_hash": row["prev_hash"],
                    "message": "前向链接断裂，前一条摘要对不上，疑似记录被抹去或补插",
                }
                break
            digest = record_digest(
                seq=row["seq"],
                prev_hash=row["prev_hash"],
                case_id=row["case_id"],
                actor=row["actor"],
                role=row["role"],
                action=row["action"],
                detail_json=row["detail_json"],
                created_at=row["created_at"],
            )
            if not hmac.compare_digest(digest, row["record_hash"]):
                earliest_break = {
                    "record_id": row["id"], "seq": row["seq"], "reason": "digest_mismatch",
                    "expected_hash": digest, "actual_hash": row["record_hash"],
                    "message": "记录摘要与内容不符，疑似记录被篡改",
                }
                break
            expected_prev = digest
            expected_seq += 1
        forks: list[dict[str, Any]] = []
        fork_break: dict[str, Any] | None = None
        fork_rows = conn.execute(
            """SELECT id, seq, prev_hash, COUNT(*) AS c FROM audit_log
               WHERE case_id=? AND prev_hash!='' GROUP BY prev_hash HAVING c > 1 ORDER BY id""",
            (case_id,),
        ).fetchall()
        for fr in fork_rows:
            forks.append({
                "record_id": fr["id"], "seq": fr["seq"], "prev_hash": fr["prev_hash"],
                "message": "发现分叉：多条记录指向同一条前条摘要，疑似并发补插",
            })
            if fork_break is None:
                fork_break = {
                    "record_id": fr["id"], "seq": fr["seq"], "reason": "fork",
                    "prev_hash": fr["prev_hash"],
                    "message": "发现分叉：多条记录指向同一条前条摘要，疑似并发补插",
                }
        if fork_break is not None and (earliest_break is None or fork_break["record_id"] < earliest_break["record_id"]):
            earliest_break = fork_break
        tail_hash = rows[-1]["record_hash"] if rows and rows[-1]["record_hash"] else GENESIS_HASH
        return {
            "case_id": case_id,
            "valid": earliest_break is None,
            "records_checked": len(rows),
            "tail_hash": tail_hash,
            "audit_status": case["audit_status"],
            "earliest_break": earliest_break,
            "forks": forks,
        }

    def check_audit_chain(self, case_id: int, actor: str, role: str, region: str) -> dict[str, Any]:
        """校验审计链；一旦发现断链或分叉，整案进入待核查并冻结变更。"""
        result = self.verify_chain(case_id, role, region)
        if not result["valid"] and result["audit_status"] != "pending_verification":
            with self.repo.tx() as conn:
                conn.execute(
                    "UPDATE cases SET audit_status='pending_verification', updated_at=? WHERE id=?",
                    (iso(), case_id),
                )
            result["audit_status"] = "pending_verification"
        return result

    def repair_chain(self, case_id: int, actor: str, role: str, body: dict[str, Any]) -> dict[str, Any]:
        """全局管理员写明原因后重新挂链修复，修复动作本身写入审计链。"""
        if role != "global_admin":
            raise ApiError(403, "repair_forbidden", "只有全局管理员可以修复审计链")
        reason = str(body.get("reason", "")).strip()
        if not reason:
            raise ApiError(400, "reason_required", "修复审计链必须写明原因")
        with self.repo.tx() as conn:
            case = self._case(conn, case_id)
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE case_id=? ORDER BY id", (case_id,)
            ).fetchall()
            prev_hash = GENESIS_HASH
            seq = 0
            relinked = 0
            for row in rows:
                seq += 1
                digest = record_digest(
                    seq=seq,
                    prev_hash=prev_hash,
                    case_id=row["case_id"],
                    actor=row["actor"],
                    role=row["role"],
                    action=row["action"],
                    detail_json=row["detail_json"],
                    created_at=row["created_at"],
                )
                if row["seq"] != seq or row["prev_hash"] != prev_hash or not hmac.compare_digest(row["record_hash"], digest):
                    conn.execute(
                        "UPDATE audit_log SET seq=?, prev_hash=?, record_hash=? WHERE id=?",
                        (seq, prev_hash, digest, row["id"]),
                    )
                    relinked += 1
                prev_hash = digest
            Repository.audit(conn, case_id, actor, role, "audit_chain_repaired",
                             {"reason": reason, "records_relinked": relinked, "records_total": len(rows)})
            conn.execute(
                "UPDATE cases SET audit_status='verified', updated_at=? WHERE id=?",
                (iso(), case_id),
            )
        return {"case_id": case_id, "relinked": relinked, "records_total": len(rows),
                "reason": reason, "audit_status": "verified"}

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
                Repository.audit(conn, case["id"], actor, role, "intake_deduplicated", {"dedupe_key": body["dedupe_key"], "source": body["source"]})
                return {"deduplicated": True, "case": dict(case), "intake_id": duplicate["id"]}
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
            Repository.audit(conn, case_id, actor, role, "case_created", {"case_no": case_no, "source": body["source"]})
            case = self._case(conn, case_id)
            return {"deduplicated": False, "case": dict(case)}

    def get_case(self, case_id: int, role: str, region: str) -> dict[str, Any]:
        case = self._case(self.repo.conn, case_id)
        if not self.can_access(case, role, region):
            raise ApiError(403, "case_forbidden", "无权查看该区域案例")
        conn = self.repo.conn
        return {
            "case": dict(case),
            "intakes": [dict(r) for r in conn.execute("SELECT id,source,dedupe_key,received_at,created_by,created_at FROM intakes WHERE case_id=? ORDER BY id", (case_id,))],
            "followups": [dict(r) for r in conn.execute("SELECT * FROM followups WHERE case_id=? ORDER BY revision", (case_id,))],
            "reports": [dict(r) for r in conn.execute("SELECT * FROM reports WHERE case_id=? ORDER BY country", (case_id,))],
            "reviews": [dict(r) for r in conn.execute("SELECT * FROM medical_reviews WHERE case_id=? ORDER BY id", (case_id,))],
            "audit": [dict(r) for r in conn.execute("SELECT id,actor,role,action,detail_json,created_at,seq,prev_hash,record_hash FROM audit_log WHERE case_id=? ORDER BY id", (case_id,))] if role in {"medical_reviewer", "global_admin"} else [],
            "audit_chain": self.verify_chain(case_id, role, region) if role in {"medical_reviewer", "global_admin"} else None,
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
        sql += " ORDER BY received_at DESC,id DESC"
        return [dict(r) for r in self.repo.conn.execute(sql, args)]

    def add_followup(self, case_id: int, actor: str, role: str, region: str, body: dict[str, Any]) -> dict[str, Any]:
        content = str(body.get("content", "")).strip()
        source = str(body.get("source", "")).strip()
        if not content or not source:
            raise ApiError(400, "missing_fields", "content 和 source 必填")
        expected = body.get("expected_revision")
        if not isinstance(expected, int):
            raise ApiError(400, "revision_required", "expected_revision 必须是整数")
        expected_tail = body.get("expected_tail_hash")
        if expected_tail is not None and not isinstance(expected_tail, str):
            raise ApiError(400, "invalid_tail_hash", "expected_tail_hash 必须是字符串")
        with self.repo.tx() as conn:
            case = self._case(conn, case_id)
            if not self.can_access(case, role, region) or role in {"medical_reviewer"}:
                raise ApiError(403, "followup_forbidden", "当前角色不能提交随访")
            if case["status"] == "merged":
                raise ApiError(409, "case_merged", "已合并案例不能再更新")
            self._require_auditable(case)
            if expected_tail is not None:
                current_tail, _ = Repository.chain_tail(conn, case_id)
                if not hmac.compare_digest(str(expected_tail), current_tail):
                    raise ApiError(409, "chain_conflict",
                                   "审计链尾已被其他追加更新，请按最新链尾重试",
                                   current_tail_hash=current_tail)
            if case["revision"] != expected:
                raise ApiError(409, "revision_conflict", "案例已被其他人员更新，请重新读取")
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
            tail = Repository.audit(conn, case_id, actor, role, "followup_added",
                                    {"revision": revision, "source": source},
                                    expected_tail_hash=expected_tail)
            return {"case": dict(self._case(conn, case_id)), "revision": revision, "audit_tail": tail}

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
            self._require_auditable(case)
            if case["revision"] != expected:
                raise ApiError(409, "revision_conflict", "案例版本已变化")
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
            Repository.audit(conn, case_id, actor, role, "medical_reviewed", {"from_revision": expected, "serious": serious, "fatal": fatal, "causality": causality})
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
            self._require_auditable(case)
            due = report_deadline(parse_time(case["received_at"]), bool(case["serious"]), bool(case["fatal"]))
            try:
                cur = conn.execute("INSERT INTO reports(case_id,country,due_at,status) VALUES(?,?,?,?)", (case_id, country, iso(due), "pending"))
            except sqlite3.IntegrityError as exc:
                raise ApiError(409, "report_exists", "该国家报告已经存在") from exc
            Repository.audit(conn, case_id, actor, role, "report_created", {"report_id": cur.lastrowid, "country": country})
            return dict(conn.execute("SELECT * FROM reports WHERE id=?", (cur.lastrowid,)).fetchone())

    def submit_report(self, report_id: int, actor: str, role: str, region: str, body: dict[str, Any]) -> dict[str, Any]:
        if role not in {"regional_lead", "global_admin"}:
            raise ApiError(403, "submit_forbidden", "当前角色不能提交监管报告")
        with self.repo.tx() as conn:
            row = conn.execute("SELECT r.*,c.region,c.audit_status FROM reports r JOIN cases c ON c.id=r.case_id WHERE r.id=?", (report_id,)).fetchone()
            if not row:
                raise ApiError(404, "report_not_found", "报告不存在")
            if not self.can_access(dict(row), role, region):
                raise ApiError(403, "region_forbidden", "无权提交其他区域报告")
            if row["audit_status"] == "pending_verification":
                raise ApiError(409, "case_pending_verification", "案例审计链待核查，期间禁止提交报告")
            if row["status"] == "submitted":
                return {"report": dict(row), "idempotent": True}
            now = parse_time(body.get("submitted_at"), utcnow())
            late = int(now > parse_time(row["due_at"]))
            conn.execute("UPDATE reports SET status='submitted',submitted_at=?,submitted_by=?,late=? WHERE id=?", (iso(now), actor, late, report_id))
            Repository.audit(conn, row["case_id"], actor, role, "report_submitted", {"report_id": report_id, "country": row["country"], "late": bool(late)})
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
            self._require_auditable(source)
            self._require_auditable(target)
            conn.execute("UPDATE cases SET status='merged',merged_into=?,revision=revision+1,updated_at=? WHERE id=?", (target_id, iso(), source_id))
            conn.execute("UPDATE intakes SET case_id=? WHERE case_id=?", (target_id, source_id))
            Repository.audit(conn, target_id, actor, role, "case_merged_in", {"source_case_id": source_id})
            Repository.audit(conn, source_id, actor, role, "case_merged_into", {"target_case_id": target_id})
            return {"case": dict(self._case(conn, source_id)), "idempotent": False}

    def overdue(self, role: str, region: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM reports WHERE status!='submitted' AND due_at < ?"
        args: list[Any] = [iso()]
        if role not in {"medical_reviewer", "global_admin"}:
            sql += " AND case_id IN (SELECT id FROM cases WHERE region=?)"
            args.append(region)
        return [dict(r) for r in self.repo.conn.execute(sql, args)]

    def escalate_overdue(self, actor: str, role: str, region: str) -> dict[str, Any]:
        if role not in {"regional_lead", "global_admin"}:
            raise ApiError(403, "escalation_forbidden", "当前角色不能执行逾期升级")
        rows = self.overdue(role, region)
        with self.repo.tx() as conn:
            for row in rows:
                conn.execute("UPDATE reports SET status='overdue' WHERE id=? AND status='pending'", (row["id"],))
                Repository.audit(conn, row["case_id"], actor, role, "report_overdue_escalated", {"report_id": row["id"], "country": row["country"]})
        return {"escalated": len(rows)}

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
        if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[2].isdigit() and parts[3] == "audit-chain":
            return 200, self.service.check_audit_chain(int(parts[2]), actor, role, region)
        if len(parts) == 3 and parts[:2] == ["api", "cases"] and parts[2].isdigit():
            return 200, self.service.get_case(int(parts[2]), role, region)
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
            json_response(self, exc.status, {"error": exc.code, "message": exc.message, **exc.extra})
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
