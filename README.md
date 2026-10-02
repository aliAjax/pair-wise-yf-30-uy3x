# 药物警戒案例处理系统

使用 Python 标准库实现的独立原型，覆盖多渠道案例接入、去重、随访更正、严重性医学裁定、分国家报告、逾期升级、跨区域权限、案例合并审计，以及**逐案例连续可校验的哈希审计链（防抹去、防补插、防分叉）**。

## 运行

要求 Python 3.11+。

```bash
python3 app.py --db pharmacovigilance.db
```

默认监听 `127.0.0.1:8201`。首页为 `http://127.0.0.1:8201/`，健康检查为 `/health`。

所有接口使用请求头 `X-User-Id`、`X-Role` 和区域角色必需的 `X-Region`。角色为 `reporter`、`regional_lead`、`medical_reviewer`、`global_admin`。

## 主要接口

- `POST /api/cases`：录入案例，`dedupe_key` 相同则返回已存在案例。
- `GET /api/cases`、`GET /api/cases/{id}`：按权限查询。`GET /api/cases?chain_state=investigating` 可筛选待核查案例。
- `POST /api/cases/{id}/followups`：用 `expected_revision` 防止覆盖随访；可附 `expected_audit_seq` 按最新审计链尾做 CAS 追加。
- `POST /api/cases/{id}/medical-review`：医学审核员更新严重性、死亡和关联性。
- `POST /api/cases/{id}/reports`、`POST /api/reports/{id}/submit`：生成并提交分国家报告。
- `POST /api/cases/{id}/merge`：全局管理员合并重复案例。
- `POST /api/escalate-overdue`、`GET /api/overdue`：逾期检查与升级。
- `GET /api/cases/{id}/audit-verify`：校验审计链，返回是否有效与**最早断点**；发现断链/分叉时整案自动转入待核查。
- `POST /api/cases/{id}/audit-repair`：**仅全局管理员**，请求体必须含非空 `reason`；修复过程本身也作为 `chain_repaired` 记录上链，并在 `chain_repairs` 表留档。

## 审计链（监管数据完整性）

每个案例的审计记录存在 `audit_chain` 中，按案内序号 `seq` 连续排列：

- **链式摘要**：每条记录的 `entry_hash = SHA256(seq, case_id, actor, role, action, detail_json, created_at, prev_hash)`，新记录携带前一条摘要；首条记录的前摘要是 64 个 0 的创世值。案例表冗余登记 `audit_tail_seq` / `audit_tail_hash`。
- **可校验并指出最早断点**：校验逐记录重算摘要并核对前驱，能区分 `hash_mismatch`（内容被抹去/篡改）、`seq_gap`（记录被删除）、`prev_hash_mismatch`（补插/替换）、`chain_fork`（同一前驱两个后继）、`genesis_mismatch`、`tail_pointer_mismatch`，并返回最靠前的断点。
- **旧数据升级**：首次启动新版时自动把旧 `audit_log` 按案例和原顺序重排、重算摘要，一次性补齐链条（`schema_meta` 记录迁移版本，不重复执行）；旧记录与新记录一样可通过校验，升级后新追加接在旧链尾之后。
- **并发追加**：所有追加在 `BEGIN IMMEDIATE` 写事务内、按最新链尾 CAS 接上。两人同时追加同一案例时只有一条成功，另一条收到 `409 revision_conflict` / `409 chain_tail_conflict`，响应 `details` 带回最新链尾，调用方按最新链尾重试即可。
- **待核查与修复授权**：追加前和读取详情时都会校验；一旦发现断链或分叉，案例 `chain_state` 置为 `investigating`，业务写入被拒绝。任何非全局管理员的修复返回 `403 repair_forbidden`；管理员修复必须写明原因，系统从最早断点起重排/重算链尾，败选支保留为 `superseded` 证据，修复后状态为 `repaired`（若再次被破坏会重新进入待核查）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

`tests/test_audit_chain.py` 覆盖正常链、各类篡改检测与最早断点、旧库迁移、并发追加重试、待核查锁定、越权/无原因修复拒绝、管理员修复留痕等场景。

## 主要局限

该实现使用请求头模拟身份，不含生产级登录、签名和密钥管理；审计链只保证“记录之间不可无痕改动并可检出”，有数据库直接写权限的攻击者仍可整体重算链条，因此生产部署应配合只追加存储/WORM、独立保管的库外锚点或定期外部公证，并锁定 DDL/DML 直写权限。SQLite 与标准库 HTTP 服务适合单机原型。分国家规则采用内置严重 15 天、死亡 7 天、非严重 90 天规则，接入真实监管网关前需按当地法规扩展。
