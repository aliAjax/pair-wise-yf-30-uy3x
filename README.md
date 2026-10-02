# 药物警戒案例处理系统

使用 Python 标准库实现的独立原型，覆盖多渠道案例接入、去重、随访更正、严重性医学裁定、分国家报告、逾期升级、跨区域权限和案例合并审计。

## 运行

要求 Python 3.11+。

```bash
python3 app.py --db pharmacovigilance.db
```

默认监听 `127.0.0.1:8201`。首页为 `http://127.0.0.1:8201/`，健康检查为 `/health`。

所有接口使用请求头 `X-User-Id`、`X-Role` 和区域角色必需的 `X-Region`。角色为 `reporter`、`regional_lead`、`medical_reviewer`、`global_admin`。

## 主要接口

- `POST /api/cases`：录入案例，`dedupe_key` 相同则返回已存在案例。
- `GET /api/cases`、`GET /api/cases/{id}`：按权限查询。
- `POST /api/cases/{id}/followups`：用 `expected_revision` 防止覆盖随访。
- `POST /api/cases/{id}/medical-review`：医学审核员更新严重性、死亡和关联性。
- `POST /api/cases/{id}/reports`、`POST /api/reports/{id}/submit`：生成并提交分国家报告。
- `POST /api/cases/{id}/merge`：全局管理员合并重复案例。
- `GET /api/cases/{id}/audit-chain`：校验案例审计链，断链/分叉时整案进入待核查。
- `POST /api/cases/{id}/audit-repair`：全局管理员写明原因后修复审计链。
- `POST /api/escalate-overdue`、`GET /api/overdue`：逾期检查与升级。

## 审计链（数据完整性核查）

每个案例的审计日志构成一条连续可校验的哈希链：新记录通过 `prev_hash` 携带前一条记录的摘要，`record_hash` 覆盖本条规范字段，创世记录前一条摘要为 64 个 0。

- `GET /api/cases/{id}/audit-chain`：校验该案例审计链，返回 `valid`、`records_checked`、`tail_hash` 与最早断点 `earliest_break`（含 `reason`：`gap` 序号不连续、`link_mismatch` 前向链接断裂、`digest_mismatch` 内容被篡改、`fork` 分叉）。发现断链或分叉时整案自动进入 `pending_verification`（待核查），期间冻结随访、医学裁定、报告、合并等变更。
- `POST /api/cases/{id}/audit-repair`：仅 `global_admin` 可调用，请求体必须写明 `reason`。修复按现存记录顺序重新挂链，修复动作本身写入审计链留痕；修复后案例恢复 `verified`。
- 并发追加：随访等追加支持 `expected_tail_hash` 乐观锁。链尾已被其他追加更新时返回 `409 chain_conflict` 并附带 `current_tail_hash`，调用方按最新链尾重试即可，保证两人同时追加只有一条接上。
- 旧数据升级：服务启动时自动为缺少摘要的历史审计记录补 `seq`/`prev_hash`/`record_hash`，旧记录也能通过校验；已有哈希的记录不被重算，篡改仍会被校验发现。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 主要局限

该实现使用请求头模拟身份，不含生产级登录、签名和密钥管理；SQLite 与标准库 HTTP 服务适合单机原型。分国家规则采用内置严重 15 天、死亡 7 天、非严重 90 天规则，接入真实监管网关前需按当地法规扩展。
