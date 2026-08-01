# intelligence/

Score aggregation. Reads ctx flags from detection+l7+transport+core, computes `ctx.score`, identifies top contributing signals.

## Purpose
Convert dozens of individual signals (each [0,1]) into a single weighted score [0,100+] that enforcement/engine consumes. Track contribution % for explainability.

## Files

| File | Role |
|---|---|
| `init.lua` | Orchestrator: `compute.run(ctx)` → `signal_merge.run(ctx)` → `context_vector.run(ctx)` → `threat/*.run(ctx)` |
| `scoring/compute.lua` | Walks `DEFAULT_WEIGHTS` table, calls `get_signal(name, ctx)` per signal, sums weighted contributions into `ctx.score`. Records `ctx.top_signals` (3 highest with contribution_pct) |
| `scoring/signal_merge.lua` | Normalizes signal sources into common shape `{name, field, type}` for compute |
| `scoring/context_vector.lua` | Build per-context dampening (resource gets lower base on every signal) |
| `threat/*.lua` | Specialized threat assessments (compound rules, attack-chain detection) — emit `ctx.corr_score`, `ctx.corr_rules`, `ctx.mismatch` |

## DEFAULT_WEIGHTS (compute.lua excerpt)
| Signal | Weight | Source |
|---|---|---|
| `ip_rep` | 45 | Redis `ip_risk:<ip>` |
| `ip_score` | 25 | core/fingerprint/ip_classify (datacenter/vpn/etc) |
| `bot_score` | varies | detection/bot |
| `header_flag` | varies | detection/anomaly/header_anomaly |
| `ua_flag` | varies | detection/anomaly/ua_anomaly |
| `proto_flag` | varies | detection/anomaly/protocol_anomaly |
| `cluster_score` | varies | detection/cluster |
| `graph_score` | varies | detection/graph |
| `behavior_score` | varies | detection/behavior |
| `session_flag` | varies | detection/session |
| `h2_bot_confidence` | varies | transport/http2 |
| `mismatch` | varies | threat correlation |
| `burst` | varies | l7/burst |
| `slow` | varies | l7/slow (boolean → multiplied) |
| `ip_surge` | 25 | l7/rate/adaptive_limit (boolean → 1.0/0.0) |

## ctx fields written
`score`, `top_signals` (array of `{signal, contribution_pct, value, weight}`), `corr_score`, `corr_rules`, `mismatch`

## ctx fields read
ALL signal fields from upstream layers. Plus `req_class` for class-based dampening.

## Flow
```
[detection.run + l7.run + transport.run all complete]
            ↓
intelligence.run(ctx)
   compute.run            → walk weights, get_signal(), sum → ctx.score
   signal_merge.run       → normalize signal table
   context_vector.run     → resource class dampening
   threat/correlate.run   → ctx.corr_score, ctx.mismatch, ctx.corr_rules
            ↓
enforcement.engine.run    → compute effective_score, decide action
```

## Related
- Reads from: every other layer (it's the aggregator)
- Writes to: `enforcement/decision/engine.lua`
- Async update: `async/risk_update.lua` writes `ip_risk:<ip>` based on action outcome (next request reads via ip_rep)

## Important rules
- New signal: register in BOTH `DEFAULT_WEIGHTS` AND `get_signal()` switch in compute.lua. Forgetting one → silent zero contribution
- Keep signals in `[0, 1]` range — compute multiplies by weight, summing >1 values would exceed score budget
- Don't add weight without removing/reducing another — total score budget should stay consistent (currently roughly 100 max for typical bot)
- `top_signals` array: keep at 3 entries, used by explain.lua + antibot.log

## Update log
- 2026-08-01 — **`mismatch`: hai luật H2 chuyển từ CỘNG DỒN sang PHÂN BẬC** (`correlation/consistency_check.lua`).
  - **Vấn đề:** `chrome_no_h2` (+0.25) và `no_h2_no_secfetch` (+0.35) đứng trên **cùng tiền đề "không có H2"**; luật mạnh chỉ thêm bằng chứng phụ. Khi cả hai cùng bắn, "không có H2" bị tính tiền **hai lần** → 0.60 (33 điểm) so với 0.35 (19,25 điểm) của nhóm chỉ có luật mạnh — cùng bằng chứng, chênh 13,75 điểm không tương ứng thông tin nào.
  - **Đo (`mm=`, 27k request):** chồng lấn **12603/15358 = 82%**. `no_h2_no_secfetch` chạy một mình 3655. `chrome_no_h2` chạy một mình **2755 (18%)** — Chrome, không H2, **có** Sec-Fetch (bot sao chép header nhưng không làm được H2) ⇒ **không xoá được luật yếu**, chỉ chuyển thành `elseif`.
  - **Bối cảnh quyết định:** `chrome_no_h2` gác bởi `ctx.ja3 ~= nil` nên **chết suốt 3 tháng**, chỉ sống lại 2026-07-31 khi JA3 được sửa. Mọi ngưỡng hiện hành được hiệu chỉnh trong thế giới 0.35. Bỏ double-count **không làm yếu một hệ đã hiệu chỉnh — nó trả hệ về đúng trạng thái đã hiệu chỉnh**; trạng thái sau bản vá JA3 mới là cái bất thường. Muốn tăng độ nhạy thì hạ ngưỡng có chủ đích, không nhận nó như tác dụng phụ của bug fix.
  - **Ảnh hưởng đo TRƯỚC khi sửa:** 12644 request mất 13,75 điểm. Trong 113 ca đang `block` chỉ **27** tụt xuống `challenge`; 175/179 ca biên ở `richness=0.00` (không có người dùng thật), top signal có `bot_score=34%` + `anomaly_score≈10%` + `risk=8%` — chứng cứ độc lập với H2 vẫn còn nên chúng rơi vào PoW chứ không thoát.
  - **Giả thuyết đã BÁC BỎ trên đường đi** (ghi lại để không đào lại): (1) `tls12` đánh nhầm văn phòng sau middlebox kiểm tra TLS — sai, 356 ca đều `richness ≤ 0.13`; (2) `mismatch` bão hoà vì trần `min(1.0)` — sai, `mm_raw > 1.0` chỉ 0.0%; (3) cụm `richness=0.80` của `chrome_no_h2` là Chrome thật qua proxy — sai, **97,5% trong số đó cũng thiếu Sec-Fetch**, và toàn bộ nhóm `richness ≥ 0.5` ra 1452 `allow` + 5 `monitor`, không một ca chặn nào.
  - **Còn treo:** profile `richness=0.80` + không Sec-Fetch + không H2 giống **scraper phát lại cookie jar** (`session_richness` chỉ đếm cookie nên bot lưu cookie là đạt 0.80 mà không cần đăng nhập). Cả nhóm đang được `allow` — nghi **lọt lưới**, chưa xử lý.
- 2026-07-31 (2) — **Đo `mismatch` theo nhánh (`mm=` trong antibot.log).** Chưa đụng trọng số, chưa đổi hành vi chặn.
  - **Lý do đo ngay:** sửa JA3 xong (xem `transport/CLAUDE.md` 2026-07-31) đã **kích hoạt hai nhánh chết suốt 3 tháng** trong `correlation/consistency_check.lua`: `chrome_no_h2` gác bởi `ctx.ja3 ~= nil` (ja3 luôn nil) và `tls12` gác bởi `ctx.tls13 == false` (tls13 nil, mà trong Lua **`nil == false` là FALSE**). Cộng lại **+0.60 = 33 điểm** (weight 55) vừa xuất hiện trong production, chưa hiệu chỉnh trên dữ liệu nào.
  - **Nghi FP cụ thể:** `tls12` không có guard theo class. Chrome thật luôn TLS 1.3 — trừ khi **middlebox kiểm tra TLS của doanh nghiệp** hạ xuống 1.2 ⇒ cả văn phòng ăn 19 điểm.
  - **Vì sao trước đây không đo được:** 4 nhánh log bằng `ngx.DEBUG`, chạy ở access phase nên per-domain `error_log` (mức mặc định `error`) lọc sạch. Thay bằng `ctx.mm_rules` → `async/logger.lua` ghi ` mm=<nhánh,nhánh> mm_raw=<tổng trước chặn trần> h2bc=<h2_bot_confidence>`.
  - **`mm_raw` để làm gì:** `ctx.mismatch = math.min(1.0, score)` mà tổng 7 nhánh = **2.25** ⇒ chỉ ~3 nhánh là **bão hoà**, mismatch phẳng 55 điểm, mất khả năng phân biệt "hơi nghi" với "chắc chắn bot". `mm_raw` đo mức bão hoà thật, **không** dùng để chấm điểm.
  - **`h2bc` ghi kèm** để đo double-count: `h2_bot_confidence` và `mismatch` cùng weight 55 và cùng bắn trên `h2_bot_pattern`/`h2_tls_mismatch`.
- 2026-07-31 — **`session_flag` + `graph_flag` bị ZERO khi khoá phiên dùng chung** (`scoring/compute.lua`). Helper `session_derived(ctx, v)` trả 0 khi `ctx.sess_shared` (đặt bởi `detection/session/session_store.lua`). Lý do: cả hai signal rút từ **thứ tự URI** trong `sess:<fp_light>`; khi nhiều client thật chung một `fp_light` (văn phòng image đồng nhất) thì danh sách đó là phiên TRỘN → `detect_loop` bắn 0.9 chắc chắn → ~38 điểm FP. Chỉ chặn ở **một điểm** (get_signal) để dễ revert; không đụng signal per-request hay per-IP/subnet. Xem `detection/CLAUDE.md` 2026-07-31.
- 2026-07-04 — **`ip_tour` signal registered** (`scoring/compute.lua`): `DEFAULT_WEIGHTS.ip_tour = 25` + `get_signal` branch returns `ctx.ip_tour and 1.0 or 0.0`. Source `ctx.ip_tour` set by `detection/ip_tour.lua` (cross-domain tour). Weight 25 = MONITOR-level for aggregation/explainability; the deterministic `challenge` comes from the ip_tour floor in `engine.lua` (challenge-first), not from this weight. Combined with other bot signals can still reach BLOCK naturally.
- 2026-05-23 — **`session_richness` NEGATIVE signal** registered (`scoring/compute.lua`): `DEFAULT_WEIGHTS.session_richness = -30` + `get_signal` branch returns `ctx.session_richness or 0`. Trust proxy — richness 0.8 trừ 24 pts khỏi total. compute loop refactor: track `pos_total` (sum positive contributions) riêng với `total` (gồm negative) để `contribution_pct` của top_signals không bị méo bởi trust signal. pts âm KHÔNG vào top_signals (filter `pts > 0.5`). Source `ctx.session_richness` set by `core/session_richness.lua` ở STEPS_COMMON. Cũng helps `fp_degraded_pen` và `corr_rule_weight` chỉ counted vào pos_total nếu > 0 (correctness fix for negative-aware percentage).
- 2026-05-22 — **ip_surge signal registered** (`scoring/compute.lua`): added `ip_surge = 25` to `DEFAULT_WEIGHTS` + `if name == "ip_surge"` branch in `get_signal()`. Reads `ctx.ip_surge` (boolean set by `l7/rate/adaptive_limit.lua` Tier 1 when `ip_rate > cfg.rate.ip_surge_threshold`). Weight tuned so signal alone reaches MONITOR (25) but not CHALLENGE (55) — clean-fingerprint browser bursting briefly stays in monitor; aggregate with other bot signals (ua_flag, header_flag, cluster_score) is what escalates to block. See `antibot-core/l7/CLAUDE.md` 2026-05-22 entry for the design rationale and incident that motivated the rewrite.
- 2026-05-19 — `threat/asn_reputation.lua` — S2.5 waiver: if `ctx.bot_identity_tier=="S2.5"` (Path 1 contact attest or Path 2 analyzer attest from `detection/bot/init.lua`), set `ctx.asn_rep=0` after threat feed load. Rationale: PTR attest already proves IP belongs to declared operator; the datacenter prior baked into `rep:asn:<asn>` is the wrong signal — Pinterestbot on AWS, PageSpeed on GCP are intentionally on datacenter ASNs. Removing this ~15pt contribution is required to push S2.5 steady-state score under MONITOR threshold.
- `72f0415` (2026-05-03) — no changes here. l7 mitigations may indirectly lower input signal values (ctx.slow, ctx.burst) for legit users, reducing computed score for FP cases
- 2026-05-04 — no direct change here. `swarm_attack` weight=120 stays. Logic moved into `detection/distributed_swarm.lua` per-class threshold lookup. Sensitivity adjusted at SOURCE (signal value range) not at WEIGHT (multiplier) — preserves contribution ranking in `top_signals`
