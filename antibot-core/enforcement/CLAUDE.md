# enforcement/

Decision + action. Last layer in pipeline. Maps `ctx.score` → action (allow/monitor/challenge/block), serves PoW challenge, writes ban entries.

## Purpose
Translate aggregated score into HTTP action. Apply class-based multipliers, kill-switches, IP-risk threshold lowering, trust caps. Short-circuit on whitelist + good_bot_verified.

## Files

| File | Role |
|---|---|
| `init.lua` | Orchestrator: `engine.run(ctx)` → if action=challenge: `challenge.serve(ctx)`. If action=block + new violation: `ban.ban_store_write.write(ctx)` |
| `decision/engine.lua` | Core: short-circuit (`whitelisted`, `good_bot_verified`), apply `score_multiplier × trust_multiplier + fp_penalty + resource_boost capped at 40`, kill-switches for resource (raw≥95→eff≥85 block, raw≥80→eff≥60 challenge), IP-risk threshold lowering (`ip_risk≥0.4` → challenge cap 40), trust cap (trusted→action_cap=monitor). Sets `ctx.action`, `ctx.action_reason`, `ctx.effective_score`, `ctx.kill_reason`. Sets debug `X-Bot-*` response headers when `$antibot_debug=1` |
| `challenge/init.lua` | `challenge.run(ctx)` — phát nonce + token, dựng trang PoW, trả **200** (KHÔNG phải 403) kèm `Cache-Control: no-store`. Trang là một máy trạng thái có điểm dừng trên mọi nhánh: SHA-256 thuần JS tự kiểm bằng vector chuẩn, băm đồng bộ theo lát 30ms, gửi bằng XHR có `timeout`, đồng hồ canh 45s, trần tải lại 2 lần, `<noscript>`. Đặt `ctx.inject_candidate=false` để beacon không chèn vào chính nó |
| `challenge/verify_token.lua` | `/antibot/verify` endpoint handler — verify PoW solution, on success set Redis `verified:<cookie>=1` (TTL ≈ session lifetime) |
| `ban/ban_store_write.lua` | Write `ban:<id>` to Redis when action=block AND not already banned. Order MUST match `l7/ban/ban_store.lua` read (identity OR fp_light) |
| `explain.lua` | Build human-readable reason string from `ctx.top_signals` + `ctx.kill_reason` + `ctx.trust_reason` (used by antibot.log + admin) |

## Constants in engine.lua
- Thresholds: `MONITOR=25, CHALLENGE=55, BLOCK=80`
- `RESOURCE_MAX_SCORE=40`, `RESOURCE_BOOST_MAX=15`
- Resource kill: `KILL_BLOCK_RAW=95→EFF=85`, `KILL_CHALLENGE_RAW=80→EFF=60`
- Generic dampened-class kill (non-resource, `mult<1.0`): `KILL_DAMP_HARD_RAW=150→floor 85% raw`, `KILL_DAMP_SOFT_RAW=110→floor 65% raw`. Bảo vệ chống FN khi raw cao nhưng class dampening che pure-threat signal storm (incident 20.9.70.139 — Azure UA-empty bot, raw 140 + unknown mult 0.5 = eff 70 = challenge mãi không lên block).
- FP penalty: `FP_DEGRADED=5`, `FP_QUALITY=3` (threshold 0.5), **`JA3_PARTIAL_PENALTY=0`** (no-stream architecture constant)
- Attack 1 IP-risk: `THRESHOLD_LOWER=0.4` → CHALLENGE cap 40 (skip for api_callback)
- Good-bot rate ceiling: `cfg.rate.good_bot_rate` table (config.lua). 3 classes (polite=180/moderate=60/aggressive=30/default=60 req/min). Adaptive promotion via `gb_aggression:<bot>` (TTL 600s self-decay): `>=10 → +1 tier`, `>=30 → +2 tier`. `action_reason="good_bot_rate_<class>"`
- **`AUTH_SESSION_RICHNESS=0.5`** — session_verified tier: `session_richness ≥ 0.5` (authenticated logged-in session) caps block/challenge → monitor (`action_reason="auth_session_cap"`). Same value as `cfg.ip_tour.richness_max`. Cookie-only richness ceilings at 0.80 → logged-in clears 0.5; anonymous ≤0.4; credential-stuffing bot =0.

## ctx fields written
`action`, `action_reason`, `effective_score`, `kill_reason`, `trust_reason`, `monitor_flag`, `ip_risk_lowered`, `good_bot_class_base`, `good_bot_class`, `good_bot_aggression`, `good_bot_rate_count`, `good_bot_rate_limit` (cuối 5 fields set khi `good_bot_verified=true`)

## ctx fields read
`whitelisted`, `good_bot_verified`, `score`, `score_multiplier`, `req_class`, `sess_len`, `session_flag`, `ip_risk`, `fp_degraded`, `fp_quality`, `ja3_partial`, `ip` plus all signals (for debug headers)

## Decision flow (engine.lua)
```
ctx.whitelisted=true → action=allow, reason=whitelisted, RETURN
ctx.good_bot_verified=true → action=allow, reason=good_bot_verified|good_bot_asn_verified|good_bot_asn_lite (preserved), RETURN

raw_score = ctx.score
multiplier = score_multiplier × trust_multiplier (trust if sess_len≥session_min, sess_flag<flag_max)
effective_score = raw × multiplier + fp_penalty + resource_boost (resource only)
              capped at RESOURCE_MAX_SCORE for resource

if resource: kill switches override (raw≥95 → eff≥85 block; raw≥80 → eff≥60 challenge)

challenge_threshold = CHALLENGE (55)
if ip_risk ≥ 0.4 and class ≠ api_callback: challenge_threshold = 40

action by effective_score:
  ≥ BLOCK (80)              → block
  ≥ challenge_threshold     → challenge
  ≥ MONITOR (25)            → monitor (silent)
  else                      → allow

if trust_reason and action=challenge: action = cfg.trust.action_cap (default monitor)
if bot_identity_tier=="S2.5" and action∈{block,challenge}: action = monitor (s25_cap_monitor)
if session_richness ≥ 0.5 and action∈{block,challenge}: action = monitor (auth_session_cap)  ← authenticated human
```

## Flow
```
intelligence.run(ctx) → ctx.score, ctx.top_signals
            ↓
enforcement.run(ctx)
   engine.run         → ctx.action, ctx.action_reason, ctx.effective_score
   if challenge:
      challenge.run   → respond 200 + HTML challenge page (no-store)
   if block + new viol:
      ban_store_write → Redis ban:<id> with TTL from cfg.ttl.ban_steps[viol]
            ↓
log_by_lua → async/logger writes /var/log/antibot/antibot.log
```

## Related
- Upstream: `intelligence/scoring/compute` (provides ctx.score), all detection layers (provide signal flags)
- Downstream: `async/risk_update` reads `ctx.action` to update `ip_risk:<ip>` async
- PoW verify cycle: challenge.run → browser solves → POST `/antibot/verify` (XHR) → verify_token → Redis `verified:<cookie>` + JSON `{"ok":true,"dest":"/..."}` → client `location.replace(dest + hash)` → next request hits cookie fast-path in init.lua

## Important rules
- Thresholds duplicated in `core/config.lua` AND `engine.lua` — change one → reconcile other
- Engine MUST `return` immediately on whitelisted/good_bot_verified — debug headers set later in function won't fire (intentional, cookie/whitelist short-circuit is by design)
- `cfg.pow.difficulty="000"` — affects user solve latency, don't change without explicit request
- `JA3_PARTIAL_PENALTY=0` — no-stream arch never captures cipher list. Penalty would fire on EVERY HTTPS request → useless signal. Don't restore
- ban_store_write MUST use SAME id source order as l7/ban/ban_store.lua read

## Update log
- 2026-09-11 — **`auth_session_cap` cổng thứ hai: phải CÓ User-Agent. Và beacon đã bị loại bằng số liệu.**
  - **Beacon KHÔNG dùng được.** Giả thuyết: đòi `ctx.beacon_received` (JS đã chạy) làm chứng cứ bổ trợ. Đo 5 máy, **743 lượt `reason=auth_session_cap`, KHÔNG MỘT lượt nào có `beacon=1`** (439 `skip`, 304 `0`). Lý do: tầng này chỉ bắn trên verdict `block`/`challenge`, mà phần lớn rơi vào XHR/`admin-ajax`/`api_callback` — không phải HTML nên beacon chưa từng được tiêm. Đã loại theo đúng luật dừng đặt ra TRƯỚC khi xem số.
  - **Nhưng phép kiểm hồi quy lại cho ra bằng chứng khác.** Sau khi deploy `dc06657` cho cả 5 máy, ba máy bật từ 0 lên 122/295/317 lượt — mà một bản vá chỉ GỠ miễn trừ thì không thể TẠO thêm sự kiện. Soi UA: `isbot()` báo 0, nhưng chúng **không phải trình duyệt**:
    - **cloud171-96, 317 lượt: `ua=-`** — client không gửi User-Agent.
    - **cloud186-126, 295 lượt: MỘT UA duy nhất** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)` — cụt ngay sau `like Gecko`, không `Chrome/`, không `Safari/`.
    - Cả hai **không tự xưng bot** nên cổng `good_bot_claimed` không chạm tới. Đúng phạm vi cổng đó; đây là phần còn lại.
  - **Vá: thêm điều kiện `ctx.ua ~= nil and ctx.ua ~= ""`.** Không trình duyệt nào bỏ User-Agent, nên rủi ro FP bằng 0, và nó gỡ 317/612 (52%) phần dư đo được.
  - **KHÔNG dùng `ctx.browser_ua_pattern` làm cổng** dù nó loại đúng cả hai nhóm: `is_browser_pattern` đòi `AppleWebKit/` nên **Firefox không bao giờ thoả** (UA Firefox không có chuỗi đó) và Safari cũng trượt. Dùng là tước miễn trừ của mọi admin Firefox/Safari. Xem `detection/CLAUDE.md` 2026-09-11.
  - **CÒN HỞ, cố ý:** 295 lượt UA cụt trên cloud186-126. Một tác nhân, một chuỗi — việc của vận hành (chặn theo UA), không phải của một vị từ tổng quát. Dựng vị từ "UA phải có tên sản phẩm trình duyệt" là quay lại đúng cái bảng-cứng đã cắn `transport/http2/pseudo_header.lua` **ba lần** (Firefox, client Go, WebView iOS).
- 2026-09-10 — **CỬA THỨ NĂM của cùng con bug, lần này ở cột đọc mọi quyết định: `eff=`.**
  - `_M.run` đặt `ctx.effective_score` ở **đúng một chỗ** (`engine.lua:538`), mà trước đó có **hai lệnh `return`**: `ctx.whitelisted` và `ctx.good_bot_verified`. Cả hai để trường đó là `nil`. `async/logger.lua` ghi `ctx.effective_score or 0` ⇒ **`eff=0.0` mang hai nghĩa lẫn nhau**: "điểm hiệu dụng bằng 0" và "chưa từng tính".
  - **Đo được, và nó suýt dẫn tới kết luận ngược.** Nhóm `ja3c=100` (16.040 request, 5.911 IP, 5 máy, cửa sổ 18,8 giờ) đọc ra `eff=0.0` ở **100%** số dòng, trong khi `score` trung bình 8,9–13,3 và đỉnh **35,1**. Đọc thẳng thì thành "hệ thống chấm chúng 0 điểm"; sự thật là **hệ thống không chấm**. Muốn biết vì sao phải đọc `reason=`, không phải `eff=`.
  - Nay `eff=` có ba trạng thái: `<số>` = đã tính, `-` = chưa từng tính. Cùng bản vá đã làm cho `ja3p=` hôm 06-09 (`transport/CLAUDE.md`), cùng con `false`-vs-`nil` đã cắn ở `waf/body.lua` (`php = false`).
  - **`score=` KHÔNG bị ảnh hưởng, và đó là bằng chứng phân biệt:** `compute.lua` chạy ở tầng intelligence, **trước** enforcement, nên `ctx.score` đã có giá trị thật khi engine thoát sớm. Một dòng `score>0` kèm `eff=-` nghĩa là điểm đã tính xong rồi bị một tầng tin cậy cho qua.
- 2026-09-09 — **`auth_session_cap` là một đường vòng: 98,6% số lần nó bắn là để miễn trừ cho bot.**
  - **Đo 24h, 5 máy.** Tầng này hạ `block`/`challenge` xuống `monitor` **1.265 lần**; **1.247 (98,6%) có UA bot**, riêng `ClaudeBot/1.0` **1.246 lần** trên cloud28-246. Số lần nó bảo vệ một trình duyệt thật: **5**. Chú thích cũ ngay trên nhánh — *"Credential-stuffing bots have richness=0 → never reach this tier"* — sai, và sai theo hướng mở cửa.
  - **Gốc nằm ở `core/session_richness.lua`, không nằm ở đây.** Nó không kiểm cookie có hợp lệ không, chỉ cộng: 50% số byte (bão hoà 500) + 30% số cookie (bão hoà 4) + 0,3 nếu có `Authorization` + 0,2 nếu có CSRF header. **Bốn cookie rác tổng 500 byte = 0,80.** Thêm nữa `richness:max:<identity>` lưu Redis 1 giờ và **tự gia hạn mỗi lần dùng**, nên đạt một lần là giữ mãi chừng nào còn gửi request.
  - **210.754 request/ngày đứng trên ngưỡng 0.5, trong đó 72.772 (34,5%) tự khai không phải trình duyệt** — chủ yếu `WordPress/x.y.z; https://<domain>` (loopback/server-to-server) và crawler. 34,5% là **SÀN**: phép đo chỉ bắt UA tự khai, bot đội lốt trình duyệt không bị đếm.
  - **Vá: thêm cổng `not ctx.good_bot_claimed`.** Client tới được nhánh này mà còn cờ đó nghĩa là nó tự xưng bot và **đã trượt xác minh** — good bot xác minh được đã thoát ở `good_bot_verified` phía trên, chưa từng chấm điểm. Cờ còn bật ở đây chỉ có hai nghĩa: claim chưa xác minh, hoặc giả mạo UA. `ua_check.run()` chạy ở cả `lite_verify` (resource) lẫn `bot/init` (phần còn lại) nên cờ luôn có giá trị tại điểm này.
  - **ClaudeBot KHÔNG đăng ký được, đã đo chứ không đoán:** 145 IP nguồn, **không IP nào có PTR**; ASN là **16509 (Amazon AWS)** và 396982 (Google Cloud). Cả bảy đường xác minh đều cần PTR hoặc ASN riêng của nhà vận hành. Đưa 16509 vào `goodbot.json` là cho bất kỳ ai thuê EC2 và ghi `ClaudeBot` vào UA được xác minh. Hệ quả vận hành: sau bản này ClaudeBot bị chấm điểm bình thường. Muốn cho qua thì dùng `goodbot:asn:<tên>` trong Redis — đó là quyết định vận hành, không phải mặc định.
  - **Nợ sâu hơn, chưa sửa:** `session_richness` là proxy đúng cho "client đã có state", đúng như tiêu đề module nó. Sai lầm là dùng một proxy về STATE làm tầng tin cậy về XÁC THỰC. Ba nơi khác cũng lấy 0.5 làm "đường ranh đã xác thực" và **chưa được đo**: `l7/expensive_filter_guard.lua:198` (miễn 429/ban), `detection/ip_tour.lua:166`, `l7/ban/ban_store.lua`.
- 2026-09-06 (v2) — **PoW tính trước được và dùng lại vô hạn + ngưỡng có HAI nguồn và không nguồn nào được đọc** (`challenge/nonce_store.lua` viết lại + `challenge/verify_token.lua` + `challenge/init.lua` + `decision/engine.lua` + `core/config.lua` + `waf/scripts/contract_test.lua` mục 7–8).
  - **Lỗ hổng: token không hề được kiểm là do máy chủ phát.** Verifier cũ chỉ kiểm `sha256(token .. n)` có tiền tố đúng rồi xoá `nonce:<identity>`. Nên: bot tự chọn **một** token cố định → tìm `n` hợp lệ **đúng một lần** (~4096 lần băm) → từ đó về sau mọi thách đố, **mọi danh tính, mọi tên miền trong đàn máy**, chỉ cần gửi lại đúng cặp đó. Mục tiêu "mỗi lần thách đố phải trả một chi phí mới" biến mất. Thiệt hại thực tế hôm nay nhỏ vì `difficulty="000"` vốn chỉ tốn ~10ms — nhưng đúng vì thế, **sửa chỗ này là điều kiện cần để `difficulty` còn là một cái núm có ý nghĩa**.
  - **Lỗi thứ hai đang bị lỗi thứ nhất CHE.** `nonce_store` dùng `SETNX nonce:<identity>` và `challenge/init.lua` **bỏ qua kết quả**. Hai tab (hoặc một lần F5) nhận token MỚI trong khi Redis giữ nonce CŨ — không ai thấy, vì token không được kiểm. Thêm một dòng kiểm HMAC vào code cũ sẽ **biến lỗi bị che thành lỗi verify thật**, nạn nhân đúng là người mở hai tab.
  - **Nên khoá đổi từ danh tính sang mã ngẫu nhiên mỗi lần thách đố:** `chal:<challenge_id> = identity | md5(token) | difficulty | issued_at`, TTL `cfg.ttl.nonce`. `SETEX` thay `SETNX` — không còn khoá dùng chung nên không còn gì để đụng. `label:` cũng chuyển sang khoá theo `cid` (trước đây hai tab thì tab sau ghi đè nhãn ground-truth của tab trước).
  - **Verifier kiểm đủ năm điều:** bản ghi tồn tại → danh tính khớp (`fp` do client gửi nên không tự chứng minh gì) → `md5(token)` khớp, **so sánh không phụ thuộc nội dung** → PoW đúng theo **độ khó đã phát** (không phải độ khó hiện hành, để sửa config giữa chừng không giết các thách đố đang bay) → **tiêu thụ nguyên tử** bằng `DEL` phải trả về 1. Hai request song song: chỉ một cái thắng, cái kia rơi xuống nhánh gửi-lại-an-toàn.
  - **`math.randomseed` KHÔNG được gọi ở bất kỳ đâu trong cây nguồn**, nên `math.random` cho cùng một dãy sau mỗi lần khởi động, ở mọi worker. Không nguy hiểm với `issue_token` (token là HMAC, không đoán được nếu không có khoá bí mật) nhưng **chí mạng với một khoá Redis**: `challenge_id` sinh bằng `resty.random.bytes(16, true)`, đường lùi là `$request_id` — tuyệt đối không `math.random`.
  - **`arg_str()`:** `ngx.req.get_post_args()` trả về **bảng** khi một tên lặp lại. Bản cũ dùng thẳng `args.token`, nên `token=a&token=b` khiến `token .. n_str` ném lỗi Lua ⇒ **500 do người lạ gửi được**. Nay mọi trường đều qua kiểm kiểu + giới hạn độ dài.
  - **Không phục vụ một thách đố không giải được:** nếu ghi `chal:` thất bại (Redis hỏng), `challenge.run` **cho request đi tiếp** (`action=monitor`, `reason=challenge_store_failed`) thay vì trả một trang chỉ dẫn tới 403 → tải lại → 403 cho tới khi chạm trần. Cùng hướng fail-open với `pool.safe_*`, và có log ERR nên không im lặng.
  - **NGƯỠNG: `cfg.thresholds` là config CHẾT.** Nó ghi `challenge=80, block=100` kèm chú thích "nâng từ 65"/"nâng từ 80", nhưng **không một dòng nào trong cây nguồn đọc nó** — engine viết cứng 25/55/80. Lần hiệu chỉnh đó **chưa bao giờ có hiệu lực**. Nay engine đọc config, và **con số trong config được đặt lại đúng bằng con số đang chạy (25/55/80)** ⇒ thay đổi này **không đổi hành vi**. Cố ý: sửa chỗ trùng lặp và đổi chính sách là hai việc.
  - **Vì sao KHÔNG trỏ thẳng engine vào 80/100.** Bốn hằng số được hiệu chỉnh so với 55/80; nâng ngưỡng mà giữ nguyên chúng thì **ba kill-switch chết lặng**: `KILL_CHALLENGE_EFF=60 < 80` (resource kill chỉ còn monitor), `KILL_BLOCK_EFF=85 < 100` (không còn chặn), `KILL_DAMP_SOFT = 110×0,65 = 71,5 < 80` (class bị giảm điểm không lên nổi challenge). Ca **20.9.70.139** đã ghi ở dưới (raw 140 ⇒ eff 91 ⇒ block) sẽ tụt xuống chỉ còn challenge. Nay hai cái `*_EFF` được **dẫn xuất** từ ngưỡng (+5) nên tự đi theo; hai cái `DAMP` là phần trăm nên không dẫn xuất được — **contract_test mục 7 kiểm bất biến**, cổng `[3b]` báo đỏ trước khi deploy.
  - **contract_test mục 8** ghim hợp đồng phát↔kiểm: `chal:<cid>` chứ không `SETNX`, client gửi mã lần thách đố, verifier đối chiếu token, tiêu thụ nguyên tử, và khoá `nonce:<identity>` cũ phải biến mất khỏi **cả hai** nửa.
  - **CHƯA làm, cần người quyết:** nâng ngưỡng lên 80/100 (lệnh đo dải 55–80 nằm trong `config.lua` ngay trên bảng); sàn cho truy cập lần đầu; redirect 80→443 trong `da_to_openresty.sh` (**file đó đang có sửa đổi chưa commit của người vận hành** nên không đụng vào).
- 2026-09-06 — **Trang challenge treo: bốn nhánh không có điểm dừng, và cách thôi vá từng cái** (`challenge/init.lua` viết lại + `challenge/verify_token.lua` + `intelligence/scoring/compute.lua` + `core/config.lua` + `waf/scripts/contract_test.lua`).
  - **Cách đặt vấn đề, chứ không phải bốn bản vá.** "Treo" không phải một lỗi — nó là **một nhánh không có điểm dừng**. Bản trước đã vá tuần tự: thêm retry, thêm backoff, sửa referrer… và lần nào cũng "xong" cho tới nguyên nhân kế tiếp. Nay trang được viết lại như một **máy trạng thái liệt kê được**, và điểm cuối cùng — **đồng hồ canh 45s** — là thứ duy nhất không phải bản vá: nó không cần biết cái gì hỏng.
  - **Nguyên nhân 1 — `crypto.subtle` không tồn tại ngoài secure context. TREO CỨNG, không báo lỗi, không một gói tin.** `nginx/da_to_openresty.sh` đặt `access_by_lua { antibot.run() }` vào **cả khối `listen 80`**, và khối đó **không chuyển hướng sang HTTPS**. Khách vào bằng `http://` mà bị thách đố ⇒ `crypto.subtle` là `undefined` ⇒ `crypto.subtle.digest` ném TypeError ngay trong `solve()` ⇒ văng ra khỏi IIFE ⇒ con quay quay mãi. Đây là nhóm "gõ tên miền vào thanh địa chỉ" — đúng nhóm khách vào lần đầu.
  - **Nguyên nhân 2 — `setTimeout(solve, 0)` MỖI LẦN BĂM.** Trình duyệt ép tối thiểu 4ms sau 5 lớp timer lồng nhau ⇒ 4096 lần băm của `difficulty="000"` mất **≥16 giây**; tab chạy nền thì timer bị hạ xuống 1 lần/giây ⇒ **68 phút**. Nonce sống 60s nên về tới nơi là 403 → tải lại → lặp. Nay băm **đồng bộ** theo lát 30ms (~3 lát).
  - **Nguyên nhân 3 — `fetch` không có hạn giờ** và không tồn tại trên WebView cũ. Promise treo thì `.catch` không bao giờ chạy (đổi Wi-Fi/4G, app vào nền, TCP nửa mở). Thay bằng `XMLHttpRequest` + `xhr.timeout`: có điểm dừng tường minh cho mọi kết cục, chạy ở mọi WebView.
  - **Nguyên nhân 4 — trang challenge không có `Cache-Control`.** Nó mang nonce dùng một lần và nằm ở **đúng URL bài viết**; lấy lại bản cũ sau khi verify = giải bằng token đã chết = 403 = tải lại = vòng lặp.
  - **Đổi lại phải tự viết SHA-256 (~55 dòng).** Rủi ro thật, nên hai lớp chặn: (a) đã kiểm trên máy dev bằng 5 vector chuẩn + đối chiếu `[System.Security.Cryptography.SHA256]` trên đúng dạng đầu vào (64 hex + chữ số); (b) **trang tự kiểm `sha256('abc')` trước khi dùng** — một bản băm sai mà im lặng còn tệ hơn treo, vì nó gửi lời giải không hợp lệ và ăn 403 mãi.
  - **`fast_solve` BỊ GỠ khỏi `DEFAULT_WEIGHTS` + `get_signal()` + `flag_fast_solve`.** Ngưỡng `sm < 50ms` chỉ có nghĩa với bộ giải cũ (mỗi lần băm qua một Promise + `setTimeout(0)` ⇒ không đời nào dưới 50ms). Bộ giải đồng bộ xong trong 10–40ms ⇒ **mọi máy để bàn thật sẽ bị đánh dấu**, trọng số 25 ⇒ +8,75đ/lần. Chỉnh ngưỡng không cứu được: sức phân biệt của tín hiệu **sinh ra từ chính sự chậm giả tạo** vừa bị gỡ, và `sm` do client gửi. Giá trị `sm` chuyển vào dòng `[fp_sample]` để còn đo được nếu sau này muốn dựng lại.
  - **`cfg.ttl.nonce` 60 → 300.** Cửa sổ không còn phải chứa thời gian giải, mà phải chứa: tải trang + thiết bị yếu + khách chuyển sang app khác rồi quay lại + tối đa 3 lần gửi có giãn cách (~28s).
  - **`safe_dest` loại cả dải `0x00–0x1F` + `0x7F`**, không chỉ `\r \n \0` — chú thích cũ nói "loại ký tự điều khiển" nhưng code chỉ loại ba, và `json_str` tin vào chú thích đó.
  - **Mọi lối thoát của `verify_token` nay đặt `ctx.action_reason`** (`verify_missing_args` / `verify_missing_id` / `verify_pow_failed` / `verify_redis_down` / `verify_nonce_missing`). Khi khách báo "quay mãi", thứ đầu tiên cần biết là verify có tới nơi không và hỏng ở bước nào — mà đúng những dòng đó đang vô danh.
  - **`contract_test.lua` mục 0 và mục 6.** Mục 6 ghim các **thuộc tính khiến trang kết thúc được** (cấm `crypto.subtle`/`fetch(`/`TextEncoder`/`URLSearchParams`/`document.referrer` trong chuỗi trang; bắt buộc có đồng hồ canh, trần tải lại, `xhr.timeout`, `<noscript>`, vector tự kiểm; đếm dấu `%` lẻ) — chứ không liệt kê bốn nguyên nhân đã biết. Mục 0 `loadfile` **mọi** file `.lua`: `nginx -t` không nạp module `require` lúc chạy, nên một lỗi cú pháp ở đây đi lọt cả `-t` lẫn `reload` rồi nổ ở request đầu tiên — và máy dev không có Lua.
  - **CHƯA làm, cần người quyết:** khối `listen 80` không chuyển hướng 301 sang HTTPS (giờ đã vô hại với challenge, nhưng vẫn là lưu lượng trần); chữ ký HMAC của token **vẫn không được kiểm** ở `verify_token` (chỉ kiểm tiền tố hash + sự tồn tại của nonce); `engine.lua` **không có sàn cho truy cập lần đầu** nên một danh tính mới toanh, không tín hiệu, được cho qua.
- 2026-08-22 (`a770ea5`) — **Tầng danh tính thứ ba: dải IP do nhà vận hành CÔNG BỐ** (`engine.lua` + `nginx/scripts/monitor_ip_sync.sh` MỚI + `async/logger.lua`).
  - **Lỗ hổng đã được ghi sẵn từ 2026-08-07** (`detection/CLAUDE.md`, "lỗ hổng lớn nhất còn lại"): hai tầng sẵn có đều dựa vào **UA tự khai** — S4 (registry + DNS hai chiều) và S2.5 (contact/analyzer attest). Không có đường nào cho nhà vận hành khai danh tính bằng cách **công bố danh sách IP** (cách OpenAI/Anthropic/Perplexity dùng).
  - **Ca đầu tiên chạm vào: công cụ uptime đa điểm.** Bắn ~35 điểm kiểm tra ĐỒNG THỜI từ 35 subnet với cùng một UA trình duyệt trần ⇒ về cấu trúc **không phân biệt được** với thăm dò có phối hợp ⇒ `distributed_swarm` (trọng số 120) chặn 403. **Bộ dò KHÔNG sai:** domain nhận 13,5 req/phút mà mốc cứng là 35 /24 trong **60 giây** — lưu lượng tự nhiên không thể chạm, chỉ một chùm bắn đồng thời mới tạo ra được. `top=` xác nhận `swarm_attack` chiếm 70-86% điểm ở mọi dòng.
  - **KHÔNG hạ ngưỡng swarm, vì nó đang kiếm được miếng ăn:** 11.307 lệnh chặn có `swarm_attack` trong top, trong đó **11.245 không cookie / 62 có cookie (0,55%)**. Người dùng thật có phiên không bị dính — `session_richness` là tín hiệu âm trọng số −30, cộng trần tin cậy. Nhóm `auth_endpoint` ở mức 100% là credential stuffing phân tán, đúng mục tiêu.
  - **TRẦN chứ không phải MIỄN TRỪ — đây là toàn bộ lý do tồn tại của cơ chế.** `wl:<ip>` cho `ctx.whitelisted` → `init.lua:162` return ngay: bỏ qua l7 rate limit, **toàn bộ** detection, enforcement, và cả thống kê — vĩnh viễn, vô hình. `mon:<ip>` chỉ chặn bước cuối không cho vượt `monitor`: mọi tầng vẫn chạy, vẫn ghi log, `ban:<ip>` vẫn chặn được ở bước 6 nếu IP đó thực sự làm bậy.
  - **Đặt trong nhánh sắp chặn là CỐ Ý.** Lua đánh giá `and` từ trái sang nên `pool.safe_get` chỉ chạy khi đã sắp block/challenge — đo được **~5% lưu lượng** (11.307/240.396). Đặt ở đầu hàm là bắt 100% request trả một lượt Redis cho thứ 95% trong số đó không bao giờ dùng tới.
  - **TTL 48h + cron 12h = FAIL-CLOSED.** Cron chết / vendor đổi URL / mạng hỏng ⇒ khoá tự hết hạn ⇒ miễn trừ biến mất ⇒ hệ về mặc định nghiêm ngặt. Biên 4 lần nên một lần mạng lỗi không làm rớt. `wl:` thì ngược lại: ghi một lần, sống mãi, không ai nhớ ra mà xoá.
  - **Cổng an toàn trong script (không phải tinh chỉnh):** loại mọi dải nội bộ/dành riêng (0/8, 10/8, 127/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, ≥224) — feed bị chiếm mà trả về `127.0.0.1` không được biến hạ tầng nội bộ thành vùng miễn trừ; **MIN 10** IP (dưới ⇒ tải hỏng, không ghi gì); **MAX 2000** (trên ⇒ nguồn đã đổi bản chất, dừng cho người xem); tải thất bại ⇒ **không ghi**, khoá cũ tự hết hạn.
  - **Thứ tự thao tác BẮT BUỘC khi triển khai** (đã cắn một lần): chạy `monitor_ip_sync.sh` xong mà chưa `./deploy.sh` thì khoá `mon:` có đủ nhưng engine chưa biết đọc ⇒ vẫn 403 với `reason=score`. Phân biệt: `reason=banned_ip` ⇒ khoá cấm CŨ che mất (dọn `ban:/ban:hit:/ip_risk:/viol:` cho các IP trong `mon:`); `reason=score` ⇒ code chưa nạp. Sau khi trần chạy thì lệnh cấm mới không hình thành nữa vì `ban.run(ctx)` chỉ được gọi ở nhánh `block`.
  - **Mở rộng:** thêm một dòng vào mảng `SOURCES` là xong. GPTBot / Perplexity / ClaudeBot đã ghi sẵn trong file nhưng **CỐ Ý CHƯA BẬT** — ba nguồn đó trả về **CIDR** mà engine khớp **IP chính xác**; phải khai triển CIDR→IP (một /24 = 256 khoá) hoặc đổi cách đọc bên Lua trước.
  - `monitor_ip_cap` thêm vào `REASON_GOODBOT` của logger — cùng nghĩa "đã định danh được" như `s25_cap_monitor`, chỉ khác đường chứng minh.
- 2026-08-09 — **Trần tốc độ cho S2.5 + tra lớp theo HỌ. Hai lỗi cùng một gốc: trần bị nhốt trong nhánh `good_bot_verified`.**
  - **Lỗi 1 — nhóm S2.5 chưa từng có trần.** `throttle_good_bot_rate` chỉ được gọi bên trong `if ctx.good_bot_verified == true` (engine.lua:375→386), mà `contact_ptr_match` / `contact_org_match` / `contact_cloud_attested` / `analyzer_attested` **không** phải `good_bot_verified`. Đo cloud28-246 (2026-08-09): 9.952 + 3.589 + 1.512 = **15.053 lượt/ngày** thuộc nhóm này; tổng `throttled` là 1.690, khớp gần đúng `good_bot_rate_aggressive`=1.697 ⇒ **không một lượt S2.5 nào từng bị siết**. Nay gọi trần ngay sau nhánh verified, gác bằng `bot_identity_tier == "S2.5"` AND `good_bot_name`.
    - **An toàn vì chỉ siết thêm, không hạ cấp:** S2.5 vốn đã được `s25_cap_monitor` chặn không cho lên block/challenge. Cố ý KHÔNG áp cho bot tự khai chưa attest — làm thế sẽ biến lệnh chặn thành 429, tức **hạ cấp** thi hành.
    - **Bắt buộc có `good_bot_name`:** `analyzer_attested` đi từ UA dạng trình duyệt nên có thể không có tên; thiếu tên thì khoá đếm rơi về `gb_rate:unknown:<phút>` — một xô dùng chung cho mọi bot vô danh.
  - **Lỗi 2 — `conf.map[bot]` khớp khoá chính xác, mà tên bot thật luôn có đuôi.** `ua_check` bóc bằng `([%w%-]+[Bb]ot[%w%-]*)`, đuôi `[%w%-]*` tham lam ⇒ tên thật là `coccocbot-web`, `duckduckbot-https`, `meta-externalagent`, `yandexrenderresourcesbot`. Kiểm 2026-08-09: **13 mục trong map, chỉ 5 mục từng chạy được** (googlebot/bingbot/applebot/amazonbot/baiduspider). `meta` và `coccocbot` lệch khoá và âm thầm rơi về `default`=60 — không lộ ra vì tình cờ bằng `moderate`=60. Còn `yandexbot`/`bytespider`/`semrushbot`/`mj12bot`/`duckduckbot` chết vì lý do khác: **không có trong `goodbot.json`** nên không bao giờ vào được nhánh verified. `ahrefsbot` chết **có chủ đích** (gỡ khỏi registry để Path 1c chạy — xem `detection/CLAUDE.md` 2026-08-06).
    - **Fix:** `class_for_bot(bot, map)` — khớp chính xác trước, trượt thì lấy **khoá dài nhất là tiền tố** của tên. Một khoá `yandex` phủ cả họ. Liệt kê từng biến thể là kiểu chống-mẫu repo đã bỏ một lần (auth_endpoint v1→v2).
    - **Không mở lỗ hổng:** chỉ ảnh hưởng TRẦN, không ảnh hưởng việc kết nạp — vào nhánh vẫn phải qua DNS. Khớp rộng quá thì hậu quả tối đa là **siết nhầm lớp**, không phải cho qua nhầm.
  - **Yandex vào registry** (`goodbot.json`: `yandexbot` + 4 biến thể đuôi `bot`) + `yandex = "aggressive"`. Yandex tự sở hữu **AS13238** và tài liệu chính thức yêu cầu PTR + xác nhận xuôi ⇒ đủ chuẩn S4 bằng DNS hai chiều, **không cần mở cổng ASN** — khác hẳn Baidu (đi nhờ AS4837) và PetalBot (cloud bán lẻ). Bằng chứng buộc phải làm: trên cloud168-118, **7/8 khoá `fl:dyn` là dải Yandex**, 598 lượt kẹt ở S2.5, 274 bị chặn hẳn.
    - **CHƯA phủ `YandexImages`/`YandexVideo`/`YandexNews`:** UA của chúng không có token `bot`/`spider`/`crawler` nên `ua_check` **không bóc được tên** — thêm vào registry là vô ích, phải thêm mẫu bóc tên trước. Chưa thấy trong dữ liệu 3 máy nên chưa làm.
  - **RANH GIỚI HAI BẢNG — đừng lẫn (sửa lại cách hiểu sai đã ghi lúc đầu):** `goodbot.json` = S4 = engine **bỏ qua chấm điểm hoàn toàn**, đặc quyền lớn, CHỈ dành cho bot có giá trị SEO/truyền thông thật. `rate.good_bot_rate.map` **không** phải danh sách ưu ái — sau thay đổi này nó có nghĩa *"nếu bot này tự đạt S2.5 qua cơ chế generic thì trần của nó là bao nhiêu"*.
    - Vì vậy `bytespider`/`mj12bot`/`duckduckbot` **KHÔNG đưa vào registry**: MJ12 là crawler tình nguyện phân tán, về bản chất không xác minh được; Bytespider không sinh giá trị. Chúng đi chấm điểm thông thường và cơ chế đang làm đúng việc (đo 2026-08-09 cloud168-101: mj12bot 5.540 lượt bị chặn hẳn, bytespider 229). Mục của chúng trong `map` đơn giản là không kích hoạt — vô hại, không phải "nợ".
    - `semrushbot` là ca ngược lại và là bằng chứng bảng `map` có tác dụng thật: 5.887 lượt đạt `contact_*` trên cloud168-101 ⇒ từ nay **thật sự bị siết 30/phút** mà không cần đụng tới registry.
- 2026-08-06 — **Cấm "vĩnh viễn" → 30 ngày, và hồ sơ bằng chứng phải sống bằng bản án** (`core/config.lua ban_steps` + `ban/ban_store_write.lua`).
  - **Số liệu buộc phải đổi (cloud28-246):** **8.261** lệnh cấm IP vĩnh viễn đã tích luỹ. Chỉ **33 (0,4%)** còn `ban_ctx` để giải thích lý do. Trong 33 đó, **13 là AhrefsBot THẬT** (PTR `proxy-*.ahrefs.net`). Và **69,5%** số IP đã ngừng hoạt động hoàn toàn — thuần rác.
  - **Hai gốc rễ:** (1) `ban_steps` bậc cuối = `0` ⇒ `SET` không TTL ⇒ **không gì xoá nó đi**, danh sách chỉ tăng, không có cơ chế rà soát; (2) `ban_ctx` ghi TTL cứng 86400 trong khi bản án vĩnh viễn ⇒ hồ sơ bay sau 24h, bản án ở lại mãi ⇒ mọi lần rà soát về sau đều mù.
  - **Lỗi kèm theo đã sửa:** `red:setex("ban_ctx:"..ip, ip_ban_ttl, ...)` với `ip_ban_ttl = 0` là **lệnh LỖI trong Redis**, và lỗi trong pipeline **bị nuốt im lặng** ⇒ đúng những lệnh cấm nặng nhất lại là những lệnh không có hồ sơ. Nay guard `(ip_ban_ttl > 0) and ip_ban_ttl or ctx_ttl`.
  - **`ban_steps = {300, 3600, 86400, 2592000}`.** Bot lì thật thì cứ 30 ngày leo lại thang trong vài phút — hiệu quả chặn gần như không đổi. Đổi lại danh sách **tự dọn** và IP đổi chủ không thành mìn. Cùng nguyên tắc khiến `intel_reporter` chọn TTL 7 ngày thay vì vĩnh viễn. `ban_store_write` đọc bậc cuối qua `steps[#steps]` để không lệch với thang identity ở `l7/ban/ban_store.lua`.
  - **Nhánh `ttl == 0` ở cả hai file GIỮ NGUYÊN** làm dự phòng — cấu hình đặt lại `0` thì vẫn chạy đúng như cũ.
  - **Đã bác bỏ: đồng bộ danh sách này sang CSF.** Ý tưởng đúng về nguyên tắc (chặn ở tầng gói tin tiết kiệm cả bắt tay TLS, và 2.520/8.261 IP vẫn đang gõ cửa) nhưng **không làm khi 99,6% danh sách không giải thích được** — firewall chôn sai lầm ở tầng antibot.log không còn nhìn thấy. Điều kiện để làm lại: sau khi danh sách tự co về phần đang hoạt động VÀ có hồ sơ. Khi đó cần `LF_IPSET="1"` + `DENY_TEMP_IP_LIMIT="20000"`, và dùng `csf -td` (tạm) chứ không `csf -d`, để Redis giữ vai trò nguồn sự thật duy nhất.
- 2026-08-01 — **Ground truth từ kết quả PoW (`label:<id>` → `[fp_sample]` + `fp_cand:<signal>`).** Chỉ đo, không đổi hành vi chặn.
  - **Vì sao:** hệ thống KHÔNG có nguồn ground-truth nào. `async/adaptive_weight.lua` viết ra để nhận feedback nhưng **không ai gọi nó với feedback** → code chết. Mọi lần hiệu chỉnh trọng số tới nay đều là bới log thủ công + suy đoán (2026-08-01: bốn giả thuyết liên tiếp bị dữ liệu bác bỏ).
  - **Cơ chế:** `challenge/nonce_store.lua` ghi `label:<id>` cùng lúc với `nonce:<id>` (cùng TTL) — ảnh chụp `score|eff|class|reason|top_signals|mm_rules|ua_claims_bot`. `challenge/verify_token.lua:consume_label()` đọc lại khi PoW được giải THẬT (nhánh `del nonce` trả 1, không phải replay) → log `[fp_sample]` + `INCR fp_cand:<signal>` TTL 7 ngày.
  - **Đọc kết quả:**
    ```
    redis-cli --scan --pattern 'fp_cand:*' | while read k; do echo "$(redis-cli GET $k) $k"; done | sort -rn
    grep -F '[fp_sample]' /var/log/nginx/domains/*.error.log
    ```
    Signal nào đứng đầu bảng `fp_cand` = signal đó hay có mặt trong top-3 của request mà client **chứng minh được là trình duyệt**.
  - **KHÔNG nối tự động vào trọng số.** Đó chính là thiết kế của `adaptive_weight` và nó chết. Vòng lặp tự động không có người kiểm tra sẽ để nhãn nhiễu ăn mòn mô hình. Giai đoạn này chỉ để người đọc.
  - **Thiên lệch phải nhớ khi đọc số:** (a) chỉ dán nhãn được dải `challenge` — request bị `block` không có cơ hội giải, nên đây KHÔNG phải tỷ lệ FP toàn hệ thống; (b) bot render JS cũng giải được PoW (đã xảy ra 2026-07-07 với crawler Meta) → UA tự khai bot bị loại khỏi mẫu và log riêng `[fp_sample] SKIP bot-claim`; (c) `challenge` chỉ ~1,6% lưu lượng → cần vài NGÀY mới đủ mẫu.
  - **Prefix `fp_cand:` chứ không phải `fp:`** — trong `verify_token.lua`, `fp:` đã mang nghĩa *fingerprint* (`fp:canvas:`, `fp:fast_solve:`).
- 2026-07-06 — **`session_verified` trust tier — `auth_session_cap`** (`engine.lua`). Thêm tier thứ 3 song song `good_bot_verified` + `ip_shared_verified`: `session_richness ≥ AUTH_SESSION_RICHNESS(0.5)` → cap block/challenge → **monitor** (đặt sau S2.5 cap, trước `ctx.action=action`).
  - **Chữ ký nhận dạng (recognition signature):** user ĐĂNG NHẬP thật (richness=0.80, UA browser thật, IP dân cư) bị chặn lặp ở `/wp-admin`, màn "Access denied.", log `reason=score` một lần rồi `reason=banned_id` cascade. `top=` toàn signal TƯƠNG QUAN identity (`session_flag/graph_flag/mismatch/cluster_score/risk`), KHÔNG có signal cấu trúc per-request (h2/ja3/ua). Xảy ra trên 1 IP/1 identity, thường trong lúc site bị bot tấn công.
  - **Gốc rễ (không phải multiplier):** admin bận rộn trên 1 identity (admin-ajax heartbeat ~15s + nhiều trang admin) trông giống bot cluster về cấu trúc → correlation signals fire → raw ~53.6 × auth_endpoint 1.5 = 80.3 ≥ BLOCK → `ban:<id>` → cascade. Mỗi block nâng `risk:<id>` → điểm sau cao hơn → **vòng lặp tự củng cố** (chính signal `risk=` là vòng lặp đang quay). Trust cũ bất lực: bị `session_flag>=max` veto (chính hành vi bận rộn set flag đó — tự phản) và chỉ cap challenge, không cap block.
  - **Fix:** authentication (richness) là ground-truth phủ quyết tiền đề "ẩn danh phối hợp" mà correlation signals dựa vào. Cap **monitor** (không challenge — admin-ajax là XHR, không render nổi PoW). Monitor cũng bẻ gãy loop vì `async/risk_update` decay `risk:<id>` khi action=monitor → KHÔNG cần sửa risk_update. Bot credential-stuffing richness=0 → không chạm tier → vẫn ×1.5 + block. Đánh đổi: antibot không hard-block user đã login (nhất quán triết lý richness−30); rủi ro còn lại = cookie-theft, nhưng lúc đó đã authenticated với app rồi. Thay thế phương án vá auth_endpoint ×1.5 richness-gate. Xem `core/session_richness.lua` (công thức, trần cookie-only 0.80) + `core/config.lua` `ip_tour.richness_max`.
- 2026-07-06 — **swarm → `ban:<ip>` on first score-block** (`ban/ban_store_write.lua`). Gate cũ `ip_risk>=0.5 and swarm` khóa chết nhánh `ip_ban_ttl=180` vì distributed swarm (nhiều IP × 1 req) khiến ip_risk KHÔNG BAO GIỜ leo tới 0.5 (EMA cần ~4 hit/IP + guard bot_score chặn nâng — xem `[[reference_swarm_flags]]`). Sửa `swarm_active = ctx.swarm==true or (ctx.swarm_attack or 0) >= 1.0` — **phải đọc `ctx.swarm_attack`** (distributed_swarm) chứ không phải boolean `ctx.swarm` (cluster/swarm_detect); attack "nhiều IP×1 req" chỉ fire swarm_attack. Guard `session_richness==0` (user thật có cookie lỡ dính flash-crowd KHÔNG bị ban:<ip>) + Tier-2 `ip_shared_verified` immunity giữ nguyên. IP swarm giờ hiện trong tab BAN (TTL 180s) + fast-path exit ở `ip_ban_check`. **Cảnh báo collateral:** `ban:<ip>` chặn ở `ip_ban_check` TRƯỚC cả richness/whitelist → user thật đến sau trên IP shared (CGNAT/office chưa đạt Tier-2) sẽ dính `reason=banned_ip`; nếu thấy triệu chứng đó, cân nhắc thêm `not ctx.ip_shared`.
- 2026-07-05 — **Tier-2 shared-IP ban immunity** (`ban/ban_store_write.lua`). After computing `should_ban_ip`, force it false when `ctx.ip_shared_verified` (proven high-user shared IP — mobile CGNAT/farm/office with ≥3 real cookied users, set by `detection/ip_tour.lua`). One bad device must not `ban:<ip>` and nuke thousands of real users behind the same IP — it is still banned PER-IDENTITY (`ban:<id>`). Only the STRICT Tier-2 flag qualifies; a UA-rotation bot that merely looks "shared" (Tier 1) has 0 real cookies → not immune → stays IP-bannable. Pairs with `async/risk_update.lua` (won't raise `ip_risk:<ip>` on Tier-2 shared) + `intelligence/scoring/compute.lua` (dampens ip_risk/ip_rep/ext_rep/ip_surge on Tier-1 `ip_shared`). See `antibot-core/CLAUDE.md` 2026-07-05.
- 2026-07-04 — **ip_tour challenge-floor** (`engine.lua`). After action compute, BEFORE trust cap: `if ctx.ip_tour and action ∉ {block,challenge} then action="challenge", reason="ip_tour"`. Placed after the `good_bot_verified` short-circuit so verified crawlers touring every domain are exempt; placed before trust cap so a genuinely trusted session can still downgrade to monitor. Guarantees a single-UA multi-domain tour reaches challenge regardless of class dampening (interaction 0.6 / unknown 0.5 would otherwise leave the weight-25 signal at monitor). Repeat offenders escalate to direct ban inside `detection/ip_tour.lua` (strike counter), not here. See `detection/CLAUDE.md` 2026-07-04.
- 2026-06-18 — **Generic verified-bot rate ceiling + adaptive class promotion** (`engine.lua` + `core/config.lua` + `async/logger.lua`). REPLACES old `throttle_meta_asn` (Meta-specific per-ASN limit 300/min).
  - **Why**: Meta-specific hardcode was anti-pattern (mai Bytespider/GPTBot tương tự lại phải add 1 function nữa). Industry pattern (Cloudflare Bot Categories, Akamai Crawler Profiles, DataDome) là per-bot-family rate ceiling — generic cho mọi verified bot.
  - **`cfg.rate.good_bot_rate`** (NEW): 3 classes với req/min ceiling:
    - `polite=180` (Google/Bing/Apple/DuckDuck — search engine ổn định)
    - `moderate=60` (Meta/CocCoc/Yandex — verified nhưng có history aggressive)
    - `aggressive=30` (Bytespider/Semrush/Ahrefs/MJ12 — known low-value crawl)
    - `default=60` (unknown verified bot fallback)
  - **`map`**: bot_name → class. Small finite list (~15 bots), stable. Metadata cho TUNING known entities, KHÔNG phải detection pattern list — distinct với anti-pattern enumeration. Đã có list verified bot trong `core/data/goodbot.json` rồi, class chỉ thêm 1 chiều thông tin.
  - **Adaptive promotion** (TTL self-decay, cùng triết lý `ip_risk` EMA decay trong `async/risk_update.lua`):
    - Mỗi 429 → INCR `gb_aggression:<bot>` với TTL 600s (10-min sliding window — TTL refresh on each violation)
    - Score thresholds: `>= 10` → +1 tier, `>= 30` → +2 tier (skip thẳng aggressive)
    - Bot quiet 10 phút → key expires → score reset → effective_class restore về base
    - "default" class fallback semantics: treat as moderate cho promotion ladder
  - **Logic flow trong `throttle_good_bot_rate(ctx)`**:
    1. Resolve `base_class` từ `cfg.rate.good_bot_rate.map[bot] or "default"`
    2. Read `gb_aggression:<bot>` → compute `effective_class` qua promotion ladder
    3. Get `limit = classes[effective_class]`
    4. INCR `gb_rate:<bot>:<minute>` (TTL 65s, minute-aligned fixed window)
    5. If `count > limit` → INCR aggression + 429 + Retry-After
    6. Set ctx fields cho logger: `good_bot_class_base`, `good_bot_class`, `good_bot_aggression`, `good_bot_rate_count`, `good_bot_rate_limit`
  - **`action_reason`**: `good_bot_rate_<class>` (e.g., `good_bot_rate_aggressive`, `good_bot_rate_moderate`). Grep theo class dễ.
  - **antibot.log** (cập nhật `async/logger.lua`): append cho MỌI good_bot_verified request (không chỉ throttle):
    - `bot=<name> base_class=<base> eff_class=<effective> agg=<score> rpm=<count>/<limit>`
    - Khi `base_class != eff_class` → bot đang bị auto-promote → grep `eff_class=aggressive base_class=moderate` audit case này
    - Khi `agg > 0` không kèm throttle → bot đã misbehave trước đó, đang trong window decay
  - **Replaces**: cũ `throttle_meta_asn` (Redis key `rate:goodbot:meta:<min>`, hardcode 300/min cho AS32934). Mới `throttle_good_bot_rate` áp universal qua `cfg.rate.good_bot_rate.map`. Meta giờ ở class moderate=60/min (chặt hơn cũ 5x), backend protect tốt hơn khi Meta aggressive.
  - **Risk update integration**: `async/risk_update.lua` đã skip `action=throttled` cho ip_rep penalty (từ 2026-05-04). Reason mới `good_bot_rate_*` cũng là throttled → giữ nguyên hành vi, verified bot không bị ip_rep penalty khi chỉ exceed rate ceiling.
- 2026-05-23 (v3) — **Generic kill-switch cho dampened class non-resource** (`engine.lua`). Resource class đã có kill-switch riêng từ trước (raw 80/95). Thêm kill cho class còn lại có `multiplier < 1.0` (interaction 0.6, api_callback 0.5, feed_or_meta 0.4, inapp_browser 0.4, unknown 0.5):
  - `raw ≥ 150` → floor effective tại 85% raw (`kill_damp_hard`)
  - `raw ≥ 110` → floor effective tại 65% raw (`kill_damp_soft`)
  - Logic chèn vào `elseif multiplier < 1.0 then` branch ngay sau resource block.
  - **Lý do**: Fix A' giảm unknown mult 1.0 → 0.5 (commit 649031e) tạo FN cho bot Azure UA-empty raw 140 — eff cap 70 → challenge mãi không lên block 80. Dampening designed để giảm FP cho normal traffic, KHÔNG bảo vệ pure-threat storm. Kill threshold cao (110) đảm bảo legit logged-in user không trigger (session_richness -30 đã trừ ~24 pts cho admin → khó đạt raw 110 nếu không bị multiple bot signal fire).
  - Verified case 20.9.70.139: raw 140 ≥ 110 → eff = max(70, 140×0.65) = 91 → block ✓
- 2026-05-19 — **S2.5 attest cap** in `engine.lua` after action compute (post trust cap):
  - if `ctx.bot_identity_tier=="S2.5"` AND action ∈ {challenge, block} → action="monitor", reason="s25_cap_monitor"
  - Bot SDKs don't execute JS → challenge=PoW-fail=block-effective. Cap at monitor is the only way "cap" actually prevents blocking.
  - Pairs with `intelligence/threat/asn_reputation.lua` waiver (asn_rep=0 when S2.5) to drop steady-state score below MONITOR threshold (25).
  - `bot_score=0` from `detection/bot/bot_score.lua` (S2.5 honor) auto-breaks `ip_risk:<ip>` EMA rise via existing `bot_score>0.3` guard in `async/risk_update.lua` — no additional change needed.
  - Cap also stops `risk:<id>` EMA loop because monitor action triggers decay branch in risk_update (line ~96).
- 2026-05-28 — `engine.lua` **Meta ASN raw rate limit** (`throttle_meta_asn`): verified Meta bot (AS32934, observed 57.141.2.x subnet) limited to 300 req/60s (= 5 req/s). Minute-aligned fixed window key `rate:goodbot:meta:<minute>` TTL 65s. Response 429 + Retry-After: 60. Fires AFTER `throttle_good_bot` inside `good_bot_verified` block. `async/risk_update.lua` already skips ip_rep penalty for `action=throttled` — no additional change needed. Motivation: ~8-9 req/s crawl of path-based filter combination URLs (`/loc-...,....html`) occupied ~8 concurrent PHP workers; `throttle_good_bot` không trigger vì URLs không có query string.
- `72f0415` (2026-05-03) — no direct changes. l7 Phase 1 mitigations indirectly lower `ctx.slow`, `ctx.burst` for unstable network users → `ctx.score` lower → action more lenient → fewer false challenges/blocks
- 2026-05-04 (v1) — `engine.lua` good_bot_throttle initial: verified bots hitting hardcoded patterns (filter_/min_price/max_price/orderby) get rate-limited at 8/min/bot_name with `429 Retry-After: 120`. Reason `good_bot_throttled`
- 2026-05-04 (v2) — `engine.lua` good_bot_throttle REWRITE to **hybrid scoring** (general, no hardcoded names):
  - **HARD**: `qs_len ≥ 200` OR `params ≥ 8` → trigger immediately (count toward RPM)
  - **SOFT**: weighted sum of 4 sub-signals ≥ `0.7` → compound subtle expensive
    - qs_len graduated 0.15/0.35/0.50 at 40/80/120 chars
    - param_count graduated 0.20/0.40 at 3/5 params
    - comma density graduated 0.10/0.25/0.40 at 1/2/4 commas (raw `,` + `%2C`)
    - search_term 0.15 if `+` or `%20` present (lenient — single Việt search pass)
  - **RPM**: `gb_throttle:<bot>:<minute>` TTL 65s; throttle khi count > 8
  - Catches WooCommerce filter, WP search, sort, faceted nav cross-site without naming params
  - Vietnamese URL handled natively (UTF-8 bytes inflate qs_len)
  - Logs include `trigger` (hard_qs_len|hard_param_count|soft_score) + `score` for tuning
  - Sets `ctx.expensive_score`, `ctx.expensive_trigger` even when allowed (debugging)
  - Pair with `async/risk_update.lua` skip when `action="throttled"` (no ip_rep penalty for legit verified bot)
