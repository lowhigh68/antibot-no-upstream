# intelligence/

Score aggregation. Reads ctx flags from detection+l7+transport+core, computes `ctx.score`, identifies top contributing signals.

## Purpose
Convert dozens of individual signals (each [0,1]) into a single weighted score [0,100+] that enforcement/engine consumes. Track contribution % for explainability.

## Files

| File | Role |
|---|---|
| `init.lua` | Orchestrator: `threat.run(ctx)` → `correlation.run(ctx)` → `scoring.run(ctx)` |
| `scoring/compute.lua` | **Nơi DUY NHẤT dựng `ctx.score`.** Walks `DEFAULT_WEIGHTS`, calls `get_signal(name, ctx)` per signal, sums weighted contributions. Records `ctx.top_signals` (3 highest with contribution_pct) |
| ~~`scoring/signal_merge.lua`~~ | **ĐÃ XOÁ 2026-09-06** — ghi `ctx.signals`, không nơi nào đọc |
| ~~`scoring/context_vector.lua`~~ | **ĐÃ XOÁ 2026-09-06** — ghi `ctx.context_multipliers` + `ctx.is_api_request`, không nơi nào đọc |
| ~~`threat/ja3_db.lua`~~ | **ĐÃ XOÁ 2026-09-06** — đọc `rep:ja3:` (không ai ghi) → `ctx.ja3_rep` (không có trong `DEFAULT_WEIGHTS`) |
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
intelligence.run(ctx)            -- init.lua:20-22, THỨ TỰ NÀY QUAN TRỌNG
   threat.run                    → ctx.asn_rep, corr_score, corr_rules
   correlation.run               → ctx.mismatch, ctx.mm_rules,
                                    ctx.browser_claim_broken
   scoring.run  (compute.lua)    → walk weights, get_signal(), sum → ctx.score
            ↓
enforcement.engine.run           → effective_score, decide action
```
**correlation chạy TRƯỚC scoring** — nên cờ do `consistency_check` đặt (`mismatch`, `browser_claim_broken`) đã sẵn sàng khi `get_signal()` đọc. Đảo thứ tự này sẽ làm mọi signal phái sinh im lặng về 0.

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

- 2026-09-12 — **VPN đang bị chấm nặng hơn datacenter. Đó là sai thứ tự, không phải một con số to.** `threat_feed_sync.sh` ghi `rep:asn:` hai bậc: datacenter **0.45**, VPN **0.75**. Nhân trọng số `asn_rep` = **35** ra **15,75** và **26,25** điểm thô. Ngưỡng CHALLENGE là 55 — nghĩa là một người dùng VPN **bắt đầu ở gần nửa đường tới thử thách trước khi làm bất cứ việc gì**. Trên hạ tầng có khách dùng VPN/WARP phổ biến, đó là nguồn chặn nhầm **có hệ thống**.
  - **Sửa bằng TRẦN, không bằng hệ số nhân** (`cfg.asn_rep.vpn_max = 0.30` → 10,5 điểm, **thấp hơn** bậc datacenter). Hệ số nhân trôi theo feed; trần giữ nguyên ý nghĩa dù nguồn đổi 0.75 thành bao nhiêu, và nó ghim thứ tự để không đảo lại lần nữa. **Không phải miễn trừ** — VPN vẫn là tiền nghiệm hợp lệ, chỉ là tiền nghiệm **yếu**.
  - **Dùng lại `asn:type:<n>`, thứ đã có sẵn mà không ai đọc.** Script ghi `datacenter`/`vpn`/`residential` từ lâu; đường đọc bị xoá cùng `ip_classify.lua` ngày 2026-09-06 vì *"không ai dùng"* — đúng vào lúc đó. Nay có người dùng. Cache 300s trong shm, và **chỉ tra khi điểm đã vượt trần** nên lưu lượng thường không trả thêm một phép I/O nào.
  - **`AS13335` (Cloudflare/WARP) không nằm trong danh sách — nhưng đó là may, không phải thiết kế.** Nguồn X4BNet thêm Cloudflare lúc nào cũng được, và khi đó **mọi người dùng WARP trên cả đàn máy ăn 26 điểm ngay lập tức mà không ai deploy gì**. Trần này cũng chặn luôn kịch bản đó.
  - **Script nay nằm trong đường deploy** (`intelligence/threat/scripts/`, trước ở `nginx/scripts/`). Đo 2026-09-12: số khoá `rep:asn:` trên ba máy là **0 / 820 / 53.454** — cùng một request bị chấm điểm khác hẳn nhau tuỳ máy nào nhận, và mọi phép so sánh giữa các máy từ trước đều mang nhiễu loạn này. Bit thực thi trong git trước là `100644`: kể cả nếu file từng tới máy chủ thì cron vẫn chết câm, đúng lỗi đã gặp với `fim.sh`. Bước `[8]` của `deploy.sh` nay báo cron, cảnh báo đường dẫn cũ, và đọc số khoá với ba dải (0 = tín hiệu chết · ~800 = đúng · >20.000 = nguồn đang ghi rác).
- 2026-09-09 — **`ja3_allowlist`: trần cipher `> 30` → `> 31`. Hiệu chỉnh TRƯỚC khi lật `ja3_cipher = "on"`, không phải sửa lỗi đang chạy.**
  - Nhánh này **chưa từng chạy một lần nào** — `run()` thoát sớm ở `ctx.ja3_partial`, mà cờ đó luôn `true` ở nấc `off`/`probe`. Nên đây là hiệu chỉnh dự phòng: lật `"on"` là bật nó cho toàn bộ lưu lượng cùng lúc, trọng số 50.
  - **Đo 09-09, 5 máy, 997.492 dòng có JA3.** `cipher > 30` chiếm **290.614 (29,1%)** lưu lượng, trong đó **9.807** request có `richness >= 0.5` (phiên đăng nhập thật). Một luật bắn vào 29% lưu lượng không phải bộ phân biệt.
  - **94,5% FP nằm trong ĐÚNG MỘT giá trị.** Dải `31`: 128.543 request, **9.263** auth, UA phổ biến nhất trong nhóm auth là Chrome/Windows trên 3/5 máy. Từ `33` trở lên là bot tự xưng tên (Amazonbot 45, SERankingBacklinksBot 49, MJ12bot 35, Pinterestbot 36, YisouSpider/QlyzeBot 52, Apache-HttpClient 50) với auth ≈ 0. Ngưỡng cũ cắt đúng giữa dải browser.
  - **Còn lại 544 request auth vẫn bị phạt**, rải ở 43/61/66/75/86/87 — dải `61` trên cloud183-139 là 227/228 auth, một nhóm người dùng thật ở 61 cipher. Đó là 0,05% lưu lượng. Nếu còn sinh chuyện thì hướng đúng là **hạ điểm 0.3**, không phải đẩy trần lên tiếp: `miss = max(...)` nên hạ xuống dưới 0.3 sẽ đổi thứ tự với `curve_score`.
  - **Chưa giải thích được, và không cần để ra quyết định:** 31 không phải số cipher của Chrome trực tiếp (Chrome thật nằm ở dải 15, dải đông nhất toàn đàn máy). Giả thuyết chưa kiểm: middlebox soi TLS chào hộ ClientHello.
  - **Quan sát phụ, đáng nghi, CHƯA xác minh:** ở dải 31, UA phổ biến nhất *trong nhóm auth* là `meta-externalads` trên cloud183-139 (2.537) và `pimeyes-downloader-api` trên cloud28-246 (132). Nếu bot đạt được `richness >= 0.5` chỉ bằng cách giữ cookie thì `auth_session_cap` là một đường vòng — cần đo riêng, xem `enforcement/CLAUDE.md`.
- 2026-09-06 — **Dọn cụm tín hiệu chết: 4 module xoá, 2 tín hiệu gỡ khỏi bảng trọng số. Không đổi hành vi.**
  - **Nguyên tắc dùng để quyết:** một tín hiệu chỉ là "chết" khi **không nơi nào đọc đầu ra của nó**, chứng minh bằng grep toàn cây. Bốn thứ dưới đây đều thoả, và đều tốn CPU/Redis mỗi request để không đổi lấy gì.
  - **`scoring/signal_merge.lua` + `scoring/context_vector.lua` XOÁ.** Chạy trên MỌI request đã chấm điểm, dựng `ctx.signals` / `ctx.context_multipliers` / `ctx.is_api_request` — cả ba **chỉ được ghi**. `compute.lua` đi thẳng từ `DEFAULT_WEIGHTS` + `get_signal()`, không chạm tới. **Một tầng chết che một tầng chết:** chúng là hai nơi duy nhất đọc `ja3_rep`, khiến tín hiệu đó trông như "có người dùng".
  - **`threat/ja3_db.lua` XOÁ.** Chết ba lần: `rep:ja3:` không nơi nào GHI; `ja3_rep` không có trong `DEFAULT_WEIGHTS`; hai chỗ đọc nó cũng chết. Nó gác `ja3_partial` nên hôm nay chưa từng chạm Redis — nhưng lên nấc `cfg.tls.ja3_cipher = "on"` thì thành một `GET` mỗi request cho giá trị không ai đọc.
  - **`async/adaptive_weight.lua` XOÁ.** Chữ ký `run(ctx, feedback)`, dòng đầu `if not feedback then return end`, mà chỗ gọi duy nhất (`init.lua`) **không truyền `feedback`** ⇒ thoát ngay, mọi lần, từ đầu. Và kể cả chạy, nó ghi `model:weight` mà `compute.lua` không đọc. Gỡ đi bớt **một `ngx.timer.at` mỗi request non-resource**. Kéo theo `cfg.weights` (19 mục, đã lệch so với `DEFAULT_WEIGHTS` 32 mục — cùng loại trùng lặp với `_M.thresholds`) và `cfg.ttl.model_weight`.
  - **`canvas_change` GỠ khỏi `DEFAULT_WEIGHTS` + `get_signal` + bộ đếm ghi.** Trọng số cũ **50** — cao thứ nhì bảng — nhưng vĩnh viễn 0: ghi `fp:canvas_change:<identity>`, đọc `fp:canvas_change:<ctx.ip>`.
    - **Không sửa bằng cách nối đúng khoá.** Nối phía đọc sang `identity` là **bật** một tín hiệu 50 điểm lên đúng nhóm vừa GIẢI XONG PoW; mà `identity = md5(ip+ua)` nên sau CGNAT hai điện thoại cùng UA Chrome dùng chung identity với hai canvas khác nhau ⇒ đánh dấu ⇒ quy tội tập thể, đúng thứ `ip_shared` sinh ra để chống. Nối phía ghi sang `ip` còn tệ hơn.
    - Ý tưởng chỉ sống lại khi có định danh THEO THIẾT BỊ thật — mà thứ đó lại dựa vào chính canvas (`build_device_id`), nên vòng tròn. `fp:canvas:<id>` (không có `_change`) **giữ nguyên**: nuôi `build_device_id` → `verified:device:`.
  - **`transport/tls/ja3s.lua` giữ file nhưng bỏ hết phần JA3S** — nó sinh hằng số MD5("0,0,") và không ai tiêu thụ. ⚠️ **Không được xoá file**: `_M.capture()` là nơi duy nhất gọi `ja3.relay()` (nhịp 2 của cầu JA3) và được 99 per-domain conf tham chiếu. Xem `transport/CLAUDE.md`.
  - **Kiểm chứng:** grep toàn cây cho 11 định danh liên quan ⇒ 0 tham chiếu mã còn lại. `contract_test` mục 0 (`loadfile` mọi file `.lua`) là cổng bắt lỗi cú pháp trước deploy.
- 2026-08-01 (3) — **Gỡ double-count GIỮA `mismatch` và `h2_bot_confidence`. Ranh giới sở hữu bằng chứng.**
  - **Ba chỗ trùng, cả hai signal đều weight 55:** `h2_bot_pattern` (h2bc +0.40 = 22đ ⊕ mismatch +0.30 = 16,5đ → **38,5đ**), `h2_tls_mismatch` (13,75 ⊕ 13,75 → **27,5đ**), Chrome/FF không H2 (h2bc +0.15 ⊕ luật no_h2 của mismatch → **22÷27,5đ**).
  - **RANH GIỚI, giữ đúng khi thêm luật mới:** `h2_bot_confidence` = *những gì tầng H2 QUAN SÁT được*; `mismatch` = *MÂU THUẪN giữa điều UA tự nhận và điều các tầng thấy*. Theo đó: gỡ `h2_bot_pattern` + `h2_tls_mismatch` khỏi `consistency_check`, gỡ nhánh `+0.15` (không có H2) khỏi `signature.lua` — không có H2 thì tầng H2 chẳng quan sát được gì.
  - **Đo TRƯỚC khi sửa** (2h, đã loại good-bot và short-circuit): ảnh hưởng 5178 request. `block → challenge` **54/171 (32%)**, `challenge → monitor` 15/136, **`block → allow` = 0, `challenge → allow` = 0** — không request nào thoát hẳn, xấu nhất là tụt xuống PoW. `monitor → allow` 721 = giảm nhiễu.
  - **Hiện vật của mô hình dự báo:** `monitor → challenge` 13 ca — không nghịch lý, đó là request `eff` cao nhưng bị **cap** xuống monitor (`auth_session_cap`/trust cap); bỏ điểm thì cap vẫn giữ chúng ở monitor.
  - **Quan sát kiến trúc từ cùng phép đo:** `bo_shortcircuit=13165` + `bo_goodbot=1302` trên `tong=25074` ⇒ **~58% lưu lượng KHÔNG đi qua tầng chấm điểm** (cookie fast-path verified / whitelist / good-bot). Mọi tinh chỉnh trọng số ở đây chỉ với tới 42% còn lại — cân nhắc khi ưu tiên việc.
- 2026-08-01 (2) — **`browser_claim_broken`: thử rồi REVERT. Nghi "lọt lưới cookie jar" là ẢO — đừng đào lại.**
  - **Nghi vấn ban đầu:** ~1450 request `richness=0.80` + không Sec-Fetch + không H2, tất cả `allow`. `core/session_richness.lua` tính `0.5·(bytes/500) + 0.3·(n_ck/4)` nên trần cookie-only **đúng 0.80** mà không cần `Authorization`/CSRF ⇒ về lý thuyết một scraper giữ cookie jar mua được `−24` điểm (`session_richness` weight −30). Đã thử: `consistency_check` đặt cờ khi luật `no_h2_no_secfetch` bắn, cờ zero signal âm ở `compute.lua` và vô hiệu `auth_session_cap` ở `engine.lua`.
  - **Dữ liệu bác bỏ:** **1571/1600 = 98,2% dân số đó là `good_bot_verified`** (Googlebot/Bingbot — dấu hiệu nhận ra: mọi dòng đều có `bot=`/`base_class=`/`eff_class=`, và **`eff=0.0` ở TẤT CẢ các dòng** vì `engine.lua` `return` ngay ở short-circuit good-bot, trước mọi tính toán). Loại good bot ra chỉ còn **29 dòng trên toàn bộ log**: 23 `allow`, 6 `monitor`, `eff` cao nhất 30,3.
  - **Vì sao revert dù cờ chạy đúng** (điểm thô có tăng +10÷23): lợi ích ≈ 0, còn cái giá là rủi ro đuôi trên người dùng thật — ai lỡ chạm `no_h2_no_secfetch` (trình duyệt tiền-2019, proxy bóc Sec-Fetch) mất **cả** −24 điểm **lẫn** lá chắn `auth_session_cap`. Đổi lợi ích gần bằng không lấy rủi ro trên người thật là sai chiều.
  - **BÀI HỌC ĐO ĐẾM:** `eff=0.0` trong khi `score` cao **luôn** nghĩa là engine đã short-circuit (`whitelisted`/`good_bot_verified`) — kiểm tra điều này TRƯỚC khi phân tích bất kỳ dân số nào. Và `grep -oP 'class=\K\S+'` bắt trúng cả `base_class=`/`eff_class=` của good-bot; giá trị `polite`/`moderate`/`aggressive`/`default` **không phải `req_class`**.
  - **Cũng sai trên đường đi:** lời giải thích "thủ phạm là signal âm chứ không phải `auth_session_cap`" — không cái nào là thủ phạm, cả hai đều nằm **sau** chỗ engine đã thoát.
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
