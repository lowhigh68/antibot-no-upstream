# detection/

Signal families that observe HOW request behaves vs HOW request looks (l7 = volume, transport = TLS shape, detection = behavioral/structural). Most expensive layer — skipped for `resource` class.

## Purpose
Compute behavioral/structural anomaly scores into ctx flags consumed by `intelligence/scoring/compute.lua`.

## Subdirectories

| Dir | Purpose | Output ctx fields |
|---|---|---|
| `bot/` | Good-bot identification (4-path verify), UA bot pattern check | `bot_score`, `bot_ua`, `good_bot_verified`, `good_bot_claimed`, `good_bot_asns`, `good_bot_ptr_only` |
| `anomaly/` | UA structure, header consistency, protocol oddity | `header_flag`, `ua_flag`, `proto_flag`, `anomaly_score`, `ua_identity_uncertain` |
| `browser/` | Beacon JS injection (2-phase), beacon handler endpoint | `inject_candidate`, `browser_needed` |
| `behavior/` | Click/scroll/timing patterns from beacon data | `behavior_score` |
| `session/` | Session path, repeat ratio, resource_starved (Attack 4) | `sess_len`, `session_flag`, `nav_count`, `res_count`, `resource_starved` |
| `cluster/` | UA/IP/URI/TLS clustering across identities | `ua_cluster`, `ip_cluster`, `uri_cluster`, `tls_cluster`, `cluster_score` |
| `graph/` | Graph correlation between identities | `graph_flag`, `graph_score`, `subnet_diversity` |

## Top-level files

| File | Role |
|---|---|
| `init.lua` | Orchestrator. Each sub-init.lua calls `should_run(ctx)` checking `ctx.skip_layers` |
| `distributed_swarm.lua` | Cross-identity attack pattern detection → `ctx.swarm_attack` (0.3–1.0, =1.0 at HARD threshold; many /24 → ONE domain). NOTE: sets `ctx.swarm_attack`, NOT the boolean `ctx.swarm` (that's `cluster/swarm_detect.lua`, a different signal) |
| `ip_tour.lua` | Cross-domain tour detection → `ctx.ip_tour` (ONE ip → many domains). Runs in `STEPS_COMMON` (after access_layer), NOT here. HLL `iptour:dom/ua:<ip>`, NAT-gated by distinct-UA, richness-exempt, strike→direct-ban |
| `wp_hardening.lua` | WordPress-specific path/payload checks |

## bot/ submodule (4-path verification)
See [`memory/project_bot_verification.md`](../../memory/project_bot_verification.md).
- `init.lua` orchestrate ua_check → dns_reverse → dns_forward → asn_fallback
- `ua_check.lua` regex match UA against good-bot patterns, hardcoded `PTR_ONLY_BOTS` table (also stores ASN list)
- `dns_reverse.lua` PTR lookup, suffix match against `goodbot:dns:<name>` (Redis)
- `dns_forward.lua` A record check IP membership; **early return if `good_bot_ptr_only`** (Meta family)
- `lite_verify.lua` resource-class only: ua_check + asn lookup + ASN match (no DNS)
- Reasons emitted: `good_bot_verified` (full DNS or PTR-only), `good_bot_asn_verified` (ASN fallback), `good_bot_asn_lite` (resource)

## ctx fields written
See per-subdir column above.

## ctx fields read
`ip`, `ua`, `req.{uri,method,host,referer,accept,accept_lang,accept_enc,sec_fetch_*}`, `device_type`, `device_is_mobile`, `device_sec_fetch_expected`, `device_ch_ua_mobile_expected`, `req_class`, `sess_len`, `fp_light`, `asn`, `tls13`, `ja3`

## Flow
```
COMMON  → ip_ban_check + access (whitelist) + transport (fp)
            ↓
class dispatch
            ↓
detection.run(ctx)
   ├─ bot.run         → may set good_bot_verified=true → engine bypass scoring
   ├─ anomaly.run     → header_flag, ua_flag, proto_flag
   ├─ session.run     → load + analyze + store; sets sess_len, session_flag, resource_starved
   ├─ behavior.run    → behavior_score (beacon-driven)
   ├─ browser.trigger → ctx.inject_candidate (decided by Accept header)
   ├─ cluster.run     → cluster_score
   ├─ graph.run       → graph_flag, graph_score
   └─ distributed_swarm.run → ctx.swarm_attack (NOT ctx.swarm — see top-level files note)
```

For `resource` class: `STEPS_RESOURCE` skips this entire layer except `bot/lite_verify.lua` (called directly from init.lua).

## Related
- Upstream: `core/ctx`, `core/fingerprint/*`, `transport/*`
- Downstream: `intelligence/scoring/compute.lua` reads ALL output flags as signals; `enforcement/decision/engine.lua` short-circuits on `good_bot_verified`
- Beacon two-phase: `browser/trigger.lua` (access) sets candidate; `header_filter_by_lua_block` confirms via Content-Type; `browser/inject.lua` (body_filter) emits JS

## Important rules
- New module MUST check `ctx.skip_layers[<name>]` via `should_run()` helper
- `good_bot_verified=true` → engine.lua immediate allow, bypass scoring (write only after PROVEN identity, not on UA claim alone)
- session_store has separate sess_age key for grace period — newly-arrived users won't trigger resource_starved
- Beacon injection NEVER short-circuits — CSS/JS/image responses must NEVER have Content-Length cleared (header_filter checks Content-Type)

## Update log
- 2026-08-08 — **Lá chắn crawler cho fleet (`crawler:<ip>`) + đón `baiduspider` vào registry.** Fleet không còn phủ quyết tầng xác minh.
  - **Số liệu bắt buộc phải sửa (cloud168-101, 24h):** `fleet_dyn_block_24:116.179.37.0/24` = **18.676** lệnh chặn, cộng /16 và /24 lân cận thành **20.042 = 25% toàn bộ lệnh chặn của máy**. Tra PTR 8/8 IP đều là `baiduspider-116-179-37-*.crawl.baidu.com`, và `dig` xuôi trỏ ngược đúng IP ⇒ **Baiduspider thật, DNS hai chiều sạch**. Nặng hơn: fleet chặn bằng `ngx.exit(444)` — RST tầng TCP — mà chính chú thích trong `check_block.lua` ghi rằng crawler đọc RST liên tục là "máy chủ không tồn tại" và **loại URL khỏi hàng đợi**.
  - **Gốc rễ là THỨ TỰ, không phải ngưỡng:** `fleet/check_block` là bước đầu tiên của `STEPS_COMMON`, tầng xác minh bot nằm tận `detection`. Crawler hợp lệ phân tán trên nhiều IP có cấu trúc **giống hệt** một đội cào (nhiều IP / ít vân tay / hội tụ đường dẫn / không cookie) nên bị gắn cờ /24 rồi chết ở cửa, **không bao giờ có cơ hội chứng minh mình là ai**. Thêm bot vào registry hoàn toàn vô nghĩa khi request không sống tới đó.
  - **Vì sao KHÔNG dùng `is_good_crawler` (đường ASN) — đã cân nhắc và bác bỏ:** dải `116.179.0.0/16` thuộc **AS4837 CHINA UNICOM China169 Backbone** (GeoLite2 xác nhận; netname `UNICOM`, RADB thêm AS135028). Baidu **đi trung chuyển**, không tự quảng bá ASN. Mở cổng theo AS4837 = miễn trừ fleet cho mọi máy thuê ở Trung Quốc chỉ cần gắn chữ `spider` vào UA — đúng vùng xuất phát của phần lớn lưu lượng cào, và fleet là tầng DUY NHẤT bắt được kiểu "nhiều IP × ít vân tay". Cổng ASN chỉ chặt khi crawler chạy trên ASN **riêng của chính họ** (Google 15169, Meta 32934…).
  - **Cơ chế:** `bot/init.lua` ghi `crawler:<ip>` TTL 1h sau khi xác minh xong → `check_block` đọc ghép vào **đúng pipeline sẵn có** (GET thứ 3, **không thêm vòng Redis nào**) và bỏ qua RST → `ctx.is_known_crawler` được `aggregator` chạy ngay sau dùng lại **miễn phí**, thôi tính IP đã xác minh vào bucket ⇒ cờ /24 hết được gia hạn ⇒ `fl:dyn` **tự hết hạn** thay vì tự nuôi mình mãi.
  - **Ranh giới cấp dấu — điểm quan trọng nhất:** CHỈ `good_bot_verified` (S4/S3 registry), `contact_ptr_match`, `contact_org_match`. **KHÔNG** `contact_cloud_attested` / `analyzer_attested`: hai đường đó chỉ chứng minh "có thuê máy ở cloud", mà **"nhiều IP thuê ở cloud" đúng là định nghĩa của cái fleet sinh ra để bắt**. Ranh giới này nhất quán với mọi quyết định đã ra: Baidu qua (S4), Ahrefs qua (`contact_org_match`), PetalBot trên Huawei Cloud **không** qua.
  - **`baiduspider` vào `goodbot.json`** (`crawl.baidu.com`) + `good_bot_rate = aggressive` (30/phút). Mọi biến thể `-image/-video/-news/-render` rút về cùng tên `baiduspider` ở `ua_check` (`([%w%-]+[Ss]pider)`) nên **chia chung một hạn mức** — rotation IP không nhân được nó lên. Đổi lại: trước đây Baidu **không có trần nào**, chỉ có bức tường; nay có trần thật.
  - **Chỉ khai một suffix là CỐ Ý.** PTR khác (`*.crawl.baidu.jp`) sẽ trượt registry rồi rơi xuống `contact_org_match` (nhãn `baidu` khớp) → vẫn S2.5, vẫn được cấp dấu. Thang đơn điệu 2026-08-07 làm việc đúng như thiết kế; không cần liệt kê cho đủ.
  - **Thao tác vận hành BẮT BUỘC sau deploy:** `redis-cli DEL fl:dyn:116.179.37.0/24 fl:dyn:116.179.33.0/24 fl:dyn:116.179.0.0/16` — khoá đang tồn tại chặn IP **chưa** kịp có dấu, và phải chờ hết TTL 1h nếu không xoá tay.
  - **Lỗ còn lại (chưa vá):** IP HOÀN TOÀN MỚI trong một /24 đang bị chặn vẫn ăn RST vì chưa có dấu. Steady-state tự khỏi (cờ hết hạn), nên chưa làm dấu mức /24. Đo trước, thấy rỉ máu thật rồi mới thêm.
- 2026-08-07 — **`bot/init.lua:run` — thang bằng chứng ĐƠN ĐIỆU. Sửa một tính chất sai, không phải vá một ca.**
  - **Bất biến mới:** thêm bằng chứng chỉ được phép **NÂNG** mức tin cậy, không bao giờ hạ.
  - **Cấu trúc cũ vi phạm:** rẽ nhánh **loại trừ** theo `dns_rev_valid`. PTR khớp registry mà forward trượt ⇒ kết luận `fake_good_bot` **ngay**, `contact_attest` nằm ở nhánh kia nên không bao giờ với tới.
  - **Cái giá đã trả (2026-08-06):** thêm `ahrefsbot` vào registry làm Ahrefs bị đánh giá **XẤU ĐI** (bot_score 0.9 thay vì S2.5) — mục registry đẩy nó sang nhánh trên rồi chết ở đó vì PTR của Ahrefs không có bản ghi A. **Cung cấp thêm thông tin ĐÚNG lại cho kết quả TỆ HƠN.** Đó là dấu hiệu của lỗi thiết kế, không phải lỗi cấu hình.
  - **Nay:** bậc 1 (`dns_fwd`) chạy khi `dns_rev_valid == true`; bậc 2/3 (`contact_attest` → `asn_fallback`) chạy khi **`good_bot_verified ~= true`** bất kể vì sao bậc 1 không thành. Chỉ khi tất cả trượt mới kết luận `fake_good_bot`.
  - **Giữ nguyên hai hành vi tinh tế:** (a) `dns_rev_timeout`/`dns_fwd_timeout` = sự cố TẠM THỜI ⇒ không kết luận giả mạo (`bot_score.lua` bảo toàn score); (b) `math.max(ctx.bot_score or 0, 0.85)` giữ 0.9 mà `dns_fwd` đã đặt — "PTR khớp registry nhưng forward phản đối" đáng ngờ hơn "không có bằng chứng nào".
  - **Không mở lỗ hổng mới:** nhóm được hưởng lợi là bot đã có `dns_rev_valid == true`, tức **đã kiểm soát reverse DNS của dải IP** — rào cản cao nhất trong toàn hệ. Giả danh Googlebot vẫn bị bắt: PTR `foo.googlebot.com` không khớp `google.com` ở 1a, nhãn `googlebot` ≠ `google` ở 1c, `googlebot.com` không có trong cloud suffixes ở 1b.
  - **`ctx.bot_ua` là nhãn thuần tuý** — grep toàn repo cho thấy nó chỉ được GHI, không nơi nào đọc để ra quyết định. Thêm giá trị `dns_timeout` là an toàn.
  - **CÒN THIẾU (lỗ hổng lớn nhất còn lại):** không có cơ chế nào cho **dải IP do nhà vận hành công bố** (JSON) — cách mà OpenAI/Anthropic/Perplexity tự khai báo. Đã cắn thật: "GPTBot" ở `74.7.x` không PTR nên không phân định được thật/giả. Hạ tầng đã có gần đủ (`threat_feed_sync.sh` vốn tải feed ngoài vào Redis). Đo trước khi xây: đếm lượt UA khai bot mà không có PTR.
- 2026-08-06 — **`contact_attest` Path 1c: cùng tổ chức, KHÁC TLD** (`bot/init.lua`) + gỡ `ahrefsbot` khỏi registry + nâng hai log xác minh lên `ERR`.
  - **Bằng chứng:** 13/13 IP AhrefsBot trong danh sách cấm **vĩnh viễn** có PTR `proxy-*.ahrefs.net` — hạ tầng chính chủ, bị cấm oan. UA khai `+http://ahrefs.com/robot/` ⇒ eTLD+1 `ahrefs.com`; PTR eTLD+1 `ahrefs.**net**` ⇒ `ptr_suffix_matches` trượt. **Ca thứ hai** của cùng lỗi với Amazonbot (`amazon.com` vs gTLD `.amazon`).
  - **Đã THỬ rồi ĐẢO NGƯỢC: thêm `ahrefsbot` vào `goodbot.json`.** Nó làm *tệ hơn*, và lý do đáng nhớ: có suffix ⇒ `dns_rev_valid = true` ⇒ chạy sang `dns_forward` ⇒ **`contact_attest` KHÔNG BAO GIỜ được gọi** (nó nằm trong nhánh `dns_rev_valid == false`). Mà forward cũng trượt vì **PTR của Ahrefs không có bản ghi A nào** (`dig proxy-ca017-san100.ahrefs.net` → rỗng) ⇒ `fake_good_bot` 0.9. ⇒ **Mục registry và Path 1c loại trừ nhau; muốn 1c chạy thì registry PHẢI không có tên đó.**
  - **Vì sao KHÔNG chọn `ptr_only` (như Meta):** Meta chạy trên AS32934 của chính Meta; Ahrefs chạy trên **OVH** — nhà cho thuê công cộng, khách tự đặt reverse DNS. Chính việc PTR Ahrefs không forward-confirm chứng tỏ OVH không bắt buộc xác nhận xuôi ⇒ kẻ thuê IP OVH đặt PTR `*.ahrefs.net` + UA AhrefsBot sẽ nhận `good_bot_verified` = **bỏ qua chấm điểm hoàn toàn**. Phần thưởng quá lớn. Path 1c chỉ cho S2.5 (**cap monitor**, vẫn chấm điểm) — tương xứng.
  - **Vì sao BỎ điều kiện "xác nhận xuôi" đã đề xuất hôm trước:** PTR của Ahrefs không có A record, nên forward-confirm sẽ chặn đúng ca cần cứu. Bù lại, 1c **không làm S2.5 yếu hơn 1a**: hôm nay kẻ sở hữu `evil.com` đã có thể đặt PTR `foo.evil.com` + UA `+http://evil.com` là qua. 1c chỉ mở thêm "cùng tổ chức, khác đuôi".
  - **Lá chắn của 1c:** `GENERIC_LABELS` loại `com`/`net`/`co`/`ne`/… và `MIN_LABEL_LEN = 4`. **BẮT BUỘC** — nếu `bot_contact_host` là eTLD+1 nhiều thành phần (`example.com.vn`) thì nhãn trích ra là `com`, khớp theo nó sẽ trúng gần như mọi PTR. Đánh đổi: thương hiệu 3 ký tự (ovh, bbc) không đi đường này.
  - **Log:** `[dns_fwd] FAKE` (WARN→**ERR**) và `[dns_rev] bad suffix` (INFO→**ERR**). Hai dòng quan trọng nhất của đường xác minh — "bot khai là X nhưng DNS bảo không phải" — trước đây bị per-domain `error_log` lọc sạch. Mất **5 tiếng** chẩn đoán ca Ahrefs chỉ vì chúng tồn tại mà không đọc được.
  - **Thao tác vận hành BẮT BUỘC khi deploy:** `goodbot_seed` **chỉ ghi, không bao giờ xoá** ⇒ gỡ tên khỏi JSON không xoá khoá Redis. Phải `redis-cli DEL goodbot:dns:ahrefsbot`, nếu không Path 1c vẫn bị chặn đường.
  - **Lệnh cấm ĐÚNG trong cùng mẫu (đừng gỡ):** MJ12bot có PTR `ns3139286.ip-51-77-216.eu` (OVH thuê chung — MJ12 là crawler phân tán chạy nhờ máy tình nguyện nên **về bản chất không xác minh được**); DotBot, ads-txt-crawler, nhóm `216.73.216-217.x`, `172.204.96.49` đều **không có PTR**.
  - **`74.7.0.0/16` là mạng cào:** 5 IP mang UA trình duyệt Mac không PTR, **cùng /16** với hai IP khai "GPTBot" ở cloud183-139 (cũng không PTR). Một mạng vừa giả GPTBot vừa giả trình duyệt ⇒ giữ nguyên lệnh cấm.
- 2026-08-04 — **Amazonbot vào registry (`goodbot.json` + lớp `aggressive`). Đối lập có chủ đích với quyết định Petal/Baidu.**
  - **Vì sao ĐƯỢC nhận trong khi Petal/Baidu bị từ chối:** cơ chế xác minh khác hẳn. Registry dùng **DNS hai chiều** — PTR phải kết thúc `crawl.amazonbot.amazon` **và** bản ghi A của chính tên PTR đó phải chứa lại IP nguồn. Muốn giả mạo phải kiểm soát reverse DNS của dải IP, tức sở hữu uỷ quyền từ RIR ⇒ **không giả được**. Petal/Baidu thì cổng là **ASN dùng chung** (Huawei Cloud bán lẻ, China Unicom backbone) ⇒ giả được bằng cách thuê VM. **Tiêu chí luôn là tính giả mạo được của bằng chứng, không phải danh tiếng của bot.**
  - **Vì sao trước đó nó trượt hết mọi đường:** không có trong registry ⇒ `good_bot_suffixes={}` ⇒ `dns_reverse` chắc chắn trượt; `contact_attest` trượt vì **lệch TLD** — URL liên hệ `developer.amazon.com` (eTLD+1 `amazon.com`) vs PTR eTLD+1 `amazonbot.amazon` (Amazon sở hữu gTLD `.amazon` riêng); `cloud_suffixes.lua` chỉ có `amazonaws.com`. Kết quả: `fake_good_bot` bot_score 0.85 → score ~216-284 → block → ban vĩnh viễn.
  - **Đánh đổi đã chấp nhận:** S4 ⇒ engine short-circuit ⇒ **bỏ qua chấm điểm hoàn toàn** (anomaly/behavior/cluster/graph mất tác dụng). Phanh còn lại là `throttle_good_bot` (URL đắt tiền) + `throttle_good_bot_rate`. Đặt `amazonbot = "aggressive"` (30/phút) vì nó gần như không sinh truy cập giới thiệu cho site tiếng Việt.
  - **KHÔNG nới `contact_attest` cho brand gTLD** (quy tắc: TLD của PTR trùng nhãn đăng ký của domain liên hệ). Đó là sửa cơ chế tổng quát cho đúng **một** ca quan sát được. Để dành tới khi gặp bot thứ hai cùng cảnh ngộ.
  - **GPTBot chưa quyết:** `74.7.227.147/148` **không có PTR** ⇒ không cơ chế DNS nào phân biệt thật/giả. Xác minh GPTBot cần đối chiếu dải IP JSON do OpenAI công bố — cơ chế hệ thống chưa có. Tạm giữ nguyên (chặn).
- 2026-08-02 — **`fleet`: Baiduspider (AS4837 CHINA UNICOM) — CỐ Ý KHÔNG miễn trừ, cùng lý do PetalBot. Đừng đào lại.**
  - **Quan sát:** `fleet_dyn_block_24:116.179.37.0/24` = **6.240 lượt/ngày**, khối chặn fleet lớn nhất đo được. PTR **6/6** khớp `baiduspider-*.crawl.baidu.com` ⇒ Baiduspider thật.
  - **ASN là AS4837 `CHINA169-Backbone — CHINA UNICOM`** — **xương sống quốc gia**, KHÔNG phải ASN của Baidu. Thêm nó vào `GOOD_CRAWLER_ASN` sẽ miễn fleet cho gần như toàn bộ Internet tiêu dùng Trung Quốc — tệ hơn cả AS136907 Huawei Cloud.
  - **NGUYÊN TẮC RÚT RA (áp cho mọi đề nghị miễn trừ crawler về sau):** cổng ASN của `is_good_crawler` chỉ dùng được khi **ASN thuộc riêng về chủ crawler** — lúc đó kẻ giả mạo UA không thể phát gói từ đó, cổng kín. Google/Bing/Meta/Apple/CocCoc thoả. Petal (cloud bán lẻ) và Baidu (backbone ISP) **không thoả**. Tiêu chí là **tính giả mạo được của ASN**, KHÔNG phải giá trị SEO của bot.
  - Muốn cho qua thì cơ chế đúng là **miễn theo CIDR**, chưa tồn tại trong `fleet/`; và vài mẫu PTR không đủ chứng minh sở hữu trọn một /16.
- 2026-08-02 — **`fleet`: PetalBot (AS136907 HUAWEI CLOUDS) đã cân nhắc và CỐ Ý KHÔNG miễn trừ. Không sửa code. Đừng đào lại.**
  - **Quan sát:** trên server thứ hai, `fleet_dyn_block_16:114.119.0.0/16` chặn **151 lượt/giờ**, toàn PetalBot (UA `Android 7.0 … (compatible; PetalBot;+http…)`). PTR **8/8** khớp `petalbot-*.petalsearch.com` ⇒ **bot thật, không phải UA giả**. Cùng lúc, PetalBot từ dải khác vẫn nhận `contact_ptr_match` bình thường ⇒ cơ chế S2.5 không hỏng.
  - **Cơ chế:** `fleet/check_block.lua` chạy trong `STEPS_COMMON`, còn `contact_attest` nằm trong `detection/bot` — **sau nó rất xa**. /16 đã gắn cờ thì mọi tầng xác thực phía sau **không có cơ hội chạy**. Đây là lý do cùng một bot ra hai kết cục trái ngược trên hai server: máy nào lỡ tích đủ điểm fleet thì chặn, máy kia tha.
  - **Vì sao KHÔNG áp khuôn Meta:** vụ Meta chạy được nhờ **AS32934 là ASN riêng của Meta** — kẻ giả mạo UA không phát gói từ đó được, nên cổng ASN **không giả được**. AS136907 là **cloud bán lẻ công cộng**, tệ hơn cả cảnh báo AS8075/Azure viết sẵn ở `fleet/trusted.lua:30-34`. Miễn trừ nó ⇒ **bất kỳ ai thuê VM Huawei Cloud và nhét chữ `bot` vào UA đều thoát tầng fleet**, mà nhét chữ vào UA thì miễn phí. Đổi một crawler khỏi bị chặn ngắt quãng lấy lỗ hổng cỡ nguyên một public cloud = không tương xứng.
  - **Ba bất đối xứng nữa so với Meta:** (1) **không có block nào đang chạy** — `fl:dyn:*` rỗng, `fl:score:16` = **0.681** dưới ngưỡng confirm 0.7, tức chặn ngắt quãng chứ không liên tục như Meta (105/105); (2) Meta chặn thì mất link preview khi người dùng chia sẻ — hữu hình; Petal Search thị phần VN gần như bằng không; (3) PetalBot là crawler nặng — server cũ đo **23.125 lượt/ngày** qua `contact_ptr_match`, là tải PHP-FPM+MySQL thật đổi lấy lượng giới thiệu gần bằng không. Nhiều chủ site chặn PetalBot có chủ đích.
  - **Bẫy đã tránh:** `TTL fl:dyn:114.119.0.0/16` = `-2` nghĩa là **khoá không tồn tại** (đã hết hạn theo TTL 3600s), không phải "khoá vĩnh viễn". Đề xuất `redis-cli DEL` ban đầu là vô nghĩa — vấn đề là **tái phát** khi điểm vượt 0.7 và giữ ≥5 phút, không phải trạng thái hiện tại.
  - **Điều gì sẽ đổi kết luận:** nếu sau này cần cho PetalBot qua, cơ chế đúng là **miễn theo CIDR** (hẹp hơn ASN nhiều), KHÔNG phải thêm ASN. Nhưng `fleet/` chưa có cơ chế đó, và 8 mẫu PTR **chưa đủ** chứng minh Petal sở hữu trọn một /16 có 65.536 địa chỉ — phải đo rộng hơn trước.
- 2026-08-02 — **`wp_hardening.lua`: đường thoát cứng giờ có TRÍ NHỚ (`escalate()` → `ban:<ip>`).**
  - **Triệu chứng:** `xmlrpc_ua_reject` **23.007 lượt/ngày**. Hai ngày liên tiếp, mỗi ngày một nguồn khác (2026-08-01 `203.2.114.122` → 2350 lượt/giờ; 2026-08-02 `43.139.153.132` + `1.12.55.42` → 93,7% của 1818 lượt/2h). Ban tay mỗi ngày là chạy theo đuôi.
  - **KHÔNG phải bỏ sót — code chặn 100% số request đó.** Thiếu là trí nhớ giữa các request. Ba cơ chế sẵn có đều không khép được vòng:
    1. `ngx.exit(444)` ở tầng **detection** ⇒ `enforcement/ban/ban_store_write` (nơi DUY NHẤT ghi ban từ đường chấm điểm) **không bao giờ chạy** ⇒ không ban, không tăng `viol:`, không có thang leo TTL.
    2. `async/risk_update` có thể nâng `ip_risk:<ip>`, nhưng nơi ĐỌC nó là `engine.lua` — cũng không chạy vì đã exit. Attacker chỉ đánh `xmlrpc.php` nên **mọi** request đều thoát sớm ⇒ vòng phản hồi không bao giờ khép.
    3. Rate limit không chạm: đo được **7,2 lượt/phút** mỗi IP — cố tình chậm, dưới mọi ngưỡng.
  - **Bất đối xứng trong chính file:** `ZONE_LOGIN` đã có bộ đếm `wp_login_notc:<ip>` (2 lần/30s), `ZONE_XMLRPC` thoát ngay lần đầu **không đếm gì**.
  - **Fix:** `escalate_xmlrpc(ctx)` — `hardexit:xmlrpc:<ip>` cửa sổ **3600s**, **20 strike** → `ban:<ip>` 24h. Ngưỡng chọn theo tốc độ THẬT: cửa sổ 300s chỉ tích ~36 lượt nên không đủ tin cậy; 1 giờ + 20 strike ⇒ khoá sau **<3 phút**. Sau ban, request kế thoát ở `l7/ban/ip_ban_check` (module thứ 6) thay vì đi hết ~15 module.
  - **ĐIỂM MÙ cần biết — `wp_hardening` thoát TRƯỚC ba module tổng hợp.** Thứ tự trong `detection/init.lua`: `bot(21) → anomaly(25) → behavior(29) → session(33) → wp_hardening(41) → distributed_swarm(48) → cluster(50) → graph(54)`. Mọi POST `/xmlrpc.php` bị `ngx.exit(444)` ở bước 5 ⇒ **`distributed_swarm`, `cluster`, `graph` KHÔNG BAO GIỜ chạy** cho traffic này, counter của chúng không ghi nhận một lượt xmlrpc nào. Đừng trông chờ ba module đó bắt tấn công xmlrpc phân tán. Thứ phủ được trục /24 là **`fleet`** — nó chạy trong `STEPS_COMMON`, trước ngã rẽ lớp, nên thấy cả request sẽ bị 444 (bằng chứng: `fleet_dyn_block_24`/`_16` trong log). "Rotate UA" cũng không giúp kẻ tấn công: luật xét **nội dung** UA, không xét tần suất.
  - **CHỈ áp cho zone xmlrpc, cố ý KHÔNG dùng chung với zone login.** Ngưỡng này suy ra từ tốc độ tấn công xmlrpc đo được; `wp-login.php` có bề mặt FP rộng hơn hẳn (người dùng thật xoá cookie, trình duyệt chặn cookie bên thứ ba) và **chưa có dữ liệu riêng**. Dùng chung một ngưỡng cho hai bề mặt khác nhau là đoán mò — muốn áp cho login thì đo trước.
  - **Mở rộng phạm vi chặn:** 444 chỉ chặn riêng endpoint, ban khoá IP trên MỌI domain. Chấp nhận vì luật xmlrpc đã là near-zero FP (client hợp lệ luôn có `wordpress`/`jetpack` trong UA nên không vào tới đây) và còn phải lặp 20 lần. Giữ miễn trừ `ip_shared_verified`.
- 2026-08-01 — **Hai nghi vấn FP được KIỂM TRA rồi BÁC BỎ. Không sửa gì. Đừng đào lại.**
  - **`ip_tour.lua:216` ghi `ban:<ip>` mà thiếu miễn trừ `ip_shared_verified`** — nghe như lỗ hổng FP, thực ra **không thể xảy ra**: cổng NAT ở dòng 173 `return` khi `uas >= distinct_ua_max (3)`, còn `ctx.ip_shared` (điều kiện cần của `ip_shared_verified`) đòi `uas >= shared_ua_min (6)` ở dòng 144. Luồng tới được nhánh ban thì `ip_shared_verified` **luôn false**. Thêm guard = code chết. Cổng NAT đã chặt hơn chính lá chắn định thêm.
  - **`browser/entropy.lua:11` gán `ctx.entropy = 0.1` khi beacon về mà thiếu trường `ent`** → đủ kích `headless_ent` (+0.45 = 24,75đ qua `mismatch`). Bẫy có thật về mặt code, nhưng **đo được: `headless_ent` bắn 1 lần/10 phút, 4 lần/2 giờ**. Không đáng sửa. Đường thứ hai tới `0.1` là `collect_request.calc_header_entropy()` khi request có **< 3 header** — UA khai trình duyệt đầy đủ mà chỉ gửi 2 header thì phạt là đúng.
  - **Vẫn là nợ kỹ thuật thật:** `ctx.entropy` bị **hai module ghi với hai ý nghĩa khác nhau** (entropy của header vs entropy từ beacon), cùng một thang đo `[0,1]` nên không ai phát hiện. Nếu sau này `headless_ent` tăng đột biến, đây là chỗ nhìn đầu tiên.
- 2026-07-31 — **Shared-session-key guard — chặn ~38 điểm FP từ phiên bị TRỘN** (`session/session_store.lua` + `intelligence/scoring/compute.lua` + `core/config.lua _M.session_shared` + `async/logger.lua`).
  - **Chữ ký nhận dạng:** nhiều người trong cùng một văn phòng/IP bị điểm cao bất thường, `top=` có `graph_flag` và/hoặc `session_flag` đứng đầu, nhưng KHÔNG có signal cấu trúc per-request (h2/ja3/ua/anomaly). Log mới: `sclients=` cao (≥4) trên cùng một `id=`.
  - **Gốc rễ:** `sess:<fp_light>` là khoá của cả session lẫn graph, mà `fp_light = md5(ip + ua_thô + asn + ja3 + h2_sig)` — **toàn thuộc tính (mạng + trình duyệt)**, không có gì thuộc về *cá thể máy*. Văn phòng dùng image đồng nhất (cùng IP, cùng bản Chrome; `ja3` luôn = `NO_JA3` ở kiến trúc no-stream; `h2_sig` do bản build trình duyệt quyết định) → mọi máy **collapse về một `fp_light`** → session của N người bị trộn thành một danh sách URI. `graph/pattern_detect.detect_loop` bắn **0.9** khi một URI lặp ≥4 lần trong 10 request cuối — phiên trộn **luôn** thoả → `graph_flag` 18 điểm + `session_flag` tới 20 điểm = **~38 điểm thuần FP**. Đây là phần lớn `raw 53.6` của sự cố admin kjab/kjob (xem `enforcement/CLAUDE.md` 2026-07-06).
  - **Bộ dò:** HLL `sess:ck:<fp_light>` PFADD `md5(Cookie header)` → `ctx.sess_clients` = số cookie-set khác nhau cùng dùng một khoá phiên. `>= cfg.session_shared.clients_min (4)` → `ctx.sess_shared = true`. Append **cuối** pipeline sẵn có nên không dịch index `res[4]`/`res[5]`.
  - **KHÔNG dùng `ctx.ip_shared`** được — nó là `distinct-UA >= 6` (`ip_tour.lua:144`), mà văn phòng đồng nhất chỉ có **1 UA** → không bao giờ fire. Nó dò IP chia sẻ *đa dạng thiết bị*, đúng ngược ca này.
  - **Không tạo FN:** bot fleet dùng chung `fp_light` thường không gửi cookie → `md5("")` giống nhau → `sess_clients = 1` → signal vẫn chạy. Và mọi signal per-request (anomaly/h2/mismatch/bot_score) + per-IP/subnet (cluster/swarm/fleet/ip_tour) **không bị đụng tới**.
  - **Zero chứ không giảm nhẹ:** pattern rút từ phiên trộn là *vô nghĩa*, không phải *nhiễu*. Tắt = `cfg.session_shared.enabled = false`. Hiệu chỉnh ngưỡng: `grep -oP 'sclients=\d+' antibot.log | sort -n | uniq -c`.
  - **Đây là Bước 1** của hướng sửa gốc "identity per-device". Bước 2 (cookie ngẫu nhiên ký HMAC nuôi cả `identity` lẫn `fp_light`) chưa làm — xem `core/CLAUDE.md` 2026-07-21.
  - **⚠️ 2026-07-31 — ĐO THỰC TẾ BÁC BỎ GIẢ THUYẾT, đã set `enforce=false`.** 55k request: `sclients=1` chiếm 97.5%, chỉ **19 request (0.034%)** có `>=4`. Bảng top-signal: **`graph_flag` KHÔNG xuất hiện lần nào**, `session_flag` chỉ 0.8% (439/55k). Tiền đề "phiên trộn sinh ~38 điểm FP" **sai** trên traffic này — giả định "văn phòng image đồng nhất" chưa được chứng minh bằng dữ liệu.
    - **Bộ dò có chế độ hỏng:** site set cookie mới mỗi response → Cookie header đổi giá trị → `sclients` tăng **1 mỗi request cho CÙNG một client** (quan sát: 1 `id`, 1 IP, 17 giây, `sclients` 4→5→6→7→8, `richness` bò 0.40→0.50 cùng lúc). Không phải nhiều người.
    - **Gây FN thật:** bot Chrome/60 Android 7 (`richness=0.00`, `score=125.8`, block) đạt `sclients=7` → `session_flag`+`graph_flag` bị zero cho chính con bot đó.
    - **Trạng thái:** `enabled=true` (giữ đo, 3 op trong pipeline sẵn có) + `enforce=false` (không tác động điểm). Bật lại chỉ khi có bằng chứng phiên trộn thật VÀ bộ dò miễn nhiễm cookie-churn (ví dụ hash tên cookie thay vì giá trị, hoặc đếm distinct `id` thay vì cookie-set).
    - **Nơi FP thật sự nằm (từ cùng bộ dữ liệu):** `h2_bot_confidence` 14 632 + `mismatch` 12 927 = **~50% toàn bộ top-signal**, cả hai **trọng số 55** và cùng bắn trên một điều kiện gốc (UA khai Chrome/Firefox nhưng `h2_is_h2 == false`) → cộng dồn tương quan tới 110 điểm cho MỘT quan sát. Kèm dấu hiệu `ja3=-`, `tls13=nil`, `fp_quality=0.40–0.60` trên mọi dòng → tầng transport đang cấp dữ liệu suy giảm cho đúng 2 signal nặng nhất. **Đây mới là mục tiêu sửa tiếp** (instrument trước, không sửa mù).
- 2026-07-04 — **`ip_tour.lua` NEW — cross-domain shared-hosting tour detector**. Targets operator-confirmed attack: a few bot IPs "tour" across many tenant domains on the shared host, each domain at MODERATE req/s (occasionally hitting wp-admin/login), so per-IP `ip_surge` and per-(IP,domain) `burst` are both blind while aggregate PHP-FPM+MySQL load spikes. Antibot's structural advantage: all tenant domains funnel through one OpenResty+Redis → a single IP's distinct-domain count is visible here, which no per-site WAF can see.
  - **Signal, not hard block**: sets `ctx.ip_tour`. Enforcement decided in `enforcement/decision/engine.lua` AFTER `good_bot_verified` short-circuit → verified crawlers (Googlebot/Bingbot legitimately crawl every domain) exempt automatically, no per-bot config. Engine floors `ip_tour` → `challenge` (challenge-first) before trust cap.
  - **Discriminators (all must hold)**: `distinct_domains ≥ cfg.ip_tour.distinct_domains` (touring) AND `distinct_ua < distinct_ua_max` (single-source — NAT gate: office/CGNAT hitting many domains ALSO carries many UAs; identity not available this early so distinct-UA is the proxy) AND `session_richness < richness_max` (logged-in multi-site admin exempt). distinct-domain is a CARDINALITY not a request count → a real user on ONE site for hours stays at 1 → zero FP on long sessions.
  - **Ban-if-repeat**: each flagged request increments `iptour:strike:<ip>`. Real user solves PoW → verified cookie → cookie fast-path → never re-enters → strikes stop. Bot can't solve → strikes cross `strike_ban` → direct `ban:<ip>` (sealed at door by `l7/ban/ip_ban_check` on every domain). Direct-ban gated on NOT `ua_claims_good_bot` (claimers go through DNS-verify/scoring, never hard-banned here). TTL escalates via `iptour:age:<ip>` (300s first → 3600s repeat).
  - **Storage** (Redis HLL, same primitive as `distributed_swarm`): `iptour:dom:<ip>` PFADD host, `iptour:ua:<ip>` PFADD md5(ua), `iptour:strike:<ip>`, `iptour:age:<ip>`. One pipeline/request (6 ops, 1 RTT), fail-open. Config `cfg.ip_tour` (core/config.lua). Signal registered in `intelligence/scoring/compute.lua` (`ip_tour=25`). Complements `distributed_swarm` (orthogonal axis) + `fleet` (per-/24) — none previously counted distinct-domain-per-IP.
- 2026-05-23 — **`session/session_store.lua` IP-level resource_starved gating** — before setting `ctx.resource_starved=true`, read `res_ip:<ip>` (populated by new `l7/rate/res_ip_counter.lua` running in `STEPS_RESOURCE`). If `res_ip >= 5` → suppress signal (IP đang load resource thật, signal sai semantic). Threshold 5 chọn để 1 stray hit từ user khác trên NAT không giải vây cho bot — giảm FN risk shared-NAT khi mix bot+human traffic. Root cause cũ: resource class skip fingerprint → res_count tracked per identity LUÔN = 0 cho mọi browser → signal fire oan. Fix FP cho WordPress admin install (Flatsome theme, tuart.xuongweb.com). New log markers: `resource_starved suppressed (ip has res activity)` (gating thắng), `resource_starved ... res_ip=X` (fire thật). See `version.txt` 2026-05-23 + `l7/CLAUDE.md`.
- 2026-05-24 (v4.4.7) — `bot/ua_check.lua` — **unregistered_bot path: thêm `ctx.good_bot_asns = get_bot_asns(bot_name)`**.
  - Root cause: khi Redis không có `goodbot:dns:<name>` (seed chưa chạy / transient flush), code rơi vào `unregistered_bot` branch. Branch này set `ctx.good_bot_suffixes={}` nhưng KHÔNG set `ctx.good_bot_asns`. `asn_fallback_verify()` trong `bot/init.lua` check `ctx.good_bot_asns` → nil → return false → bot bị classify là fake. Mất fallback path dù AS15169 đã hardcode trong PTR_ONLY_BOTS.
  - Fix: gọi `get_bot_asns(bot_name)` (đọc từ PTR_ONLY_BOTS trước, Redis sau) và gán vào `ctx.good_bot_asns` trong cả hai branch.
- 2026-05-19 (v2) — `bot/init.lua:contact_attest` Path 1b — fall back to cloud-PTR check when PTR doesn't match contact URL eTLD+1 (Pingdom-on-AWS case). Same S2.5 reward but new reason `contact_cloud_attested`. Single function edit.
- 2026-05-19 — **S2.5 attest tier** in `bot/init.lua`:
  - 2 new helpers `contact_attest()` (Path 1) + `analyzer_attest()` (Path 2) — both grant `ctx.bot_identity_tier="S2.5"` and set `ctx.skip_layers.cluster/graph = true` (cascade prevention)
  - `ua_check.lua` populates `bot_ua_compliant`, `bot_contact_host`, `browser_ua_pattern`, `analyzer_marker` up-front before headless/bot-claim branches
  - `bot_score.lua` honors `ctx.bot_identity_tier=="S2.5"` (returns bot_score=0, skips ua_flag escalation that would re-raise it)
  - `dns_reverse.lua:lookup_ptr(ip)` exported for Path 2 (called when good_bot_claimed=false)
  - `cloud_suffixes.lua` (new) — hardcoded `CLOUD_PTR_SUFFIXES` + `BROWSER_STANDARD_TOKENS` blacklist for marker regex
- `72f0415` (2026-05-03) — no changes here, Phase 1 only touched l7/
- 2026-05-04 — `distributed_swarm.lua` class-aware thresholds (Option C):
  - navigation `25/45` (relax — VN popular product flash crowd OK)
  - auth_endpoint `8/15` (tighten — credential stuffing protection)
  - api_callback `12/25`, feed_or_meta `45/90`, interaction `20/35`
  - inapp_browser `20/35`, unknown `15/30` (legacy default)
  - Weight `swarm_attack = 120` GIỮ NGUYÊN — không thay đổi scoring math
  - Logs include `class=` + threshold values for tuning per-class
  - Fix: VN e-commerce popular product page bị block khi 30 /24 cùng UA Chrome browse simultaneously (organic flash crowd ≠ swarm bot)
