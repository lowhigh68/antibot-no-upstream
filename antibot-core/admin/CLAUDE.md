# admin/

Web UI + JSON API for runtime introspection. Mounted at `/antibot-admin` in hostname.conf only (Basic-auth + IP allowlist).

## Purpose
Operator visibility: ban list, ip_risk top, signal weights, recent decisions, manual override (unban, set goodbot, change weight).

## Files

| File | Role |
|---|---|
| `init.lua` | Single-file router. HTML/JS embedded as Lua long-string (`[[ ... ]]`). Routes: `/` (dashboard), `/api/stats`, `/api/bans`, `/api/unban`, `/api/goodbot`, `/api/weights`, `/api/recent` |

## Auth
Hardcoded in `init.lua`:
- `AUTH_USER`, `AUTH_PASS` — Basic-auth
- IP allowlist enforced in nginx server block before `content_by_lua_block`:
```nginx
location ^~ /antibot-admin {
    access_by_lua_block {
        local allowed = { ["192.168.168.114"]=true, ["14.191.162.213"]=true, ["127.0.0.1"]=true }
        if not allowed[ngx.var.remote_addr] then ngx.exit(403) end
    }
    content_by_lua_block { require("antibot.admin").router() }
}
```

## ctx fields read
None (admin endpoint, separate from request pipeline)

## Redis keys read/written
Reads: `ban:*`, `ip_risk:*`, `viol:*`, `goodbot:*`, `weights:*`, `verified:*`, recent decisions
Writes: same (manual override)

## Flow
```
Operator browser → https://<hostname>/antibot-admin/
  ↓ Basic-auth + IP check
content_by_lua → admin.router()
  ↓ dispatch URI to handler
respond JSON or HTML
```

## Important rules
- AUTH_USER/AUTH_PASS hardcoded — DON'T log or rotate casually
- IP allowlist hardcoded in nginx conf — update when admin IP changes
- Endpoint NOT mounted on per-domain confs — only hostname.conf (so attacker can't probe via random vhost)
- Modifications via API mirror Redis writes — same TTL/key conventions as core code

## Update log
- 2026-08-31 — **`SCAN_COUNT` 1000→10000, bỏ tab Intelligence, gỡ ASN Type Overrides, sửa ô ASN luôn=0** (`init.lua`).
  - **Ba máy CÙNG DỮ LIỆU hiện ba kết quả KHÁC NHAU.** Bảng "Good Bot DNS Registry" ra 18 / 17 / 15 mục trong khi Redis có đủ **41 trên cả ba** (`EXISTS goodbot:dns:<tên>` = 1 với mọi tên). Các tập con còn chồng chéo lộn xộn: máy A có `googlebot-video` mà không có `googlebot`, máy B ngược lại. Gốc: `scan_keys` `break` ở `iter >= SCAN_MAX_ITER` ⇒ trần phủ `1000 × 100 = 100.000` khoá, trong khi `DBSIZE` đo được **250.647 / 259.071 / 317.756**. Bảo đảm "mọi khoá đều được trả về ít nhất một lần" của Redis SCAN **chỉ có hiệu lực khi chạy hết tới `cursor == 0`** — cắt sớm là tự bước ra ngoài cam kết; ngoài cam kết thì `bucket = hash(tên) & (cỡ_bảng − 1)` mà bảng băm co giãn theo tổng số khoá (2^18 với 250k, 2^19 với 318k) nên cùng một tên rơi vào bucket khác trên mỗi máy. **Nâng `COUNT` chứ không nâng `MAX_ITER`**: cùng khối lượng duyệt keyspace nhưng ~32 round-trip thay vì ~318, trần phủ 100.000 → 1.000.000. KHÔNG ảnh hưởng xử lý request — đường xác minh đọc đích danh (`detection/bot/ua_check.lua:100`), không quét.
  - **Cờ `truncated` giờ có người đọc.** Trước đó chỉ 2/13 nơi gọi `scan_keys` đọc nó (`ban_keys`, `verified_keys`), phần còn lại cắt xong im lặng — đó là lý do lỗi sống được lâu. Thêm `wl_capped` / `goodbot_capped` / `ja3_capped` + hàm JS `caprow()` chèn dòng ⚠ vào đầu bảng. `wl:*` là cái nguy hiểm nhất trong nhóm: `wl:` là miễn trừ toàn phần mà bảng soát chỉ hiện ~40% sự thật.
  - **Gỡ hẳn "ASN Type Overrides"** (action `asn_type_set`/`asn_type_del`, `scan_keys(asn:type:*)`, `asn_types` trong payload, HTML + JS). Khoá `asn:type:<n>` chảy vào `ctx.ip_net_type` rồi **dừng ở đó** — không module nào đọc, vì `core/fingerprint/ip_classify.lua:113` ghim `ctx.ip_score = 0.0`. Tệ hơn vô dụng: admin ghi **không TTL**, mà `threat_feed_sync.sh:251` `continue` khi thấy `asn:type:` tồn tại, và `continue` đó nhảy qua **cả dòng ghi `rep:asn:`** ngay dưới — nên đánh dấu tay một ASN là "datacenter" lại **gỡ mất** hình phạt datacenter (`asn_rep`, trọng số 35). Ba nhu cầu khai báo ASN có thật (`MANUAL_OVERRIDE_RESIDENTIAL`, `VN_DATACENTER_ASNS`, `goodbot:asn:`) đều đã giải bằng hardcode đi qua git; không cái nào dùng `asn:type:`.
  - **Tab Intelligence biến mất, 9 tab → 8.** "Good Bot DNS Registry" + "JA3 TLS Fingerprint" chuyển sang tab `sync`, đổi tên thành **📡 Feed & Registry** — cả ba khối cùng bản chất "dữ liệu nạp từ ngoài vào Redis". `showTab` hoàn toàn generic nên gỡ cặp tab/pane là an toàn.
  - **Ô "ASNs Loaded" luôn hiện 0 là LỖI, không phải số liệu vô nghĩa.** Đọc `obj.asn`, mà `threat_feed_sync.sh:365` ghi ra `{"ip":…,"asn_rep":…,"asn_type":…}` — không có trường `asn` ⇒ `or 0`. Sửa thành `obj.asn_rep`, đổi nhãn "ASN Reputation" + chú thích ngưỡng. Giá của việc để nó hỏng: cùng ngày phát hiện hai máy chạy `threat_feed_sync.sh` đời cũ chỉ nạp **27** ASN thay vì **53.610** — `asn_rep` gần như mù nhiều ngày; nếu ô này chạy đúng thì đã lộ ra trong một cái liếc thay vì phải lần từ log.
- 2026-07-05 — **Bans tab reworked — grouped IP→identity + per-level Unban/Whitelist** (`init.lua`). Replaced the two disconnected tables (banned IPs / banned identities) with ONE tidy table grouped by IP: an IP group-header row (IP, risk, TTL, ACTIVE/IDLE, [Unban IP][Whitelist IP]) followed by its banned identities (↳ id, device, risk, TTL, [Unban][Whitelist]). Identities whose ban_ctx has no IP group under `(unknown)`. New API action `wl_id` (SET `wl:id:<id>` persistent + clear ban/risk/viol/ban:age) + new JS `whitelistId()`. Identity-whitelist is enforced in `l7/ban/ban_store.lua` (checks `wl:id:<id>` in the same pipeline as `ban:<id>` → sets `ctx.whitelisted`, bypass). NOTE: the ban-action fetch URLs are `/antibot-admin/wl` (Read/Grep may mis-render the forward slashes as backslashes — the bytes are correct).
- 2026-07-05 — **Device pane → "Client Distribution" + Intent relabel** (`init.lua`). Device table now 6 groups (Browser·Desktop/Mobile/Tablet, Crawler, Tool, Unknown) via new `crawler`/`http_client` device types (`core/fingerprint/device_classifier.lua`) — the old `unknown` (largest bucket) drains into Crawler/Tool, leaving `unknown` = browser-shaped-unclassified (small, actionable). Intent buckets relabelled: `good_bot`→`goodbot` (label "Good bot"), `bot`→"Bad bot", `ambiguous`→`watch` (label "Watch"). Renaming good_bot→goodbot removes the only underscore in intent/group names, fixing the pre-existing `%w+` stat-parse bugs (`^intent_(%w+)$`, `^ibd_(%w+)_(%w+)$`) that silently dropped every good_bot count (Good Bot row + device Human% always undercounted). `GROUP_ORDER` reordered browsers-first. Backend `intent_stats`/`intent_by_device` keys + JS `renderDevices` icons/labels + intent `imap` updated. Data model changed → operator clears `stat:*` for a fresh baseline (dashboard reads today's keys only, so it self-heals within a day regardless).
- 2026-06-19 (later) — **Subnet Blocks tab REMOVED, Fleet Detection tab ADDED** (`init.lua`). Old `🛡️ Subnet Blocks` tab + its data path removed alongside `core/access/subnet_block.lua` deletion. New `🎯 Fleet Detection` tab shows: mode (shadow/scoring/enforce), /24 candidates with 3-axis breakdown (fp_poverty, path_convergence, cookie_vacuum) + status (suspect/confirm), /16 roll-up flags, dynamic block list (enforce mode). Reads `fl:flag:24:*`, `fl:flag:16:*`, `fl:dyn:*` + score/axis/last keys via existing `scan_keys` helper. See `antibot-core/CLAUDE.md` 2026-06-19 (replace operator-driven CIDR list) for the detection model.
- 2026-06-19 — **Subnet Blocks dashboard tab** added then removed same day (see entry above).
- `72f0415` (2026-05-03) — no changes
