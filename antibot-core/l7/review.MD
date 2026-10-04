# Review layer L7

## Lần review 1 — Luồng admission, rate/burst, resource lane và khả năng chống tăng tải đột biến

Ngày review: 2026-10-04  
Phạm vi chính: toàn bộ module trong `antibot-core/l7`, các điểm gọi L7 trong
`antibot-core/init.lua`, cùng những dependency trực tiếp quyết định class và
verdict (`core/req_classifier.lua`, `core/session_richness.lua`,
`detection/bot/lite_verify.lua`, scoring và decision engine).

### Kết luận ngắn

L7 hiện có cấu trúc module khá rõ và đã làm được ba việc hữu ích: kiểm tra ban,
phát sinh tín hiệu rate/burst, và bảo vệ riêng kiểu truy vấn faceted-filter tốn
kém. Tuy nhiên, nó **chưa phải một lớp admission/load-shedding đáng tin cậy**.
Phần lớn rate/burst chỉ tạo tín hiệu cho scoring; nhiều class sau khi nhân hệ số
vẫn chỉ ra `monitor`, nghĩa là request vẫn tới Apache/PHP. Nghiêm trọng hơn, hai
cửa `verified` và `resource` có thể bỏ qua toàn bộ `l7_layer`, trong đó class
`resource` lại có thể được chọn bằng header do client tự gửi.

Do đó hiện tượng request bẩn lọt vào backend và làm tải tăng vọt là phù hợp với
logic đang chạy. Đây không phải thiếu thêm vài signature tấn công; gốc vấn đề là
L7 đang hoạt động giống **nguồn tín hiệu cho anti-bot** hơn là **cửa kiểm soát tài
nguyên bắt buộc trước backend**.

### Những phần đang hợp lý

- Tách `counter`, `adaptive_limit`, `burst_counter`, `burst_decision` và ban
  store giúp thay thuật toán từng phần mà không phải viết lại toàn luồng.
- IP ban được đặt trong `STEPS_COMMON`, sớm hơn các bước phân tích đắt tiền.
- `expensive_filter_guard.lua` dùng bucket thời gian cố định và đếm distinct
  combination theo resource; hướng này đúng cho distributed faceted crawl mà
  per-IP rate không bắt được.
- Nhánh hard-ban của `adaptive_limit.lua` đã tránh ban IP reverse proxy và dùng
  TTL ngắn, giảm blast radius khi phán đoán sai.
- Các module Lua trong `l7/` đều qua được kiểm tra cú pháp bằng OpenResty/WSL.

Các điểm trên đáng giữ lại, nhưng hiện bị các cửa bypass và semantics counter
làm giảm mạnh hiệu quả thực tế.

### 1. Critical — Client có thể tự đưa request động vào lane `resource`

`core/req_classifier.lua:426-450` trả về `resource` trước khi kiểm tra auth
endpoint. Hai điều kiện được tin trực tiếp là:

- URI kết thúc bằng extension ảnh/font;
- `Sec-Fetch-Dest` bằng `image`, `script`, `style` hoặc `font`.

Đây đều là dữ liệu client kiểm soát. Đặc biệt, `Sec-Fetch-Dest` không phải bằng
chứng server-side và curl/bot có thể gửi tùy ý. Test OpenResty xác nhận:

```text
POST /wp-login.php
Sec-Fetch-Dest: image
Content-Type: application/x-www-form-urlencoded

=> req_class = resource
```

Test thứ hai cũng xác nhận `/index.php/expensive.jpg` được xếp `resource` chỉ vì
đuôi URI. Với cấu hình Nginx hiện tại, static candidate không tồn tại có thể
fallback sang Apache, nên “trông giống file tĩnh” không đồng nghĩa “không dùng
PHP”.

`antibot-core/init.lua:108-120` cho lane `resource` chỉ chạy:

1. `res_ip_counter`;
2. `bot_lite_verify`;
3. intelligence;
4. enforcement.

Nó không chạy fingerprint, `l7_layer`, detection đầy đủ, rate limit hay burst
limit. `res_ip_counter` chỉ nuôi heuristic `resource_starved`, hoàn toàn không
throttle. `expensive_filter_guard` cũng bỏ qua resource ở dòng 96. Vì vậy một
header giả có thể đồng thời bỏ qua L7 và expensive-filter guard.

Hướng sửa:

- `resource` chỉ được xét cho `GET`/`HEAD`; mọi `POST`, `PUT`, `PATCH`, `DELETE`
  không bao giờ được vào lane này.
- `Sec-Fetch-*` chỉ là modifier phục vụ scoring, không được tự mình quyết định
  lane. Extension cũng chỉ là static candidate.
- Dù là resource thật, request vẫn phải qua một admission limiter nhẹ. Chỉ bỏ
  fingerprint/detection đắt tiền, không bỏ quota.
- Static miss fallback sang Apache phải dùng cùng admission budget với dynamic
  request. Không cần `stat()` file trong Lua trên mọi request; có thể đặt một
  limiter nhẹ luôn chạy cho mọi class, rồi xử lý riêng dynamic fallback ở Nginx.

### 2. Critical — Fake good-bot + resource lane tạo chuỗi fail-open hoàn chỉnh

Ba hành vi đang ghép lại thành một đường né mạnh:

- `l7/ban/ip_ban_check.lua:21-25` hoãn một IP ban chỉ vì UA **tự khai** là good
  bot.
- `l7/expensive_filter_guard.lua:104` loại UA tự khai good-bot khỏi cả meter lẫn
  enforcement trước khi UA đó được xác minh.
- `detection/bot/lite_verify.lua:60-70` phát hiện ASN mismatch nhưng không tăng
  `bot_score`. `ua_check` trước đó đã đặt `bot_score=0` cho claimed bot, nên giá
  trị 0 được giữ nguyên khi mismatch.

Test OpenResty với `Googlebot/2.1`, ASN thực 64500 và ASN mong đợi 15169 cho kết
quả:

```text
good_bot_claimed = true
good_bot_verified = nil
bot_score = 0
```

Nếu request đồng thời tự gửi `Sec-Fetch-Dest: image`, nó vào lite resource lane:
IP ban đã bị hoãn, expensive-filter đã bỏ qua, L7 rate/burst không chạy, còn ASN
mismatch không tạo điểm xấu. Đây là một bypass dễ tự động hóa và có khả năng
liên quan trực tiếp đến request bẩn đang lọt.

Hướng sửa:

- Chỉ `good_bot_verified == true` mới được miễn meter/ban. `claims_good_bot()`
  chỉ có quyền chọn lane xác minh, không có quyền nới chính sách.
- Khi lite verify thiếu ASN hoặc ASN mismatch, đặt verdict rõ ràng
  (`bot_score` cao, `bot_ua=fake_good_bot`) và cache negative verdict.
- IP đã ban phải được seal trừ khi có **positive verdict đã cache** gắn với bot
  và IP/ASN; không mở seal chỉ bằng UA. Việc stale-ban crawler thật nên được xử
  lý khi ghi ban hoặc bằng positive cache, không bằng self-claim.
- Nếu cần tránh crawler thật làm phồng `xf` counter, xác minh ASN rẻ ở COMMON
  trước guard rồi mới miễn; ASN đã được resolve sớm trong flow hiện tại.

### 3. Critical — Cookie `verified` bỏ qua toàn bộ admission trong 7 ngày

`antibot-core/init.lua:219-220` kiểm tra `verified:<cookie>` rồi return trước
classifier và trước toàn bộ `STEPS_COMMON`. Cửa thứ hai ở dòng 235 lại return
trước dispatch L7. Trong khi đó `cfg.ttl.verified=604800` và PoW hiện dùng
`difficulty="000"`.

Vì vậy một client giải PoW một lần có thể bỏ qua IP ban, rate/burst, ip-tour,
expensive-filter, transport detection và enforcement cho các request bình
thường trong tối đa 7 ngày. WAF pre vẫn chạy, nhưng các request tốn CPU/DB không
khớp rule WAF vẫn đi thẳng tới backend.

`verified` nên có nghĩa “bỏ qua challenge và phân tích fingerprint đắt tiền”,
không được có nghĩa “không còn quota tài nguyên”.

Hướng sửa: tạo một `STEPS_ADMISSION` ngắn, bắt buộc chạy **trước mọi trust exit**:

1. normalize IP/host/class tối thiểu;
2. positive/negative ban seal;
3. per-host, per-IP/per-identity và per-route token bucket;
4. circuit breaker/concurrency guard bảo vệ PHP;
5. sau đó mới cho verified/whitelist hợp lệ bỏ qua deep detection.

Whitelist vận hành có thể được miễn security scoring, nhưng vẫn nên chịu một
absolute overload ceiling đủ cao để lỗi cron/plugin nội bộ không làm cạn PHP
workers.

### 4. High — Counter 60 giây và burst 1 giây không phải time window

`rate/counter.lua:73-83` thực hiện `INCRBYFLOAT` rồi `EXPIRE TTL` trên **mỗi
request**. `redis_pool.safe_incr`, được `burst_counter` dùng, cũng `INCR` rồi
`EXPIRE` lại mỗi lần. Đây là idle-expiry counter: khóa chỉ reset sau khi traffic
im hoàn toàn đủ TTL, không phải số request trong cửa sổ gần nhất.

Test mô phỏng đúng Redis expiry cho ba request tại giây 0, 59 và 118 cho kết quả:

```text
rate = 1, 2, 3
```

Ở giây 118, request giây 0 đã nằm ngoài cửa sổ 60 giây nhưng vẫn còn trong
counter vì request giây 59 đã kéo dài TTL. Tương tự, 10 request cách nhau 0,9
giây làm `burst:<id>` tăng tới 10 dù cửa sổ được mô tả là 1 giây. Một luồng chậm
nhưng liên tục cuối cùng vẫn vượt ngưỡng (FP), trong khi threshold không còn diễn
đạt “req/60s” hoặc “req/s” như comment/config.

Ngoài ra retry discount ở `counter.lua:28-44` giảm 70% cho **mọi** request cùng
URI nếu mỗi request tới cách request trước dưới 3 giây. Test cùng URI ở giây
100, 101, 102, 103 cho rate `1.0, 1.3, 1.6, 1.9`: đây không phải một retry được
chiết khấu mà là một stream được chiết khấu vô hạn. Hammer một endpoint cố định
chính là kiểu traffic được hưởng lợi nhiều nhất.

Hướng sửa:

- Dùng token bucket/leaky bucket atomic bằng Redis Lua, hoặc fixed bucket có
  timestamp trong key (`floor(now/window)`) và TTL lớn hơn window.
- Burst ngắn nên ưu tiên `ngx.shared.DICT`/Nginx `limit_req`: local, rất rẻ và
  vẫn bảo vệ được backend khi Redis lỗi.
- Retry discount chỉ áp dụng tối đa một lần cho một request signature trong cửa
  sổ, không refresh quyền discount sau mỗi lần gọi. Không discount POST/auth và
  endpoint tốn kém chỉ dựa vào same URI.
- `rate:ids:<ip>` cũng phải là cửa sổ thật. Hiện set này giữ toàn bộ identity
  miễn là IP còn traffic, khiến cardinality chỉ tăng và ngày càng dễ được coi là
  NAT.

### 5. High — Rate/burst chủ yếu chỉ “ghi điểm”, không bảo vệ tải tức thời

`adaptive_limit.lua` đặt `rate_flag` và `ip_surge`; `burst_decision.lua` đặt
`burst_flag`. Với weights hiện tại, rate + burst có raw score 55. Sau class
multiplier:

| Class | Effective chỉ từ rate + burst | Kết quả thông thường |
|---|---:|---|
| navigation | 55 | challenge |
| auth_endpoint | 82,5 | block |
| interaction | 33 | monitor, vẫn qua backend |
| api_callback | 27,5 | monitor, vẫn qua backend |
| unknown | 27,5 | monitor, vẫn qua backend |
| feed_or_meta / inapp | 22 | allow |
| resource | không chạy L7 | không có rate/burst |

Do đó `rate limit` trong tên module không đồng nghĩa với việc quá ngưỡng sẽ bị
429. Với phần lớn class bị dampen, ngay cả rate và burst cùng bắn vẫn không ngăn
request. Tier hard-ban chỉ xuất hiện ở `ip_rate > 5000`, ghi `ban:<ip>` cho
request sau, và còn bị tắt nếu có từ 3 identity trở lên. Attacker chỉ cần xoay
vài UA vì identity bắt nguồn từ IP+UA để được coi như NAT diversity.

Điểm số phù hợp để quyết định bot/ban lâu dài; nó không phù hợp làm cơ chế cứu
tải. Cần hai đường độc lập:

- **Security verdict:** scoring, challenge, ban; ưu tiên giảm FP.
- **Resource admission:** quota/concurrency/load shedding trả 429/503 ngắn hạn;
  ưu tiên giữ PHP/DB sống, không kết tội hay ban dài hạn.

Khi vượt hard resource budget, phải trả 429 ngay, bất kể score hiện tại là bao
nhiêu. Diversity có thể giảm độ dài ban, nhưng không được vô hiệu hóa per-IP
load shedding.

### 6. High — Session grace và richness đang nới L7 bằng bằng chứng chưa đủ mạnh

`burst_counter.lua:14` đặt `burst=0` khi `sess_len>=5` và `session_flag<0.4`.
Nhưng tại thời điểm L7 chạy, fingerprint mới chỉ gọi `session_load`; phép
`session_analyze` đặt `session_flag` chạy **sau L7** trong detection. Giá trị
khởi tạo là 0, nên mọi identity có ít nhất 5 entry được grace trước khi hành vi
phiên được phân tích. Test xác nhận `sess_len=5, session_flag=0` làm module không
gọi Redis burst counter lần nào.

Song song, rate threshold, burst threshold, ban-store bypass và expensive-filter
exemption dùng `ctx.session_richness`. Giá trị này chủ yếu đo số lượng/bytes
cookie và có thể đạt 0,8 bằng cookie rác; chính decision engine đã phải thêm
`session_richness_own` và `session_cookie_known`, nhưng các module L7 chưa dùng
các cổng chặt tương ứng.

Hướng sửa:

- Phân tích session trước khi dùng `session_flag`, hoặc bỏ hoàn toàn “sess_len
  đủ dài thì không đếm burst”. Một session lâu không phải quyền miễn absolute
  burst cap.
- Mọi nới ngưỡng phải dựa vào trạng thái của request hiện tại và cookie do host
  đã học/đã cấp (`session_richness_own` + `session_cookie_known == true`), không
  dựa vào richness kế thừa hay khối lượng cookie.
- Chỉ lift soft threshold; luôn giữ một absolute ceiling.
- Không cho richness thô bypass một identity ban. Nếu cần tránh collateral do
  identity IP+UA bị collapse, tách operator/hard ban khỏi auto-ban và cho người
  thật đi challenge/reauth bằng bằng chứng mạnh hơn.

### 7. High về kiến trúc vận hành — Redis fail-open đồng nghĩa mất toàn bộ phanh

Khi Redis unavailable, `counter.lua` đặt rate/ip_rate/burst về 0 và cho đi;
ban/expensive-filter cũng fail-open. Redis có thể vẫn là nơi phối hợp dài hạn,
nhưng một sự cố Redis đúng lúc traffic burst không được phép làm mất cơ chế bảo
vệ PHP.

Nên có limiter khẩn cấp trong `lua_shared_dict` hoặc Nginx `limit_req` /
`limit_conn`, ít nhất theo `host`, `host+route` và IP. Đây là phanh local, không
phải phán quyết security nên có thể dùng TTL rất ngắn và trả 429/503 thay vì ban.
Quota global/concurrency phải gắn với năng lực PHP workers/DB của máy, vì một
botnet phân tán có thể giữ từng IP dưới ngưỡng nhưng vẫn làm tổng tải vượt khả
năng phục vụ.

### Thứ tự sửa đề xuất

#### P0 — đóng đường bypass và bảo vệ tải

1. Thêm universal admission lane chạy trước `verified`, whitelist và class
   dispatch; có local token bucket/concurrency ceiling và immediate 429.
2. Không cho header `Sec-Fetch-*` tự quyết định `resource`; cấm mọi non-GET/HEAD
   vào resource lane. Resource vẫn chịu lightweight quota.
3. Sửa lite good-bot mismatch thành negative verdict; chỉ verified bot mới được
   miễn guard/ban.
4. Chuyển verified fast-path xuống sau admission. Giữ deep-detection bypass để
   không mất performance.

#### P1 — làm đúng semantics và giảm FP

1. Thay idle-expiry counter bằng token/fixed buckets atomic; bỏ retry discount
   vô hạn.
2. Tách hard resource quota khỏi bot scoring. Route/host overload trả 429 ngắn,
   không tự động ghi ban.
3. Sửa thứ tự session analysis và chỉ dùng first-party state để lift threshold.
4. Thay raw identity cardinality trong NAT guard bằng bằng chứng user thật
   (known cookie/verified sessions); UA rotation không được tạo miễn trừ.

#### P1.5 — quan sát để hiệu chỉnh

- Log rõ `admission_reason`, `bucket_remaining`, `route_key`, `backend_class`,
  `resource_candidate` và `resource_actual/fallback` nếu Nginx cung cấp được.
- Đo top route theo request count, upstream response time, 499/502/504 và số PHP
  worker bận. Threshold nên suy từ capacity thực, không từ một con số chung cho
  mọi máy.
- Tách dashboard “security block” khỏi “capacity throttle”; 429 cứu tải không
  được tính như bằng chứng bot để tránh vòng lặp tự nâng risk/ban.

### Kết quả test WSL/OpenResty

Các test được chạy bằng `resty` trong WSL với stub Redis có mô phỏng expiry;
file test tạm đã được xóa sau khi chạy.

```text
SYNTAX_OK 9
RATE_AT_0_59_118 1,2,3
RETRY_RATES 1.0,1.3,1.6,1.9
BURST_GRACE 0 0
BURST_AT_0P9_INTERVAL 10 10
CLASS_POST_LOGIN_FETCH_IMAGE resource
CLASS_DYNAMIC_JPG resource
LITE_MISMATCH true nil 0 64500
```

Ý nghĩa:

- 9/9 file Lua L7 hợp lệ về cú pháp.
- Rate TTL 60 giây và burst TTL 1 giây đang là idle expiry, không phải window.
- Same-URI stream được discount liên tục.
- Session grace tắt hẳn phép đếm burst.
- Client-controlled header/extension đưa dynamic request vào resource lane.
- Fake Googlebot sai ASN vẫn giữ `bot_score=0` trong lite lane.

### Đánh giá tổng thể

Phần detection/scoring của codebase có nhiều tín hiệu và đã chú ý FP, nhưng L7
hiện thiếu bất biến quan trọng nhất của shared hosting: **mọi request có khả năng
đến Apache/PHP đều phải đi qua một ngân sách tài nguyên rẻ, bắt buộc và không thể
được miễn chỉ bằng cookie, UA hay header do client sở hữu**.

Đóng đúng bốn mục P0 sẽ đem lại hiệu quả giảm tải lớn hơn việc thêm tiếp
signature SQLi/XSS hoặc tinh chỉnh vài điểm score. Sau đó mới hiệu chỉnh P1 bằng
log thực tế; nếu làm ngược lại, attacker vẫn có thể chọn resource/verified lane
để bỏ qua toàn bộ phần vừa tinh chỉnh.

---

## Lần review 2 — Hoàn thiện admission/load-shedding cho cả frontend và backend

Ngày review: 2026-10-04.

### Tóm tắt

Bản sửa đã đóng các đường bypass mức cao tìm thấy ở lần review 1 và tách đúng
hai khái niệm trước đây bị trộn:

- **Capacity verdict:** local admission và `limit_conn`, vượt ngưỡng trả 429
  ngắn hạn; không cộng risk, không ghi ban, không kết tội bot.
- **Security verdict:** Redis rate/burst, fingerprint, bot verification, scoring,
  challenge và ban; dùng để nhận diện, không phải phanh tải duy nhất.

Kết quả hiện tại phù hợp hơn nhiều với mục tiêu shared hosting: request không còn
được miễn ngân sách tài nguyên chỉ vì mang cookie verified, UA crawler hoặc header
`Sec-Fetch-*`. Không còn lỗi logic mức Critical/High đã biết trong chính luồng
vừa sửa. Các giới hạn còn lại chủ yếu là hiệu chỉnh capacity và phạm vi phân tán,
không phải một cửa bypass đơn giản như bản trước.

### Những gì đã làm được

#### 1. Universal admission độc lập Redis

Thêm `l7/admission.lua` và hai vùng nhớ tách biệt:

- `antibot_l7_core`: global, host, host-group và route-shard. Không chứa
  cardinality theo IP nên IP churn không thể đẩy mất circuit breaker cốt lõi.
- `antibot_l7_clients`: budget per-IP. Vùng này có thể chịu cardinality lớn mà
  không làm mất host/global protection.

Admission dùng fixed bucket ngắn 1 giây và dài 10 giây. TTL chỉ được đặt khi tạo
khoá bucket mới, không refresh theo từng request. Nó chạy theo thứ tự:

```text
ctx + fast classifier
  → xác định proxy origin
  → local admission
  → Redis IP-ban lookup
  → WAF body scan
  → verified/whitelist/class fast-path
```

Thứ tự này có ý nghĩa: request bị quá tải bị loại trước khi đọc/scan body WAF và
trước Redis ban lookup; một IP đã bị ban nhưng tiếp tục flood không còn được dùng
Redis như một dịch vụ unlimited. Admission vẫn đứng sau `proxy_origin` để không
áp quota per-IP lên một edge đã được xác định là reverse proxy.

Các trục hiện có:

- toàn OpenResty instance;
- từng virtual host;
- host × `resource|dynamic`;
- host × group × route shard có cardinality cố định;
- IP × request class;
- budget riêng cho static miss chuyển sang Apache;
- budget riêng cho `/antibot/verify` và `/antibot/beacon`.

Ngưỡng vượt trả `429`, có `Retry-After`, `Cache-Control: no-store`,
`X-L7-Admission`, `action=throttled`; không tạo `ban:*` và không tăng reputation.

#### 2. Frontend/resource lane không còn là đường né

Classifier chỉ coi request là resource khi đồng thời:

- method là `GET` hoặc `HEAD`;
- URI có extension tĩnh nằm trong danh sách server-side.

`Sec-Fetch-Dest` hiện chỉ là telemetry (`resource_declared`), không còn cho client
tự chọn resource lane. Vì vậy `POST /wp-login.php` kèm
`Sec-Fetch-Dest: image` vẫn là `auth_endpoint`, còn `POST /dynamic.jpg` vẫn đi
dynamic lane.

Resource thật vẫn qua universal admission. Nếu `try_files` xác nhận file không
tồn tại và chuyển tới `@static_backend`, named location gọi
`run_backend_fallback()` trước khi proxy sang Apache. Như vậy vẫn giữ được mô
hình compatible-all-CMS và rewrite của `.htaccess`, nhưng bot quét hàng loạt
`.jpg/.css` giả không còn biến thành tải PHP không giới hạn.

Hai endpoint nội bộ trước đây override server-level `access_by_lua` nay tự gọi
`run_endpoint()`, nên verify/beacon không còn là cửa bypass.

#### 3. Verified fast-path vẫn nhanh nhưng không còn unlimited

Cookie verified vẫn bỏ qua fingerprint, full detection và phần lớn Redis pipeline
để giữ hiệu năng. Tuy nhiên nó bắt buộc qua:

- local admission;
- IP ban;
- WAF pre-scan;
- expensive faceted-filter guard.

Guard faceted-filter tự return trước Redis nếu URL không có chữ ký multi-value,
nên request verified thông thường vẫn rẻ. Verified không được coi là quyền
enumerate vô hạn một không gian URL gây truy vấn DB đắt.

#### 4. Rate/burst có semantics theo cửa sổ

`rate/counter.lua` dùng current bucket + previous bucket nhân phần còn lại của
cửa sổ để xấp xỉ sliding window. Request mới không còn gia hạn và mang toàn bộ
lịch sử cũ đi vô hạn. Retry discount theo same URI đã bỏ: hammer một endpoint
vẫn là tải thật dù client gọi nó là retry.

`burst_counter.lua` đưa bucket thời gian vào tên khoá. Qua biên một giây sẽ tạo
bucket mới; request đều đặn không còn làm TTL luôn sống và biến counter thành
tổng vô hạn. Session-length grace bị bỏ vì trước đây nó đọc `session_flag` trước
khi session analyzer chạy.

`res_ip_counter` cũng chuyển sang key có bucket; `session_store` đọc current và
previous bucket thay cho một idle-expiry counter.

#### 5. Trust/CGNAT và crawler proof chặt hơn

- Rate/burst threshold lift và identity-ban lift chỉ dùng
  `session_richness_own` khi `session_cookie_known == true`; cookie rác hoặc
  richness kế thừa không còn là bằng chứng miễn trừ.
- Extreme IP-rate ban không dùng raw identity/UA cardinality nữa. UA rotation
  không thể tự tạo nhãn CGNAT; miễn ban tập thể chỉ dựa vào
  `ip_shared_verified` hoặc reverse proxy đã xác định.
- Extreme hard-ban có hiệu lực ngay trên request hiện tại, không chỉ ghi Redis
  rồi chờ request sau.
- Self-declared Googlebot/Bingbot không còn được mở IP/identity ban hay expensive
  guard chỉ bằng UA. Cần positive cache `crawler:<ip>` từ lần xác minh thực.
- Resource lite verification sai ASN/thiếu proof sẽ đặt
  `bot_lite_needs_full=true` và chuyển sang full detection. Nếu full DNS/ASN cũng
  kết luận giả mạo, decision engine block `fake_good_bot` trực tiếp, không để
  class multiplier của resource làm rơi điểm xuống allow.

#### 6. Native concurrency ceiling

`nginx.conf` khai báo zone theo client IP và server name. File sinh vhost đặt
`limit_conn` cho cả HTTP/HTTPS và trả 429 khi vượt ngưỡng. Đây là phanh native,
không phụ thuộc Redis hay Lua scoring, bổ sung cho rate budget khi request giữ
kết nối/upstream lâu.

#### 7. Quan sát và chống regression

`async/logger.lua` đã ghi thêm khi phù hợp:

- `adm`, `adm_n`, `adm_lim`, `adm_win`;
- `adm_grp`, `adm_route`;
- `backend`, `rcand`, `ractual`.

Các trường này tách capacity throttle khỏi security verdict. Static fallback được
đánh dấu `backend=static_fallback`, `ractual=false`.

Thêm hai fixture cố định trong `l7/tests/`:

- `l7_regression.lua`: kiểm semantics Lua và contract tích hợp;
- `nginx_l7_smoke.conf`: biên dịch thật các directive shared-dict/limit-conn.

Contract WAF cũng được cập nhật để hiểu `STEPS_ADMISSION`,
`STEPS_RESOURCE_PRE` và `STEPS_RESOURCE_FINAL`; phép kiểm thứ tự cờ không còn báo
sai vì chỉ biết cấu trúc pipeline cũ.

### Kết quả giả lập WSL/OpenResty

Chạy trực tiếp bằng OpenResty cài trong WSL:

```text
L7_REGRESSION_OK 47

contract_test.lua:
  OK 145 file Lua biên dịch được
  291 qua, 0 hỏng

bash -n nginx/da_to_openresty.sh:
  exit 0

openresty -t -e stderr -p /tmp -c .../nginx_l7_smoke.conf:
  syntax is ok
  test is successful
```

Các ca regression quan trọng đã chạy:

- request thứ ba vượt per-IP short budget trả 429; bucket giây kế tiếp không
  kế thừa toàn bộ count cũ;
- static fallback và verify endpoint có budget độc lập;
- fake `Sec-Fetch-Dest` không che được auth POST;
- POST có đuôi tĩnh không được vào resource lane;
- rate tại `t=118s` chỉ còn khoảng `1,07`, không giữ tổng `3` như idle expiry;
- session dài không tắt burst counter và giây mới bắt đầu bucket mới;
- crawler claim sai ASN được đẩy vào full lane với score tối thiểu 0,85;
- admission đứng trước WAF body scan, verified exit và Redis IP-ban lookup;
- generated vhost chứa fallback/endpoint guard và native connection limits.

### Các vấn đề còn tồn tại

#### 1. High về vận hành — ngưỡng mới vẫn là giá trị rollout, chưa phải capacity thật

Các ngưỡng global/host/route/IP và `limit_conn` đang cố ý đặt tương đối cao để
giảm FP. Chưa có dữ liệu chứng minh chúng khớp số PHP workers, Apache concurrency,
DB capacity và traffic p99 của từng máy. Hệ quả có thể theo hai chiều:

- cao quá: admission chỉ bắn sau khi backend đã bắt đầu nghẽn;
- thấp quá: sale/flash crowd, office NAT hoặc ứng dụng SPA nhiều request bị 429.

Cần đo theo host và class: p50/p95/p99 request/s, active requests, upstream
latency, 429/499/502/504, Apache/PHP busy workers. Sau đó đặt global ceiling theo
năng lực máy, host ceiling theo tenant và giữ khoảng an toàn thay vì copy một
bộ số cho mọi server.

#### 2. Fixed bucket có boundary burst

Một client có thể gửi sát cuối bucket rồi sát đầu bucket kế tiếp, đạt gần 2 lần
short limit trong một khoảng rất ngắn. Long window hạn chế sustained load nhưng
không xoá hoàn toàn boundary burst. Đây là đánh đổi để counter cực rẻ và atomic.
Chỉ nên đổi sang GCRA/token bucket nếu số liệu cho thấy burst biên thực sự làm
backend nghẽn; không cần tăng độ phức tạp trước khi đo.

#### 3. Counter local không phải quota toàn cụm

`lua_shared_dict` dùng chung giữa worker trong một OpenResty master, nhưng không
chia sẻ giữa nhiều server. Với một domain được cân bằng qua nhiều node, mỗi node
có ngân sách riêng. Điều này đúng cho local survival brake; nếu cần quota toàn
cụm phải thêm tầng điều phối riêng, không nên thay local brake bằng Redis vì sẽ
làm Redis outage xoá luôn phanh cuối.

#### 4. Redis fail-open vẫn làm mất security correlation

Khi Redis hỏng, rate scoring, ban lookup và expensive-filter HLL vẫn fail-open.
Điểm đã cải thiện là local admission + native concurrency vẫn bảo vệ capacity;
nhưng danh tiếng, ban lịch sử và phối hợp swarm không còn đầy đủ. Đây là degraded
mode có chủ đích, không phải “hệ thống vẫn bảo vệ như bình thường”. Nên có metric
và cảnh báo riêng cho `rate_degraded`/Redis errors.

#### 5. `limit_conn` per-IP không hiểu proxy khai báo ở Lua

Native Nginx key dùng địa chỉ kết nối. Mô hình Cloudflare được xử lý ở thư mục
`nginx/CF` riêng nên không áp kết luận từ generator generic vào đó. Tuy nhiên nếu
một vhost generic được đặt sau reverse proxy khác bằng khai báo Redis, Lua biết
`behind_proxy` nhưng `limit_conn` không biết; nhiều client có thể bị gộp vào một
edge và chạm ngưỡng 80. Khi triển khai trường hợp này phải dùng config proxy
riêng, key từ real-IP đã được trust đúng cách, nâng/tắt per-IP native limit cho
vhost đó; host/global admission vẫn giữ nguyên.

#### 6. Chưa có feedback trực tiếp từ trạng thái backend

Admission hiện dựa trên request count/concurrency cố định, chưa phản ứng theo số
PHP worker đang bận, DB queue hay upstream latency đang tăng. Vì vậy nó là
circuit breaker định trước, chưa phải adaptive load controller. Bước phát triển
tiếp theo hợp lý là thêm backend saturation signal có hysteresis và thời gian tự
hồi phục; không dùng một request chậm riêng lẻ làm bằng chứng bot.

#### 7. Route budget dùng shard, không phải exact endpoint

Hash vào 64 shard giới hạn cardinality và chống key-flood, đổi lại hai route
không liên quan có thể va cùng shard và chia budget. Với threshold hiện tại đây
là hành vi bảo thủ chấp nhận được. Nếu log cho thấy collision gây 429 thật, tăng
số shard hoặc tạo exact budget chỉ cho một số endpoint đã được đo là đắt; không
quay lại key theo URI tuỳ ý của client.

#### 8. Cần regenerate/reload trước khi các phần Nginx có hiệu lực

Code Lua có thể deploy riêng, nhưng static fallback guard và `limit_conn` chỉ tồn
tại trên vhost sau khi chạy lại generator rồi `openresty -t` và reload thành
công. Không nên coi kết quả source test là bằng chứng production đã dùng config
mới.

### Đánh giá cuối lần 2

So với lần review 1, L7 đã chuyển từ một lớp **chấm điểm có nhiều fast-path**
thành hai tầng rõ ràng:

1. một phanh tải local bắt buộc, bao phủ frontend static, dynamic backend,
   verified traffic và endpoint nội bộ;
2. một pipeline security sâu hơn để nhận diện, challenge và ban.

Kiến trúc này đã đủ làm baseline production cho mục tiêu chống burst/bot load ở
shared hosting sau khi rollout có quan sát. Việc ưu tiên tiếp theo không phải thêm
signature SQLi/XSS hay response inspection, mà là đo capacity thật, hiệu chỉnh
ngưỡng theo từng cụm và bổ sung cảnh báo degraded/backend saturation. Response
inspection/CSP và các luật payload dễ FP vẫn là phạm vi khác, không nên trộn vào
capacity verdict của L7.

---

## Lần review 3 — Thu hồi tích hợp Nginx, chốt phạm vi Lua-only

Ngày điều chỉnh: 2026-10-04.

### Tóm tắt

Theo yêu cầu của operator, toàn bộ thay đổi do lần review 2 đưa vào
`nginx/nginx.conf` và `nginx/da_to_openresty.sh` đã được thu hồi. Hai file này
không còn chứa shared dictionary mới, `limit_conn`, `run_backend_fallback()` hay
`run_endpoint()` do L7 thêm vào. Từ lần này trở đi, L7 chỉ tích hợp bằng Lua.

Lần review 3 **thay thế kết luận triển khai Nginx của lần review 2**. Các phần
phân tích rate/burst/trust/crawler và thứ tự Lua vẫn giữ nguyên.

### Cách thực hiện Lua-only

- `admission.lua` tái sử dụng `ngx.shared.antibot_cache` đã tồn tại; không yêu
  cầu khai báo shared dictionary mới.
- Request thông thường vẫn đi qua local admission trong `antibot-core/init.lua`
  trước WAF body scan, Redis IP-ban lookup và các fast-path.
- `/antibot/verify` gọi `run_endpoint("verify")` ngay trong
  `enforcement/challenge/verify_token.lua`.
- `/antibot/beacon` gọi `run_endpoint("beacon")` ngay trong
  `detection/browser/beacon_handler.lua`.
- Regression test khóa bất biến rằng hai file Nginx không chứa admission-specific
  shared dict, `limit_conn` hoặc require `antibot.l7.admission`.

### Các khả năng đã chủ động bỏ

1. **Không còn native concurrency ceiling.** Không có `limit_conn_zone` hay
   `limit_conn`; Lua fixed-bucket chỉ giới hạn số request, không đo chính xác số
   request/upstream đang đồng thời active.
2. **Không có budget riêng sau `try_files`.** Access-phase Lua chỉ biết đây là
   resource candidate; nó không biết file sẽ hit trên disk hay rơi vào
   `@static_backend`. Static miss vẫn chịu global/host/resource-route/per-IP
   admission ban đầu, nhưng không có ceiling riêng dành cho tải Apache/PHP.
3. **Không có shared dict tách core/client.** Core và per-IP admission cùng dùng
   `antibot_cache` 5 MiB. Prefix và route shard hạn chế namespace core, nhưng IP
   churn lớn có thể tạo LRU pressure lên cache đang dùng chung với module khác.

Đây là giới hạn rõ ràng của ràng buộc Lua-only, không được che giấu như thể đã
có native connection control hoặc static-fallback awareness.

### Kết quả test sau thu hồi

```text
L7_REGRESSION_OK 48
contract_test.lua: 145 file Lua compile OK
contract_test.lua: 291 qua, 0 hỏng
bash -n nginx/da_to_openresty.sh: exit 0
```

`nginx_l7_smoke.conf` đã bị xoá vì nó kiểm tra một khả năng Nginx không còn nằm
trong phạm vi triển khai. Không cần regenerate per-domain config cho thay đổi L7
này; chỉ triển khai các file Lua theo quy trình hiện có.

---

## Lần review 4 — Kiểm chứng độc lập bản sửa, và một lỗ còn mở

Ngày review: 2026-10-04. Người review: Claude (phiên khác với lần 1–3).

Phạm vi: đối chiếu **từng khẳng định** của lần 1–3 với code đang chạy, bằng cách
đọc code và dựng harness đo, không tin phần mô tả của review.

### Bốn Critical của lần 1: đã đóng, kiểm bằng code

| Lần 1 gọi Critical | Trạng thái | Bằng chứng trong code |
|---|---|---|
| `Sec-Fetch-Dest` tự chọn lane `resource` | đóng | `req_classifier.lua:437-441` chỉ nhận `GET/HEAD` + extension server-side; header thành `ctx.resource_declared` |
| Cookie `verified` bỏ qua admission 7 ngày | đóng | `init.lua:210` chạy `STEPS_ADMISSION` trước mọi trust exit |
| Fake good-bot + resource lane fail-open | đóng | `lite_verify.lua:15` đặt `bot_score ≥ 0.85` và `bot_lite_needs_full`; `init.lua:267` đẩy sang `STEPS_FULL_DETECTION`; `engine.lua:578` block `fake_good_bot` |
| Counter idle-expiry không phải window | đóng | bucket nằm trong tên khoá (`counter.lua:16-20`, `burst_counter.lua:14-17`) |

Đo per-IP: `auth_endpoint` ngưỡng 30 → request **31** bị 429, khớp đáp án tính
tay. Xoay 64 URI khác nhau **không** né được, vì khoá per-IP không chứa URI.

Đo counter (stub Redis mô phỏng expiry thật, `WINDOW=60`):

```text
t=0 -> 1.00   t=59 -> 2.00   t=118 -> 1.07     (lần 1 đo được 1,2,3)
stream đều 1 req/s × 120s -> 61.00              (trước: ~1.9 do retry discount)
flood 500 req trong 1 giây -> 500.00
```

Cả ba khớp đáp án tính tay trước khi chạy. Phần mô tả của lần 2 về semantics
counter là **đúng**, không khai gian.

### Lỗ còn mở: static MISS dùng ngân sách `resource`

`req_classifier.lua` khi đó ghi: *"Static miss se bi `@static_backend` admission
guard dem lai truoc Apache."* Guard đó **không tồn tại** — lần review 3 đã thu
hồi nó theo ràng buộc Lua-only, và `da_to_openresty.sh:240-242` đặt
`access_by_lua_block { return; }` trong named location, tức **tắt hẳn** Lua ở đó.
Chú thích mô tả code đã bị gỡ.

Lần 3 **có khai** giới hạn này (mục "Các khả năng đã chủ động bỏ", điểm 2), nên
đây không phải che giấu. Vấn đề là nó bị khai ở review rồi chú thích trong code
nói ngược, và ngưỡng `resource` được đặt cao (4000/s/host) đúng vì giả định
"static thì rẻ" — giả định **sai với static MISS**: `try_files` miss →
`@static_backend` → Apache/PHP, và với WordPress thì `.htaccess` rewrite thành
`index.php`.

Đo trên harness cùng hình dạng (1 host, 2000 IP, `.jpg` không tồn tại):

| kịch bản | lọt tới Apache |
|---|---|
| 1 IP, 1 giây | 250 (per-IP giữ được) |
| 2000 IP dồn 1 giây, URI phân tán 64 shard | 4.000 req/s |
| 2000 IP × 10 req trải đều 10 giây | **20.000/20.000 lọt — 2.000 req/s** |
| 2000 IP × 2 req/s, bền vững 60 giây | **3.200 req/s liên tục, 80% lọt** |

Cùng lưu lượng đó nếu là `.php` chỉ 350 req/s lọt. Khác 9 lần, và chênh lệch đó
không phản ánh chi phí thực tế nào ở backend.

### Đã sửa

`admission.lua` thêm `static_target_exists()`: `io.open(document_root .. uri)`,
kết quả cache trong `antibot_cache` với TTL ngắn (`static_probe_ttl = 30`).
`class_group()` đưa static miss vào ngân sách `dynamic`.

Ba tính chất quan trọng của cách này:

1. **Rẻ.** Một flood 240.000 request vào cùng đường dẫn chỉ tốn **2** lần
   `io.open` trong 60 giây; URI phân tán 64 shard tốn 64 lần. Không phải một
   syscall mỗi request — đúng điều lần 1 cảnh báo.
2. **Fail-open có chủ đích.** Không đọc được `document_root`, dict lỗi, hay
   `io.open` lỗi vì lý do khác → coi như static thật (ngân sách `resource`).
   Một phép đo không chắc chắn không được phép biến thành 429 cho khách thật.
3. **Không chạm file tĩnh thật.** File có trên đĩa vẫn giữ nguyên ngân sách
   `resource` 4000/s, nên site nhiều ảnh/CSS không bị ảnh hưởng — khác hẳn
   phương án "hạ ngưỡng resource" vốn áp lên cả hai.

Sau khi sửa, cùng kịch bản bền vững: **3.200 → 100 req/s** (giảm 32 lần).

`static_probe = false` là đường lui nhanh nếu `io.open` gây vấn đề hiệu năng.

### Test

`l7/tests/l7_regression.lua`: **48 → 65** ca. Nhóm mới khoá sáu bất biến:
file có thật → `resource`; file thiếu → `dynamic` **và thực sự bị chặn theo trần
dynamic** (không chỉ đổi nhãn); cache hết hạn đúng TTL; `document_root` rỗng →
fail-open về `resource`; `static_probe=false` giữ hành vi cũ; class không phải
`resource` không bao giờ chạm đĩa.

`Dict` stub của test được thêm `get`/`set` — thiếu hai hàm đó thì module nổ ở
access phase, và một stub thiếu hàm của production API là phép đo sai chiều.

Năm mutation, tất cả đều bị bắt:

```text
bỏ phép tách (exists==false -> false)     -> FAIL "static MISS chuyen sang dynamic"
fail-open sai chiều (== false -> ~= true)  -> FAIL "fail-open ve resource"
bỏ đường lùi (static_probe)                -> FAIL "static_probe=false giu hanh vi cu"
bỏ đọc cache                               -> FAIL "probe duoc cache" (4 syscall thay vì 1)
TTL -> nil (cache vĩnh viễn)               -> FAIL "qua TTL: probe chay lai"
```

Mutation cuối ban đầu **không** bị bắt — đó là lỗ trong *phép đo*, không trong
code: cache vĩnh viễn làm một file vừa upload bị coi là thiếu mãi mãi. Đã thêm
ca 2b để khoá.

### Phần L7 còn lại: kiểm, không thấy lỗ mới

- `expensive_filter_guard.lua:104` — miễn trừ crawler đòi `crawler:<ip> == "1"`
  từ xác minh thật, không chỉ UA. Đóng đúng.
- `ip_ban_check.lua:22` — defer ban cũng đòi positive cache. Đóng đúng.
- `adaptive_limit.lua:88` — hard-ban tier 2 dùng `ip_shared_verified` /
  `behind_proxy`, không dùng raw UA cardinality; có hiệu lực ngay trên request
  hiện tại. Đóng đúng.
- `ban_enabled = false` **chỉ** thuộc `expensive_filter_guard` (hai cơ chế khác
  nhau), không khoá tier 2 của `adaptive_limit`. Không phải lỗi.

### Còn tồn tại, không sửa trong lần này

1. **Boundary burst của fixed bucket** — đo được: 60 request qua trong ~0,02s
   quanh biên giây (30 cuối bucket + 30 đầu bucket kế). Lần 2 đã khai đúng ở
   mục 2. Đánh đổi để counter rẻ và atomic; chỉ nên đổi sang GCRA/token bucket
   nếu số liệu cho thấy burst biên thực sự làm backend nghẽn.
2. **Ngưỡng vẫn là giá trị rollout** (lần 2, mục 1). Chưa đo capacity thật của
   từng máy. Riêng `host_group.dynamic.short = 500` giờ gánh thêm static miss,
   nên con số đó đáng đo sớm: một site WordPress có nhiều ảnh bị xoá/đổi tên
   (ví dụ sau khi migrate) có thể sinh static miss hợp lệ liên tục.
3. **Chưa có feedback từ trạng thái backend** (lần 2, mục 6). Admission vẫn là
   circuit breaker định trước, chưa phải adaptive controller.

### Ba câu hỏi của operator (04-10), trả lời bằng code

#### 1. Admission trước WAF có hợp lý? — Hợp lý, nhưng lý lẽ của lần 2 không phải lý lẽ đúng

Lần 2 biện hộ: *"request bị quá tải bị loại trước khi đọc/scan body WAF"*. Lợi
thế đó **nhỏ hơn nhiều** so với mô tả, vì ba điều kiểm được trong code:

1. **Mọi luật `block` của WAF đều URI-only** — `dotfile_exposed`,
   `dump_exposed`, `wellknown_exec`, `wp_upload_exec`, `wp_content_exec`,
   `wp_includes_exec`, `wp_admin_includes_exec`. Không luật nào cần thân.
2. **WAF tự nó đã terminate trước `body.probe`** (`waf/init.lua:1093`):
   `policy.decide(state, false)` rồi `terminate` — chú thích tại đó nói thẳng
   *"Hard URI invariants can terminate before reading an upload body"*.
3. Nên lợi thế "429 trước khi đọc body" chỉ áp cho POST **không khớp luật URI
   nào**, tức POST hợp pháp về đường dẫn.

**Thứ tự vẫn đúng, vì một lý do khác và mạnh hơn:** `read_body()` ở access phase
**thực sự** gây đọc thân. Bằng chứng: spill tồn tại thật (~283 lượt/ngày,
`nginx.conf:50`) — nếu nginx đã đọc trọn thân trước access phase thì không có
khái niệm spill tại thời điểm đó. Với `auth_endpoint` ngưỡng 30/s/IP, admission
chặn ở request 31; nếu WAF đứng trước thì cả 31 POST đều bị `read_body()` +
`core.scan()` rồi mới 429.

**Giá phải trả, lần 2 không nêu:** request bị 429 **mất dòng `waf.log`** —
`ctx.waf_hits` rỗng nên `uri_hit = false` trong `run_log`. Một flood dùng đúng
payload mà WAF quan tâm sẽ bị throttle **và không được ghi nhận**. Điểm cứu:
`wp_paths.needs_mark` đọc `ngx.var.uri` trực tiếp, không qua `run_pre`, nên việc
đánh dấu host WordPress **vẫn chạy** sau 429.

#### 2. Không sửa `da_to_openresty.sh` có hợp lý? — Hợp lý, và sau bản sửa static-miss thì không còn lý do để sửa

Trước đó có một lý do thật: static miss không có budget riêng. Giờ
`admission.lua` kiểm đĩa trong Lua nên **đã giải quyết bằng Lua** (3.200 → 100
req/s). Ba chỗ `access_by_lua_block { return; }` còn lại đều không phải lỗ:

| location | lý do giữ nguyên |
|---|---|
| `/.well-known/acme-challenge/` | đọc thẳng từ đĩa (`try_files $uri =404`), **không** tới Apache. Bỏ Lua là **bắt buộc**: ACME không có JS/JA3/cookie nên bị chấm điểm như bot → "FAILED HTTP CHECKS" hàng loạt, âm thầm |
| `@static_backend` | admission **đã** đếm request này ở lần vào đầu (server-level `access_by_lua`), và sau bản sửa thì đếm đúng vào budget `dynamic` |
| `/antibot/verify`, `/antibot/beacon` | tự gọi `admission.run_endpoint()` trong Lua (`verify_token.lua:487`, `beacon_handler.lua:10`) |

Thêm `run_backend_fallback()` vào `@static_backend` giờ chỉ cho thêm **một** thứ
— biết chắc đã miss thay vì suy từ `io.open` — mà đổi lại phải regenerate 73
vhost mỗi lần thay đổi. Phép kiểm đĩa có cache chỉ sai trong cửa sổ 30 giây sau
khi upload tệp mới, và sai **theo chiều an toàn** (tính vào `dynamic`).

#### 3. `limit_conn` — ràng buộc cứng, không đề xuất lại

Operator: *"nginx.conf tôi tuyệt đối không dùng limit_conn"*. Xác nhận bằng
grep: `nginx.conf` và `da_to_openresty.sh` **không** có
`limit_conn`/`limit_conn_zone`/`limit_req` nào. Lần 3 đã thu hồi sạch.

Cái mất, phải nói thật chứ không che: admission đếm **số request**, không đếm
**số kết nối đồng thời**. Kịch bản nó **không** che được là *ít request nhưng mỗi
request giữ upstream rất lâu* — query DB 30 giây, hoặc slow upstream. 100 req/s
đều đi qua budget, nhưng nếu mỗi cái chiếm một PHP worker 20 giây thì worker pool
cạn mà **không trục nào bị vượt**.

Thứ thay thế được **mà vẫn Lua-only**: đọc trạng thái backend thật (số PHP
worker đang bận) rồi hạ budget động — đúng mục 6 "còn tồn tại" ở lần 2. Cần đo
capacity trước; không làm trước khi có số.
