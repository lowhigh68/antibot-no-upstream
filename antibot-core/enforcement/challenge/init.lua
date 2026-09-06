local _M = {}

local issue_token = require "antibot.enforcement.challenge.issue_token"
local pow         = require "antibot.enforcement.challenge.pow_challenge"
local nonce_store = require "antibot.enforcement.challenge.nonce_store"
local pool        = require "antibot.core.redis_pool"
local cfg         = require "antibot.core.config"

function _M.run(ctx)
    local nonce = issue_token.run(ctx)
    pow.run(ctx)
    nonce_store.run(ctx, nonce)

    -- KHÔNG cho beacon chèn vào chính trang này.
    --
    -- `header_filter_by_lua` đọc `ctx.inject_candidate` (đặt ở access phase khi
    -- client gửi `Accept: text/html`) rồi xác nhận bằng Content-Type thật. Trang
    -- challenge là text/html ⇒ khớp ⇒ `body_filter` chèn BEACON_JS vào trước
    -- `</body>` của nó. Trên điện thoại yếu, đoạn đó chạy canvas + WebGL +
    -- AudioContext + một timer 2s SONG SONG với vòng giải PoW — đúng lúc thiết
    -- bị đang chật vật. Mà không đổi lấy gì: `verify` đã thu canvas rồi.
    ctx.inject_candidate = false

    ngx.status = 200
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    -- Trang này MANG một nonce dùng một lần và nằm ở ĐÚNG URL bài viết. Để
    -- trình duyệt giữ lại bản sao ⇒ sau khi verify xong, `location.replace`
    -- lấy lại chính nó từ bộ nhớ ⇒ giải lại bằng token đã chết ⇒ 403 ⇒ tải lại
    -- ⇒ vòng lặp không lối thoát. Ba header cho ba thế hệ bộ nhớ đệm.
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    ngx.header["Pragma"]        = "no-cache"
    ngx.header["Expires"]       = "0"
    ngx.say(_M.challenge_html(ctx))
    ngx.exit(200)
    return true
end

-- ── TRANG CHALLENGE LÀ MỘT MÁY TRẠNG THÁI. MỌI NHÁNH PHẢI CÓ ĐIỂM DỪNG ──
--
-- "Treo" không phải một lỗi — nó là MỘT NHÁNH KHÔNG CÓ ĐIỂM DỪNG. Và vá từng
-- lỗi một thì không bao giờ hết, vì mỗi phụ thuộc mới lại thêm một nhánh mới.
-- Nên cách làm ở đây là liệt kê máy trạng thái rồi CHỨNG MINH từng nhánh về
-- được một điểm dừng:
--
--   NẠP
--    ├─ JS bị tắt ................ <noscript>                        [dừng]
--    └─ JS chạy
--        ├─ tự kiểm SHA-256 sai ... màn hình lỗi + nút Thử lại       [dừng]
--        ├─ vòng PoW
--        │   ├─ tìm thấy .......... GỬI
--        │   └─ chạm trần lặp ..... màn hình lỗi + nút Thử lại       [dừng]
--        └─ GỬI (XHR)
--            ├─ 2xx + JSON ........ điều hướng tới đích              [dừng]
--            ├─ 2xx không JSON .... điều hướng tới URL hiện tại      [dừng]
--            ├─ 400/403 ........... tải lại, TỐI ĐA 2 lần rồi dừng   [dừng]
--            ├─ 5xx/mạng/quá hạn .. thử lại, TỐI ĐA 3 lần rồi dừng   [dừng]
--            └─ không gì cả ....... ĐỒNG HỒ CANH 45s                 [dừng]
--
-- Đồng hồ canh là lưới cho những nguyên nhân CHƯA BIẾT. Đó là thứ duy nhất ở
-- đây không phải một bản vá: nó không cần biết cái gì hỏng.
--
-- ── BA PHỤ THUỘC ĐÃ BỊ GỠ, VÀ VÌ SAO ────────────────────────────────────
--
-- 1. `crypto.subtle` — TREO CỨNG, KHÔNG BÁO LỖI, KHÔNG MỘT GÓI TIN.
--    WebCrypto chỉ tồn tại trong secure context. Bộ sinh config
--    (`nginx/da_to_openresty.sh`) đặt `access_by_lua { antibot.run() }` vào CẢ
--    khối `listen 80`, và khối đó KHÔNG chuyển hướng sang HTTPS. Nên khách vào
--    bằng `http://` mà bị thách đố sẽ nhận trang này qua HTTP ⇒ `crypto.subtle`
--    là `undefined` ⇒ `crypto.subtle.digest` NÉM TypeError ngay trong `solve()`
--    ⇒ văng ra khỏi IIFE ⇒ con quay quay mãi. Gỡ bằng SHA-256 thuần JS: không
--    cần secure context, không Promise, không thể bị từ chối. Đổi lại phải TỰ
--    KIỂM bằng vector chuẩn trước khi dùng — một bản SHA-256 sai mà im lặng
--    thì còn tệ hơn.
--
-- 2. `setTimeout(solve, 0)` MỖI LẦN BĂM — đó là cái làm nó "mãi không xong".
--    Trình duyệt ép tối thiểu 4ms sau 5 lớp timer lồng nhau ⇒ 4096 lần băm của
--    độ khó "000" mất >=16 GIÂY. Và khi tab chạy nền thì timer bị hạ xuống
--    1 lần/giây ⇒ 4096 giây = 68 PHÚT. Khách bấm link, chuyển sang app khác
--    trong lúc "verifying", quay lại — vẫn đang quay. Nonce chỉ sống 60s nên
--    về tới nơi là 403, tải lại, lặp lại. Nay băm ĐỒNG BỘ theo lát 30ms: cả
--    vòng ~3 lát, nên chạy nền cũng chỉ ~3 giây.
--
-- 3. `fetch` — không có hạn giờ, và không tồn tại trên WebView cũ.
--    Promise đang chờ mãi thì `.catch` không bao giờ chạy: đổi mạng Wi-Fi/4G,
--    app vào nền, TCP nửa mở. `XMLHttpRequest` có `timeout` sẵn, có điểm dừng
--    tường minh cho mọi kết cục, và chạy ở mọi WebView. Một đường, không ranh
--    giới nào để hai nửa hiểu khác nhau.
--
-- ── VÀ MỘT ĐƯỜNG LÙI ĐÃ BỊ GỠ ───────────────────────────────────────────
--
-- `document.referrer` KHÔNG còn được dùng ở bất cứ đâu. Trang này ĐANG Ở chính
-- URL khách yêu cầu, nên `location` là nguồn sự thật duy nhất; referrer thì
-- TRỐNG với đúng nhóm khách vào lần đầu (gõ URL, bookmark, quét QR, mở từ app,
-- quảng cáo `rel=noreferrer`). Giữ nó làm đường lùi nghĩa là vẫn còn một nhánh
-- ném họ về `/`.
function _M.challenge_html(ctx)
    local token      = ctx.token or ""
    local difficulty = ctx.pow and ctx.pow.difficulty or "000"
    local id         = ctx.identity or ctx.fp_light or ""

    -- Attack 3 — Stealth browser / undetected-chromedriver:
    -- JS probe thu thập browser environment fingerprint gửi kèm POST
    -- /antibot/verify. Cross-session: stealth tools randomize canvas mỗi
    -- session → canvas hash thay đổi → inconsistency → flag.
    --
    -- LƯU Ý KHI SỬA ĐOẠN DƯỚI: chuỗi này đi qua `string.format`, nên mọi dấu
    -- `%` phải được viết gấp đôi. Vì vậy JS ở đây KHÔNG dùng toán tử chia dư
    -- (`& 3`, `& 255` thay cho `% 4`, `% 256`). `waf/scripts/contract_test.lua`
    -- mục 6 kiểm điều này — một `%` lẻ sẽ làm cả trang không dựng được.
    return string.format([=[
<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser...</title>
<style>
  body{margin:0;display:flex;align-items:center;justify-content:center;
       min-height:100vh;font-family:sans-serif;background:#f5f5f5;color:#333;}
  .box{text-align:center;padding:2rem;background:#fff;border-radius:8px;
       box-shadow:0 2px 8px rgba(0,0,0,.1);max-width:340px;width:90%%;}
  #sp{width:36px;height:36px;border:3px solid #e0e0e0;
      border-top-color:#555;border-radius:50%%;
      animation:spin .8s linear infinite;margin:1rem auto;}
  @keyframes spin{to{transform:rotate(360deg)}}
  #msg{font-size:14px;color:#666;margin-top:.5rem;}
  #err{font-size:13px;color:#c0392b;margin-top:.75rem;display:none;}
  #rt{display:none;margin-top:1rem;padding:.5rem 1.25rem;font-size:14px;
      border:1px solid #999;border-radius:4px;background:#fafafa;color:#333;
      cursor:pointer;}
</style>
</head><body>
<div class="box">
  <div id="sp"></div>
  <p id="msg">Verifying your browser, please wait...</p>
  <p id="err"></p>
  <button id="rt" type="button">Try again</button>
  <noscript>
    <style>#sp{display:none}#msg{display:none}</style>
    <p>JavaScript is required to continue. Please enable it, then reload this page.</p>
  </noscript>
</div>
<script>
(function(){
  var token  = %q;
  var prefix = %q;
  var fp     = %q;

  var WATCHDOG_MS    = 45000;
  var XHR_TIMEOUT_MS = 8000;
  var MAX_ATTEMPTS   = 3;
  var BASE_DELAY_MS  = 1200;
  var MAX_RELOAD     = 2;
  var SLICE_MS       = 30;
  var MAX_ITER       = 4194304;
  var SELFTEST_IN    = 'abc';
  var SELFTEST_OUT   =
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

  var startTime = +new Date();
  var here      = location.pathname + location.search;
  var n         = 0;
  var done      = false;

  var msgEl = document.getElementById('msg');
  var errEl = document.getElementById('err');
  var spEl  = document.getElementById('sp');
  var btEl  = document.getElementById('rt');

  // Lưới cho mọi nguyên nhân CHƯA BIẾT. Đặt trước mọi thứ khác.
  var wd = setTimeout(function(){
    fail('The check did not finish in time.');
  }, WATCHDOG_MS);

  // Số lần tải lại giữ trong COOKIE chứ không phải sessionStorage: Android
  // WebView mặc định TẮT DOM storage, và đó chính là nhóm thiết bị hay treo
  // nhất. Cookie thì cả luồng này vốn đã phải dựa vào rồi.
  function tries(){
    var m = document.cookie.match(/(?:^|; )ab_try=(\d+)/);
    return m ? (parseInt(m[1], 10) || 0) : 0;
  }
  function setTries(v){
    document.cookie = 'ab_try=' + v + '; Path=/; Max-Age=600; SameSite=Lax';
  }
  function clearTries(){
    document.cookie = 'ab_try=; Path=/; Max-Age=0; SameSite=Lax';
  }

  function finish(url){
    if (done) return;
    done = true;
    clearTimeout(wd);
    clearTries();
    location.replace(url);
  }

  function fail(reason){
    if (done) return;
    done = true;
    clearTimeout(wd);
    if (spEl) spEl.style.display = 'none';
    msgEl.textContent = 'Could not verify your browser.';
    errEl.textContent = reason;
    errEl.style.display = 'block';
    btEl.style.display  = 'inline-block';
  }

  // Tải lại CÓ TRẦN. Không trần thì 403 lặp vô hạn trong lúc người dùng nhìn
  // thấy một con quay không đổi.
  function again(reason){
    var t = tries();
    if (t >= MAX_RELOAD) { fail(reason + ' Please try again.'); return; }
    setTries(t + 1);
    msgEl.textContent = reason + ' Retrying...';
    setTimeout(function(){ location.reload(); }, 1200);
  }

  btEl.onclick = function(){ clearTries(); location.reload(); };

  // ── SHA-256 thuần JS ────────────────────────────────────────────
  // Đầu vào luôn là ASCII: token là chuỗi hex, n là chữ số. Nên không cần
  // bộ mã hoá byte nào, `charCodeAt & 255` đã là đúng byte cần băm.
  var K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var HEX = '0123456789abcdef';

  function sha256hex(s){
    var H0=0x6a09e667,H1=0xbb67ae85,H2=0x3c6ef372,H3=0xa54ff53a,
        H4=0x510e527f,H5=0x9b05688c,H6=0x1f83d9ab,H7=0x5be0cd19;
    var len=s.length, nb=((len+8)>>6)+1, M=new Array(nb<<4), i, t, b;
    for(i=0;i<M.length;i++) M[i]=0;
    for(i=0;i<len;i++) M[i>>2] |= (s.charCodeAt(i)&255) << (24-((i&3)<<3));
    M[len>>2] |= 128 << (24-((len&3)<<3));
    M[(nb<<4)-1] = len<<3;
    var W=new Array(64);
    for(b=0;b<nb;b++){
      var o=b<<4;
      for(t=0;t<16;t++) W[t]=M[o+t];
      for(t=16;t<64;t++){
        var x=W[t-15], y=W[t-2];
        var s0=((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3);
        var s1=((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10);
        W[t]=(W[t-16]+s0+W[t-7]+s1)|0;
      }
      var a=H0,c1=H1,c=H2,d=H3,e=H4,f=H5,g=H6,h=H7;
      for(t=0;t<64;t++){
        var S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
        var T1=(h+S1+((e&f)^(~e&g))+K[t]+W[t])|0;
        var S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
        var T2=(S0+((a&c1)^(a&c)^(c1&c)))|0;
        h=g;g=f;f=e;e=(d+T1)|0;d=c;c=c1;c1=a;a=(T1+T2)|0;
      }
      H0=(H0+a)|0;H1=(H1+c1)|0;H2=(H2+c)|0;H3=(H3+d)|0;
      H4=(H4+e)|0;H5=(H5+f)|0;H6=(H6+g)|0;H7=(H7+h)|0;
    }
    var out='', v=[H0,H1,H2,H3,H4,H5,H6,H7];
    for(i=0;i<8;i++){
      var w=v[i];
      for(t=28;t>=0;t-=4) out += HEX.charAt((w>>>t)&15);
    }
    return out;
  }

  // Attack 3: Browser environment probe.
  // Values are stable on a real browser, randomized on stealth tools.
  function collectEnv(){
    var env = {cv:'err', pt:'-1', hw:'0', dp:'10', cd:'0', st:'0'};
    try {
      var cv = document.createElement('canvas');
      cv.width = 200; cv.height = 50;
      var cx = cv.getContext('2d');
      cx.textBaseline = 'top';
      cx.font = '14px Arial';
      cx.fillStyle = '#f60';
      cx.fillRect(125, 1, 62, 20);
      cx.fillStyle = '#069';
      cx.fillText('antibot❤', 2, 15);
      cx.fillStyle = 'rgba(102,204,0,0.7)';
      cx.fillText('antibot❤', 4, 17);
      env.cv = cv.toDataURL().slice(-32);
    } catch(e) {}
    try {
      var t0 = performance.now();
      var t1 = performance.now();
      env.pt = ((t1 - t0) * 1000 | 0).toString();
    } catch(e) {}
    try {
      env.hw = (navigator.hardwareConcurrency || 0).toString();
      env.dp = (Math.round((window.devicePixelRatio || 1) * 10)).toString();
      env.cd = (screen.colorDepth || 0).toString();
    } catch(e) {}
    env.st = startTime.toString();
    return env;
  }

  // Tự dựng chuỗi thân, không mượn lớp dựng sẵn nào: mỗi phụ thuộc là một
  // nhánh nữa có thể ném lỗi rồi treo im lặng trên WebView cũ.
  function buildBody(solveMs, env){
    var f = [
      ['token', token], ['n', String(n)], ['fp', fp],
      ['cv', env.cv],   ['pt', env.pt],   ['hw', env.hw],
      ['dp', env.dp],   ['cd', env.cd],   ['st', env.st],
      ['sm', solveMs],
      // `dest` — ĐÍCH ĐẾN THẬT, gửi tường minh. Chỉ gửi ĐƯỜNG DẪN, không gửi
      // cả URL: `origin` do client gửi thì không có gì máy chủ chưa biết, còn
      // nhận nó vào là mở một open redirect.
      ['dest', here]
    ];
    var out = [];
    for (var i = 0; i < f.length; i++) {
      out.push(encodeURIComponent(f[i][0]) + '=' + encodeURIComponent(f[i][1]));
    }
    return out.join('&');
  }

  function retry(body, attempt, reason){
    if (attempt >= MAX_ATTEMPTS) { fail(reason + '.'); return; }
    var delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
    msgEl.textContent = reason + '. Retrying in ' +
                        Math.round(delay / 1000) + 's...';
    setTimeout(function(){ submit(body, attempt + 1); }, delay);
  }

  function submit(body, attempt){
    if (done) return;
    msgEl.textContent = (attempt > 1)
      ? ('Retrying... (' + attempt + '/' + MAX_ATTEMPTS + ')')
      : 'Verifying...';

    var xhr;
    try { xhr = new XMLHttpRequest(); }
    catch(e) { fail('This browser cannot submit the check.'); return; }

    var settled = false;
    try {
      xhr.open('POST', '/antibot/verify', true);
      xhr.timeout = XHR_TIMEOUT_MS;
      xhr.setRequestHeader('Content-Type',
                           'application/x-www-form-urlencoded');
    } catch(e) { fail('This browser cannot submit the check.'); return; }

    // MỘT điểm xử lý cho MỌI kết cục. Quá hạn cũng đưa về readyState 4 với
    // status 0, giống hệt lỗi mạng — nên không có nhánh nào không được đếm.
    xhr.onreadystatechange = function(){
      if (xhr.readyState !== 4 || settled || done) return;
      settled = true;
      var st = xhr.status;
      if (st === 0) { retry(body, attempt, 'Network error'); return; }
      if (st >= 200 && st < 300) {
        var dest = here;
        try {
          var d = JSON.parse(xhr.responseText);
          if (d && d.dest) dest = d.dest;
        } catch(e) {}
        finish(dest + location.hash);
        return;
      }
      // 400/403 = PoW sai hoặc nonce hết hạn. Tải lại — nhưng CÓ TRẦN.
      if (st === 400 || st === 403) { again('Verification failed.'); return; }
      retry(body, attempt, 'Server error (' + st + ')');
    };

    try { xhr.send(body); }
    catch(e) { retry(body, attempt, 'Could not send'); }
  }

  // Băm ĐỒNG BỘ theo lát thời gian. Yếu tố quyết định không phải "nhanh hơn"
  // mà là KHÔNG NHƯỜNG QUYỀN CHO TIMER giữa mỗi lần băm — đó là chỗ trần 4ms
  // và việc hạ timer khi chạy nền biến 4096 lần băm thành hàng chục phút.
  function work(){
    if (done) return;
    var t0 = +new Date();
    while (n < MAX_ITER) {
      if (sha256hex(token + n).indexOf(prefix) === 0) {
        var env     = collectEnv();
        var solveMs = ((+new Date()) - startTime).toString();
        submit(buildBody(solveMs, env), 1);
        return;
      }
      n++;
      if ((n & 255) === 0 && ((+new Date()) - t0) > SLICE_MS) {
        setTimeout(work, 0);
        return;
      }
    }
    fail('Could not complete the check on this device.');
  }

  // Tự kiểm trước khi dùng. Một bản SHA-256 sai mà im lặng còn tệ hơn treo:
  // nó sẽ gửi lên lời giải không hợp lệ và ăn 403 mãi mãi.
  if (sha256hex(SELFTEST_IN) !== SELFTEST_OUT) {
    fail('This browser cannot run the verification check.');
  } else {
    work();
  }
})();
</script>
</body></html>
]=], token, difficulty, id)
end

return _M
