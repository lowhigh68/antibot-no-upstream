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

    ngx.status = 200
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.say(_M.challenge_html(ctx))
    ngx.exit(200)
    return true
end

function _M.challenge_html(ctx)
    local token      = ctx.token or ""
    local difficulty = ctx.pow and ctx.pow.difficulty or "000"
    local id         = ctx.identity or ctx.fp_light or ""

    -- Attack 3 — Stealth browser / undetected-chromedriver:
    -- JS probe thu thập browser environment fingerprint gửi kèm POST /antibot/verify.
    -- Cross-session: stealth tools randomize canvas mỗi session
    -- → canvas hash thay đổi → inconsistency → flag.
    --
    -- Network resilience — Fix tình huống mất mạng / rớt gói:
    -- Thay f.submit() bằng fetch() với exponential backoff retry.
    -- Lý do: f.submit() không có callback, không retry, không feedback
    -- → user bị kẹt màn hình "Verifying..." vĩnh viễn khi POST bị drop.
    -- fetch() cho phép bắt lỗi mạng và retry tự động tối đa MAX_ATTEMPTS lần.
    -- Referer được lưu trước khi submit để redirect đúng trang sau khi verify.

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
  .spinner{width:36px;height:36px;border:3px solid #e0e0e0;
           border-top-color:#555;border-radius:50%%;
           animation:spin .8s linear infinite;margin:1rem auto;}
  @keyframes spin{to{transform:rotate(360deg)}}
  #msg{font-size:14px;color:#666;margin-top:.5rem;}
  #err{font-size:13px;color:#c0392b;margin-top:.75rem;display:none;}
</style>
</head><body>
<div class="box">
  <div class="spinner"></div>
  <p id="msg">Verifying your browser, please wait...</p>
  <p id="err"></p>
</div>
<script>
(function(){
  var token     = %q;
  var prefix    = %q;
  var fp        = %q;
  var n         = 0;
  var startTime = Date.now();

  var MAX_ATTEMPTS  = 4;
  var BASE_DELAY_MS = 1200;

  var msgEl = document.getElementById('msg');
  var errEl = document.getElementById('err');

  var returnUrl = (document.referrer && document.referrer !== '')
                ? document.referrer
                : '/';

  function toHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(function(b){ return ('0'+b.toString(16)).slice(-2); })
      .join('');
  }

  // Attack 3: Browser environment probe.
  // Values are stable on a real browser, randomized on stealth tools.
  function collectEnv() {
    var env = {};

    // Canvas fingerprint — stealth tools randomize → hash changes each session
    try {
      var cv = document.createElement('canvas');
      cv.width = 200; cv.height = 50;
      var cx = cv.getContext('2d');
      cx.textBaseline = 'top';
      cx.font = '14px Arial';
      cx.fillStyle = '#f60';
      cx.fillRect(125, 1, 62, 20);
      cx.fillStyle = '#069';
      cx.fillText('antibot\u2764', 2, 15);
      cx.fillStyle = 'rgba(102,204,0,0.7)';
      cx.fillText('antibot\u2764', 4, 17);
      env.cv = cv.toDataURL().slice(-32);
    } catch(e) { env.cv = 'err'; }

    // performance.now() resolution — stealth tools often return rounded integers
    try {
      var t0 = performance.now();
      var t1 = performance.now();
      env.pt = ((t1 - t0) * 1000 | 0).toString();
    } catch(e) { env.pt = '-1'; }

    env.hw = (navigator.hardwareConcurrency || 0).toString();
    env.dp = (Math.round((window.devicePixelRatio || 1) * 10)).toString();
    env.cd = (screen.colorDepth || 0).toString();
    env.st = startTime.toString();
    return env;
  }

  // Build URLSearchParams payload once PoW is solved.
  function buildBody(solveMs, env) {
    var body = new URLSearchParams();
    var fields = [
      ['token', token], ['n', String(n)], ['fp', fp],
      ['cv', env.cv],   ['pt', env.pt],   ['hw', env.hw],
      ['dp', env.dp],   ['cd', env.cd],   ['st', env.st],
      ['sm', solveMs]
    ];
    fields.forEach(function(p){ body.append(p[0], p[1]); });
    return body;
  }

  // Submit with fetch + exponential backoff retry.
  // attempt: 1-based attempt counter.
  function submit(body, attempt) {
    if (attempt > 1) {
      msgEl.textContent = 'Retrying... (' + attempt + '/' + MAX_ATTEMPTS + ')';
    }

    fetch('/antibot/verify', {
      method:      'POST',
      body:        body,
      credentials: 'same-origin',
      headers:     { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
    .then(function(r) {
      // 302 redirect means verified — follow to returnUrl.
      if (r.redirected) {
        window.location.href = r.url;
        return;
      }
      // 200 with Location header set in some proxy configs.
      var loc = r.headers.get('Location');
      if (loc) {
        window.location.href = loc;
        return;
      }
      if (r.ok || r.status === 302 || r.status === 200) {
        window.location.href = returnUrl;
        return;
      }
      // 403/400 = PoW invalid or nonce expired — do not retry, reload page.
      if (r.status === 403 || r.status === 400) {
        msgEl.textContent = 'Verification failed. Reloading...';
        setTimeout(function(){ window.location.reload(); }, 1500);
        return;
      }
      // 5xx or unexpected — retry if attempts remain.
      handleRetry(body, attempt, 'Server error (' + r.status + ')');
    })
    .catch(function(e) {
      // Network error (connection dropped, DNS fail, timeout).
      handleRetry(body, attempt, 'Network error');
    });
  }

  function handleRetry(body, attempt, reason) {
    if (attempt >= MAX_ATTEMPTS) {
      errEl.style.display = 'block';
      errEl.textContent   = reason + '. Please refresh the page.';
      msgEl.textContent   = 'Verification could not complete.';
      return;
    }
    // Exponential backoff: 1.2s, 2.4s, 4.8s
    var delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
    msgEl.textContent = reason + '. Retrying in ' +
                        Math.round(delay / 1000) + 's...';
    setTimeout(function(){ submit(body, attempt + 1); }, delay);
  }

  function solve() {
    var data = new TextEncoder().encode(token + n);
    crypto.subtle.digest('SHA-256', data).then(function(buf) {
      var h = toHex(buf);
      if (h.indexOf(prefix) === 0) {
        var env     = collectEnv();
        var solveMs = (Date.now() - startTime).toString();
        var body    = buildBody(solveMs, env);
        msgEl.textContent = 'Verifying...';
        submit(body, 1);
      } else {
        n++;
        setTimeout(solve, 0);
      }
    });
  }

  solve();
})();
</script>
</body></html>
]=], token, difficulty, id)
end

return _M
