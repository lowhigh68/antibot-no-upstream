local _M = {}

-- Two %s placeholders: (1) endpoint path, (2) fingerprint token.
-- Field names are obfuscated to raise the bar for scraper adaptation:
--   p=fp, a=cv, b=wgl, c=nav, d=ent, e=hd, f=beh, t=timestamp(ms)
-- Headless signals (hd) and behavioral biometrics (beh) collected before
-- fetch fires after a 2s delay to capture interaction window.
local BEACON_JS = [[
<script>
(function(){
  var ep="%s",fp="%s";
  try{
    var c=document.createElement('canvas');
    var g=c.getContext('2d');
    g.textBaseline='top';g.font='14px Arial';
    g.fillText('antibot beacon \u{1F916}',2,2);
    var cv=c.toDataURL().slice(-50);

    var gl=c.getContext('webgl')||c.getContext('experimental-webgl');
    var wgl='';
    if(gl){var ex=gl.getExtension('WEBGL_debug_renderer_info');
      if(ex)wgl=gl.getParameter(ex.UNMASKED_RENDERER_WEBGL)||'';}

    var nav={
      lang:navigator.language,
      tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
      plat:navigator.platform,
      cores:navigator.hardwareConcurrency,
      mem:navigator.deviceMemory,
      plugins:navigator.plugins.length,
      touch:'ontouchstart' in window
    };

    var ent=0;
    try{var ac=new(window.AudioContext||window.webkitAudioContext)();
      var osc=ac.createOscillator();var an=ac.createAnalyser();
      osc.connect(an);an.connect(ac.destination);
      osc.start(0);var arr=new Float32Array(an.frequencyBinCount);
      an.getFloatFrequencyData(arr);
      ent=arr.reduce(function(s,v){return s+Math.abs(v);},0)/arr.length;
      osc.stop();ac.close();}catch(e){}

    var hd={
      wd:navigator.webdriver?1:0,
      da:(window.domAutomation||window.domAutomationController)?1:0,
      cfl:(function(){if(typeof window.chrome==='undefined')return 2;
        return window.chrome.runtime?0:1;})(),
      langs:(navigator.languages||[]).length,
      sw:screen.width,sh:screen.height,
      nfn:(Function.prototype.toString.call(window.alert).indexOf('[native code]')>=0)?0:1
    };

    var beh={mm:0,sc:0,kp:0,td:0};
    document.addEventListener('mousemove',function(){beh.mm++;},{passive:true});
    document.addEventListener('scroll',function(){beh.sc++;},{passive:true});
    document.addEventListener('keypress',function(){beh.kp++;},{passive:true});

    setTimeout(function(){
      var t0=performance.timeOrigin||(performance.timing&&performance.timing.navigationStart)||0;
      beh.td=t0>0?Math.round(Date.now()-t0):0;
      fetch(ep,{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({p:fp,a:cv,b:wgl,c:nav,d:ent,e:hd,f:beh,t:Date.now()}),
        credentials:'same-origin'
      });
    },2000);
  }catch(e){}
})();
</script>
]]

-- filter() is called from body_filter_by_lua_block.
-- Reads ctx.browser_needed — the CONFIRMED state set by header_filter_by_lua_block
-- after verifying the actual upstream response Content-Type is text/html.
-- This is intentionally different from inject_candidate (tentative, request-phase).
-- If browser_needed is nil here it means either:
--   a) inject_candidate was never set (request not HTML-wanting), or
--   b) inject_candidate was set but header_filter saw a non-HTML Content-Type response.
-- In both cases: correct behaviour — do not inject.
function _M.filter()
    local ctx = ngx.ctx.antibot
    if not ctx or not ctx.browser_needed then return end

    local chunk = ngx.arg[1]
    local eof   = ngx.arg[2]

    if eof and chunk then
        local fp       = ctx.fp_light or ""
        local endpoint = (require("antibot.core.config").beacon or {}).endpoint
                         or "/antibot/beacon"
        local script   = BEACON_JS:format(endpoint, fp)
        local inject_pos = chunk:find("</body>")
        if inject_pos then
            ngx.arg[1] = chunk:sub(1, inject_pos-1) .. script
                       .. chunk:sub(inject_pos)
        else
            ngx.arg[1] = chunk .. script
        end
    end
end

-- run() is called from browser/init.lua in the access phase pipeline,
-- gated by inject_candidate (tentative flag).
-- Only purpose: emit a debug log entry so the access-phase decision is visible
-- in nginx error.log when antibot_debug="1".
function _M.run(ctx)
    if ctx.inject_candidate then
        ngx.log(ngx.DEBUG, "[browser] inject_candidate=true, awaiting response ct confirm fp=", ctx.fp_light)
    end
end

return _M
