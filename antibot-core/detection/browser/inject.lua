local _M = {}

local BEACON_JS = [[
<script>
(function(){
  var fp="%s";
  try{
    // Canvas fingerprint
    var c=document.createElement('canvas');
    var g=c.getContext('2d');
    g.textBaseline='top';
    g.font='14px Arial';
    g.fillText('antibot beacon \u{1F916}',2,2);
    var cv=c.toDataURL().slice(-50);

    // WebGL renderer
    var gl=c.getContext('webgl')||c.getContext('experimental-webgl');
    var wgl='';
    if(gl){var ext=gl.getExtension('WEBGL_debug_renderer_info');
      if(ext)wgl=gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)||'';}

    // Navigator entropy signals
    var nav={
      lang:navigator.language,
      tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
      plat:navigator.platform,
      cores:navigator.hardwareConcurrency,
      mem:navigator.deviceMemory,
      plugins:navigator.plugins.length,
      touch:'ontouchstart' in window
    };

    // Audio fingerprint (async, best effort)
    var ent=0;
    try{var ac=new(window.AudioContext||window.webkitAudioContext)();
      var osc=ac.createOscillator();var an=ac.createAnalyser();
      osc.connect(an);an.connect(ac.destination);
      osc.start(0);var arr=new Float32Array(an.frequencyBinCount);
      an.getFloatFrequencyData(arr);
      ent=arr.reduce(function(s,v){return s+Math.abs(v);},0)/arr.length;
      osc.stop();ac.close();}catch(e){}

    // POST beacon
    fetch('/antibot/beacon',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({fp:fp,cv:cv,wgl:wgl,nav:nav,ent:ent}),
      credentials:'same-origin'
    });
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
        local fp    = ctx.fp_light or ""
        local script= BEACON_JS:format(fp)
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
