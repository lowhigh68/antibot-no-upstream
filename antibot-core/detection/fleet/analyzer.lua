local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

-- Analyzer — 3-axis evaluation at BOTH /24 and /16 granularities.
--
-- Runs on a periodic timer (cfg.fleet_detection.timing.evaluator_period s).
-- For each closed-window minute bucket, iterates `fl:active:24:<min>` and
-- `fl:active:16:<min>` sets and computes the same axis triple at each
-- prefix length:
--
--   fp_poverty       = clamp(distinct_IPs / distinct_fp / 20, 0, 1)
--   path_convergence = (sum top-3 zset scores) / total_hits
--   cookie_vacuum    = 1 - max(verified, has_cookie) / total_hits
--
-- Score gates:
--   ≥ confirm  → fl:flag:<scope>:<cidr> = "confirm"
--   ≥ suspect  → fl:flag:<scope>:<cidr> = "suspect"
--   else       → clear flag
--
-- Why evaluate /16 directly (in addition to /24 roll-up):
-- rotation attacks (43.172/15 case) spread thin per /24 — each /24 may see
-- only 5-15 hits per minute, below the /24 min_hits floor. The /16 prefix
-- aggregates 256 /24s and reliably crosses min_hits_16 even under heavy
-- rotation. fp_poverty at /16 still discriminates: real users in a /16
-- bring many distinct fingerprints (~hundreds of devices), bot fleet
-- collapses to a handful (Chrome version cycling).
--
-- Sustained tracking (enforce mode only): per-cidr counter increments while
-- status stays "confirm", resets otherwise. When counter ≥
-- enforce.sustained_minutes → write fl:dyn:<cidr> dynamic block key.

local function fdcfg() return cfg.fleet_detection or {} end

local function clamp01(v)
    if v < 0 then return 0 end
    if v > 1 then return 1 end
    return v
end

local function n(v)
    if v == nil or v == ngx.null then return 0 end
    return tonumber(v) or 0
end

local function compute_score(hits, d_ips, d_fp, path_zrange, verified, cookies)
    local fdc = fdcfg()
    local w   = fdc.weights or {}
    local wfp = w.fp_poverty or 0.6
    local wpc = w.path_convergence or 0.25
    local wcv = w.cookie_vacuum or 0.15

    local ratio = (d_fp > 0) and (d_ips / d_fp) or 0
    local fp_poverty = clamp01(ratio / 20)

    local top3_sum = 0
    if type(path_zrange) == "table" then
        for i = 2, #path_zrange, 2 do
            top3_sum = top3_sum + (tonumber(path_zrange[i]) or 0)
        end
    end
    local path_convergence = clamp01((hits > 0) and (top3_sum / hits) or 0)

    local with_cookie = math.max(verified, cookies)
    if with_cookie > hits then with_cookie = hits end
    local cookie_vacuum = clamp01(1 - (with_cookie / hits))

    local score = fp_poverty * wfp + path_convergence * wpc + cookie_vacuum * wcv
    return score, {
        fp_poverty       = fp_poverty,
        path_convergence = path_convergence,
        cookie_vacuum    = cookie_vacuum,
        hits             = hits,
        distinct_ips     = d_ips,
        distinct_fp      = d_fp,
    }
end

local function status_for(score)
    local thr = fdcfg().thresholds or {}
    local suspect = thr.suspect or 0.5
    local confirm = thr.confirm or 0.7
    if score >= confirm then return "confirm" end
    if score >= suspect then return "suspect" end
    return nil
end

-- Read previous-minute bucket for a /24 → (status, score, axes).
local function evaluate_24(red, cidr, minute)
    local fdc = fdcfg()
    local thr = fdc.thresholds or {}
    local min_hits = thr.min_hits or 30

    local k_hit  = "fl:24:hit:"  .. cidr .. ":" .. minute
    local k_ips  = "fl:24:ips:"  .. cidr .. ":" .. minute
    local k_fp   = "fl:24:fp:"   .. cidr .. ":" .. minute
    local k_path = "fl:24:path:" .. cidr .. ":" .. minute
    local k_ver  = "fl:24:ver:"  .. cidr .. ":" .. minute
    local k_ck   = "fl:24:ck:"   .. cidr .. ":" .. minute

    red:init_pipeline()
    red:get(k_hit)
    red:pfcount(k_ips)
    red:pfcount(k_fp)
    red:zrevrange(k_path, 0, 2, "WITHSCORES")
    red:get(k_ver)
    red:get(k_ck)
    local res, perr = red:commit_pipeline()
    if not res then
        ngx.log(ngx.WARN, "[fleet.analyzer] read24 err: ", tostring(perr))
        return nil, 0, nil
    end

    local hits = n(res[1])
    if hits < min_hits then return nil, 0, nil end
    local score, axes = compute_score(hits, n(res[2]), n(res[3]),
                                      res[4], n(res[5]), n(res[6]))
    return status_for(score), score, axes
end

-- Same but for a /16.
local function evaluate_16(red, cidr, minute)
    local fdc = fdcfg()
    local thr = fdc.thresholds or {}
    local min_hits = thr.min_hits_16 or 50

    local k_hit  = "fl:16:hit:"  .. cidr .. ":" .. minute
    local k_ips  = "fl:16:ips:"  .. cidr .. ":" .. minute
    local k_fp   = "fl:16:fp:"   .. cidr .. ":" .. minute
    local k_path = "fl:16:path:" .. cidr .. ":" .. minute
    local k_ver  = "fl:16:ver:"  .. cidr .. ":" .. minute
    local k_ck   = "fl:16:ck:"   .. cidr .. ":" .. minute

    red:init_pipeline()
    red:get(k_hit)
    red:pfcount(k_ips)
    red:pfcount(k_fp)
    red:zrevrange(k_path, 0, 2, "WITHSCORES")
    red:get(k_ver)
    red:get(k_ck)
    local res, perr = red:commit_pipeline()
    if not res then
        ngx.log(ngx.WARN, "[fleet.analyzer] read16 err: ", tostring(perr))
        return nil, 0, nil
    end

    local hits = n(res[1])
    if hits < min_hits then return nil, 0, nil end
    local score, axes = compute_score(hits, n(res[2]), n(res[3]),
                                      res[4], n(res[5]), n(res[6]))
    return status_for(score), score, axes
end

-- Generic flag writer. scope = "24" or "16".
local function write_flag(red, scope, cidr, status, score, axes, flag_ttl, parent_16)
    red:init_pipeline()
    if status then
        red:setex("fl:flag:"  .. scope .. ":" .. cidr, flag_ttl, status)
        red:setex("fl:score:" .. scope .. ":" .. cidr, flag_ttl, string.format("%.3f", score))
        red:setex("fl:axis:fp:"  .. cidr, flag_ttl, string.format("%.3f", axes.fp_poverty))
        red:setex("fl:axis:path:".. cidr, flag_ttl, string.format("%.3f", axes.path_convergence))
        red:setex("fl:axis:ck:"  .. cidr, flag_ttl, string.format("%.3f", axes.cookie_vacuum))
        red:setex("fl:last:hits:".. cidr, flag_ttl, tostring(axes.hits))
        red:setex("fl:last:ips:" .. cidr, flag_ttl, tostring(axes.distinct_ips))
        red:setex("fl:last:fp:"  .. cidr, flag_ttl, tostring(axes.distinct_fp))
        red:setnx("fl:first:"    .. cidr, tostring(ngx.time()))
        red:expire("fl:first:"   .. cidr, flag_ttl)
        if scope == "24" and status == "confirm" and parent_16 then
            red:sadd("fl:rollup:set:" .. parent_16, cidr)
            red:expire("fl:rollup:set:" .. parent_16, flag_ttl)
        end
    else
        red:del("fl:flag:"  .. scope .. ":" .. cidr)
        red:del("fl:score:" .. scope .. ":" .. cidr)
    end
    local _, perr = red:commit_pipeline()
    if perr then
        ngx.log(ngx.WARN, "[fleet.analyzer] flag pipeline err: ", tostring(perr))
    end
end

local function parent_16_of(cidr_24)
    local a, b = cidr_24:match("^(%d+)%.(%d+)%.")
    if not a then return nil end
    return a .. "." .. b .. ".0.0/16"
end

local function update_sustained(red, cidr, status, sustained_target, dyn_ttl, scope)
    local skey = "fl:sustained:" .. cidr
    if status == "confirm" then
        red:init_pipeline()
        red:incr(skey)
        red:expire(skey, 180)  -- gap > 3 min breaks streak
        local res = red:commit_pipeline()
        local cnt = (res and tonumber(res[1])) or 0
        if cnt >= sustained_target then
            local info = string.format("auto:scope=%s:sustained=%d:t=%d",
                                       scope or "?", cnt, ngx.time())
            pool.safe_set("fl:dyn:" .. cidr, info, dyn_ttl)
            ngx.log(ngx.WARN, "[fleet.analyzer] DYN BLOCK ", cidr,
                    " scope=", tostring(scope),
                    " sustained=", cnt, "min ttl=", dyn_ttl)
        end
    else
        red:del(skey)
    end
end

-- Single evaluation pass over previous-minute bucket.
function _M.evaluate()
    local fdc = fdcfg()
    local timing = fdc.timing or {}
    local flag_ttl = timing.flag_ttl or 300
    local dyn_ttl  = timing.dyn_block_ttl or 3600
    local enforce_cfg = fdc.enforce or {}
    local rollup_cfg  = fdc.rollup or {}
    local rollup_min  = rollup_cfg.min_24s_per_16 or 3
    local sustained_target = enforce_cfg.sustained_minutes or 5
    local mode = fdc.mode or "shadow"

    local minute = math.floor(ngx.time() / 60) - 1   -- closed window

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[fleet.analyzer] redis err: ", tostring(err))
        return
    end

    -- ── /24 pass ──────────────────────────────────────────────────
    local active_24, smerr = red:smembers("fl:active:24:" .. minute)
    if smerr then
        ngx.log(ngx.WARN, "[fleet.analyzer] smembers24 err: ", tostring(smerr))
    end
    if not active_24 or active_24 == ngx.null then active_24 = {} end

    local n_eval_24, n_conf_24, n_susp_24, n_skip_24 = 0, 0, 0, 0
    local rollup_pending = {}

    for _, cidr_24 in ipairs(active_24) do
        local status, score, axes = evaluate_24(red, cidr_24, minute)
        if axes == nil then
            n_skip_24 = n_skip_24 + 1
        else
            n_eval_24 = n_eval_24 + 1
            if status == "confirm" then n_conf_24 = n_conf_24 + 1 end
            if status == "suspect" then n_susp_24 = n_susp_24 + 1 end
        end
        local p16 = parent_16_of(cidr_24)
        write_flag(red, "24", cidr_24, status, score, axes or {}, flag_ttl, p16)

        if mode == "enforce" then
            update_sustained(red, cidr_24, status, sustained_target, dyn_ttl, "24")
        end

        if status == "confirm" and p16 then
            rollup_pending[p16] = true
        end
    end

    -- ── /16 pass (direct evaluation) ──────────────────────────────
    local active_16, smerr16 = red:smembers("fl:active:16:" .. minute)
    if smerr16 then
        ngx.log(ngx.WARN, "[fleet.analyzer] smembers16 err: ", tostring(smerr16))
    end
    if not active_16 or active_16 == ngx.null then active_16 = {} end

    local n_eval_16, n_conf_16, n_susp_16, n_skip_16 = 0, 0, 0, 0
    for _, cidr_16 in ipairs(active_16) do
        local status, score, axes = evaluate_16(red, cidr_16, minute)
        if axes == nil then
            n_skip_16 = n_skip_16 + 1
        else
            n_eval_16 = n_eval_16 + 1
            if status == "confirm" then n_conf_16 = n_conf_16 + 1 end
            if status == "suspect" then n_susp_16 = n_susp_16 + 1 end
        end
        write_flag(red, "16", cidr_16, status, score, axes or {}, flag_ttl, nil)

        if mode == "enforce" then
            update_sustained(red, cidr_16, status, sustained_target, dyn_ttl, "16")
        end
    end

    -- ── /16 roll-up: dyn block any /16 with ≥ rollup_min confirmed /24s ──
    -- (Independent of /16 direct evaluation above — a /16 may roll up even
    --  if its own aggregate score didn't cross confirm, because multiple
    --  /24 hot-spots are themselves enough evidence.)
    for cidr_16, _ in pairs(rollup_pending) do
        local n_confirmed = red:scard("fl:rollup:set:" .. cidr_16)
        n_confirmed = tonumber(n_confirmed) or 0
        red:init_pipeline()
        red:setex("fl:rollup:count:" .. cidr_16, flag_ttl, tostring(n_confirmed))
        if n_confirmed >= rollup_min then
            red:setex("fl:flag:16:" .. cidr_16, flag_ttl, "confirm")
            red:setnx("fl:first:16:" .. cidr_16, tostring(ngx.time()))
            red:expire("fl:first:16:" .. cidr_16, flag_ttl)
            if mode == "enforce" then
                local info = string.format("auto:rollup_16=%d:t=%d",
                                           n_confirmed, ngx.time())
                red:setex("fl:dyn:" .. cidr_16, dyn_ttl, info)
                ngx.log(ngx.WARN, "[fleet.analyzer] DYN BLOCK rollup ", cidr_16,
                        " confirmed_24=", n_confirmed)
            end
        end
        local _, perr = red:commit_pipeline()
        if perr then
            ngx.log(ngx.WARN, "[fleet.analyzer] rollup pipeline err: ", tostring(perr))
        end
    end

    pool.put(red)

    ngx.log(ngx.WARN,
        "[fleet.analyzer] cycle min=", minute,
        " /24 active=", #active_24,
        " eval=", n_eval_24,
        " skip=", n_skip_24,
        " confirm=", n_conf_24,
        " suspect=", n_susp_24,
        " | /16 active=", #active_16,
        " eval=", n_eval_16,
        " skip=", n_skip_16,
        " confirm=", n_conf_16,
        " suspect=", n_susp_16,
        " mode=", mode)
end

return _M
