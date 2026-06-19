local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

-- Analyzer — 3-axis evaluation, flag set, /16 roll-up, sustained tracking.
--
-- Runs on a periodic timer (cfg.fleet_detection.timing.evaluator_period s).
-- Reads the PREVIOUS minute bucket (closed window) per active /24, computes:
--
--   fp_poverty       = clamp((distinct_IPs / distinct_fp) / 20, 0, 1)
--   path_convergence = (sum top-3 zset scores) / total_hits
--   cookie_vacuum    = 1 - (verified + has_cookie) / total_hits
--                       (clamped so verified+ck > hits doesn't over-shoot)
--
-- Final score = weighted sum per cfg.fleet_detection.weights.
--
-- Score gates:
--   ≥ confirm  → fl:flag:24:<cidr> = "confirm"  (TTL flag_ttl)
--   ≥ suspect  → fl:flag:24:<cidr> = "suspect"
--   else       → clear flag
--
-- /16 roll-up: for each /16 with ≥ rollup.min_24s_per_16 confirmed /24 in
-- the window → fl:flag:16:<cidr_16> = "confirm".
--
-- Sustained tracking (enforce mode only): track consecutive minutes a /24
-- stays in "confirm" via fl:sustained:<cidr> counter. When counter ≥
-- enforce.sustained_minutes → write fl:dyn:<cidr> dynamic block key.
--
-- Modes:
--   shadow  — write flags + scores, that's it.
--   scoring — same as shadow + score signal consumed by scoring/compute.lua.
--   enforce — same as scoring + auto dyn-block on sustained.

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

-- Evaluate a single /24 against previous-minute bucket.
-- Returns: (status_string, score, axes_table) where status_string is one of
-- "confirm" / "suspect" / nil.
local function evaluate_24(red, cidr, minute)
    local fdc = fdcfg()
    local thr = fdc.thresholds or {}
    local min_hits = thr.min_hits or 100

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
        ngx.log(ngx.WARN, "[fleet.analyzer] read pipeline err: ", tostring(perr))
        return nil, 0, nil
    end

    local hits = n(res[1])
    if hits < min_hits then return nil, 0, nil end

    local d_ips = n(res[2])
    local d_fp  = n(res[3])
    local path_zrange = res[4] or {}
    local verified = n(res[5])
    local cookies  = n(res[6])

    -- Axis 1: fp_poverty
    local ratio = (d_fp > 0) and (d_ips / d_fp) or 0
    local fp_poverty = clamp01(ratio / 20)

    -- Axis 2: path_convergence — sum of top-3 zscores / total_hits
    local top3_sum = 0
    if type(path_zrange) == "table" then
        -- ZREVRANGE ... WITHSCORES returns flat array: { member1, score1, member2, score2, ... }
        for i = 2, #path_zrange, 2 do
            top3_sum = top3_sum + (tonumber(path_zrange[i]) or 0)
        end
    end
    local path_convergence = clamp01((hits > 0) and (top3_sum / hits) or 0)

    -- Axis 3: cookie_vacuum
    -- Combined "has any cookie evidence" = max(verified, cookies) since a
    -- verified user implicitly has cookies. Floor at hits to avoid >1 due
    -- to per-axis double-counting if both increments happen.
    local with_cookie = math.max(verified, cookies)
    if with_cookie > hits then with_cookie = hits end
    local cookie_vacuum = clamp01(1 - (with_cookie / hits))

    local w = fdc.weights or {}
    local wfp = w.fp_poverty or 0.6
    local wpc = w.path_convergence or 0.25
    local wcv = w.cookie_vacuum or 0.15
    local score = fp_poverty * wfp + path_convergence * wpc + cookie_vacuum * wcv

    local suspect = thr.suspect or 0.5
    local confirm = thr.confirm or 0.7

    local status
    if score >= confirm then status = "confirm"
    elseif score >= suspect then status = "suspect"
    end

    local axes = {
        fp_poverty       = fp_poverty,
        path_convergence = path_convergence,
        cookie_vacuum    = cookie_vacuum,
        hits             = hits,
        distinct_ips     = d_ips,
        distinct_fp      = d_fp,
    }
    return status, score, axes
end

local function write_flag(red, cidr, status, score, axes, flag_ttl, parent_16)
    red:init_pipeline()
    if status then
        red:setex("fl:flag:24:"  .. cidr, flag_ttl, status)
        red:setex("fl:score:24:" .. cidr, flag_ttl, string.format("%.3f", score))
        red:setex("fl:axis:fp:"  .. cidr, flag_ttl, string.format("%.3f", axes.fp_poverty))
        red:setex("fl:axis:path:".. cidr, flag_ttl, string.format("%.3f", axes.path_convergence))
        red:setex("fl:axis:ck:"  .. cidr, flag_ttl, string.format("%.3f", axes.cookie_vacuum))
        red:setex("fl:last:hits:".. cidr, flag_ttl, tostring(axes.hits))
        red:setex("fl:last:ips:" .. cidr, flag_ttl, tostring(axes.distinct_ips))
        red:setex("fl:last:fp:"  .. cidr, flag_ttl, tostring(axes.distinct_fp))
        red:setnx("fl:first:"    .. cidr, tostring(ngx.time()))
        red:expire("fl:first:"   .. cidr, flag_ttl)
        if status == "confirm" and parent_16 then
            red:sadd("fl:rollup:set:" .. parent_16, cidr)
            red:expire("fl:rollup:set:" .. parent_16, flag_ttl)
        end
    else
        red:del("fl:flag:24:" .. cidr)
        red:del("fl:score:24:" .. cidr)
        red:del("fl:axis:fp:"  .. cidr)
        red:del("fl:axis:path:".. cidr)
        red:del("fl:axis:ck:"  .. cidr)
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

local function update_sustained(red, cidr, status, sustained_target, dyn_ttl)
    local skey = "fl:sustained:" .. cidr
    if status == "confirm" then
        red:init_pipeline()
        red:incr(skey)
        red:expire(skey, 180)  -- gap > 3 min breaks streak
        local res = red:commit_pipeline()
        local cnt = (res and tonumber(res[1])) or 0
        if cnt >= sustained_target then
            local info = string.format("auto:sustained=%d:t=%d", cnt, ngx.time())
            pool.safe_set("fl:dyn:" .. cidr, info, dyn_ttl)
            ngx.log(ngx.WARN, "[fleet.analyzer] DYN BLOCK ", cidr,
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

    local active_key = "fl:active:24:" .. minute
    local cidrs, smerr = red:smembers(active_key)
    if smerr then
        ngx.log(ngx.WARN, "[fleet.analyzer] smembers err: ", tostring(smerr))
        pool.put(red)
        return
    end
    if not cidrs or cidrs == ngx.null then cidrs = {} end

    -- Track which /16 had confirmed /24 in this minute → rollup eval after.
    local rollup_pending = {}

    for _, cidr_24 in ipairs(cidrs) do
        local status, score, axes = evaluate_24(red, cidr_24, minute)
        local p16 = parent_16_of(cidr_24)
        write_flag(red, cidr_24, status, score, axes or {}, flag_ttl, p16)

        if mode == "enforce" then
            update_sustained(red, cidr_24, status, sustained_target, dyn_ttl)
        end

        if status == "confirm" and p16 then
            rollup_pending[p16] = true
        end
    end

    -- /16 roll-up: count confirmed /24s in fl:rollup:set:<cidr_16>.
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
                local info = string.format("auto:rollup_16=%d:t=%d", n_confirmed, ngx.time())
                red:setex("fl:dyn:" .. cidr_16, dyn_ttl, info)
                ngx.log(ngx.WARN, "[fleet.analyzer] DYN BLOCK /16 ", cidr_16,
                        " confirmed_24=", n_confirmed)
            end
        end
        local _, perr = red:commit_pipeline()
        if perr then
            ngx.log(ngx.WARN, "[fleet.analyzer] rollup pipeline err: ", tostring(perr))
        end
    end

    pool.put(red)
end

return _M
