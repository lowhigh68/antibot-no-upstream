local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

-- Analyzer — 3-axis evaluation at BOTH /24 and /16 granularities, reading
-- 5-minute sliding aggregation buckets written by aggregator.lua.
--
-- Reads previous CLOSED bucket (math.floor(ngx.time() / 300) - 1). Tracks
-- last-evaluated bucket in Redis to dedup repeat evaluations within the
-- 5-min window (analyzer timer fires every 30s but only does real work
-- when a new bucket has closed).
--
-- Axes (same math as before, on cumulative 5-min counters):
--   fp_poverty       = clamp(distinct_IPs / distinct_fp / 20, 0, 1)
--   path_convergence = (sum top-3 zset scores) / total_hits
--   cookie_vacuum    = 1 - max(verified, has_cookie) / total_hits
--
-- Score gates (cfg.fleet_detection.thresholds): suspect/confirm.
--
-- Connection error handling: if Redis pipeline returns "closed" mid-cycle,
-- abort the rest of the cycle (don't burn through 80+ iterations writing
-- identical warnings — see incident 2026-06-19 22:03:40). Next cycle gets
-- a fresh connection.
--
-- Sustained tracking (enforce mode): incremented once per fresh bucket
-- evaluation. cfg.enforce.sustained_minutes is semantically "consecutive
-- closed-bucket confirms" with this 5-min-bucket design. Set to 1 for
-- immediate block on first confirm; raise for more conservative behaviour.

local BUCKET_SECS = 300

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

-- ── Connection-dead flag (per-cycle) ───────────────────────────────────
-- Set when any pipeline commit returns an error containing "closed".
-- Subsequent helpers short-circuit so we don't spam the error log.
local _CONN_DEAD = false

local function note_pipeline_err(perr)
    if perr and tostring(perr):find("closed", 1, true) then
        _CONN_DEAD = true
    end
end

-- ── Score / status helpers ─────────────────────────────────────────────
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

-- ── Bucket read ────────────────────────────────────────────────────────
local function evaluate_prefix(red, scope, cidr, bucket, min_hits)
    if _CONN_DEAD then return nil, 0, nil end

    local p = "fl:" .. scope .. ":"
    red:init_pipeline()
    red:get(p .. "hit:"  .. cidr .. ":" .. bucket)
    red:pfcount(p .. "ips:" .. cidr .. ":" .. bucket)
    red:pfcount(p .. "fp:"  .. cidr .. ":" .. bucket)
    red:zrevrange(p .. "path:" .. cidr .. ":" .. bucket, 0, 2, "WITHSCORES")
    red:get(p .. "ver:" .. cidr .. ":" .. bucket)
    red:get(p .. "ck:"  .. cidr .. ":" .. bucket)
    local res, perr = red:commit_pipeline()
    if not res then
        note_pipeline_err(perr)
        if not _CONN_DEAD then
            ngx.log(ngx.WARN, "[fleet.analyzer] read", scope,
                    " err: ", tostring(perr))
        end
        return nil, 0, nil
    end

    local hits = n(res[1])
    if hits < min_hits then return nil, 0, nil end
    local score, axes = compute_score(hits, n(res[2]), n(res[3]),
                                      res[4], n(res[5]), n(res[6]))
    return status_for(score), score, axes
end

-- ── Flag writer ────────────────────────────────────────────────────────
local function write_flag(red, scope, cidr, status, score, axes, flag_ttl, parent_16)
    if _CONN_DEAD then return end
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
        note_pipeline_err(perr)
        if not _CONN_DEAD then
            ngx.log(ngx.WARN, "[fleet.analyzer] flag pipeline err: ", tostring(perr))
        end
    end
end

local function parent_16_of(cidr_24)
    local a, b = cidr_24:match("^(%d+)%.(%d+)%.")
    if not a then return nil end
    return a .. "." .. b .. ".0.0/16"
end

local function update_sustained(red, cidr, status, sustained_target, dyn_ttl, scope)
    if _CONN_DEAD then return end
    local skey = "fl:sustained:" .. cidr
    if status == "confirm" then
        red:init_pipeline()
        red:incr(skey)
        red:expire(skey, 2 * BUCKET_SECS + 60)  -- gap > 1 bucket breaks streak
        local res, perr = red:commit_pipeline()
        if not res then
            note_pipeline_err(perr)
            return
        end
        local cnt = (res and tonumber(res[1])) or 0
        if cnt >= sustained_target then
            local info = string.format("auto:scope=%s:buckets=%d:t=%d",
                                       scope or "?", cnt, ngx.time())
            pool.safe_set("fl:dyn:" .. cidr, info, dyn_ttl)
            ngx.log(ngx.WARN, "[fleet.analyzer] DYN BLOCK ", cidr,
                    " scope=", tostring(scope),
                    " sustained_buckets=", cnt, " ttl=", dyn_ttl)
        end
    else
        red:del(skey)
    end
end

-- Returns bucket number to evaluate (previous closed bucket) if it hasn't
-- been evaluated yet; otherwise nil (skip cycle).
local function pick_bucket()
    local prev_bucket = math.floor(ngx.time() / BUCKET_SECS) - 1
    local last = tonumber(pool.safe_get("fl:analyzer:last_bucket")) or 0
    if prev_bucket <= last then return nil end
    pool.safe_set("fl:analyzer:last_bucket", tostring(prev_bucket), 2 * BUCKET_SECS)
    return prev_bucket
end

-- ── Fast-path eval (current bucket, partial data) ──────────────────────
-- Runs every analyzer cycle (30s) on the CURRENT still-filling bucket.
-- Targets sub-2-minute detection for heavy attacks instead of waiting for
-- the closed bucket + slow-path. Bypasses sustained counter — fires DYN
-- BLOCK on first confirm because the use case IS rapid response.
--
-- Higher min_hits floors (fast > slow) so partial-bucket statistics stay
-- meaningful. Low-rate attacks that don't accumulate enough in a partial
-- bucket still get caught by the slow path on closed-bucket eval.
local function fast_path_eval(red, mode, dyn_ttl, flag_ttl)
    if mode ~= "enforce" then return 0, 0 end
    if _CONN_DEAD then return 0, 0 end

    local fdc = fdcfg()
    local thr = fdc.thresholds or {}
    local fast_24 = thr.min_hits_fast or 80
    local fast_16 = thr.min_hits_16_fast or 50

    local current = math.floor(ngx.time() / BUCKET_SECS)
    local n_fast_24, n_fast_16 = 0, 0

    -- /16 fast-path first — distributed attacks aggregate cleanest here
    local active_16, err16 = red:smembers("fl:active:16:" .. current)
    if err16 then note_pipeline_err(err16) end
    if active_16 and active_16 ~= ngx.null then
        for _, cidr in ipairs(active_16) do
            if _CONN_DEAD then break end
            local status, score, axes = evaluate_prefix(red, "16", cidr, current, fast_16)
            if status == "confirm" then
                n_fast_16 = n_fast_16 + 1
                local ratio = (axes.distinct_fp > 0)
                    and (axes.distinct_ips / axes.distinct_fp) or 0
                local info = string.format(
                    "auto:fast=16:hits=%d:ips=%d:fp=%d:ratio=%.1f:t=%d",
                    axes.hits, axes.distinct_ips, axes.distinct_fp,
                    ratio, ngx.time())
                pool.safe_set("fl:dyn:" .. cidr, info, dyn_ttl)
                write_flag(red, "16", cidr, "confirm", score, axes, flag_ttl, nil)
                ngx.log(ngx.WARN, "[fleet.analyzer] FAST DYN BLOCK ", cidr,
                        " hits=", axes.hits,
                        " ips=", axes.distinct_ips,
                        " fp=", axes.distinct_fp,
                        " score=", string.format("%.3f", score))
            end
        end
    end

    if _CONN_DEAD then return n_fast_24, n_fast_16 end

    -- /24 fast-path — catches concentrated attacks before they roll up
    local active_24, err24 = red:smembers("fl:active:24:" .. current)
    if err24 then note_pipeline_err(err24) end
    if active_24 and active_24 ~= ngx.null then
        for _, cidr in ipairs(active_24) do
            if _CONN_DEAD then break end
            local status, score, axes = evaluate_prefix(red, "24", cidr, current, fast_24)
            if status == "confirm" then
                n_fast_24 = n_fast_24 + 1
                local ratio = (axes.distinct_fp > 0)
                    and (axes.distinct_ips / axes.distinct_fp) or 0
                local info = string.format(
                    "auto:fast=24:hits=%d:ips=%d:fp=%d:ratio=%.1f:t=%d",
                    axes.hits, axes.distinct_ips, axes.distinct_fp,
                    ratio, ngx.time())
                pool.safe_set("fl:dyn:" .. cidr, info, dyn_ttl)
                write_flag(red, "24", cidr, "confirm", score, axes,
                           flag_ttl, parent_16_of(cidr))
                ngx.log(ngx.WARN, "[fleet.analyzer] FAST DYN BLOCK ", cidr,
                        " hits=", axes.hits,
                        " ips=", axes.distinct_ips,
                        " fp=", axes.distinct_fp,
                        " score=", string.format("%.3f", score))
            end
        end
    end

    return n_fast_24, n_fast_16
end

-- ── Main evaluator ─────────────────────────────────────────────────────
function _M.evaluate()
    _CONN_DEAD = false

    local fdc = fdcfg()
    local timing = fdc.timing or {}
    local flag_ttl = timing.flag_ttl or 600
    local dyn_ttl  = timing.dyn_block_ttl or 3600
    local thr = fdc.thresholds or {}
    local min_hits_24 = thr.min_hits or 20
    local min_hits_16 = thr.min_hits_16 or 30
    local enforce_cfg = fdc.enforce or {}
    local rollup_cfg  = fdc.rollup or {}
    local rollup_min  = rollup_cfg.min_24s_per_16 or 3
    local sustained_target = enforce_cfg.sustained_minutes or 1
    local mode = fdc.mode or "shadow"

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[fleet.analyzer] redis err: ", tostring(err))
        return
    end

    -- Fast path runs every cycle on the CURRENT bucket.
    local n_fast_24, n_fast_16 = fast_path_eval(red, mode, dyn_ttl, flag_ttl)

    -- Slow path: only when the previous closed bucket hasn't been done yet.
    local bucket = pick_bucket()
    if bucket == nil then
        pool.put(red)
        if n_fast_24 > 0 or n_fast_16 > 0 then
            ngx.log(ngx.WARN,
                "[fleet.analyzer] fast-only cycle fast24=", n_fast_24,
                " fast16=", n_fast_16,
                " mode=", mode,
                _CONN_DEAD and " CONN_DEAD" or "")
        end
        return
    end

    -- ── /24 pass ──────────────────────────────────────────────────
    local active_24, smerr = red:smembers("fl:active:24:" .. bucket)
    if smerr then
        ngx.log(ngx.WARN, "[fleet.analyzer] smembers24 err: ", tostring(smerr))
        note_pipeline_err(smerr)
    end
    if not active_24 or active_24 == ngx.null then active_24 = {} end

    local n_eval_24, n_conf_24, n_susp_24, n_skip_24 = 0, 0, 0, 0
    local rollup_pending = {}

    for _, cidr_24 in ipairs(active_24) do
        if _CONN_DEAD then break end
        local status, score, axes = evaluate_prefix(red, "24", cidr_24, bucket, min_hits_24)
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
    local n_eval_16, n_conf_16, n_susp_16, n_skip_16 = 0, 0, 0, 0
    local active_16 = {}
    if not _CONN_DEAD then
        local a16, smerr16 = red:smembers("fl:active:16:" .. bucket)
        if smerr16 then
            ngx.log(ngx.WARN, "[fleet.analyzer] smembers16 err: ", tostring(smerr16))
            note_pipeline_err(smerr16)
        end
        if a16 and a16 ~= ngx.null then active_16 = a16 end

        for _, cidr_16 in ipairs(active_16) do
            if _CONN_DEAD then break end
            local status, score, axes = evaluate_prefix(red, "16", cidr_16, bucket, min_hits_16)
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
    end

    -- ── /16 roll-up ───────────────────────────────────────────────
    if not _CONN_DEAD then
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
                note_pipeline_err(perr)
                if not _CONN_DEAD then
                    ngx.log(ngx.WARN, "[fleet.analyzer] rollup err: ", tostring(perr))
                end
            end
        end
    end

    pool.put(red)

    ngx.log(ngx.WARN,
        "[fleet.analyzer] cycle bucket=", bucket,
        " window=", BUCKET_SECS, "s",
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
        " | fast24=", n_fast_24,
        " fast16=", n_fast_16,
        " mode=", mode,
        _CONN_DEAD and " CONN_DEAD" or "")
end

return _M
