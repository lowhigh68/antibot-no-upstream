local _M        = {}
local ua_check  = require "antibot.detection.bot.ua_check"
local dns_rev   = require "antibot.detection.bot.dns_reverse"
local dns_fwd   = require "antibot.detection.bot.dns_forward"
local bot_score = require "antibot.detection.bot.bot_score"
local cloud_sx  = require "antibot.detection.bot.cloud_suffixes"

local CLOUD_PTR_SUFFIXES = cloud_sx.CLOUD_PTR_SUFFIXES

-- Suffix-match helper: ptr ends with "." .. host, or equals host (case-insensitive).
-- Used by Path 1 (contact attest) and Path 2 (analyzer attest).
local function ptr_suffix_matches(ptr, host)
    if not ptr or not host or ptr == "" or host == "" then return false end
    local p = ptr:lower():gsub("%.+$", "")
    local h = host:lower()
    if p == h then return true end
    return p:sub(-(#h + 1)) == "." .. h
end

-- Cloud-provider PTR check (Path 2): ptr ends in one of the hardcoded
-- CLOUD_PTR_SUFFIXES. PTR is set by IP block owner — not spoofable.
local function ptr_matches_cloud(ptr)
    if not ptr or ptr == "" then return false end
    local p = ptr:lower():gsub("%.+$", "")
    for _, suffix in ipairs(CLOUD_PTR_SUFFIXES) do
        local s = suffix:lower()
        if p == s or p:sub(-(#s + 1)) == "." .. s then
            return true
        end
    end
    return false
end

-- Path 1 — contact attest (S2.5). Two sub-paths:
--
--   1a (strong) — PTR suffix matches contact URL eTLD+1.
--      Example: UA `(Pinterestbot/1.0; +http://www.pinterest.com/bot.html)`
--               + PTR `crawl-54-236-1-11.pinterest.com` → match → S2.5
--               reason="contact_ptr_match".
--
--   1b (cloud fallback) — compliant UA + PTR ends in a known cloud provider
--      suffix. Operator runs from major cloud but does NOT setup their
--      domain's reverse DNS for cloud-rented IPs (very common — only Pinterest,
--      Google, Microsoft do the full PTR-on-AWS-pool work).
--      Example: UA `(pingbot/2.0; +http://www.pingdom.com/)` from AWS
--               + PTR `ec2-54-153-18-201.us-west-1.compute.amazonaws.com`
--               → contact URL host `pingdom.com` does NOT appear in PTR,
--               but PTR ends in `amazonaws.com` (cloud list) → S2.5
--               reason="contact_cloud_attested".
--
-- Threat model 1b: attacker needs domain (~$10) + cloud account (anti-abuse
-- friction) + matching compliant UA. Higher bar than UA-only residential spoof.
-- Cap monitor (engine.lua) still scores via anomaly/behavior — true bad actors
-- get caught by signals, not bypassed entirely.
--
-- Both sub-paths set tier S2.5, bot_score=0, skip cluster+graph. Do NOT set
-- good_bot_verified (engine still scores, caps action at monitor).
local function contact_attest(ctx)
    if not ctx.bot_ua_compliant then return false end
    if not ctx.bot_contact_host then return false end
    if not ctx.dns_rev then return false end

    local reason
    if ptr_suffix_matches(ctx.dns_rev, ctx.bot_contact_host) then
        reason = "contact_ptr_match"
    elseif ptr_matches_cloud(ctx.dns_rev) then
        reason = "contact_cloud_attested"
    else
        return false
    end

    ctx.bot_identity_tier = "S2.5"
    ctx.bot_score         = 0.0
    ctx.action_reason     = reason
    ctx.skip_layers       = ctx.skip_layers or {}
    ctx.skip_layers.cluster = true
    ctx.skip_layers.graph   = true

    ngx.log(ngx.INFO,
        "[bot] S2.5 ", reason,
        " bot=", ctx.good_bot_name or "?",
        " ip=", ctx.ip or "?",
        " ptr=", ctx.dns_rev,
        " host=", ctx.bot_contact_host)
    return true
end

-- Path 2 — analyzer attest (S2.5).
-- Fires when UA is browser-pattern + has tool marker (Chrome-Lighthouse,
-- GTmetrix, ...) + IP PTR ends in a recognized cloud provider suffix.
-- Independent of good_bot_claimed — runs when UA does NOT trigger bot path
-- (i.e. PageSpeed, GTmetrix have browser UAs, no "bot" token).
local function analyzer_attest(ctx)
    if not ctx.browser_ua_pattern then return false end
    if not ctx.analyzer_marker then return false end

    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return false
    end

    -- PTR not yet looked up (good_bot path didn't run dns_rev).
    -- Use the exported cache-aware helper.
    local ptr = ctx.dns_rev
    if not ptr then
        ptr = dns_rev.lookup_ptr(ip)
        ctx.dns_rev = ptr  -- cache on ctx for downstream + logging
    end
    if not ptr then return false end
    if not ptr_matches_cloud(ptr) then return false end

    ctx.bot_identity_tier = "S2.5"
    ctx.action_reason     = "analyzer_attested"
    ctx.skip_layers       = ctx.skip_layers or {}
    ctx.skip_layers.cluster = true
    ctx.skip_layers.graph   = true

    ngx.log(ngx.INFO,
        "[bot] S2.5 analyzer_attested marker=", ctx.analyzer_marker,
        " ip=", ip,
        " ptr=", ptr)
    return true
end

-- ASN fallback verify: dùng khi PTR/A verification fail nhưng bot UA + ASN
-- owner thật khớp với registry → tin được. Sở hữu ASN từ RIR (RIPE/ARIN/APNIC)
-- yêu cầu pháp nhân + IP block delegation — attack difficulty tương đương
-- spoof PTR.
--
-- Áp dụng cho mọi bot có ctx.good_bot_asns (không gated vào ptr_only).
-- ptr_only chỉ điều khiển: có skip forward DNS hay không.
local function asn_fallback_verify(ctx)
    local expected = ctx.good_bot_asns
    if not expected or #expected == 0 then return false end
    local actual = ctx.asn and ctx.asn.asn_number
    if not actual then return false end
    for _, asn in ipairs(expected) do
        if asn == actual then
            ngx.log(ngx.INFO,
                "[bot] VERIFIED asn_fallback bot=", ctx.good_bot_name or "?",
                " ip=", ctx.ip or "?", " asn=AS", actual)
            return true
        end
    end
    ngx.log(ngx.INFO,
        "[bot] asn_fallback miss bot=", ctx.good_bot_name or "?",
        " ip=", ctx.ip or "?", " actual=AS", actual,
        " expected=AS", table.concat(expected, ",AS"))
    return false
end

function _M.run(ctx)
    ua_check.run(ctx)

    if ctx.good_bot_claimed then
        dns_rev.run(ctx)

        if ctx.dns_rev_valid == true then
            dns_fwd.run(ctx)
        elseif ctx.dns_rev_valid == false then
            -- PTR resolved nhưng không match suffix HOẶC NXDOMAIN.
            -- Try Path 1 (contact attest) BEFORE asn_fallback — generic
            -- mechanism that grants S2.5 to compliant-UA bots whose PTR
            -- matches the contact URL in their UA, without needing a
            -- hardcoded registry entry.
            if contact_attest(ctx) then
                -- bot_score=0 set inside; fall through to bot_score.run
                -- which honors tier S2.5 and keeps it at 0.
                ctx.bot_ua = "good_bot_contact_attested"
            elseif asn_fallback_verify(ctx) then
                -- Cho ptr_only bot (Meta family): fallback sang ASN verification.
                -- Reverse DNS không đáng tin với rotating pool / no-PTR IP blocks.
                ctx.good_bot_verified = true
                ctx.bot_score         = 0.0
                ctx.bot_ua            = "good_bot_asn_verified"
            else
                ctx.bot_ua            = "fake_good_bot"
                ctx.bot_score         = 0.85
                ctx.good_bot_verified = false
            end
        elseif ctx.dns_rev_valid == nil and ctx.dns_rev_timeout then
            -- DNS timeout (resolver không response). Cho ptr_only bot có ASN
            -- list, fallback ASN. Không thì giữ behavior cũ (bot_score.lua sẽ
            -- bảo toàn score=0 để không penalize timeout transient).
            if asn_fallback_verify(ctx) then
                ctx.good_bot_verified = true
                ctx.bot_score         = 0.0
                ctx.bot_ua            = "good_bot_asn_verified"
            end
        end
    else
        -- Path 2 (analyzer attest) — for browser-pattern UAs with a tool
        -- marker tail (Chrome-Lighthouse, GTmetrix, ...). These don't have
        -- a "bot" token in UA so they never enter the good_bot_claimed
        -- branch. PTR check against hardcoded cloud suffix list grants S2.5.
        if analyzer_attest(ctx) then
            ctx.bot_ua = "analyzer_attested"
        end
    end

    bot_score.run(ctx)

    return true, false
end

return _M
