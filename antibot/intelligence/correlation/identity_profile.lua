local _M = {}

local TRACKED_SIGNALS = {
    "ja3", "h2_sig", "canvas", "webgl", "entropy",
    "geo", "asn", "ip_type", "session", "timing",
}

function _M.run(ctx)
    local present, missing = {}, {}

    for _, sig in ipairs(TRACKED_SIGNALS) do
        if ctx[sig] ~= nil then
            present[#present + 1] = sig
        else
            missing[#missing + 1] = sig
        end
    end

    ctx.profile = { present = present, missing = missing }
end

return _M
