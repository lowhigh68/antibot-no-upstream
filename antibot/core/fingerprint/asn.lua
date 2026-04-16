local _M = {}

local MMDB_PATH = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

local _mmdb = nil
local _mmdb_err = nil
local _mmdb_checked = false

local function get_mmdb()
    if _mmdb_checked then
        return _mmdb, _mmdb_err
    end
    _mmdb_checked = true

    local ok, maxminddb = pcall(require, "resty.maxminddb")
    if not ok then
        _mmdb_err = "lua-resty-maxminddb not installed"
        ngx.log(ngx.WARN,
            "[asn] ", _mmdb_err,
            " — install: /usr/local/openresty/bin/opm install leafo/lua-resty-maxminddb")
        return nil, _mmdb_err
    end

    if not maxminddb.initted() then
        local init_ok, init_err = maxminddb.init(MMDB_PATH)
        if not init_ok then
            _mmdb_err = "mmdb init failed: " .. tostring(init_err)
            ngx.log(ngx.WARN,
                "[asn] ", _mmdb_err,
                " — download GeoLite2-ASN.mmdb from maxmind.com")
            return nil, _mmdb_err
        end
    end

    _mmdb = maxminddb
    return _mmdb, nil
end

function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" then return end

    local mmdb, err = get_mmdb()
    if not mmdb then
        return
    end

    local ok, res = pcall(function()
        return mmdb.lookup(ip)
    end)

    if not ok or not res then
        ngx.log(ngx.DEBUG, "[asn] lookup failed ip=", ip,
                " err=", tostring(res))
        return
    end

    local asn_number = res.autonomous_system_number
    local asn_org    = res.autonomous_system_organization

    if not asn_number then
        ngx.log(ngx.DEBUG, "[asn] no ASN data for ip=", ip)
        return
    end

    ctx.asn = {
        asn_number = tonumber(asn_number),
        asn_org    = asn_org or "",
    }

    ngx.log(ngx.DEBUG,
        "[asn] ip=", ip,
        " AS", asn_number,
        " org=", tostring(asn_org))
end

return _M
