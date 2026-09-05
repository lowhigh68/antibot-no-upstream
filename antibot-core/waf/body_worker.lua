local core = require "antibot.waf.body_core"

local _M = {}

-- CHAY TRONG THREAD RIENG qua `ngx.run_worker_thread`. Khong co `ngx` o day —
-- moi thu phai la Lua thuan. Do cung la ly do `body_core` khong duoc dung
-- `ngx.re`.
--
-- Vi sao ton tai: than vuot `client_body_buffer_size` bi nginx ghi ra file tam,
-- va truoc day tang nay bo qua han. Do la mot duong ne CHU DONG — don them byte
-- la vuot moi con so buffer, nen nang `client_body_buffer_size` khong bao gio
-- dong duoc. Doc file o access phase thi la I/O CHAN tren duong di cua moi
-- request; doc trong thread pool thi khong.

-- `client_max_body_size` dang la 50M. De tran cao hon con so do nhung VAN co
-- tran, de neu cau hinh doi thi that bai co bao chu khong am tham nuot 1 GiB.
local MAX_SPILL_BYTES = 64 * 1024 * 1024

function _M.scan_file(path, content_type, max_bytes)
    if type(path) ~= "string" or path == "" then
        return core.pack_error("spill_path")
    end

    local fh = io.open(path, "rb")
    if not fh then return core.pack_error("spill_open") end

    local size = fh:seek("end")
    if not size then
        fh:close()
        return core.pack_error("spill_seek")
    end

    local ceiling = tonumber(max_bytes) or MAX_SPILL_BYTES
    if size > ceiling then
        fh:close()
        return core.pack_error("spill_big", size)
    end

    if not fh:seek("set", 0) then
        fh:close()
        return core.pack_error("spill_seek", size)
    end

    local data = fh:read("*a")
    fh:close()
    if not data then return core.pack_error("spill_read", size) end
    -- Doc thieu byte thi KHONG duoc coi la da soi: mot phan multipart nam o
    -- doan bi cut se im lang bien mat.
    if #data ~= size then return core.pack_error("spill_short", size) end

    local r = core.scan(data, content_type)
    r.spill, r.source, r.scan = true, "file", "ok"
    return core.pack(r)
end

return _M
