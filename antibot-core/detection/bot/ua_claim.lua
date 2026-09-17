-- ua_claim — "UA nay co TU KHAI la crawler cua mot nha van hanh khong".
--
-- VI SAO TACH RA MOT MODULE RIENG. Phep kiem nay truoc day bi SAO CHEP SAU
-- lan, va cac ban da lech nhau that chu khong phai nguy co ly thuyet:
-- `detection/fleet/trusted.lua` thieu `mediapartners` va `bingpreview` so voi
-- nam ban con lai, nen `Mediapartners-Google` tu AS15169 khong duoc mien khoi
-- viec gom nhom fleet trong khi moi noi khac deu coi no la good-bot claim.
-- Cung ly do da gom `is_private` ve `core/ip_scope.lua` hom 13-09.
--
-- DAY LA CONG **HOAN**, KHONG PHAI CONG **CHO QUA**. Doc ky truoc khi sua:
-- match o day chi dua request vao lane xac minh (DNS nguoc + xuoi, hoac ASN),
-- va chinh lane do moi quyet dinh cho qua hay khong. Ke gia mao UA `Google`
-- tu mot IP ngoai Google van truot xac minh, bi ghi phan quyet `fake:<id>`,
-- roi bi niem phong lai. Nen mo rong danh sach nay KHONG noi long he thong —
-- no chi doi cho ra quyet dinh tu "chan ngay o cua" sang "kiem tra roi chan".
--
-- HAI HUONG DUNG, va chung nguoc nhau — dung nham se tao lo hong:
--
--   HOAN / MIEN (fail-open cho crawler that):
--     l7/ban/ip_ban_check, l7/ban/ban_store — hoan lenh cam de DNS phan xu
--     l7/expensive_filter_guard             — loai khoi phep do faceted-filter
--     detection/fleet/trusted               — mien khoi viec gom nhom /24
--     detection/ip_tour                     — khong ban cung theo strike
--
--   TU CHOI (fail-closed, chan crawler khoi lane NGUOI):
--     core/access/whitelist — UA tu khai crawler khong bao gio duoc vao lane
--     xac minh-nguoi (cookie / device-canvas / early-id). Ro ri Meta 07-07.
--
-- Mot token them vao day lam NOI LONG huong mot va SIET CHAT huong hai cung
-- luc. Do la ly do chi them token DAT TEN NHA VAN HANH (`google-`,
-- `playstore-google`), khong bao gio them token chung chung co the xuat hien
-- trong UA trinh duyet that.

local _M = {}

-- Token nam trong UA cua crawler. Giu nguyen bay token goc, khong bot.
local SUBSTRINGS = {
    "bot",                  -- googlebot, bingbot, amazonbot, facebookbot, ...
    "spider",
    "crawler",
    "facebookexternal",
    "mediapartners",        -- Mediapartners-Google (AdSense)
    "bingpreview",
    "meta-external",        -- meta-externalagent / -fetcher / -ads

    -- ── THEM 18-09-2026 ────────────────────────────────────────────────
    -- Cac fetcher chinh danh KHONG mang chu "bot" trong UA. Do tren
    -- cloud183-139: UA dung bang `Google` bi `banned_id` 204 luot +
    -- `banned_ip` 46 luot, va dat score 106,7 — trong khi Googlebot cung
    -- ky do duoc cho qua 134.471 luot. Khac biet duy nhat la sau chu cai.
    --
    -- Ho hang cua no deu dang di duong CHAM DIEM chu khong phai duong
    -- registry, tuc chung lot qua vi diem THAP chu khong phai vi duoc XAC
    -- MINH: `Google-Safety` (2.706), `Google-NotebookLM`, `Google-adstxt`,
    -- `Google-Site-Verification`, `GoogleDocs`, `Google-Test`,
    -- `PlayStore-Google`, `Chrome Privacy Preserving Prefetch Proxy`.
    -- Hom nao diem cua chung vuot nguong la chan — dung nhu `Google` da dinh.
    --
    -- `google-` CO dau gach noi: tranh khop "google" tran trong UA trinh
    -- duyet (vi du chuoi "Google Chrome" tren mot so WebView), vi huong hai
    -- o tren se TU CHOI nham mot nguoi that neu khop rong.
    "google-",              -- Google-Safety, Google-NotebookLM, Google-InspectionTool, ...
    "googleother",
    "googledocs",
    "playstore-google",
    "feedfetcher",          -- FeedFetcher-Google
    "chrome privacy preserving",   -- Chrome Privacy Preserving Prefetch Proxy
}

-- UA dung bang mot trong cac chuoi nay (sau khi ha chu thuong). Rieng `google`
-- tran KHONG the la substring — xem chu thich `google-` o tren — nen no phai
-- la phep so BANG TUYET DOI.
local EXACT = {
    ["google"] = true,
}

function _M.claims_good_bot(ua)
    if not ua or ua == "" then return false end
    local ul = ua:lower()

    if EXACT[ul] then return true end

    for i = 1, #SUBSTRINGS do
        if ul:find(SUBSTRINGS[i], 1, true) then return true end
    end
    return false
end

return _M
