local _M = {}

-- A rule id remains stable because it is an external telemetry contract.  The
-- metadata below is the single place where detectors become policy facts.
local RULES = {}

local function add(id, family, phase, profile, action, mode, score, severity,
                   confidence, labels, why)
    RULES[id] = {
        id         = id,
        version    = 1,
        family     = family,
        phase      = phase,
        profile    = profile,
        action     = action,
        mode       = mode,
        score      = score,
        severity   = severity,
        confidence = confidence,
        labels     = labels or {},
        why        = why,
    }
end

-- Generic URI invariants.
add("dotfile_exposed", "exposure", "uri", "generic", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "exposure.secret" })
add("dump_exposed", "exposure", "uri", "generic", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "exposure.backup" })
add("wellknown_exec", "exposure", "uri", "generic", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable" })

-- Generic argument/body facts.  They are signals, not verdicts.
add("arg_traversal", "argument", "request", "generic", "signal", "enforce",
    35, 3, 0.80, { "attack.traversal" })
add("arg_php_wrapper", "argument", "request", "generic", "signal", "enforce",
    50, 4, 0.92, { "attack.php_wrapper" })
add("arg_null_byte", "argument", "request", "generic", "signal", "enforce",
    50, 4, 0.95, { "attack.null_byte" })
add("body_php_code", "body", "request_body", "generic", "signal", "enforce",
    50, 4, 0.75, { "body.php_code" })
add("body_scan_incomplete", "body", "request_body", "generic", "observe", "enforce",
    0, 1, 1.00, { "body.scan_incomplete" })

-- B1 (roadmap muc 2): than MULTIPART khong soi het — khong soi duoc (`scan` khac
-- ok/empty) HOAC kenh ten tep dung truoc khi xem het cac part
-- (`body_core.FN_INCOMPLETE`). Tach khoi `body_scan_incomplete` vi multipart la
-- noi tep di vao; chinh sach theo route cho nhom nay (B2) chon SAU, con cac than
-- khac giu luat cu.
--
-- `observe`, diem 0: GIAI DOAN DO. Nguoi dung 27-09 — phan chua xac dinh chinh
-- xac thi ghi lai roi lay log xu ly; chua gia dinh "multipart = upload".
add("body_multipart_incomplete", "body", "request_body", "generic", "observe", "enforce",
    0, 1, 1.00, { "body.multipart_incomplete" })

-- Mot luat tham so khop trong NOI DUNG mot tep dinh kem, khong trong tham so.
--
-- `action = "observe"` va `score = 0`, va do la ca CHINH SACH chu khong phai mot
-- muc do thap: mot chuoi `../` trong byte cua mot tep khong phai mot tan cong
-- tham so. Do 25-09 tren sau may: nhom `<multipart>` la 9/9 ca FP — Magento admin
-- upload anh san pham, `cl` 1,1-2,0 MB, `../` nam trong noi dung tep.
--
-- VI SAO MOT LUAT RIENG chu khong phai `arg_traversal` voi diem ha xuong: mot
-- `factor` nho VAN de lai nhan (`policy.lua:162` goi `add_labels` theo `action`,
-- khong theo `score`), nen nhom nay van kich hoat duoc correlation tuong lai. Mot
-- luat rieng voi nhan rieng thi khong.
--
-- Nhan `body.file_content` KHONG trung voi `attack.traversal`: mot correlation ve
-- sau muon dung bang chung nay phai goi ten no, khong duoc nhan nham no la mot
-- tan cong tham so. Do la ca diem cua viec tach.
add("body_file_traversal", "body", "request_body", "generic", "observe", "enforce",
    0, 1, 0.30, { "body.file_content" })

-- ── V7: luat tham so doi theo VUNG cua than ─────────────────────────────────
--
-- `body_core.scan` bao ba vung (`nonfile`, `file`, `filename`) va KHONG quyet
-- dinh gi. Bang nay la noi DUY NHAT noi mot luat tham so thanh luat nao o vung
-- `file` — noi dung tep dinh kem, chi ton tai khi than chung minh duoc (`pf=ok`).
-- `nonfile` va `filename` giu nguyen luat va nguyen diem.
--
-- MOI luat trong `args.RULES` phai co MOT dong o day, ke ca khi no giu nguyen:
-- hop dong trong `contract_test.lua` ghim dieu do, nen them mot luat tham so moi
-- ma quen quyet dinh vung `file` cho no la bao do, khong lang le.
--
-- Hai luat giu nguyen (50 diem, nhu truoc V7): chua co so lieu `php://`/`%00`
-- trong noi dung tep that. Doi chung la mot quyet dinh policy rieng, sau khi
-- shadow cho so lieu — khong gop vao lan tach vung nay.
local FILE_REGION = {
    arg_traversal   = "body_file_traversal",
    arg_php_wrapper = "arg_php_wrapper",
    arg_null_byte   = "arg_null_byte",
}
_M.FILE_REGION = FILE_REGION

-- Luat ma mot lan khop `rule_id` o `region` tro thanh. Khong co dong cho vung
-- `file` thi GIU NGUYEN luat — "khong biet" khong bao gio duoc ha diem.
function _M.region_rule(rule_id, region)
    if region == "file" then return FILE_REGION[rule_id] or rule_id end
    return rule_id
end

-- Upload names.  Scores are deliberately non-terminal until fleet data says
-- otherwise; the exact sub-label is retained for tuning.
add("upload_apache_config", "upload", "request_body", "generic", "signal", "enforce",
    45, 5, 0.90, { "upload.config", "upload.handler_config" })
add("upload_php_config", "upload", "request_body", "generic", "signal", "enforce",
    40, 5, 0.88, { "upload.config", "upload.php_config" })
add("upload_foreign_config", "upload", "request_body", "generic", "signal", "enforce",
    5, 2, 0.35, { "upload.config", "upload.foreign_config" })
add("upload_config_case", "upload", "request_body", "generic", "signal", "enforce",
    20, 3, 0.55, { "upload.config", "upload.case_variant" })
add("upload_php_ext", "upload", "request_body", "generic", "signal", "enforce",
    40, 5, 0.90, { "upload.executable" })
add("upload_php_double", "upload", "request_body", "generic", "signal", "enforce",
    45, 5, 0.92, { "upload.executable", "upload.double_extension" })
add("upload_php_legacy_ext", "upload", "request_body", "generic", "signal", "enforce",
    15, 3, 0.45, { "upload.possible_executable" })

-- WordPress is an optional overlay, never the generic foundation.
add("wp_upload_exec", "wordpress_path", "uri", "wordpress", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable", "wordpress.upload_exec" })
add("wp_content_exec", "wordpress_path", "uri", "wordpress", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable" })
add("wp_root_unknown", "wordpress_path", "uri", "wordpress", "signal", "enforce",
    25, 3, 0.55, { "path.direct_php", "wordpress.root_unknown" })
add("wp_plugin_direct", "wordpress_path", "uri", "wordpress", "signal", "enforce",
    12.5, 2, 0.45, { "path.direct_php", "wordpress.plugin_direct" })
add("wp_muplugin_direct", "wordpress_path", "uri", "wordpress", "signal", "enforce",
    25, 3, 0.70, { "path.direct_php", "wordpress.muplugin_direct" })
add("wp_theme_direct", "wordpress_path", "uri", "wordpress", "signal", "enforce",
    12.5, 2, 0.45, { "path.direct_php", "wordpress.theme_direct" })
add("wp_includes_exec", "wordpress_path", "uri", "wordpress", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable" })
add("wp_admin_includes_exec", "wordpress_path", "uri", "wordpress", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable" })

-- Filesystem evidence and policy correlations.  New block-capable correlations
-- start in shadow mode and require an explicit measured promotion.
add("fim_new_executable", "filesystem", "uri", "generic", "signal", "enforce",
    50, 4, 0.85, { "fs.new_executable" })
add("corr_upload_php_payload", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.96, { "correlation.upload_php_payload" })
add("corr_upload_config_php_payload", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.96, { "correlation.upload_config_php_payload" })
add("corr_new_direct_executable", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.95, { "correlation.new_direct_executable" })

-- ── Buoc 4: bang chung CUNG MOT PART (review 27-09) ─────────────────────────
--
-- Hai correlation cu (`corr_upload_php_payload`, `corr_upload_config_php_payload`)
-- ghep hai fact TOAN REQUEST: mot nhan `upload.executable` tu `up_rule` (gia tri cua
-- ca request) va mot nhan `body.php_code` tu co `php` (boolean toan than). Nen
-- `shell.php` RONG o part 1 cong `<?php` trong mot FORM FIELD o part 2 cho ra Y HET
-- `shell.php` chua `<?php`. Do la ly do chung khong the promote.
--
-- Bon luat duoi day doi hoi CUNG MOT PART, dung tren V8 part record. Chung KHONG
-- dung nhan toan cuc — `waf/init.lua` phat chung tu `parts`, khong qua bang
-- `CORRELATIONS`.
--
-- `mode = "shadow"`: KHONG chan gi hom nay, ke ca khi `mode` toan cuc la `enforce`.
-- Promote can so lieu tu `postdeploy.sh` muc 11 (bao nhieu luot "cung part" vs "hai
-- part khac nhau") va cot `auth` cua `wafstat` muc 0c — cung cong da dat cho moi
-- correlation truoc.
--
-- `family = "correlation"` nen `policy.lua` KHONG cong diem cua chung vao
-- `state.score`: chung la phan quyet duoc suy ra tu fact DA duoc cham diem, va cong
-- lan nua la dem mot bang chung hai lan.
add("upload_php_executable_content", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.97, { "correlation.same_part_php_exec" })
add("upload_php_double_content", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.95, { "correlation.same_part_php_double" })
add("upload_apache_handler_content", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.97, { "correlation.same_part_apache_handler" })
add("upload_php_autoload_content", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.96, { "correlation.same_part_php_autoload" })

-- ── Muc 7: DUOI hua mot dinh dang, BYTE DAU noi dang khac ───────────
--
-- KHONG phai composite cung-part, va do la diem chinh. Bon luat o tren doi hoi
-- `name_flags` khac `false` — tuc TEN da dang nghi. Hai luat duoi day quan trong
-- nhat dung khi TEN SACH:
--
--     shell.jpg   ten sach (`name_flags = false`), byte dau `MZ` hoac `\127ELF`
--
-- Do la duong ma ca kenh TEN (`upload.lua`) lan `find_php_tag` deu mu: khong co
-- duoi chay duoc, khong co the mo PHP. Nen day la fact DOC LAP theo part, khong
-- phai mot phan quyet suy ra tu fact khac.
--
-- `observe`, diem 0 — GIAI DOAN DO, cung khuon B1/B3 (roadmap muc 2) va cung ly
-- do: chua co MOT con so nao tren dan may nay ve bao nhieu upload THAT co duoi
-- lech byte dau. Nguon FP nghi ra duoc ngay: `.doc` cu (OLE2) vs `.docx` (ZIP),
-- cong cu ghi JFIF/Exif khac nhau, va tep 2 byte chua du de ket luan. Chua co so
-- thi khong cong diem. Quyet tu `postdeploy.sh` muc 12.
--
-- Hai luat RIENG chu khong mot luat "magic": chung tra loi hai cau khac nhau va
-- se co hai ty le FP khac nhau. `magic_exec` la "day la ma da bien dich" — dung
-- ke ca khi duoi khong biet. `magic_mismatch` la "duoi nay co trong bang va byte
-- dau khong khop" — mot cau yeu hon, va la cau co nhieu FP hop le hon.
add("upload_magic_exec", "body", "request_body", "generic", "observe", "enforce",
    0, 1, 1.00, { "upload.magic_exec" })
add("upload_magic_mismatch", "body", "request_body", "generic", "observe", "enforce",
    0, 1, 1.00, { "upload.magic_mismatch" })

-- ── Muc 8: tep CAU HINH vua bi sua o thu muc cua URI dang goi ───────
--
-- `fim.sh` da bao `NEW` (file moi) qua `waf:fimnew:` tu lau. Nhom nay la duong ma
-- `NEW` MU: mot dong `AddType application/x-httpd-lsphp .jpg` them vao mot
-- `.htaccess` DA CO bat lai PHP cho ca thu muc, ma khong tao file moi nao.
--
-- `observe`, diem 0 — GIAI DOAN DO, va o day ly do dac biet manh: `.htaccess` bi
-- ghi lai HOP LE boi LiteSpeed Cache, Wordfence, va moi lan doi permalink cua
-- WordPress. Chua co mot con so nao ve tan suat do tren 43 domain. Nguoi dung
-- 27-09 chon dung: chi them khoa, diem 0, do truoc quyet sau. Quyet tu
-- `postdeploy.sh` muc 13.
--
-- KHONG dung `fim_new_executable` voi mot `factor` nho: mot `factor` VAN de lai
-- nhan (`policy.lua` goi `add_labels` theo `action`, khong theo `score`), nen
-- nhom nay se kich hoat duoc moi correlation dung nhan `fs.new_executable` — tuc
-- mot lan plugin ghi `.htaccess` doc thanh "co file thuc thi moi". Mot luat rieng
-- voi nhan rieng thi khong. Cung lap luan da dung cho `body_file_traversal`.
add("fim_config_changed", "correlation", "uri", "generic", "observe", "enforce",
    0, 1, 1.00, { "fs.config_changed" })

-- Ten tep + co noi dung -> luat cung-part. `body_core` bao `name_flags` va
-- `content_flags` cua CUNG mot part; bang nay la noi DUY NHAT quyet chung thanh mot
-- phan quyet.
--
-- `upload_php_config` (`.user.ini` VA `php.ini`) dung CHUNG co `autoload` — cung mot
-- directive, cung co che — nhung tach o day va o `name_flags`: `.user.ini` duoc PHP
-- doc THEO THU MUC o FPM/CGI nen mot tep upload vao webroot co tac dung THAT, con
-- `php.ini` thi khong. Hom nay ca hai vao cung mot rule id vi `name_flags` chua phan
-- biet duoc hai ten; khi so lieu cho thay `php.ini` chiem phan lon thi tach
-- `name_flags` truoc, roi tach rule sau.
local SAME_PART = {
    upload_php_ext        = { php_tag  = "upload_php_executable_content" },
    upload_php_double     = { php_tag  = "upload_php_double_content" },
    upload_apache_config  = { handler  = "upload_apache_handler_content" },
    upload_php_config     = { autoload = "upload_php_autoload_content" },
}
_M.SAME_PART = SAME_PART

-- Luat cung-part cua mot (ten, co), hoac nil.
function _M.same_part_rule(name_flags, content_flag)
    local by_name = name_flags and SAME_PART[name_flags]
    return by_name and by_name[content_flag] or nil
end

local CORRELATIONS = {
    {
        id = "corr_upload_php_payload",
        all = { "upload.executable", "body.php_code" },
    },
    {
        id = "corr_upload_config_php_payload",
        all = { "upload.handler_config", "body.php_code" },
    },
    {
        id = "corr_new_direct_executable",
        all = { "fs.new_executable", "path.direct_php" },
    },
}

function _M.get(id)
    return RULES[id]
end

function _M.all()
    return RULES
end

function _M.correlations()
    return CORRELATIONS
end

function _M.has_family(name)
    for _, rule in pairs(RULES) do
        if rule.family == name then return true end
    end
    return false
end

-- Catch detector/catalog drift during startup or tests.  This does not mutate
-- detector tables and therefore cannot change the behaviour of V1.
function _M.validate_sources(sources)
    local errors = {}
    for source, rules in pairs(sources or {}) do
        for id in pairs(rules or {}) do
            local meta = RULES[id]
            if not meta then
                errors[#errors + 1] = source .. ": missing registry rule " .. id
            elseif source == "wordpress" and meta.profile ~= "wordpress" then
                errors[#errors + 1] = source .. ": wrong profile for " .. id
            end
        end
    end
    return #errors == 0, errors
end

return _M
