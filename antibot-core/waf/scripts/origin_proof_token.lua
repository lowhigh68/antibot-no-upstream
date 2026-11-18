-- Print one host-bound token for a reverse-proxy edge rule.
--
-- Usage on a production node:
--   ANTIBOT_SRC=/usr/local/openresty/nginx/conf/antibot \
--   /usr/local/openresty/bin/resty \
--     /usr/local/openresty/nginx/conf/antibot/waf/scripts/origin_proof_token.lua \
--     example.com cloudflare
--
-- Configure the resulting value as an OVERWRITE Transform Rule for
-- X-Antibot-Origin-Proof. Never print or copy the underlying secret.

local src = os.getenv("ANTIBOT_SRC")
    or "/usr/local/openresty/nginx/conf/antibot"
src = src:gsub("/+$", "") .. "/"
package.path = src .. "?.lua;" .. src .. "?/init.lua;" .. package.path

local zone = arg and arg[1] or nil
local rule = arg and arg[2] or "cloudflare"
if not zone or zone == "" then
    io.stderr:write("usage: origin_proof_token.lua <zone> [rule]\n")
    os.exit(2)
end

local proof = require "antibot.core.origin_proof"
local token, err = proof.issue(zone, rule)
if not token then
    io.stderr:write("ORIGIN_PROOF_ERROR ", tostring(err), "\n")
    os.exit(1)
end

io.write("X-Antibot-Origin-Proof: ", token, "\n")
