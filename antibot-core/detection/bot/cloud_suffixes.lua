local _M = {}

-- Cloud provider reverse-DNS suffixes — universal infrastructure identifiers,
-- NOT a bot/tool list. Used by Path 2 analyzer attest in bot/init.lua:
-- a browser-pattern UA with a tool marker tail (e.g. "Chrome-Lighthouse")
-- coming from an IP whose PTR ends in one of these suffixes is granted
-- S2.5 tier (cap action at monitor, waive bot_score/asn_rep).
--
-- PTR is set by the IP block owner — not spoofable. Cloud providers
-- delegate PTR per-customer subdomain, so a hostname ending in these
-- suffixes proves the IP was rented from (and authenticated by) that cloud.
--
-- New cloud → append here. Keep alphabetically grouped within major vendors
-- so diffs are reviewable.
_M.CLOUD_PTR_SUFFIXES = {
    -- Google Cloud / PSI / Lighthouse infra
    "googleusercontent.com",
    "google.com",
    "googlebot.com",
    "1e100.net",

    -- Amazon Web Services
    "amazonaws.com",
    "compute.amazonaws.com",
    "compute-1.amazonaws.com",
    "cloudfront.net",
    "elasticbeanstalk.com",

    -- Microsoft Azure
    "azure.com",
    "azurewebsites.net",
    "cloudapp.net",
    "cloudapp.azure.com",

    -- Oracle Cloud
    "oraclecloud.com",
    "oraclevcn.com",

    -- DigitalOcean
    "digitalocean.com",

    -- Linode (Akamai)
    "linode.com",
    "linodeusercontent.com",

    -- Vultr
    "vultr.com",
    "vultrusercontent.com",

    -- Fastly
    "fastly.net",

    -- Cloudflare
    "cloudflare.com",
    "cloudflareresolve.com",

    -- Akamai
    "akamaitechnologies.com",
    "akamai.com",

    -- OVH
    "ovh.net",
    "ovh.com",

    -- Hetzner
    "hetzner.com",
    "your-server.de",

    -- Contabo
    "contabo.com",
    "contabo.net",
}

-- Standard browser tokens that may appear at UA tail — these are NEVER
-- analyzer markers. Real browsers (Chrome, Firefox, Safari, mobile variants)
-- terminate UA with one of these. A tail token NOT in this set AND matching
-- the strict regex (PascalCase-PascalCase or PascalCase ≥5) is an analyzer.
--
-- Q23=a strict policy: false positives here mean a real-tool marker is
-- ignored (under-detection of analyzer, falls to normal scoring) — acceptable.
-- False negatives (a real browser token missing here) would WRONGLY grant
-- S2.5 to real users on cloud IPs — UNACCEPTABLE. So this list errs toward
-- inclusion of every known browser variant.
_M.BROWSER_STANDARD_TOKENS = {
    -- Chromium-based
    ["Mobile"]          = true,
    ["Safari"]          = true,
    ["Edge"]            = true,
    ["EdgA"]            = true,
    ["EdgiOS"]          = true,
    ["CriOS"]           = true,
    ["HeadlessChrome"]  = true,

    -- Firefox
    ["Firefox"]         = true,
    ["FxiOS"]           = true,

    -- Opera family
    ["OPR"]             = true,
    ["Opera"]           = true,
    ["OperaTablet"]     = true,
    ["OperaMobi"]       = true,

    -- Other Chromium forks
    ["Vivaldi"]         = true,
    ["Brave"]           = true,
    ["YaBrowser"]       = true,
    ["YaSearchBrowser"] = true,
    ["Yandex"]          = true,
    ["SamsungBrowser"]  = true,
    ["MiuiBrowser"]     = true,
    ["HuaweiBrowser"]   = true,
    ["UCBrowser"]       = true,
    ["QQBrowser"]       = true,
    ["MaxthonBrowser"]  = true,
    ["DuckDuckGo"]      = true,

    -- Apple / iOS variants
    ["GSA"]             = true,
    ["AppleNews"]       = true,

    -- Mobile WebView / in-app tokens that may appear at tail
    ["WebView"]         = true,
    ["wv"]              = true,
}

return _M
