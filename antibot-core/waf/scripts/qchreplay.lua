-- Offline query-churn replay for one domain/access-log scope.
-- Reads standard Nginx/Apache access lines from stdin.  It never sends HTTP.

local from_epoch = tonumber(arg[1])
local to_epoch = tonumber(arg[2])
local wanted_ip = tostring(arg[3] or "-")
local window = tonumber(os.getenv("QCH_WINDOW")) or 10
local shards = tonumber(os.getenv("QCH_SHARDS")) or 64
local max_query_bytes = tonumber(os.getenv("QCH_MAX_QUERY_BYTES")) or 2048
local path_prefix = tostring(os.getenv("QCH_PATH_PREFIX") or "")

if not from_epoch or not to_epoch or from_epoch > to_epoch then
    io.stderr:write("QCHREPLAY_ERROR invalid epoch window\n")
    return
end
if window < 1 or shards < 8 or shards > 128 then
    io.stderr:write("QCHREPLAY_ERROR invalid window/shards\n")
    return
end

local months = {
    Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6,
    Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12,
}

-- Gregorian civil time to Unix epoch, independent from the machine timezone.
local function civil_epoch(year, month, day, hour, minute, second, zone)
    if month <= 2 then year = year - 1 end
    local era = math.floor(year / 400)
    local yoe = year - era * 400
    local mp = month + (month > 2 and -3 or 9)
    local doy = math.floor((153 * mp + 2) / 5) + day - 1
    local doe = yoe * 365 + math.floor(yoe / 4)
        - math.floor(yoe / 100) + doy
    local days = era * 146097 + doe - 719468
    local sign = zone:sub(1, 1) == "-" and -1 or 1
    local zone_seconds = sign * ((tonumber(zone:sub(2, 3)) or 0) * 3600
        + (tonumber(zone:sub(4, 5)) or 0) * 60)
    return days * 86400 + hour * 3600 + minute * 60 + second
        - zone_seconds
end

local function parse_line(line)
    local ip, day, mon, year, hour, minute, second, zone, method, target =
        line:match('^(%S+)%s+%S+%s+%S+%s+%[(%d%d)/(%a%a%a)/(%d%d%d%d):(%d%d):(%d%d):(%d%d)%s+([+-]%d%d%d%d)%]%s+"([A-Z]+)%s+([^%s]+)%s+HTTP/')
    local month = months[mon]
    if not ip or not month then return nil end
    local ts = civil_epoch(tonumber(year), month, tonumber(day),
        tonumber(hour), tonumber(minute), tonumber(second), zone)
    return ip, ts, method, target
end

local function bounded_query(raw)
    if not raw or raw == "" then return nil end
    local limit = math.max(math.min(math.floor(max_query_bytes), 8192), 128)
    if #raw <= limit then return raw end
    local half = math.floor((limit - 24) / 2)
    return raw:sub(1, half) .. ":" .. tostring(#raw) .. ":"
        .. raw:sub(-half)
end

local function query_shard(raw)
    local hex = ngx.md5(raw)
    local n = tonumber(hex:sub(1, 8), 16) or 0
    return n % shards
end

local read_lines, parsed_lines, selected_lines, bad_lines, path_skipped =
    0, 0, 0, 0, 0
local events = {}
for line in io.lines() do
    read_lines = read_lines + 1
    local ip, ts, method, target = parse_line(line)
    if not ip then
        bad_lines = bad_lines + 1
    else
        parsed_lines = parsed_lines + 1
        if ts >= from_epoch and ts <= to_epoch
           and (wanted_ip == "-" or ip == wanted_ip) then
            selected_lines = selected_lines + 1
            if method == "GET" or method == "HEAD" then
                local path = target:match("^([^?]*)") or ""
                if path_prefix == "" or path:sub(1, #path_prefix) == path_prefix then
                    local query = target:match("^[^?]*%?(.*)$")
                    query = bounded_query(query)
                    if query then
                        events[#events + 1] = {
                            ts = ts, ip = ip, query = query, seq = read_lines,
                        }
                    end
                else
                    path_skipped = path_skipped + 1
                end
            end
        end
    end
end

table.sort(events, function(a, b)
    if a.ts == b.ts then return a.seq < b.seq end
    return a.ts < b.ts
end)

local buckets, qch_values, qcd_values = {}, {}, {}
for i = 1, #events do
    local event = events[i]
    local bucket_id = math.floor(event.ts / window)
    local key = event.ip .. "\0" .. tostring(bucket_id)
    local bucket = buckets[key]
    if not bucket then
        bucket = {
            ip = event.ip, id = bucket_id, hits = 0,
            distinct = 0, seen = {},
        }
        buckets[key] = bucket
    end
    bucket.hits = bucket.hits + 1
    local shard = query_shard(event.query)
    if not bucket.seen[shard] then
        bucket.seen[shard] = true
        bucket.distinct = bucket.distinct + 1
    end
    qch_values[#qch_values + 1] = bucket.hits
    qcd_values[#qcd_values + 1] = bucket.distinct
end

local function percentile(values, pct)
    if #values == 0 then return "-" end
    local copy = {}
    for i = 1, #values do copy[i] = values[i] end
    table.sort(copy)
    local index = math.ceil(#copy * pct / 100)
    if index < 1 then index = 1 end
    return copy[index]
end

local bucket_list = {}
for _, bucket in pairs(buckets) do
    bucket_list[#bucket_list + 1] = bucket
end
table.sort(bucket_list, function(a, b)
    if a.hits ~= b.hits then return a.hits > b.hits end
    if a.distinct ~= b.distinct then return a.distinct > b.distinct end
    if a.id ~= b.id then return a.id < b.id end
    return a.ip < b.ip
end)

local unique_sources = {}
for i = 1, #events do unique_sources[events[i].ip] = true end
local source_count = 0
for _ in pairs(unique_sources) do source_count = source_count + 1 end

print("=== QCH OFFLINE REPLAY ===")
print("from=" .. tostring(from_epoch))
print("to=" .. tostring(to_epoch))
print("ip=" .. wanted_ip)
print("window=" .. tostring(window) .. " shards=" .. tostring(shards))
print("path_prefix=" .. (path_prefix ~= "" and path_prefix or "-"))
print(string.format(
    "read=%d parsed=%d selected=%d path_skipped=%d bad=%d query_events=%d sources=%d buckets=%d",
    read_lines, parsed_lines, selected_lines, path_skipped, bad_lines, #events,
    source_count, #bucket_list))

if #events == 0 then
    print("QCHREPLAY_EMPTY")
    print("QCHREPLAY_OK")
    return
end

print(string.format(
    "SET replay rows=%d qch[p50=%s p95=%s p99=%s max=%s] qcd[p50=%s p95=%s p99=%s max=%s]",
    #events,
    tostring(percentile(qch_values, 50)),
    tostring(percentile(qch_values, 95)),
    tostring(percentile(qch_values, 99)),
    tostring(percentile(qch_values, 100)),
    tostring(percentile(qcd_values, 50)),
    tostring(percentile(qcd_values, 95)),
    tostring(percentile(qcd_values, 99)),
    tostring(percentile(qcd_values, 100))))

print("=== TOP BUCKETS (MAX 20) ===")
print("bucket_start ip hits distinct")
for i = 1, math.min(#bucket_list, 20) do
    local bucket = bucket_list[i]
    print(string.format("%d %s %d %d", bucket.id * window,
        bucket.ip, bucket.hits, bucket.distinct))
end
print("QCHREPLAY_OK")
