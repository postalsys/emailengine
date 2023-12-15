-- NB!
-- This script is not compatible with Redis clustering if using account id as the hash slot key

local listKey = KEYS[1];

local filterState = ARGV[1];
local skip = tonumber(ARGV[2]) or 0;
local count = tonumber(ARGV[3]) or 0;
local prefix = ARGV[4];
local strsearch = ARGV[5];

local total = redis.call("SCARD", listKey);

local list = redis.call("SMEMBERS", listKey);

if skip >= total then
	return {total,skip, {}}
end

local shouldSkip = skip;
local matching = 0;
local result = {}

-- sort list by account IDs
table.sort(list);

for index, account in ipairs(list) do

    local state;
    if filterState ~= '*' then
        -- load only if we actually need to compare account state value
        state = redis.call("HGET", prefix .. "iad:" .. account, "state"); 
    end

    -- string search match defaults to true
    local strmatch = true
    if strsearch and strsearch  ~= '' then
        local account = redis.call("HGET", prefix .. "iad:" .. account, "account") or ""; 
        local name = redis.call("HGET", prefix .. "iad:" .. account, "name") or ""; 
        local email = redis.call("HGET", prefix .. "iad:" .. account, "email") or "";

        if string.find(string.lower(account), strsearch, 0, true) or string.find(string.lower(name), strsearch, 0, true) or string.find(string.lower(email), strsearch, 0, true) then
            strmatch = true
        else
            strmatch = false
        end
    end

    if (filterState == '*' or filterState == state) and strmatch then
        -- state matches, can use this entry for listing        

        if shouldSkip == 0 then
            -- enough entries skipped, can use
            if #result < count then
                -- now we can actually use this record
                result[#result + 1] = redis.call("HGETALL", prefix .. "iad:" .. account);
            else
                -- max number entries in result buffer
                if filterState == '*' then
                    -- no point looking further, we already know the total count
                    matching = total;
                    break;
                end
            end
        else
            shouldSkip = shouldSkip - 1;
        end

        matching = matching + 1;
    end    
end

return {matching, skip, result}