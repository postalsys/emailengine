--[[
Script: s-list-accounts.lua
Purpose: Lists and filters accounts from a Redis set with pagination and search

KEYS:
  [1] listKey - Set key containing account IDs

ARGV:
  [1] filterState - Account state to filter by ('*' for all states)
  [2] skip - Number of matching entries to skip (pagination offset)
  [3] count - Maximum number of entries to return
  [4] prefix - Key prefix for account data hashes (e.g., "ee:")
  [5] strsearch - Case-insensitive substring to search in account, name, or email fields

Returns:
  Array with:
    [1] Total number of matching entries
    [2] Skip value used
    [3] Array of account data (HGETALL results for each matching account)

NOTE: This script is not compatible with Redis clustering if using account id as the hash slot key
--]]

local listKey = KEYS[1];

local filterState = ARGV[1];
local skip = tonumber(ARGV[2]) or 0;
local count = tonumber(ARGV[3]) or 0;
local prefix = ARGV[4];
local strsearch = ARGV[5];

local total = redis.call("SCARD", listKey);  -- Get total account count

local list = redis.call("SMEMBERS", listKey);  -- Load all account IDs

-- Early return if offset exceeds total
if skip >= total then
	return {total,skip, {}}
end

local shouldSkip = skip;
local matching = 0;
local result = {}

-- Sort list by account IDs for consistent ordering
table.sort(list);

local listAll = false;
if strsearch and strsearch  ~= '' then
    listAll = true;  -- Need to check all accounts when searching
end

for index, account in ipairs(list) do

    local state;
    if filterState ~= '*' then
        -- Load state only if filtering by state
        state = redis.call("HGET", prefix .. "iad:" .. account, "state"); 
    end

    -- String search match defaults to true
    local strmatch = true

    if strsearch and strsearch  ~= '' then
        local accountData = redis.call("HGET", prefix .. "iad:" .. account, "account") or ""; 
        local name = redis.call("HGET", prefix .. "iad:" .. account, "name") or ""; 
        local email = redis.call("HGET", prefix .. "iad:" .. account, "email") or "";

        -- Search for substring in account, name, or email fields
        if string.find(string.lower(accountData), strsearch, 0, true) or string.find(string.lower(name), strsearch, 0, true) or string.find(string.lower(email), strsearch, 0, true) then
            strmatch = true
        else
            strmatch = false
        end
    end

    -- Check if account matches filter criteria
    if (filterState == '*' or filterState == state) and strmatch then      

        if shouldSkip == 0 then
            -- Pagination offset reached, can include this entry
            if #result < count then
                -- Add account data to result
                result[#result + 1] = redis.call("HGETALL", prefix .. "iad:" .. account);
            else
                -- Result buffer full
                if filterState == '*' and listAll == false then
                    -- Optimization: skip remaining when not searching
                    matching = total;
                    break;
                end
            end
        else
            shouldSkip = shouldSkip - 1;  -- Decrement skip counter
        end

        matching = matching + 1;  -- Count matching entries
    end    
end

return {matching, skip, result}