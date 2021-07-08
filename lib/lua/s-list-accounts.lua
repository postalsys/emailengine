local listKey = KEYS[1];

local filterState = ARGV[1];
local skip = tonumber(ARGV[2]) or 0;
local count = tonumber(ARGV[3]) or 0;

local total = redis.call("SCARD", listKey);

local list = redis.call("SMEMBERS", listKey);

if skip >= total then
	return {total,skip, {}}
end

local shouldSkip = skip;
local matching = 0;
local result = {}

for index, account in ipairs(list) do

    local state;
    if filterState ~= '*' then
        -- load only if we actually need to compare account state value
        state = redis.call("HGET", "iad:" .. account, "state"); 
    end

    if filterState == '*' or filterState == state then
        -- state matches, can use this entry for listing        

        if shouldSkip == 0 then
            -- enough entries skipped, can use
            if #result < count then
                -- now we can actually use this record
                result[#result + 1] = redis.call("HGETALL", "iad:" .. account);
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