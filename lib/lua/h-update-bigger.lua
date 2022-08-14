local hashKey = KEYS[1];
local hashField = ARGV[1];

local lowerThanVal = tonumber(ARGV[2]) or 0;
local uptatedVal = tonumber(ARGV[3]) or 0;

if redis.call("HEXISTS", hashKey, hashField) == 1 then
    local existing = redis.call("HGET", hashKey, hashField);
    if tonumber(existing) < lowerThanVal then
        redis.call("HSET", hashKey, hashField, uptatedVal);
        return 2;
    end;
else
    redis.call("HSET", hashKey, hashField, uptatedVal);
    return 1;
end;

return 0;
