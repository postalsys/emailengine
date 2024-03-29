local hashKey = KEYS[1];
local entryKey = ARGV[1];

local value = ARGV[2];

if redis.call("HEXISTS", hashKey, entryKey) == 1 then
    local existing = redis.call("HGET", hashKey, entryKey);
    if tonumber(value) > tonumber(existing) then
        redis.call("HSET", hashKey, entryKey, value);
        return 3;
    else
        return 1;
    end;
elseif redis.call("EXISTS", hashKey) == 1 then
    redis.call("HSET", hashKey, entryKey, value);
    return 2;
end;

return 0;
