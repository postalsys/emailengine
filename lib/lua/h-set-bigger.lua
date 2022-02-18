local hashKey = KEYS[1];
local entryKey = ARGV[1];

local value = ARGV[2];

if redis.call("HEXISTS", hashKey, entryKey) == 1 then
    local existing = redis.call("HGET", hashKey, entryKey);
    if tonumber(value) > tonumber(existing) then
        redis.call("HSET", hashKey, entryKey, value);
        return 2;
    end;
else
    redis.call("HSET", hashKey, entryKey, value);
    return 1;
end;

return 0;
