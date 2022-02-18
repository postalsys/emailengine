local hashKey = KEYS[1];
local entryKey = ARGV[1];

local buf = ARGV[2];

if redis.call("HEXISTS", hashKey, entryKey) == 1 then
    local content = redis.call("HGET", hashKey, entryKey);
    redis.call("HSET", hashKey, entryKey, content .. buf);
    return 2;
else
    redis.call("HSET", hashKey, entryKey, buf);
    return 1;
end;

