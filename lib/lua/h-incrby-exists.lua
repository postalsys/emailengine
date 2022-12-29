local hashKey = KEYS[1];
local entryKey = ARGV[1];

local value = tonumber(ARGV[2]) or 0;

if redis.call("EXISTS", hashKey) == 1 then
    return redis.call("HINCRBY", hashKey, entryKey, value);
else
    return 0;
end;

