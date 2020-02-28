local hashKey = KEYS[1];
local id = ARGV[1];

return redis.call("HGET", hashKey, "ix:" .. id)
