local accountKey = KEYS[1];
local hashKey = KEYS[2];

local path = ARGV[1];

local id = tonumber(redis.call("HGET", hashKey, path)) or 0;
if id == 0 then
    -- ID not yet created
    id = redis.call("HINCRBY", accountKey, 'listRegistry', 1);
    redis.call("HSET", hashKey, path, id);
    redis.call("HSET", hashKey, "ix:" .. id, path);
end;

return id;

