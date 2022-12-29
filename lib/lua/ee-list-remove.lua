local listsKey = KEYS[1];
local entryKey = KEYS[2];

local list = ARGV[1];
local address = ARGV[2];

local removed = redis.call("HDEL", entryKey, address);

if removed == 1 then
    redis.call("HINCRBY", listsKey, list, -1);
    local count = redis.call("HGET", listsKey, list);
    if tonumber(count) == 0 then
        redis.call("HDEL", listsKey, list);
    end;
end;

return removed;