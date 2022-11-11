local listsKey = KEYS[1];
local entryKey = KEYS[2];

local list = ARGV[1];
local address = ARGV[2];
local data = ARGV[3];

local added = redis.call("HSET", entryKey, address, data);

if added == 1 then
    redis.call("HINCRBY", listsKey, list, 1);
end;

return added;