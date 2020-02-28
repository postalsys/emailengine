local listKey = KEYS[1];

local uid = tonumber(ARGV[1]) or 0;
local buf = ARGV[2];

if redis.call("EXISTS", listKey) == 1 then
   redis.call("ZREMRANGEBYSCORE", listKey, uid, uid);
end

local added = redis.call("ZADD", listKey, uid, buf);
if added ~= 1 then
    -- could not add?
    return nil;
end;

-- return sequence number for the inserted entry
return redis.call("ZCOUNT", listKey, 0, uid);