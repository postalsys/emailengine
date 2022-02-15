local listKey = KEYS[1];
local mailboxKey = KEYS[2];

local seq = tonumber(ARGV[1]) or 0;
local uid = tonumber(ARGV[2]) or 0;

if redis.call("EXISTS", listKey) == 1 then

    local entry;

    if seq > 0 then
        local list = redis.call("ZRANGE", listKey, seq-1, seq-1, "WITHSCORES");
        entry = list[1];
        uid = tonumber(list[2]) or 0;
    elseif uid < 1 then
        -- No UID value provided
        return nil;
    else
        local list = redis.call("ZRANGEBYSCORE", listKey, uid, uid);
        entry = list[1];
    end

    if entry ~= nil and entry ~= "" and uid > 0 then 
        local y = redis.call("ZREMRANGEBYSCORE", listKey, uid, uid);
        if y == 1 then
            redis.call("HINCRBY", mailboxKey, "messages", -1);
        end
        return {uid, entry};
    end;
end;

return nil;
