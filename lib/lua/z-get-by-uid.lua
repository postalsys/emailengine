local listKey = KEYS[1];

local uid = tonumber(ARGV[1]) or 0;

if redis.call("EXISTS", listKey) == 1 then
    local list = redis.call("ZRANGEBYSCORE", listKey, uid, uid, "WITHSCORES");
    local entry = list[1];
    local uid = tonumber(list[2]) or 0;

    if entry ~= nil and entry ~= "" and uid > 0 then 
        local seq = redis.call("ZCOUNT", listKey, 0, uid);
        return {uid, entry, seq};
    end;
end;

return nil;
