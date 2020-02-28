local listKey = KEYS[1];

local seq = tonumber(ARGV[1]) or 0;

if redis.call("EXISTS", listKey) == 1 then
    local list = redis.call("ZRANGE", listKey, seq-1, seq-1, "WITHSCORES");
    local entry = list[1];
    local uid = tonumber(list[2]) or 0;

    if entry ~= nil and entry ~= "" and uid > 0 then 
        return {uid, entry, seq};
    end;
end;

return nil;
