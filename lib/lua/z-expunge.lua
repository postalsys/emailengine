local listKey = KEYS[1];
local mailboxKey = KEYS[2];

local seq = tonumber(ARGV[1]) or 0;
local uid = tonumber(ARGV[2]) or 0;

-- Input validation
if seq < 0 or uid < 0 then
    return redis.error_reply("Invalid sequence or UID value");
end

-- Check if list exists
if redis.call("EXISTS", listKey) == 0 then
    return nil;  -- No list, nothing to expunge
end

local entry;
local actualUid;

if seq > 0 then
    -- Get by sequence number
    local list = redis.call("ZRANGE", listKey, seq-1, seq-1, "WITHSCORES");
    if #list >= 2 then
        entry = list[1];
        actualUid = tonumber(list[2]) or 0;
        
        -- If UID was also provided, verify it matches
        if uid > 0 and uid ~= actualUid then
            return redis.error_reply("Sequence/UID mismatch");
        end
        uid = actualUid;
    end
elseif uid > 0 then
    -- Get by UID
    local list = redis.call("ZRANGEBYSCORE", listKey, uid, uid);
    if #list >= 1 then
        entry = list[1];
        actualUid = uid;
    end
else
    -- Neither seq nor uid provided
    return redis.error_reply("Either sequence or UID must be provided");
end

-- Process removal if entry found
if entry and entry ~= "" and uid > 0 then 
    -- Atomic removal
    local removed = redis.call("ZREMRANGEBYSCORE", listKey, uid, uid);
    
    if removed == 1 then
        -- Only decrement if mailbox exists and count is positive
        if redis.call("EXISTS", mailboxKey) == 1 then
            local currentCount = tonumber(redis.call("HGET", mailboxKey, "messages") or "0");
            
            if currentCount > 0 then
                redis.call("HINCRBY", mailboxKey, "messages", -1);
            else
                redis.log(redis.LOG_WARNING, "Attempted to decrement messages below 0 for mailbox: " .. mailboxKey);
            end
        else
            redis.log(redis.LOG_WARNING, "Mailbox key does not exist: " .. mailboxKey);
        end
        
        -- Return successful removal
        return {uid, entry};
    else
        -- Entry disappeared between check and removal (race condition)
        redis.log(redis.LOG_WARNING, "Entry disappeared during removal: uid=" .. uid);
        return nil;
    end
end

-- No entry found
return nil;