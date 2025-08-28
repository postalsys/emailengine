--[[
Script: z-get-by-uid.lua
Purpose: Retrieves a message from a sorted set by UID

KEYS:
  [1] listKey - Sorted set key containing messages (score = UID)

ARGV:
  [1] uid - Message UID to retrieve

Returns:
  Array with [uid, entry, seq] if message found
    - uid: The message UID
    - entry: The message data
    - seq: The sequence number (position + 1)
  nil if message not found or list doesn't exist
--]]

local listKey = KEYS[1];

local uid = tonumber(ARGV[1]) or 0;

if redis.call("EXISTS", listKey) == 1 then
    local list = redis.call("ZRANGEBYSCORE", listKey, uid, uid, "WITHSCORES");
    
    -- Check if list has results before accessing elements
    if #list >= 2 then
        local entry = list[1];
        local actualUid = tonumber(list[2]) or 0;

        if entry ~= nil and entry ~= "" and actualUid > 0 then 
            -- Calculate sequence number based on UID position
            local seq = redis.call("ZCOUNT", listKey, 0, actualUid);
            return {actualUid, entry, seq};
        end;
    end;
end;

return nil;
