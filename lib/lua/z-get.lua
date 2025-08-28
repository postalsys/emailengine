--[[
Script: z-get.lua
Purpose: Retrieves a message from a sorted set by sequence number

KEYS:
  [1] listKey - Sorted set key containing messages (score = UID)

ARGV:
  [1] seq - Message sequence number (1-based index)

Returns:
  Array with [uid, entry, seq] if message found
    - uid: The message UID
    - entry: The message data
    - seq: The sequence number (same as input)
  nil if message not found or list doesn't exist
--]]

local listKey = KEYS[1];

local seq = tonumber(ARGV[1]) or 0;

if redis.call("EXISTS", listKey) == 1 then
    -- Get message at sequence position (0-based index, so seq-1)
    local list = redis.call("ZRANGE", listKey, seq-1, seq-1, "WITHSCORES");
    
    -- Check if list has results before accessing elements
    if #list >= 2 then
        local entry = list[1];
        local uid = tonumber(list[2]) or 0;

        if entry ~= nil and entry ~= "" and uid > 0 then 
            return {uid, entry, seq};
        end;
    end;
end;

return nil;
