--[[
Script: z-set.lua
Purpose: Adds or replaces a message in a sorted set with UID as score

KEYS:
  [1] listKey - Sorted set key for storing messages

ARGV:
  [1] uid - Message UID (used as score)
  [2] buf - Message data to store

Returns:
  The sequence number (position + 1) of the inserted entry
  nil if the entry could not be added

Notes:
  - Removes any existing entry with the same UID before adding
  - Returns the new sequence number based on UID ordering
--]]

local listKey = KEYS[1];

local uid = tonumber(ARGV[1]) or 0;
local buf = ARGV[2];

-- Remove any existing entry with same UID to ensure uniqueness
if redis.call("EXISTS", listKey) == 1 then
   redis.call("ZREMRANGEBYSCORE", listKey, uid, uid);
end

-- Add new entry with UID as score
local added = redis.call("ZADD", listKey, uid, buf);
if added ~= 1 then
    -- Failed to add entry
    return nil;
end;

-- Return sequence number (1-based position) for the inserted entry
return redis.call("ZCOUNT", listKey, 0, uid);