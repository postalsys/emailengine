--[[
Script: h-push.lua
Purpose: Appends data to a hash field value (concatenates strings)

KEYS:
  [1] hashKey - The hash key to operate on

ARGV:
  [1] entryKey - The hash field name
  [2] buf - The string buffer to append

Returns:
  2 if field existed and data was appended
  1 if field was newly created with the data
--]]

local hashKey = KEYS[1];
local entryKey = ARGV[1];

local buf = ARGV[2];

if redis.call("HEXISTS", hashKey, entryKey) == 1 then
    -- Field exists, append to existing content
    local content = redis.call("HGET", hashKey, entryKey);
    redis.call("HSET", hashKey, entryKey, content .. buf);
    return 2;  -- Indicates append operation
else
    -- Field doesn't exist, create new
    redis.call("HSET", hashKey, entryKey, buf);
    return 1;  -- Indicates new field creation
end;

