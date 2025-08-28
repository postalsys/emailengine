--[[
Script: h-set-exists.lua
Purpose: Sets a hash field value only if the hash exists

KEYS:
  [1] hashKey - The hash key to operate on

ARGV:
  [1] entryKey - The hash field name
  [2] value - The value to set

Returns:
  1 if hash exists and field was set
  0 if hash doesn't exist (no operation)
--]]

local hashKey = KEYS[1];
local entryKey = ARGV[1];

local value = ARGV[2];

-- Only set field if hash exists
if redis.call("EXISTS", hashKey) == 1 then
    redis.call("HSET", hashKey, entryKey, value);
    return 1;  -- Field was set
else
    return 0;  -- Hash doesn't exist, no operation
end;

