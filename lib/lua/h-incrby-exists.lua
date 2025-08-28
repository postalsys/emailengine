--[[
Script: h-incrby-exists.lua
Purpose: Increments a hash field value only if the hash exists

KEYS:
  [1] hashKey - The hash key to operate on

ARGV:
  [1] entryKey - The hash field name
  [2] value - The increment value (numeric)

Returns:
  The new value after increment if hash exists
  0 if hash does not exist (no operation performed)
--]]

local hashKey = KEYS[1];
local entryKey = ARGV[1];

local value = tonumber(ARGV[2]) or 0;

-- Only increment if the hash exists
if redis.call("EXISTS", hashKey) == 1 then
    return redis.call("HINCRBY", hashKey, entryKey, value);
else
    return 0;  -- Hash doesn't exist, return 0
end;

