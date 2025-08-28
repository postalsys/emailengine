--[[
Script: h-set-new.lua
Purpose: Sets a hash field value only if the field doesn't already exist

KEYS:
  [1] hashKey - The hash key to operate on

ARGV:
  [1] entryKey - The hash field name
  [2] value - The value to set

Returns:
  1 if field didn't exist and was created
  0 if field already exists (no operation)
--]]

local hashKey = KEYS[1];
local entryKey = ARGV[1];

local value = ARGV[2];

-- Only set if field doesn't exist (set-if-not-exists)
if redis.call("HEXISTS", hashKey, entryKey) == 0 then
    redis.call("HSET", hashKey, entryKey, value);
    return 1;  -- New field created
else
    return 0;  -- Field already exists, no operation
end;

