--[[
Script: h-set-bigger.lua
Purpose: Sets a hash field value only if the new value is greater than existing value or field doesn't exist

KEYS:
  [1] hashKey - The hash key to operate on

ARGV:
  [1] entryKey - The hash field name
  [2] value - The new numeric value to set

Returns:
  3 if field existed and new value was bigger (updated)
  2 if field didn't exist but hash exists (created)
  1 if field existed but new value was not bigger (no change)
  0 if hash doesn't exist (no operation)
--]]

local hashKey = KEYS[1];
local entryKey = ARGV[1];

local value = ARGV[2];

if redis.call("HEXISTS", hashKey, entryKey) == 1 then
    -- Field exists, compare values
    local existing = redis.call("HGET", hashKey, entryKey);
    if tonumber(value) > tonumber(existing) then
        -- New value is bigger, update it
        redis.call("HSET", hashKey, entryKey, value);
        return 3;  -- Updated with bigger value
    else
        return 1;  -- Existing value is bigger or equal, no change
    end;
elseif redis.call("EXISTS", hashKey) == 1 then
    -- Hash exists but field doesn't, create new field
    redis.call("HSET", hashKey, entryKey, value);
    return 2;  -- Created new field
end;

return 0;  -- Hash doesn't exist
