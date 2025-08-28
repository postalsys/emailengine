--[[
Script: h-update-bigger.lua
Purpose: Updates a hash field value only if the existing value is lower than a threshold

KEYS:
  [1] hashKey - The hash key to operate on

ARGV:
  [1] hashField - The hash field name
  [2] lowerThanVal - Update only if existing value is lower than this threshold
  [3] updatedVal - The new value to set

Returns:
  2 if field was updated (existing was lower or non-numeric)
  1 if field didn't exist and was created
  0 if existing value was >= threshold (no operation)
--]]

local hashKey = KEYS[1];
local hashField = ARGV[1];

local lowerThanVal = tonumber(ARGV[2]) or 0;
local uptatedVal = tonumber(ARGV[3]) or 0;

if redis.call("HEXISTS", hashKey, hashField) == 1 then
    local existing = redis.call("HGET", hashKey, hashField);
    local existingNum = tonumber(existing);

    -- Handle case where existing value is not a valid number
    if existingNum == nil then
        -- Treat non-numeric existing value as 0
        redis.call("HSET", hashKey, hashField, uptatedVal);
        return 2;  -- Updated (non-numeric treated as lower)
    elseif existingNum < lowerThanVal then
        -- Existing value is below threshold, update it
        redis.call("HSET", hashKey, hashField, uptatedVal);
        return 2;  -- Updated
    end;
else
    -- Field doesn't exist, create it
    redis.call("HSET", hashKey, hashField, uptatedVal);
    return 1;  -- Created new field
end;

return 0;  -- No update needed (value >= threshold)