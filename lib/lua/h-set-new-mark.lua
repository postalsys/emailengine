--[[
Script: h-set-new-mark.lua
Purpose: Sets a hash field value only if the field doesn't already exist, and stamps a second
         marker field in the same atomic step when it does. Used for seeded defaults that a
         marker field declares "still owned by the seeder": writing the two separately leaves a
         crash window where the seeded value exists without its marker and can never be told
         apart from an explicit choice.

KEYS:
  [1] hashKey - The hash key to operate on

ARGV:
  [1] entryKey - The hash field name
  [2] value - The value to set
  [3] markerKey - The marker field name, written only when the value field was created
  [4] markerValue - The marker value

Returns:
  1 if the value field didn't exist and both fields were written
  0 if the value field already exists (no operation, the marker is not touched)
--]]

local hashKey = KEYS[1];
local entryKey = ARGV[1];

local value = ARGV[2];
local markerKey = ARGV[3];
local markerValue = ARGV[4];

if redis.call("HEXISTS", hashKey, entryKey) == 0 then
    redis.call("HSET", hashKey, entryKey, value);
    redis.call("HSET", hashKey, markerKey, markerValue);
    return 1;  -- New field created and marked
else
    return 0;  -- Field already exists, no operation
end;
