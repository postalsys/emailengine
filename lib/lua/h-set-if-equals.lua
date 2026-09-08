--[[
Script: h-set-if-equals.lua
Purpose: Replaces a hash field only when it still holds the value the caller last read, so two
         processes that both decided to replace the same record converge on one winner instead of
         overwriting each other.

         HSETNX converges only when the field is absent. Deleting first and then HSETNX looks
         equivalent but is not: between the delete and the set, a second process sees an empty field
         and wins the HSETNX too, and both walk away believing they own the record.

KEYS:
  [1] hashKey - The hash key to operate on

ARGV:
  [1] entryKey - The hash field name
  [2] value - The value to set
  [3] expected - The value the caller read; an empty string means "expect the field to be absent"

Returns:
  1 if the field matched and was replaced (or was absent as expected and created)
  0 if the field holds something else, meaning another process got there first
--]]

local hashKey = KEYS[1];
local entryKey = ARGV[1];

local value = ARGV[2];
local expected = ARGV[3];

-- HGET answers a missing field with false, which is the same test as any other mismatch once it
-- is read as the empty string
local current = redis.call("HGET", hashKey, entryKey) or "";

if current ~= expected then
    return 0;
end

redis.call("HSET", hashKey, entryKey, value);
return 1;
