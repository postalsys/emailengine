--[[
Script: h-del-if-equals.lua
Purpose: Drops a set of hash fields only when a guard field still holds the value the caller read,
         so a record that was replaced between the read and the delete is left for whoever wrote it.

         The error state of an account is read, judged and then dropped. Everything in between is
         an await, and another failure written in that window would be deleted by a decision taken
         before it existed - leaving the account reporting a healthy state it is not in.

KEYS:
  [1] hashKey - The hash key to operate on

ARGV:
  [1] guardKey - The hash field whose value the decision was taken on
  [2] expected - The value the caller read; an empty string means "expect the field to be absent"
  [3..] fields - The fields to delete

Returns:
  1 if the guard matched and the fields were dropped
  0 if the guard holds something else, meaning the record is no longer the one that was judged
--]]

local hashKey = KEYS[1];
local guardKey = ARGV[1];
local expected = ARGV[2];

-- HGET answers a missing field with false, which is the same test as any other mismatch once it
-- is read as the empty string
local current = redis.call("HGET", hashKey, guardKey) or "";

if current ~= expected then
    return 0;
end

if #ARGV > 2 then
    redis.call("HDEL", hashKey, unpack(ARGV, 3));
end

return 1;
