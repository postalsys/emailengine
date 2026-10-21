--[[
Script: z-head-scores.lua
Purpose: Returns the scores of the lowest-scored entries of a sorted set, without the members.
For a queue scored by UID whose members are full JSON payloads, the UIDs are all a caller wants,
and ZRANGE WITHSCORES would send every payload along with them

KEYS:
  [1] key - Sorted set key

ARGV:
  [1] count - How many entries to read from the head of the set

Returns:
  Array of scores (as strings), lowest first; empty when the set does not exist
--]]

local count = tonumber(ARGV[1]) or 0;
if count < 1 then
    return {};
end;

local list = redis.call("ZRANGE", KEYS[1], 0, count - 1, "WITHSCORES");
local scores = {};
for i = 2, #list, 2 do
    scores[#scores + 1] = list[i];
end;

return scores;
