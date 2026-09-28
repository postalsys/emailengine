--[[
Script: ee-reserve-attempts.lua
Purpose: Reserves one attempt in every failure budget at once, or in none of them

INCR and the limit check are one step, so parallel attempts cannot all read the same count and
each go ahead. A refused reservation is taken back, so a spent budget holds at its limit rather
than growing with every refused attempt. A reservation for an attempt that then succeeds is
given back with ee-release-attempts.lua, so only failures stay counted.

KEYS:
  [i] the counter of budget i

ARGV:
  [2i-1] limit - attempts budget i admits, inclusive
  [2i]   ttl - seconds its counter lives, refreshed on every reservation

Returns:
  {1, count1, count2, ...} when the attempt was reserved, the counts including it
  {0, count1, count2, ...} when some budget is spent, the counts as they were
--]]

local counts = {}
local over = false

for i, key in ipairs(KEYS) do
    local count = redis.call("INCR", key)
    redis.call("EXPIRE", key, ARGV[i * 2])
    counts[i] = count
    if count > tonumber(ARGV[i * 2 - 1]) then
        over = true
    end
end

if over then
    for i, key in ipairs(KEYS) do
        redis.call("DECR", key)
        counts[i] = counts[i] - 1
    end
    return {0, unpack(counts)}
end

return {1, unpack(counts)}
