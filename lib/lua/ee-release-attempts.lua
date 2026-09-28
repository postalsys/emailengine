--[[
Script: ee-release-attempts.lua
Purpose: Gives back a reservation made by ee-reserve-attempts.lua, for an attempt that succeeded

A counter that is back at zero is deleted, and one that already expired is not recreated as a
negative number.

KEYS:
  [i] the counter of budget i

Returns:
  1
--]]

for _, key in ipairs(KEYS) do
    if redis.call("EXISTS", key) == 1 then
        if redis.call("DECR", key) <= 0 then
            redis.call("DEL", key)
        end
    end
end

return 1
