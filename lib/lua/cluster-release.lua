--[[
Script: cluster-release.lua
Purpose: Gives up ownership of an account, provided the releasing instance still owns it.

KEYS:
  [1] ownerKey - Owner record (cluster:own:<account>)

ARGV:
  [1] owner - Id of the releasing instance

Returns:
  1 when released
  0 when another instance owns it (nothing is changed)
--]]

if redis.call("GET", KEYS[1]) == ARGV[1] then
    redis.call("DEL", KEYS[1]);
    return 1;
end;

return 0;
