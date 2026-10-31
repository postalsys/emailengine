--[[
Script: cluster-leave.lua
Purpose: Removes the record of an instance run that is shutting down, so the other instances see it
         gone at once instead of after its TTL. A record registered meanwhile by another run with the
         same id is left alone.

KEYS:
  [1] instanceKey - Hash of the instance (cluster:inst:<id>)
  [2] instancesKey - Set of registered instance ids (cluster:instances)

ARGV:
  [1] id - Instance id
  [2] token - Token of this run

Returns:
  1 when the record was removed or was already gone
  0 when it belongs to another run
--]]

local instanceKey = KEYS[1];
local instancesKey = KEYS[2];

local current = redis.call("HGET", instanceKey, "token");
if current and current ~= ARGV[2] then
    return 0;
end;

redis.call("DEL", instanceKey);
redis.call("SREM", instancesKey, ARGV[1]);

return 1;
