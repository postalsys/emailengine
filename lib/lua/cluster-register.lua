--[[
Script: cluster-register.lua
Purpose: Registers one run of an instance in the cluster, replacing whatever an earlier run with
         the same instance id left behind, but never a record that is still alive under another
         token: two live processes configured with one instance id must not both believe they are it.

KEYS:
  [1] instanceKey - Hash of the instance (cluster:inst:<id>)
  [2] instancesKey - Set of registered instance ids (cluster:instances)

ARGV:
  [1] id - Instance id
  [2] token - Random token of this run
  [3] ttl - Milliseconds the record lives unless renewed
  [4...] field, value pairs of the record

Returns:
  1 when registered
  0 when a live record of another run holds the id
--]]

local instanceKey = KEYS[1];
local instancesKey = KEYS[2];

local current = redis.call("HGET", instanceKey, "token");
if current and current ~= ARGV[2] then
    return 0;
end;

redis.call("DEL", instanceKey);
redis.call("HSET", instanceKey, "token", ARGV[2], unpack(ARGV, 4));
redis.call("PEXPIRE", instanceKey, ARGV[3]);
redis.call("SADD", instancesKey, ARGV[1]);

return 1;
