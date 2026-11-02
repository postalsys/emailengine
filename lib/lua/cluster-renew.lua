--[[
Script: cluster-renew.lua
Purpose: Renews the heartbeat of an instance run and updates its record, but only while the record
         is still the one this run registered. A record that expired (the process was frozen or cut
         off from Redis for longer than its TTL) is gone for good: other instances may have taken its
         accounts, and the run has to find out rather than quietly bring the record back.

KEYS:
  [1] instanceKey - Hash of the instance (cluster:inst:<id>)
  [2] instancesKey - Set of registered instance ids (cluster:instances)

ARGV:
  [1] id - Instance id
  [2] token - Token of this run
  [3] ttl - Milliseconds the record lives unless renewed again
  [4...] field, value pairs to update

Returns:
  1 when renewed
  0 when the record is gone or belongs to another run
--]]

local instanceKey = KEYS[1];
local instancesKey = KEYS[2];

if redis.call("HGET", instanceKey, "token") ~= ARGV[2] then
    return 0;
end;

if #ARGV > 3 then
    redis.call("HSET", instanceKey, unpack(ARGV, 4));
end;
redis.call("PEXPIRE", instanceKey, ARGV[3]);
-- Idempotent, and it puts back a set member lost some other way (the set evicted or edited by
-- hand); a prune cannot race this, cluster-prune.lua checks the record and removes in one step
redis.call("SADD", instancesKey, ARGV[1]);

return 1;
