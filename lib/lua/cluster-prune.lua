--[[
Script: cluster-prune.lua
Purpose: Removes an instance id from the member set once its record has expired. Checked and removed
         in one step: a reader that saw the record missing and then removed the id separately could
         remove an instance that registered in between, which every other instance would then treat
         as dead while it serves its accounts.

KEYS:
  [1] instanceKey - Hash of the instance (cluster:inst:<id>)
  [2] instancesKey - Set of registered instance ids (cluster:instances)

ARGV:
  [1] id - Instance id

Returns:
  1 when the id was removed
  0 when the record is alive
--]]

if redis.call("EXISTS", KEYS[1]) == 1 then
    return 0;
end;

redis.call("SREM", KEYS[2], ARGV[1]);
return 1;
