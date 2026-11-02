--[[
Script: account-set-state.lua
Purpose: Records the connection state of an account, together with the run of the process that
         reached it, but only while that run owns the account.

         Several EmailEngine instances share one Redis (lib/cluster/). The instance that claims an
         account writes its run into the account record as `ownerRun` (cluster-claim.lua). A process
         that lost the account (frozen past its heartbeat while another instance took over, then
         thawed) still runs its connection for a moment before it notices; its state writes would
         overwrite the new owner's, so they are refused here. A record that has no `ownerRun` was
         never claimed through the cluster and is always written.

         The stored `runIndex` equal to `ownerRun` is what tells the API the state is current
         (lib/account/account-state.js).

KEYS:
  [1] accountKey - Account record (iad:<account>)

ARGV:
  [1] state - New connection state
  [2] runIndex - Run of the writing process

Returns:
  {1, previousCount, newCount} when written; previousCount is the state's counter before this
     write (false when it had none), newCount after it
  {0} when the account no longer exists
  {-1} when another run owns the account
--]]

local accountKey = KEYS[1];
local state = ARGV[1];
local runIndex = ARGV[2];

if redis.call("EXISTS", accountKey) == 0 then
    return {0};
end;

local ownerRun = redis.call("HGET", accountKey, "ownerRun");
if ownerRun and ownerRun ~= runIndex then
    return {-1};
end;

local counterKey = "state:count:" .. state;
local previous = redis.call("HGET", accountKey, counterKey);

redis.call("HSET", accountKey, "state", state, "runIndex", runIndex);
local current = redis.call("HINCRBY", accountKey, counterKey, 1);

return {1, previous, current};
