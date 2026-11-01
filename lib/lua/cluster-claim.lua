--[[
Script: cluster-claim.lua
Purpose: Takes ownership of an account, provided its owner record still says what the claiming
         instance read. Two instances that both decided to claim (one saw the owner dead a moment
         before the other) converge on one winner.

         Taking an account from another instance requires that instance's record to be gone at the
         moment of the claim, not only when the caller read it: an instance that was frozen or cut
         off registers again and keeps every account still recorded as its own, and a claim planned
         from the earlier read would otherwise land after that and leave both serving the account.

         The run of the claiming instance is written into the account record as `ownerRun`. The
         connection writes its own run as `runIndex` once it has connected, so an account whose
         `runIndex` differs from `ownerRun` has not connected in its current owner yet, which is how
         the API tells a fresh state from a stale one (lib/account/account-state.js).

KEYS:
  [1] ownerKey - Owner record (cluster:own:<account>)
  [2] accountKey - Account record (iad:<account>)
  [3] expectedKey - Record of the expected owner (cluster:inst:<expected>), checked only when the
      expected owner is another instance

ARGV:
  [1] expected - Owner the caller read, empty for none
  [2] owner - Id of the claiming instance
  [3] ownerRun - Run index of the claiming instance

Returns:
  {1, owner} when claimed
  {0, current} when the record changed or the expected owner is alive again, current being the
     owner it holds now
  {-1, ''} when the account no longer exists; a stale owner record is removed
--]]

local ownerKey = KEYS[1];
local accountKey = KEYS[2];
local expectedKey = KEYS[3];

local current = redis.call("GET", ownerKey) or "";
if current ~= ARGV[1] then
    return {0, current};
end;

if current ~= "" and current ~= ARGV[2] and redis.call("EXISTS", expectedKey) == 1 then
    return {0, current};
end;

if redis.call("EXISTS", accountKey) == 0 then
    redis.call("DEL", ownerKey);
    return {-1, ""};
end;

redis.call("SET", ownerKey, ARGV[2]);
redis.call("HSET", accountKey, "ownerRun", ARGV[3]);

return {1, ARGV[2]};
