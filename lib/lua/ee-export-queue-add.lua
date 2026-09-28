--[[
Script: ee-export-queue-add.lua
Purpose: Queues one message of an export in a single round trip

ZADD into the pending set, count the message on the export record only when it was new, and keep
the set alive as long as the record. A retried folder queues the messages its failed attempt
already queued: ZADD leaves an existing member alone, and only a new one may count, or
messagesQueued ends up above exported + skipped and the progress never reaches it. Nothing is
counted on a record that no longer exists (a deleted export), which HINCRBY would otherwise
recreate as a hash holding nothing but the counter.

KEYS:
  [1] exportKey - The export record hash
  [2] queueKey - The pending-message sorted set

ARGV:
  [1] score
  [2] member
  [3] counterField - The record field counting queued messages

Returns:
  1 when the member was new, 0 when it was already queued
--]]

local exportKey = KEYS[1]
local queueKey = KEYS[2]

local added = redis.call("ZADD", queueKey, ARGV[1], ARGV[2])

local ttl = redis.call("PTTL", exportKey)
if ttl > 0 then
    redis.call("PEXPIRE", queueKey, ttl)
end

if added == 1 and ttl ~= -2 then
    redis.call("HINCRBY", exportKey, ARGV[3], 1)
end

return added
