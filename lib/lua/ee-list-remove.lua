--[[
Script: ee-list-remove.lua
Purpose: Atomically removes an email address from a list and updates list counts

KEYS:
  [1] listsKey - Hash key storing counts for each list (e.g., "lists:counts")
  [2] entryKey - Hash key storing actual list entries (e.g., "list:allowlist")

ARGV:
  [1] list - Name of the list (e.g., "allowlist", "blocklist")
  [2] address - Email address to remove

Returns:
  1 if the entry was removed
  0 if the entry did not exist
--]]

local listsKey = KEYS[1];
local entryKey = KEYS[2];

local list = ARGV[1];
local address = ARGV[2];

-- Remove the address from the list
local removed = redis.call("HDEL", entryKey, address);

if removed == 1 then
    -- Entry was removed, decrement list count
    redis.call("HINCRBY", listsKey, list, -1);
    local count = redis.call("HGET", listsKey, list);
    if tonumber(count) == 0 then
        -- Clean up empty list counter
        redis.call("HDEL", listsKey, list);
    end;
end;

return removed;