--[[
Script: ee-list-add.lua
Purpose: Atomically adds an email address to a list (e.g., allowlist/blocklist) and tracks list counts

KEYS:
  [1] listsKey - Hash key storing counts for each list (e.g., "lists:counts")
  [2] entryKey - Hash key storing actual list entries (e.g., "list:allowlist")

ARGV:
  [1] list - Name of the list (e.g., "allowlist", "blocklist")
  [2] address - Email address to add
  [3] data - Associated data/metadata for the entry

Returns:
  1 if the entry was newly added
  0 if the entry already existed (update only)
--]]

local listsKey = KEYS[1];
local entryKey = KEYS[2];

local list = ARGV[1];
local address = ARGV[2];
local data = ARGV[3];

-- Add or update the address in the list
local added = redis.call("HSET", entryKey, address, data);

if added == 1 then
    -- New entry was added, increment list count
    redis.call("HINCRBY", listsKey, list, 1);
end;

return added;