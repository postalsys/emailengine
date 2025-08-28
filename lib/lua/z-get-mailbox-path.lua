--[[
Script: z-get-mailbox-path.lua
Purpose: Retrieves a mailbox path by its numeric ID

KEYS:
  [1] hashKey - Hash key containing ID-to-path mappings

ARGV:
  [1] id - The numeric mailbox ID to look up

Returns:
  The mailbox path string if found
  nil if ID doesn't exist
--]]

local hashKey = KEYS[1];
local id = ARGV[1];

-- Look up path by ID using the index prefix
return redis.call("HGET", hashKey, "ix:" .. id)
