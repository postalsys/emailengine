--[[
Script: z-get-mailbox-id.lua
Purpose: Gets or creates a numeric mailbox ID for a given mailbox path

KEYS:
  [1] accountKey - Hash key for account-level data (contains 'listRegistry' counter)
  [2] hashKey - Hash key for path-to-ID mappings

ARGV:
  [1] path - The mailbox path (e.g., "INBOX", "Sent/2024")

Returns:
  Numeric mailbox ID (existing or newly created)

Notes:
  - Creates a bidirectional mapping: path -> ID and "ix:ID" -> path
  - Auto-increments 'listRegistry' counter for new IDs
  - Clears old mappings when creating first ID (id=1) for an account
--]]

local accountKey = KEYS[1];
local hashKey = KEYS[2];

local path = ARGV[1];

-- Check if path already has an ID
local id = tonumber(redis.call("HGET", hashKey, path)) or 0;
if id == 0 then
    -- ID not yet created, generate new one
    id = redis.call("HINCRBY", accountKey, 'listRegistry', 1);
    if id == 1 then
        -- First entry on the account, clean up any old mappings
        redis.call("DEL", hashKey);
    end;

    -- Create bidirectional mapping: path <-> ID
    redis.call("HSET", hashKey, path, id);
    redis.call("HSET", hashKey, "ix:" .. id, path);
end;

return id;

