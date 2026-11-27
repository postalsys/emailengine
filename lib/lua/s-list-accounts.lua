--[[
Script: s-list-accounts.lua
Purpose: Lists and filters accounts from a Redis set with pagination and search

KEYS:
  [1] listKey - Set key containing account IDs

ARGV:
  [1] filterState - Account state to filter by: '*' for all states, a single state,
      or a comma-separated list of states (entry matches any listed state)
  [2] skip - Number of matching entries to skip (pagination offset)
  [3] count - Maximum number of entries to return
  [4] prefix - Key prefix for account data hashes (e.g., "ee:")
  [5] strsearch - Case-insensitive substring to search in account, name, or email fields.
      Folded here as well as by the caller, so a caller that passes it as typed still gets a
      case-insensitive search. string.lower() folds ASCII only; a caller that has to match
      non-ASCII has to fold the needle itself before passing it in.
  [6] domain - Optional email domain. Matches an address whose part after the last "@" is the
      domain itself or a subdomain of it: "acme.com" matches "a@acme.com" and "a@eu.acme.com",
      never "a@acme.com.au" or "a@notacme.com". Empty for no domain filter.
  [7] kinds - Optional comma-separated account kinds to keep (imap, sending, delegated, and the
      kinds named in ARGV[8]). Empty for no kind filter.
  [8] appKinds - The kind of each OAuth2 app, as "appId=kind" entries separated by newlines.
      An account bound to an app missing from this list has the kind "oauth2".

The kind mirrors the `type` Account#listAccounts() reports, decided from the stored `oauth2` and
`imap` JSON alone, so a kind filter never reads a whole account record: a provider app decides it
first, then a delegated credential, then an IMAP configuration that the operator has not switched
off (a park by the auth-failure safety net, marked by `_authFailureDisabled`, is still IMAP), and
anything else is "sending".

Returns:
  Array with:
    [1] Total number of matching entries
    [2] Skip value used
    [3] Array of account data (HGETALL results for each matching account)

NOTE: Single-node only. The per-account hashes are built from the prefix inside the script
instead of being declared in KEYS, so a Redis Cluster cannot route or slot-check them.
--]]

local listKey = KEYS[1];

local filterState = ARGV[1];
local skip = tonumber(ARGV[2]) or 0;
local count = tonumber(ARGV[3]) or 0;
local prefix = ARGV[4];
local strsearch = string.lower(ARGV[5] or '');
local domain = string.lower(ARGV[6] or '');
local kindFilter = ARGV[7] or '';
local appKindList = ARGV[8] or '';

-- filterState may be a comma-separated list; build a lookup set once
local stateSet = nil;
if filterState ~= '*' then
    stateSet = {};
    for stateEntry in string.gmatch(filterState, "([^,]+)") do
        stateSet[stateEntry] = true;
    end
end

local kindSet = nil;
if kindFilter ~= '' then
    kindSet = {};
    for kindEntry in string.gmatch(kindFilter, "([^,]+)") do
        kindSet[kindEntry] = true;
    end
end

local appKinds = {};
for appEntry in string.gmatch(appKindList, "([^\n]+)") do
    local eq = string.find(appEntry, "=", 1, true);
    if eq then
        appKinds[string.sub(appEntry, 1, eq - 1)] = string.sub(appEntry, eq + 1);
    end
end

-- Parsed JSON object, or nil for a missing value, a JSON null or anything that does not parse
local function decodeObject(value)
    if not value then
        return nil;
    end
    local ok, decoded = pcall(cjson.decode, value);
    if ok and type(decoded) == 'table' then
        return decoded;
    end
    return nil;
end

local function isString(value)
    return type(value) == 'string' and value ~= '';
end

-- The fields an account is read for, decided once: only what the active filters look at, read in
-- one HMGET per account
local fields = {};
local slot = {};
local function want(field)
    if not slot[field] then
        fields[#fields + 1] = field;
        slot[field] = #fields;
    end
end
if stateSet then want("state") end
if strsearch ~= '' then want("account"); want("name"); want("email") end
if domain ~= '' then want("email") end
if kindSet then want("oauth2"); want("imap"); want("_authFailureDisabled") end

local function accountKind(values)
    local oauth2 = decodeObject(values[slot.oauth2]);

    if oauth2 and isString(oauth2.provider) then
        return appKinds[oauth2.provider] or 'oauth2';
    end

    if oauth2 and type(oauth2.auth) == 'table' and isString(oauth2.auth.delegatedAccount) then
        return 'delegated';
    end

    -- decoded only when no OAuth2 configuration decided it
    local imap = decodeObject(values[slot.imap]);
    if imap and (imap.disabled ~= true or values[slot._authFailureDisabled]) then
        return 'imap';
    end

    return 'sending';
end

local function domainMatches(email)
    email = string.lower(email or "");
    local at = string.match(email, "^.*()@");  -- position of the last "@"
    if not at then
        return false;
    end
    local host = string.sub(email, at + 1);
    if host == domain then
        return true;
    end
    local suffix = "." .. domain;
    return #host > #suffix and string.sub(host, -#suffix) == suffix;
end

local total = redis.call("SCARD", listKey);  -- Get total account count

local list = redis.call("SMEMBERS", listKey);  -- Load all account IDs

local filtered = filterState ~= '*' or strsearch ~= '' or domain ~= '' or kindSet ~= nil;

-- Early return if offset exceeds total. Only for an unfiltered listing: with a filter or a search
-- the first value is the number of MATCHING accounts, which SCARD is not, so a page past the end
-- used to report every account as matching.
if skip >= total and not filtered then
	return {total,skip, {}}
end

local shouldSkip = skip;
local matching = 0;
local result = {}

-- Sort list by account IDs for consistent ordering
table.sort(list);

for index, account in ipairs(list) do
    local key = prefix .. "iad:" .. account;

    local values = #fields > 0 and redis.call("HMGET", key, unpack(fields)) or {};

    -- Cheapest test first; the JSON is decoded last, and only for accounts still in the running
    local matches = true;

    if stateSet then
        local state = values[slot.state];
        matches = state and stateSet[state] or false;
    end

    if matches and strsearch ~= '' then
        matches = false;
        for _, field in ipairs({ "account", "name", "email" }) do
            local value = values[slot[field]];
            if value and string.find(string.lower(value), strsearch, 1, true) then
                matches = true;
                break;
            end
        end
    end

    if matches and domain ~= '' then
        matches = domainMatches(values[slot.email]);
    end

    if matches and kindSet then
        matches = kindSet[accountKind(values)] or false;
    end

    if matches then
        if shouldSkip == 0 then
            -- Pagination offset reached, can include this entry
            if #result < count then
                -- Add account data to result
                result[#result + 1] = redis.call("HGETALL", key);
            elseif not filtered then
                -- Result buffer full, and with nothing to filter every remaining account matches
                matching = total;
                break;
            end
        else
            shouldSkip = shouldSkip - 1;  -- Decrement skip counter
        end

        matching = matching + 1;  -- Count matching entries
    end
end

return {matching, skip, result}
