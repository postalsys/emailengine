
--[[
Script: ee-get-idempotency.lua
Purpose: Manages idempotency keys for preventing duplicate task execution across time-bucketed hashes

KEYS:
  [1] bucketKeyPrefix - Prefix for bucket hash keys (e.g., "ee:idempotency:")

ARGV:
  [1] idempotencyKey - Unique key for the operation to check/store
  [2] runIndex - Current run index (numeric) to detect stale pending tasks
  [3] threadId - Thread ID (numeric) processing this task
  [4] buckets - Comma-separated list of time bucket suffixes to check (e.g., "2024-01-01,2024-01-02")

Returns:
  JSON string containing:
    - status: 'new' (newly created), 'pending' (in progress), 'completed', etc.
    - bucketKey: The Redis key where the idempotency entry is stored
    - runIndex: The run index of the task
    - threadId: The thread ID processing the task
--]]

local bucketKeyPrefix = KEYS[1];
local idempotencyKey = ARGV[1];

local runIndex = tonumber(ARGV[2]);
local threadId = tonumber(ARGV[3]);

local buckets = ARGV[4];

local lastBucket = nil;

-- Iterate through time buckets to find existing idempotency key
for bucket in string.gmatch(buckets, "([^,]+)") do
    local bucketKey = bucketKeyPrefix .. bucket;
    if redis.call("HEXISTS", bucketKey, idempotencyKey) == 1 then
        local existingValue = redis.call("HGET", bucketKey, idempotencyKey);

        local parsedValue = cjson.decode(existingValue);
        local existingStatus = parsedValue["status"];
        local existingRunIndex = parsedValue["runIndex"];
        local existingThreadId = parsedValue["threadId"];

        -- Check if this is a stale pending task from a previous run
        if existingStatus == "pending" and (existingRunIndex < runIndex or existingThreadId ~= threadId) then
            -- Ignore stale pending task
            redis.log( redis.LOG_NOTICE, "EE: Ignoring pending task with old run index: " .. existingValue .. " Current run index: " .. tostring(runIndex).. " Current thread ID: " .. tostring(threadId));
        else
            -- Return existing valid entry
            parsedValue['bucketKey'] = bucketKey;
            return cjson.encode(parsedValue);  -- Return the modified parsedValue with bucketKey
        end

    end

    lastBucket = bucket;  -- Track the last bucket for new entry creation
end

-- No idempotency key found, create a new entry in the newest bucket
local bucketKey = bucketKeyPrefix .. lastBucket;

local newValue = {
    ['status'] = 'pending',
    ['runIndex'] = runIndex,
    ['threadId'] = threadId
};

redis.call("HSET", bucketKey, idempotencyKey, cjson.encode(newValue));
redis.call("EXPIRE", bucketKey, 24 * 3600);  -- Set 24-hour expiration for bucket

-- Return with "new" status to indicate newly created entry
newValue['status'] = 'new';
newValue['bucketKey'] = bucketKey;
return cjson.encode(newValue)