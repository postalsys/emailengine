
local bucketKeyPrefix = KEYS[1];
local idempotencyKey = ARGV[1];

-- Use run index and thread ID check to determine if previously pending job has been terminated
-- EmailEngine assigns a specific thread to process all actions for the same user
local runIndex = tonumber(ARGV[2]);
local threadId = tonumber(ARGV[3]);

local buckets = ARGV[4];

local lastBucket = nil;

for bucket in string.gmatch(buckets, "([^,]+)") do
    local bucketKey = bucketKeyPrefix .. bucket;
    if redis.call("HEXISTS", bucketKey, idempotencyKey) == 1 then
        local existingValue = redis.call("HGET", bucketKeyPrefix .. bucket, idempotencyKey);

        local parsedValue = cjson.decode(existingValue);
        local existingStatus = parsedValue["status"];
        local existingRunIndex = parsedValue["runIndex"];
        local existingThreadId = parsedValue["threadId"];

        if existingStatus == "pending" and (existingRunIndex < runIndex or existingThreadId ~= threadId) then
            -- found match but ignore it
            redis.log( redis.LOG_NOTICE, "EE: Ignoring pending task with old run index: " .. existingValue .. " Current run index: " .. tostring(runIndex).. " Current thread ID: " .. tostring(threadId));
        else
            parsedValue['bucketKey'] = bucketKey;
            return existingValue;
        end

    end

    lastBucket = bucket;
end

-- No idempotency key found, create a new entry to the newest bucket
local bucketKey = bucketKeyPrefix .. lastBucket;

local newValue = {
    ['status'] = 'pending',
    ['runIndex'] = runIndex,
    ['threadId'] = threadId
};

redis.call("HSET", bucketKey, idempotencyKey, cjson.encode(newValue));
redis.call("EXPIRE", bucketKey, 24 * 3600);

-- return with a "new" status
newValue['status'] = 'new';
newValue['bucketKey'] = bucketKey;
return cjson.encode(newValue)