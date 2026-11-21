---
description: The in-house queue browser at /admin/queues and the outbox rules for submit-queue actions (retry, promote, delete, retained failed content).
paths:
  - "lib/queue-browser/**"
  - "lib/ui-routes/queue-routes.js"
  - "lib/outbox.js"
  - "lib/queue-retention.js"
  - "lib/queue-job-actions.js"
  - "lib/queue-stats.js"
  - "static/js/queues.js"
  - "views/queues/**"
  - "workers/submit.js"
  - "test/queue-*.js"
  - "test/outbox-*.js"
---

## Queue browser

`/admin/queues` (`lib/ui-routes/queue-routes.js`, model in `lib/queue-browser/`) is the in-house browser for the three BullMQ queues, which replaced the bundled bull-board page on 2026-10-14; `/admin/bull-board` and its deep links redirect there. `definitions.js` names the queues, the five states and which actions apply (the export queue is read-only: an export is managed from its account page, where cancelling it also removes its file); `format.js` turns a stored job into a webhook delivery, an outgoing message or an export and explains a failure in the worker's own terms (pure, tested in `test/queue-browser-format-test.js`); `index.js` holds everything that touches Redis. Listings read one page of a state straight from BullMQ, and a search is a scan of that state bounded by `SCAN_LIMIT` (500 jobs, newest first) that the page reports the extent of - a queue has no index by account or anything else in the payload, and an unbounded scan would read every webhook payload with it. Counts refresh by polling `/admin/queues/counts` from `static/js/queues.js`, not over the change feed: a busy instance fans out thousands of queue events a minute and none of them is worth pushing to a page that shows totals.

Two things make the submit queue different from a generic BullMQ queue, and they are why bull-board was wrong for it: a message's content lives outside its job in the account's `iaq:` hash, so removing a job alone orphans the message in Redis, and retrying a job whose content is gone completes without sending anything while reporting success. Every submit action therefore goes through `lib/outbox.js`, which owns both halves: `del()` removes the content with the job (refusing one a worker holds), `retry()` refuses a message that is not failed or whose content is gone (409 with `code` NotFailed / ContentGone) and otherwise resets the attempt count, `promote()` sends a delayed message now. The REST API exposes the same two as `POST /v1/outbox/{queueId}/retry` and `/promote` (MCP tools `retry_queued_message` and `send_queued_message_now`, in the `mcp-manage` surface next to the cancel, never in the pinned mail table). For a retry to have something to send, the submit worker's `failed` handler keeps the content of a finally failed message (`retainFailedContent()`) instead of deleting it, within the bounds above (`selectFailedContentToDrop()` in `lib/queue-retention.js`, pure); `pruneFailedContent()` runs from the periodic queue cleanup in `server.js` and after a clean of the failed set, and drops the content of any job that is gone. Both workers record a failed attempt on the job's progress field (`{status: 'error', error: {message, code, statusCode, responseCode}}`, the shape the submit worker always wrote, now with the SMTP reply code so `describeFailure()` can ask `isPermanentDeliveryError()` instead of reading a status as a verdict), because BullMQ itself keeps only the failure message; a delivered webhook is recorded as the processor's return value, which BullMQ stores in the same write that completes the job. The retained contents are a hash (`iaqf`, field `[account, queueId]`, value `{t, s}`) so a release is one HDEL; the count bound is capped at `FAILED_JOB_RETENTION_COUNT` and the age is the failed-job age, so BullMQ's own `removeOnFail` never removes a job before its content goes.
