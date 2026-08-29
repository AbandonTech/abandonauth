-- Counts one request against a fixed window and reports the running total.
--
-- The insert and the increment are one statement, so concurrent workers cannot
-- both read a count below the limit and then both write it. The caller derives
-- window_start by truncating the current time to the window length, which keeps
-- the key stable for every request in the same window.
-- name: CountRequestInWindow :one
INSERT INTO rate_limit_bucket (bucket_key, endpoint_group, window_start, expires_at, count)
VALUES ($1, $2, sqlc.arg(window_start), sqlc.arg(expires_at), 1)
ON CONFLICT (bucket_key, endpoint_group, window_start)
DO UPDATE SET count = rate_limit_bucket.count + 1
RETURNING count;

-- name: DeleteExpiredRateLimitBuckets :execrows
DELETE FROM rate_limit_bucket
WHERE (bucket_key, endpoint_group, window_start) IN (
    SELECT bucket_key, endpoint_group, window_start
    FROM rate_limit_bucket
    WHERE expires_at <= CURRENT_TIMESTAMP
    LIMIT sqlc.arg(max_rows)
);
