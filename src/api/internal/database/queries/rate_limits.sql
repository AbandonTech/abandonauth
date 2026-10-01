-- Counts one request against a fixed window and returns the running total and
-- the seconds remaining in that window.
--
-- Windows are aligned by PostgreSQL rather than the caller, so every API
-- instance buckets a request identically. The insert and the increment are a
-- single statement, so concurrent requests cannot both observe a count below
-- the limit and then both write. The remaining time is rounded up to a whole
-- second, with a minimum of one, as Retry-After requires.
-- name: CountRequestInWindow :one
WITH current_window AS (
    SELECT
        date_bin(
            make_interval(secs => sqlc.arg(window_seconds)::bigint),
            CURRENT_TIMESTAMP,
            TIMESTAMPTZ '1970-01-01 00:00:00+00'
        ) AS window_start,
        make_interval(secs => sqlc.arg(window_seconds)::bigint) AS window_length
)
INSERT INTO rate_limit_bucket (bucket_key, endpoint_group, window_start, expires_at, count)
SELECT $1, $2, window_start, window_start + window_length, 1
FROM current_window
ON CONFLICT (bucket_key, endpoint_group, window_start)
DO UPDATE SET count = rate_limit_bucket.count + 1
RETURNING
    count,
    GREATEST(
        1,
        ceil(extract(epoch FROM (rate_limit_bucket.expires_at - CURRENT_TIMESTAMP)))
    )::bigint AS retry_after_seconds;

-- name: DeleteExpiredRateLimitBuckets :execrows
DELETE FROM rate_limit_bucket
WHERE (bucket_key, endpoint_group, window_start) IN (
    SELECT bucket_key, endpoint_group, window_start
    FROM rate_limit_bucket
    WHERE expires_at <= CURRENT_TIMESTAMP
    LIMIT sqlc.arg(max_rows)
);
