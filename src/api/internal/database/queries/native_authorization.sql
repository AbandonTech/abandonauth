-- Held until the transaction ends by every change to a native authorization,
-- code, refresh family or access token revocation. Rotation takes this row FOR
-- UPDATE, so a change either commits before rotation and is deleted by it, or
-- waits and then finds the epoch it compares against replaced.
-- name: LockAuthEpochShared :one
SELECT epoch
FROM auth_epoch
WHERE singleton
FOR SHARE;

-- Serialises counting the native authorizations in progress with creating one.
-- name: LockNativeAuthorizationCapacity :one
SELECT singleton
FROM oauth_native_authorization_capacity
WHERE singleton
FOR UPDATE;

-- name: DeleteExpiredNativeAuthorizations :execrows
DELETE FROM oauth_native_authorization
WHERE id IN (
    SELECT id
    FROM oauth_native_authorization
    WHERE expires_at <= CURRENT_TIMESTAMP
    ORDER BY expires_at, id
    LIMIT sqlc.arg(max_rows)
);

-- name: CountNativeAuthorizations :one
SELECT count(*)
FROM oauth_native_authorization;

-- name: CreateNativeAuthorization :one
INSERT INTO oauth_native_authorization (
    application_id,
    browser_binding_hash,
    redirect_uri,
    scopes,
    client_state,
    client_nonce,
    code_challenge,
    stage,
    page_handle_hash,
    auth_epoch,
    expires_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    'page',
    sqlc.arg(page_handle_hash),
    sqlc.arg(auth_epoch),
    CURRENT_TIMESTAMP + interval '5 minutes'
)
RETURNING expires_at;

-- What the authorization page may show, and only while the request is still
-- waiting for a choice in the browser that began it.
-- name: GetPendingNativeAuthorization :one
SELECT
    a."name" AS application_name,
    r.scopes,
    r.expires_at
FROM oauth_native_authorization r
JOIN "DeveloperApplication" a ON a."id" = r.application_id
JOIN auth_epoch e ON e.singleton AND e.epoch = r.auth_epoch
WHERE r.page_handle_hash = $1
  AND r.browser_binding_hash = $2
  AND r.stage = 'page'
  AND r.expires_at > CURRENT_TIMESTAMP
  AND a."client_type" = 'public';

-- Spends the page handle on a provider choice. The stage condition is
-- rechecked after any row lock wait, so of a choice and a cancellation racing
-- for one request only one finds it.
-- name: AdvanceNativeAuthorizationToProvider :one
UPDATE oauth_native_authorization
SET stage = 'provider',
    page_handle_hash = NULL
WHERE page_handle_hash = $1
  AND browser_binding_hash = $2
  AND stage = 'page'
  AND expires_at > CURRENT_TIMESTAMP
  AND auth_epoch = sqlc.arg(auth_epoch)
RETURNING id, application_id;

-- name: CancelNativeAuthorization :one
DELETE FROM oauth_native_authorization
WHERE page_handle_hash = $1
  AND browser_binding_hash = $2
  AND stage = 'page'
  AND expires_at > CURRENT_TIMESTAMP
  AND auth_epoch = sqlc.arg(auth_epoch)
RETURNING redirect_uri, client_state;

-- The authorization a verified provider sign-in continues, locked so its code
-- is created at most once, and only while its client is still public.
-- name: LockNativeAuthorizationAwaitingProvider :one
SELECT r.redirect_uri, r.client_state
FROM oauth_native_authorization r
JOIN "DeveloperApplication" a ON a."id" = r.application_id AND a."client_type" = 'public'
WHERE r.id = $1
  AND r.stage = 'provider'
  AND r.expires_at > CURRENT_TIMESTAMP
  AND r.auth_epoch = sqlc.arg(auth_epoch)
FOR UPDATE OF r;

-- A code never outlives its authorization.
-- name: CreateNativeAuthorizationCode :execrows
INSERT INTO oauth_native_authorization_code (
    code_hash,
    authorization_id,
    user_id,
    authenticated_at,
    expires_at
)
SELECT
    $1,
    r.id,
    sqlc.arg(user_id),
    CURRENT_TIMESTAMP,
    LEAST(CURRENT_TIMESTAMP + interval '120 seconds', r.expires_at)
FROM oauth_native_authorization r
WHERE r.id = sqlc.arg(authorization_id);

-- name: MarkNativeAuthorizationCodeIssued :execrows
UPDATE oauth_native_authorization
SET stage = 'code'
WHERE id = $1
  AND stage = 'provider';

-- name: DeleteNativeAuthorization :execrows
DELETE FROM oauth_native_authorization
WHERE id = $1;

-- Spends a code only when every binding matches. A wrong verifier, client or
-- redirect matches no row, so the code stays usable for the rightful request.
-- name: RedeemNativeAuthorizationCode :one
WITH redeemed AS (
    DELETE FROM oauth_native_authorization_code
    USING oauth_native_authorization, "DeveloperApplication"
    WHERE oauth_native_authorization_code.code_hash = $1
      AND oauth_native_authorization_code.expires_at > CURRENT_TIMESTAMP
      AND oauth_native_authorization.id = oauth_native_authorization_code.authorization_id
      AND oauth_native_authorization.application_id = sqlc.arg(application_id)
      AND oauth_native_authorization.redirect_uri = sqlc.arg(redirect_uri)
      AND oauth_native_authorization.code_challenge = sqlc.arg(code_challenge)
      AND oauth_native_authorization.stage = 'code'
      AND oauth_native_authorization.auth_epoch = sqlc.arg(auth_epoch)
      AND "DeveloperApplication"."id" = oauth_native_authorization.application_id
      AND "DeveloperApplication"."client_type" = 'public'
    RETURNING
        oauth_native_authorization_code.authorization_id,
        oauth_native_authorization_code.user_id,
        oauth_native_authorization_code.authenticated_at
)
SELECT
    redeemed.authorization_id,
    redeemed.user_id,
    redeemed.authenticated_at,
    u."username",
    r.scopes,
    r.client_nonce
FROM redeemed
JOIN oauth_native_authorization r ON r.id = redeemed.authorization_id
JOIN "User" u ON u."id" = redeemed.user_id;

-- name: GetPairwiseSubject :one
SELECT subject
FROM oauth_pairwise_subject
WHERE application_id = $1
  AND user_id = $2;

-- Yields to a concurrent creation for the same person and application, and to
-- a subject another person already holds, so neither can be overwritten.
-- name: CreatePairwiseSubject :execrows
INSERT INTO oauth_pairwise_subject (application_id, user_id, subject)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- Serialises everything bounded per person and application: offline grants
-- and access token revocations.
-- name: LockPairwiseSubject :one
SELECT subject
FROM oauth_pairwise_subject
WHERE application_id = $1
  AND user_id = $2
FOR UPDATE;

-- name: LockPairwiseSubjectBySubject :one
SELECT user_id
FROM oauth_pairwise_subject
WHERE application_id = $1
  AND subject = $2
FOR UPDATE;

-- name: DeleteEndedRefreshFamiliesForPair :execrows
DELETE FROM oauth_refresh_family
WHERE application_id = $1
  AND user_id = $2
  AND LEAST(expires_at, active_until) <= CURRENT_TIMESTAMP;

-- Leaves room for one more family by revoking the least recently created ones
-- beyond nine. Ties on creation time are broken by identifier, so the choice is
-- the same whichever worker makes it.
-- name: EvictOldestRefreshFamilies :execrows
DELETE FROM oauth_refresh_family
WHERE id IN (
    SELECT oldest.id
    FROM oauth_refresh_family oldest
    WHERE oldest.application_id = $1
      AND oldest.user_id = $2
    ORDER BY oldest.created_at, oldest.id
    LIMIT GREATEST(
        (SELECT count(*) FROM oauth_refresh_family held
         WHERE held.application_id = $1 AND held.user_id = $2) - 9,
        0
    )
);

-- name: CreateRefreshFamily :one
INSERT INTO oauth_refresh_family (
    application_id,
    user_id,
    scopes,
    authenticated_at,
    auth_epoch,
    expires_at,
    active_until
)
VALUES (
    $1, $2, $3, $4,
    sqlc.arg(auth_epoch),
    CURRENT_TIMESTAMP + interval '90 days',
    CURRENT_TIMESTAMP + interval '30 days'
)
RETURNING id;

-- Issues the family's current token. Its remaining life is measured against
-- the same database timestamp it was created at, never a worker's clock.
-- name: CreateRefreshToken :one
INSERT INTO oauth_refresh_token (token_hash, family_id, expires_at)
SELECT $1, f.id, f.active_until
FROM oauth_refresh_family f
WHERE f.id = sqlc.arg(family_id)
RETURNING floor(extract(epoch FROM expires_at - CURRENT_TIMESTAMP))::bigint AS expires_in;

-- The presented token and its family, locked so that of two refreshes, or a
-- refresh and a revocation, of one family each sees the other's result.
-- name: LockRefreshToken :one
SELECT
    f.id AS family_id,
    (t.consumed_at IS NOT NULL)::boolean AS consumed,
    (t.expires_at > CURRENT_TIMESTAMP)::boolean AS unexpired,
    (LEAST(f.expires_at, f.active_until) > CURRENT_TIMESTAMP)::boolean AS family_active,
    f.user_id,
    f.scopes,
    f.authenticated_at,
    f.auth_epoch,
    f.member_count,
    a."client_type",
    u."username",
    s.subject
FROM oauth_refresh_token t
JOIN oauth_refresh_family f ON f.id = t.family_id
JOIN "DeveloperApplication" a ON a."id" = f.application_id
JOIN "User" u ON u."id" = f.user_id
JOIN oauth_pairwise_subject s ON s.application_id = f.application_id AND s.user_id = f.user_id
WHERE t.token_hash = $1
  AND f.application_id = $2
FOR UPDATE OF f, t;

-- name: ConsumeRefreshToken :execrows
UPDATE oauth_refresh_token
SET consumed_at = CURRENT_TIMESTAMP
WHERE token_hash = $1
  AND consumed_at IS NULL;

-- name: AdvanceRefreshFamily :execrows
UPDATE oauth_refresh_family
SET member_count = member_count + 1,
    scopes = sqlc.arg(scopes),
    active_until = LEAST(CURRENT_TIMESTAMP + interval '30 days', expires_at)
WHERE id = $1;

-- name: DeleteRefreshFamily :execrows
DELETE FROM oauth_refresh_family
WHERE id = $1;

-- A token of another application, or of no family, revokes nothing.
-- name: RevokeRefreshFamilyByToken :execrows
DELETE FROM oauth_refresh_family f
USING oauth_refresh_token t
WHERE t.token_hash = $1
  AND f.id = t.family_id
  AND f.application_id = $2;

-- name: DeleteExpiredAccessTokenRevocationsForPair :execrows
DELETE FROM oauth_access_token_revocation
WHERE application_id = $1
  AND user_id = $2
  AND expires_at <= CURRENT_TIMESTAMP;

-- name: AccessTokenRevocationExists :one
SELECT EXISTS (
    SELECT 1
    FROM oauth_access_token_revocation
    WHERE jti = $1
) AS revoked;

-- name: CountAccessTokenRevocationsForPair :one
SELECT count(*)
FROM oauth_access_token_revocation
WHERE application_id = $1
  AND user_id = $2;

-- name: CreateAccessTokenRevocation :execrows
INSERT INTO oauth_access_token_revocation (jti, application_id, user_id, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (jti) DO NOTHING;

-- Everything UserInfo must establish beyond the signature, read under the
-- shared authority lock so a rotation is either wholly before or wholly after.
-- name: ResolveAccessTokenGrant :one
SELECT
    u."username",
    (e.epoch = sqlc.arg(auth_epoch)::uuid)::boolean AS current_authority,
    EXISTS (
        SELECT 1
        FROM oauth_access_token_revocation v
        WHERE v.jti = sqlc.arg(jti)
          AND v.expires_at > CURRENT_TIMESTAMP
    ) AS revoked
FROM oauth_pairwise_subject s
JOIN "DeveloperApplication" a ON a."id" = s.application_id AND a."client_type" = 'public'
JOIN "User" u ON u."id" = s.user_id
CROSS JOIN (SELECT epoch FROM auth_epoch WHERE singleton FOR SHARE) e
WHERE s.application_id = $1
  AND s.subject = $2;

-- name: DeleteEndedRefreshFamilies :execrows
DELETE FROM oauth_refresh_family
WHERE id IN (
    SELECT id
    FROM oauth_refresh_family
    WHERE LEAST(expires_at, active_until) <= CURRENT_TIMESTAMP
    ORDER BY LEAST(expires_at, active_until), id
    LIMIT sqlc.arg(max_rows)
);

-- name: DeleteExpiredAccessTokenRevocations :execrows
DELETE FROM oauth_access_token_revocation
WHERE jti IN (
    SELECT jti
    FROM oauth_access_token_revocation
    WHERE expires_at <= CURRENT_TIMESTAMP
    ORDER BY expires_at, jti
    LIMIT sqlc.arg(max_rows)
);
