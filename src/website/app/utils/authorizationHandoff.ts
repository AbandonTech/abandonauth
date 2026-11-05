/** What every authorization page says once it has no valid action to offer. */
export const unavailableRequestMessage = "This sign-in request is no longer available. Return to the application and start again."

// 32 bytes as unpadded base64url: the last character carries two zero bits, so a
// handle has one spelling and nothing else is sent to the API.
const handoff = /^#request=([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$/

const wholeSecondInstant = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/

/**
 * Takes the handle out of the address before anything else can read it. The
 * handle arrives only in the fragment, which a browser never sends to a server
 * or puts in a referrer; a query or any other fragment is accepted as nothing.
 */
export function takeHandoffHandle(path: string): string | undefined {
  const { hash, search } = window.location
  const handle = search === "" ? handoff.exec(hash)?.[1] : undefined

  if (hash !== "" || search !== "") {
    window.history.replaceState(null, "", path)
  }

  return handle
}

/**
 * Milliseconds until an API deadline, or undefined when it is not a future
 * instant. This only decides what the page shows: the API rechecks every
 * submission against the database's clock.
 */
export function millisecondsUntil(expiresAt: unknown): number | undefined {
  if (typeof expiresAt !== "string" || !wholeSecondInstant.test(expiresAt)) {
    return undefined
  }

  const remaining = Date.parse(expiresAt) - Date.now()

  return Number.isFinite(remaining) && remaining > 0 ? remaining : undefined
}
