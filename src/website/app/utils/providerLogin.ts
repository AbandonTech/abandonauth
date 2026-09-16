/** The providers a person can sign in with. */
export type SignInProvider = "discord" | "github" | "google";

/**
 * providerLoginUrl is where a browser goes to begin a sign-in.
 *
 * The provider's own authorization address is not built here. The state, code
 * challenge and nonce that let the returning browser be recognised are created
 * and held by the API, which sends the browser on to the provider.
 */
export function providerLoginUrl(provider: SignInProvider, applicationId: string, callbackUri: string): string {
  const query = new URLSearchParams({
    application_id: applicationId,
    callback_uri: callbackUri,
  });

  return `/api/ui/${provider}/authorize?${query}`;
}
