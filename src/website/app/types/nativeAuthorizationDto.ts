/** A scope a public client can ask for, in the order the API reports them. */
export type RequestedScope = "openid" | "profile" | "offline_access"

/** A provider the person can sign in with. */
export type AuthorizationProvider = "discord" | "github" | "google" | "steam"

/** Everything the authorization page may show about a pending request. */
export type PendingAuthorizationDto = {
    application_name: string,
    scopes: RequestedScope[],
    expires_at: string,
    providers: AuthorizationProvider[]
}
