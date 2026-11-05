import type { RequestedScope } from '~/types/nativeAuthorizationDto';

/** Everything the consent page may show about a pending consent. */
export type NativeConsentDto = {
    application_name: string,
    scopes: RequestedScope[],
    expires_at: string,
}
