/** The RFC 6749 client type an application is registered as. It never changes. */
export type ClientType = "confidential" | "public"

/** What each client type is offered as when an application is registered. */
export const clientTypeLabels: Record<ClientType, string> = {
    confidential: "Confidential client — server-side application that can protect a credential",
    public: "Public client — installed application that cannot protect a shared credential",
}

export type DeveloperApplicationDto = {
    id: string,
    name: string,
    owner_id: string,
    client_type: ClientType,
    callback_uris: string[]
}

export type DeveloperApplicationUpdateCallbackDto = {
    id: string,
    name: string,
    owner_id: string,
    client_type: ClientType
}

/** A registration's answer. Only a confidential application has a token. */
export type CreateDeveloperApplicationDto = {
    id: string,
    name: string,
    owner_id: string,
    client_type: ClientType,
    token?: string
}
