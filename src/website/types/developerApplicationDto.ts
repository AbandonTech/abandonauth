export type DeveloperApplicationDto = {
    id: string,
    name: string,
    owner_id: string
    callback_uris: string[]
}

export type DeveloperApplicationUpdateCallbackDto = {
    id: string,
    name: string,
    owner_id: string
}

export type CreateDeveloperApplicationDto = {
    id: string,
    name: string,
    owner_id: string
    token: string
}
