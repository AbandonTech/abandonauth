# Steam OpenID Setup

Steam signs people in through OpenID 2.0, not OAuth2. There is nothing to
register with Valve and nothing to configure: no application, no client ID, no
client secret, no Steam Web API key and no AbandonAuth setting.

Steam returns people to `/api/ui/steam-callback` on the site, so with
`ABANDON_AUTH_SITE_URL=https://auth.example.com` that is
`https://auth.example.com/api/ui/steam-callback`. The site already sends
everything under `/api` to the API, so this needs no extra routing. Steam shows
the person the site's origin (`https://auth.example.com/`) as the site asking
them to sign in.

The API must be able to reach `https://steamcommunity.com/openid/login`,
because every Steam sign-in is confirmed there before anyone is signed in.

The first sign-in with a Steam account creates an AbandonAuth account named
`steam:` followed by the 64-bit Steam ID, and later sign-ins with that Steam ID
are the same account. AbandonAuth reads no persona name, avatar or profile.
