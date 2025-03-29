package ui

import (
	"net/http"

	"github.com/abandontech/abandonauth/internal/config"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

type UiRouter struct {
	*http.ServeMux

	discordConf oauth2.Config
	gitHubConf  oauth2.Config
}

func NewUiRouter(discordConf config.DiscordOAuth, githubConf config.GitHubOAuth) UiRouter {
	r := UiRouter{
		ServeMux: http.NewServeMux(),
		discordConf: oauth2.Config{
			ClientID:     discordConf.ClientID,
			ClientSecret: discordConf.ClientSecret,
			RedirectURL:  discordConf.RedirectURL,
			Scopes:       []string{"identify"},
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://discord.com/api/v10/oauth2/token",
			},
		},
		gitHubConf: oauth2.Config{
			ClientID:     githubConf.ClientID,
			ClientSecret: githubConf.ClientSecret,
			RedirectURL:  githubConf.RedirectURL,
			Scopes:       []string{"user:email"},
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://github.com/login/oauth/access_token",
			},
		},
	}

	r.HandleFunc("GET /", index)
	r.HandleFunc("GET /ui/discord-callback", r.discordCallback)
	r.HandleFunc("GET /ui/github-callback", r.gitHubCallback)
	return r
}

func index(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}

func (u UiRouter) discordCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	_, err := u.discordConf.Exchange(r.Context(), code)
	if err != nil {
		log.Err(err).Msg("Failed to exchange token")
		return
	}

	log.Info().
		Msg("Exchanged token")

	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}

func (u UiRouter) gitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	_, err := u.gitHubConf.Exchange(r.Context(), code)
	if err != nil {
		log.Err(err).Msg("Failed to exchange token")
		return
	}

	log.Info().
		Msg("Exchanged token")

	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}
