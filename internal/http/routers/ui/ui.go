package ui

import (
	"math"
	"net/http"

	"github.com/abandontech/abandonauth/internal/config"
	"github.com/abandontech/abandonauth/internal/database"
	"github.com/google/go-github/v70/github"
	"github.com/jackc/pgx/v5"
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

	r.HandleFunc("GET /ui/", index)
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

	token, err := u.gitHubConf.Exchange(r.Context(), code)
	if err != nil {
		log.Err(err).Msg("Failed to exchange token")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	client := github.NewClient(nil).WithAuthToken(token.AccessToken)
	gitHubUser, _, err := client.Users.Get(r.Context(), "")
	if err != nil {
		log.Err(err).Msg("Failed to retrieve user using token")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// TODO: Add a migration to use int64 compatiable type.
	if *gitHubUser.ID > math.MaxInt32 {
		log.Error().
			Msg("We cannot handle a github id that exceeds the max value of int32")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// With the previous assertion/check, we are safe to do this. Please make sure you take this into account
	//   if there are refactors before the TODO: above is resolved.
	gitHubId := int32(*gitHubUser.ID)

	userID, err := database.Engine.GetUserIDByGitHubID(r.Context(), gitHubId)
	if err != pgx.ErrNoRows && err != nil {
		log.Err(err).
			Msg("Failed to retrieve user from database")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err == pgx.ErrNoRows {
		userID, err = database.Engine.CreateUserWithGitHubID(r.Context(), database.CreateUserWithGitHubIDParams{
			Username: *gitHubUser.Name,
			ID:       gitHubId,
		})
		if err != pgx.ErrNoRows && err != nil {
			log.Err(err).
				Msg("Failed to create user")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	log.Info().
		Interface("UserID", userID).
		Msg("Logged in user")

	// TODO: Generate JWT and return to requester.
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}
