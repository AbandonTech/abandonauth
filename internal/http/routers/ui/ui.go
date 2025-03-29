package ui

import "net/http"

type UiRouter struct {
	*http.ServeMux
}

func NewUiRouter() UiRouter {
	router := UiRouter{ServeMux: http.NewServeMux()}
	router.HandleFunc("GET /", index)
	router.HandleFunc("GET /discord-callback", discordCallback)
	router.HandleFunc("GET /github-callback", gitHubCallback)
	return router
}

func index(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}

func discordCallback(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}

func gitHubCallback(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}
