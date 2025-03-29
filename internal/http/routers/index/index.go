package index

import "net/http"

type IndexRouter struct {
	*http.ServeMux
}

func NewIndexRouter() IndexRouter {
	router := IndexRouter{ServeMux: http.NewServeMux()}
	router.HandleFunc("GET /", indexGet)
	router.HandleFunc("GET /user/applications", indexGetUserApplications)
	router.HandleFunc("GET /me", indexGetMe)
	router.HandleFunc("POST /login", indexPostLogin)
	router.HandleFunc("POST /burn-token", indexPostBurnToken)
	return router
}

func indexGet(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "http://localhost:3000", http.StatusTemporaryRedirect)
}

func indexGetUserApplications(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}

func indexGetMe(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}

func indexPostLogin(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}

func indexPostBurnToken(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}
