package developer_application

import "net/http"

type DeveloperApplicationRouter struct {
	*http.ServeMux
}

func NewDeveloperApplicationRouter() DeveloperApplicationRouter {
	router := DeveloperApplicationRouter{ServeMux: http.NewServeMux()}
	router.HandleFunc("POST /", createDeveloperApplication)

	return router
}

func createDeveloperApplication(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}
