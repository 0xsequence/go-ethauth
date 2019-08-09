package ethwebtoken

import "net/http"

func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: set request context with the address
		// also set the message on the request context
		next.ServeHTTP(w, r)
	})
}
