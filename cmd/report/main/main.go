package main

import (
	"net/http"
)

func main() {
	http.Handle(
		"/",
		http.FileServer(
			http.Dir(
				"/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/cmd/report/main/static",
			),
		),
	)
	http.ListenAndServe(":3000", nil)
}
