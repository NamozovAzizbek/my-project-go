package server

import (
	"fmt"
	"log"
	"net/http"
)

func Start(handler http.Handler) {
	fmt.Println("Staring server on 0.0.0.0:8080")

	srv := http.Server{
		Handler: handler,
		Addr:    "0.0.0.0:8080",
	}
	log.Fatal(srv.ListenAndServe())
}
