package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"cargoos/api/httpapi"
	"cargoos/pds"
)

func main() {
	address := os.Getenv("PDS_HTTP_ADDRESS")
	if address == "" {
		address = ":8080"
	}
	server := &http.Server{
		Addr:              address,
		Handler:           httpapi.NewHandler(pds.NewService(nil)),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("Cargo OS PDS listening on %s", address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
