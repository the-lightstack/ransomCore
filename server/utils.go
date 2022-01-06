package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"log"
	"os"
	"regexp"

	_ "github.com/mattn/go-sqlite3"
)

const KEY_SIZE_AES = 16
const DATABSE_PATH = "./encryptionKeys.db"
const MAC_ADDR_REGEX = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

// Check for errors and panic them if found
func checkError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

// Returns base64 URL-encoded key (128 bit)
func GenerateAESKey() string {
	key := make([]byte, KEY_SIZE_AES)
	rand.Read(key)
	b64EncodedKey := base64.URLEncoding.EncodeToString(key)
	return b64EncodedKey
}

// Check if file at path exists and is file (not dir)
func fileExists(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return bool(err == nil && !fileInfo.IsDir())
}

// Returns connection to de-/encryption database
// Make sure to `defer conn.Close()`` after getting conn
func GetDatabaseConnection() *sql.DB {
	// We don't want to overwrite existing data
	if !fileExists(DATABSE_PATH) {
		_, err := os.Create(DATABSE_PATH)
		checkError(err)
	}

	dbConn, err := sql.Open("sqlite3", DATABSE_PATH)
	checkError(err)

	return dbConn
}

// Check's if supplied string matches regex pattern
func IsMacAddress(mac string) bool {
	res, err := regexp.MatchString(MAC_ADDR_REGEX, mac)
	if err != nil {
		log.Print("Regex error:", err)
	}
	return res
}

// Sets up sqlite database for storing
// users with their de-/encryption key
func SetupDatabase(dbConnection *sql.DB) {
	const setupQuery = `CREATE TABLE IF NOT EXISTS keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac INTEGER,
		b64Key TEXT
		)`
	createTableStatement, err := dbConnection.Prepare(setupQuery)
	checkError(err)
	createTableStatement.Exec()
}

// Insert MAC address together with AES key into database
func InsertKeyMacPair(macAddress string, b64AesKey string, dbConn *sql.DB) {
	insertStatement, err := dbConn.Prepare("INSERT INTO keys (id, mac, b64Key) VALUES (NULL,?,?)")
	checkError(err)
	insertStatement.Exec(macAddress, b64AesKey)
}
