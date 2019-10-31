package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	_ "io/ioutil"
	"log"
	"os"
	"strings"
)

// notes/intentions --------------------------

// crypt -h md5 -f <path to file>
// crypt -h sha256 -f <path to file>
// crypt -h sha128 -s "string to hash"
// crypt -h sha256 -s "string to hash"
// crypt -h sha512 -f <path to file>
// crypt -h sha512 -s "string to hash"

// PROMPT for key for these:
// crypt -e aes256 -f <path to file>
// crypt -d aes256 -f <path to file>
// crypt -e aes128 -f <path to file>
// crypt -d aes128 -f <path to file>
// crypt -e aes256 -s "string to encrypt"
// crypt -d aes256 -s "string to decrypt"

// FUNCTIONS ---------------------------------

func createHash(value string, algo string) string {

	var sum_bytes []byte

	switch algo {

	case "sha1":
		hasher := sha1.New()
		io.WriteString(hasher, value)
		sum_bytes = hasher.Sum(nil)

	case "sha256":
		hasher := sha256.New()
		io.WriteString(hasher, value)
		sum_bytes = hasher.Sum(nil)

	case "sha512":
		hasher := sha512.New()
		io.WriteString(hasher, value)
		sum_bytes = hasher.Sum(nil)

	case "md5":
		hasher := md5.New()
		io.WriteString(hasher, value)
		sum_bytes = hasher.Sum(nil)

	default:
		log.Fatal("Valid algo was not passed in to function: createHash. ")
	}

	return hex.EncodeToString(sum_bytes)
}

func createFileHash(algo string, pathToFile string) string {

	f, err := os.Open(pathToFile)
	if err != nil {
		fmt.Println("Error opening file:  " + pathToFile)
		log.Fatal(err)
	}

	defer f.Close()

	var sum_bytes []byte

	switch algo {

	case "sha1":
		hasher := sha1.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatal(err)
		}

		sum_bytes = hasher.Sum(nil)

	case "sha256":
		hasher := sha256.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatal(err)
		}

		sum_bytes = hasher.Sum(nil)

	case "sha512":
		hasher := sha512.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatal(err)
		}

		sum_bytes = hasher.Sum(nil)

	case "md5":
		hasher := md5.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatal(err)
		}

		sum_bytes = hasher.Sum(nil)

	default:
		log.Fatal("Valid algo was not passed in to function: createFileHash. ")
	}

	return hex.EncodeToString(sum_bytes)
}

// AES128/256, GCM
func encrypt(plaintext_bytes []byte, passphrase string, algo string) ([]byte, error) {

	// AES 128 or 256 determined by key size, 16 bytes for AES128 and 32 bytes for AES256
	// key derived by hashing passphrase to appropriate length

	key, _ := hex.DecodeString(createHash(passphrase, "sha256")) // returns []byte, error

	switch algo {

	case "aes128":
		// grab first 16 bytes for AES128 key
		key = key[:16]

	case "aes256":
		// k, all good, key is already 32 bytes

	default:
		return nil, errors.New("encrypt: Invalid algo")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext_bytes, nil), nil
}

func decrypt(ciphertext_bytes []byte, passphrase string, algo string) ([]byte, error) {

	key, _ := hex.DecodeString(createHash(passphrase, "sha256")) // returns []byte, error

	switch algo {

	case "aes128":
		// grab first 16 bytes for AES128 key
		key = key[:16]

	case "aes256":
		// k, all good, key is already 32 bytes
		fmt.Println("HERE")

	default:
		return nil, errors.New("encrypt: Invalid algo")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext_bytes) < gcm.NonceSize() {
		return nil, errors.New("Malformed ciphertext")
	}

	return gcm.Open(nil, ciphertext_bytes[:gcm.NonceSize()], ciphertext_bytes[gcm.NonceSize():], nil)
}

func showUsage() {
	msg := `
crypt -h [md5|sha1|sha128|sha256|sha512] -f <path to file>
crypt -h [md5|sha1|sha128|sha256|sha512] -s "string literal"
crypt -e [aes128|aes256] -f <path to file>
crypt -d [aes128|aes256] -s "string literal"

-h: hash
-e: encrypt
-d: decrypt

encryption/decryption commands will prompt for key.
`
	fmt.Println(msg)
	os.Exit(0)
}

// BEGIN MAIN ---------------------------------

func main() {

	// input params
	hashParam := flag.String("h", "", "Specify the hashing algorithm")
	encryptParam := flag.String("e", "", "Specify algorithm for encrytion")
	decryptParam := flag.String("d", "", "Specify algorith for decryption")
	filepathParam := flag.String("f", "", "Specify the path to the file to encrypt/decrypt")
	stringParam := flag.String("s", "", "Specify the literal string to encrypt/decrypt")

	// input validation ------------------------------------
	flag.Parse()
	var command string

	if *hashParam == "" && *encryptParam == "" && *decryptParam == "" {
		showUsage()
	}

	if *filepathParam == "" && *stringParam == "" {
		showUsage()
	}

	// ensure only ONE command is supplied
	if *hashParam != "" && (*encryptParam != "" || *decryptParam != "") {
		showUsage()
	}

	if *encryptParam != "" && (*decryptParam != "" || *hashParam != "") {
		showUsage()
	}

	if *decryptParam != "" && (*encryptParam != "" || *hashParam != "") {
		showUsage()
	}

	// ensure only ONE command parameter is supplied (either -f or -s, not both (filepath or string))
	if *filepathParam != "" && *stringParam != "" {
		showUsage()
	}

	// below assignment of 'command' will work only because above input validation has already garaunteed only ONE of the 3 options have been supplied
	if *hashParam != "" {
		command = "hash"
	} else if *encryptParam != "" {
		command = "encrypt"
	} else if *decryptParam != "" {
		command = "decrypt"
	}

	// begin main switch
	switch command {
	case "hash":

		if *filepathParam != "" {
			fmt.Println(createFileHash(strings.ToLower(*hashParam), *filepathParam))
		} else if *stringParam != "" {
			fmt.Println(createHash(*stringParam, strings.ToLower(*hashParam)))
		}

	case "encrypt":

		// get passphrase (used to create key)
		passphrase := ""
		fmt.Print("Enter passphrase: ")
		fmt.Scan(&passphrase)

		fmt.Println(passphrase)
		fmt.Println(len(passphrase))

		if *stringParam != "" {

			// encrypt and base64 encode the supplied string - send to stdout
			encrypted_bytes, err := encrypt([]byte(*stringParam), passphrase, strings.ToLower(*encryptParam))
			if err != nil {
				log.Fatal("Error occurred during encryption. ", err)
			}

			fmt.Println(base64.StdEncoding.EncodeToString(encrypted_bytes))

		} else if *filepathParam != "" {

			// encrypt supplied file - create new file named the same as the source file with .crypt appended - leave source file in tact

		}

	case "decrypt":

		// get passphrase (used to create key)
		passphrase := ""
		fmt.Print("Enter passphrase: ")
		fmt.Scan(&passphrase)

		if *stringParam != "" {

			// base64 decode and decrypt the supplied string - send to stdout
			encrypted_bytes, err := base64.StdEncoding.DecodeString(*stringParam)
			if err != nil {
				log.Fatal("Error base64 decoding encrypted string. ", err)
			}

			decrypted_bytes, err := decrypt(encrypted_bytes, passphrase, strings.ToLower(*decryptParam))
			if err != nil {
				log.Fatal("Error occurred during decryption. ", err)
			}

			fmt.Println(string(decrypted_bytes))

		} else if *filepathParam != "" {

			// decrypt supplied file, remove .crypt extension, if file with same name already exists (likely), prompt user for overwrite
		}
	}
}
