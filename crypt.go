package main

import (
	_ "crypto/aes"
	_ "crypto/cipher"
	"crypto/md5"
	_ "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
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
		log.Fatal("Valid algo was not passed in to function: createHash.")
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
		log.Fatal("Valid algo was not passed in to function: createFileHash.")
	}

	return hex.EncodeToString(sum_bytes)
}

//func encrypt(data []byte, passphrase string) []byte {
//	block, _ := aes.NewCipher([]byte(createMD5Hash(passphrase)))
//	gcm, _ := cipher.NewGCM(block)
//	nonce := make([]byte, gcm.NonceSize())
//	io.ReadFull(rand.Reader, nonce)
//	ciphertext := gcm.Seal(nonce, nonce, data, nil)
//	return ciphertext
//}
//
//func decrypt(data []byte, passphrase string) []byte {
//	key := []byte(createMD5Hash(passphrase))
//	block, _ := aes.NewCipher(key)
//	gcm, _ := cipher.NewGCM(block)
//	nonceSize := gcm.NonceSize()
//	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
//	plaintext, _ := gcm.Open(nil, nonce, ciphertext, nil)
//	return plaintext
//}
//
//func encryptFile(filename string, data []byte, passphrase string) {
//	f, _ := os.Create(filename)
//	defer f.Close()
//	f.Write(encrypt(data, passphrase))
//}
//
//func decryptFile(filename string, passphrase string) []byte {
//	data, _ := ioutil.ReadFile(filename)
//	return decrypt(data, passphrase)
//}

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
	//	ciphertext := encrypt([]byte("hello world"), password)
	//	fmt.Println(string(ciphertext))
	//
	//	plaintext := decrypt(ciphertext, "password")
	//	fmt.Println(string(plaintext))
	//
	//	encryptFile("example.txt", []byte("hello world"), "password")
	//	plaintext = decryptFile("example.txt", "password")
	//	fmt.Println(string(plaintext))

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
		//kjkjj
	case "decrypt":
		//kjjkjk
	}
}
