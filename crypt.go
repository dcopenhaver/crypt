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
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// Notes/intentions --------------------------

// crypt -h md5 -f <path to file>
// crypt -h sha256 -f <path to file>
// crypt -h sha1 -s "string to hash"
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

// IMPORTANT:
// This basic utility was written only because I needed some of this functionality for another project.
// I just decided there was enough I needed to figure out that I could add a little more and make it it's own project and utility.
// Example: I'm not using any buffered i/o to account for very large files that might not fit in RAM.
// So it is not robust in that sense, and won't work on files too large to fit in RAM.
// Maybe I'll update it later to handle this and other things I would consider needed to be a more full featured and robust utility.

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
		log.Fatalln("Valid algo was not passed in to function: createHash.")
	}

	return hex.EncodeToString(sum_bytes)
}

func createFileHash(algo string, pathToFile string) string {

	f, err := os.Open(pathToFile)
	if err != nil {
		log.Fatalf("Error opening file %s\n%s", pathToFile, err)
	}

	defer f.Close()

	var sum_bytes []byte

	switch algo {

	case "sha1":
		hasher := sha1.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatalf("Error during io.Copy.\n%s", err)
		}

		sum_bytes = hasher.Sum(nil)

	case "sha256":
		hasher := sha256.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatalf("Error during io.Copy.\n%s", err)
		}

		sum_bytes = hasher.Sum(nil)

	case "sha512":
		hasher := sha512.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatalf("Error during io.Copy.\n%s", err)
		}

		sum_bytes = hasher.Sum(nil)

	case "md5":
		hasher := md5.New()

		if _, err := io.Copy(hasher, f); err != nil {
			log.Fatalf("Error during io.Copy.\n%s", err)
		}

		sum_bytes = hasher.Sum(nil)

	default:
		log.Fatalln("Valid algo was not passed in to function: createFileHash.")
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

func fileExists(path string) bool {

	f_info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}

	// ok we have a FileInfo object, but it could be a dir, check if it's a directory
	return !f_info.IsDir()
}

func showUsage() {
	msg := `

crypt -h [md5|sha1|sha256|sha512] -f <path to file>
crypt -h [md5|sha1|sha256|sha512] -s "string literal"
crypt -e [aes128|aes256] -f <path to file>
crypt -d [aes128|aes256] -s "string literal"

-h: hash
-e: encrypt
-d: decrypt

encryption/decryption commands will prompt for key.

`
	fmt.Println(msg)
	os.Exit(1)
}

// BEGIN MAIN ---------------------------------

func main() {

	// input params
	hashParam := flag.String("h", "", "Specify the hashing algorithm")
	encryptParam := flag.String("e", "", "Specify algorithm for encrytion")
	decryptParam := flag.String("d", "", "Specify algorithm for decryption")
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

		if *stringParam != "" {

			// encrypt and base64 encode the supplied string - send to stdout
			encrypted_bytes, err := encrypt([]byte(*stringParam), passphrase, strings.ToLower(*encryptParam))
			if err != nil {
				log.Fatalln("Error occurred during encryption.", err)
			}

			fmt.Println(base64.StdEncoding.EncodeToString(encrypted_bytes))

		} else if *filepathParam != "" {

			// encrypt supplied file - create new file named the same as the source file with .crypt appended - leave source file in tact
			plaintext_bytes, err := ioutil.ReadFile(*filepathParam)
			if err != nil {
				log.Fatalf("Error reading file: %s\n%s", *filepathParam, err)
			}

			encrypted_bytes, err := encrypt(plaintext_bytes, passphrase, strings.ToLower(*encryptParam))
			if err != nil {
				log.Fatalf("Error encrypting file: %s\n%s", *filepathParam, err)
			}

			if ioutil.WriteFile(*filepathParam+".crypt", encrypted_bytes, 0664) != nil {
				log.Fatalf("Error writting encrypted file: %s%s\n%s", *filepathParam, ".crypt", err)
			} else {
				fmt.Printf("Encrypted file created: %s%s\n", *filepathParam, ".crypt")
			}
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
				log.Fatalln("Error base64 decoding encrypted string.", err)
			}

			decrypted_bytes, err := decrypt(encrypted_bytes, passphrase, strings.ToLower(*decryptParam))
			if err != nil {
				log.Fatalln("Error occurred during decryption.", err)
			}

			fmt.Println(string(decrypted_bytes))

		} else if *filepathParam != "" {

			// decrypt supplied file, remove .crypt extension, if file with same name already exists (likely), prompt user for overwrite

			if !strings.HasSuffix(*filepathParam, ".crypt") {
				log.Fatalf("%s: does not have a '.crypt' suffix - will not attempt decryption.", *filepathParam)
			}

			decrypted_filepath := strings.TrimSuffix(*filepathParam, ".crypt")

			encrypted_bytes, err := ioutil.ReadFile(*filepathParam)
			if err != nil {
				log.Fatalf("Error reading file %s\n%s", *filepathParam, err)
			}

			decrypted_bytes, err := decrypt(encrypted_bytes, passphrase, strings.ToLower(*decryptParam))
			if err != nil {
				log.Fatalf("Error decrypting file %s\n%s", *filepathParam, err)
			}

			// check if file already exists, prompt for overwrite answer
			if fileExists(decrypted_filepath) {

				fmt.Printf("%s: already exists and will be overwritten!", decrypted_filepath)
				fmt.Print("\nOverwrite existing file? [y/n]: ")
				overwrite := "n"
				fmt.Scan(&overwrite)

				if strings.ToLower(strings.TrimSpace(overwrite)) == "y" {
					if ioutil.WriteFile(decrypted_filepath, decrypted_bytes, 0664) != nil {
						log.Fatalf("Error writting decrypted file: %s\n%s", decrypted_filepath, err)
					} else {
						fmt.Printf("File decryption completed. Decrypted file:\n%s\n", decrypted_filepath)
					}
				}
			}

		}
	}
}
