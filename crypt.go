package main
import(
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "golang.org/x/crypto/scrypt"
    "io"
    "log"
    "os"
)

/* Master Password Validation scrypt parameters */
const VALIDATION_SCRYPT_N = 262144 // 16384
const VALIDATION_SCRYPT_R = 8
const VALIDATION_SCRYPT_P = 1

/* Encryption scrypt parameters */
const ENCRYPTION_SCRYPT_N = 32768 // 16384
const ENCRYPTION_SCRYPT_R = 8
const ENCRYPTION_SCRYPT_P = 1

// === Encryption ===

func encrypt(key []byte, text string) string {
	// key := []byte(keyText)
	plaintext := []byte(text)
 
	aes, err := aes.NewCipher(key)
	if err != nil {
		 log.Fatalln(err)
	}
    aesgcm, err := cipher.NewGCM(aes)
    if err != nil {
        log.Fatalln(err)
    }
    nsz := aesgcm.NonceSize() 
	// The nonce needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ct := make([]byte, nsz + len(plaintext) + aesgcm.Overhead())
	nonce := ct[:nsz]
    enc := ct[nsz:]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalln(err)
	}
    enc = aesgcm.Seal(enc[:0], nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct[:nsz + len(enc)])
}
 
// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ct, err := base64.StdEncoding.DecodeString(cryptoText)
    if err != nil {
        log.Fatalln(err)
    } 
	aes, err := aes.NewCipher(key)
	if err != nil {
		 log.Fatalln(err)
	}
    aesgcm, err := cipher.NewGCM(aes)
    if err != nil {
        log.Fatalln(err)
    }
    nonce := ct[:aesgcm.NonceSize()]
    enc := ct[aesgcm.NonceSize():]

    plaintext, err := aesgcm.Open(enc[:0], nonce, enc, nil)
    if err != nil {
        fmt.Println("Invalid password")
        os.Exit(0)
    }
	// convert to base64
	return string(plaintext)
}

// === Salt and Hash ===
func genSalt() []byte{
    salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatalln(err)
	}
    return salt
}

func genValidationHash(key []byte, salt []byte) []byte {
    hash, err := scrypt.Key(key, salt, VALIDATION_SCRYPT_N, VALIDATION_SCRYPT_R, VALIDATION_SCRYPT_P, 32)
    if err != nil {
        log.Fatalln(err)
    }
    return hash
}
func genEncryptionHash(key []byte, salt []byte) []byte {
    hash, err := scrypt.Key(key, salt, ENCRYPTION_SCRYPT_N, ENCRYPTION_SCRYPT_R, ENCRYPTION_SCRYPT_P, 32)
    if err != nil {
        log.Fatalln(err)
    }
    return hash
}

func genValidationHashSalt(key []byte) ([]byte, []byte) {
    /* Make salt */
    salt := genSalt()
    /* Make hash */
    hash := genValidationHash(key, salt)
    return hash, salt
}

func genEncryptionHashSalt(key []byte) ([]byte, []byte) {
    /* Make salt */
    salt := genSalt()
    /* Make hash */
    hash := genEncryptionHash(key, salt)
    return hash, salt
}

func ValidateMasterPassword(pw []byte, hashstr string, saltstr string) bool {
    hash, err := base64.URLEncoding.DecodeString(hashstr)
    if err != nil{
        log.Fatalln(err)
    }
    salt, err := base64.URLEncoding.DecodeString(saltstr)
    if err != nil{
        log.Fatalln(err)
    }
    newhash, err := scrypt.Key(pw, salt, VALIDATION_SCRYPT_N, VALIDATION_SCRYPT_R, VALIDATION_SCRYPT_P, 32)
    if err != nil {
        log.Fatalln(err)
    }
    return string(hash) == string(newhash)
}

