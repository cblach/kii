package main
import(
    "fmt"
    "os"
    "os/user"
    "flag"
    "encoding/json"
    "encoding/base64"
    "crypto/aes"
    "crypto/cipher"
    "golang.org/x/crypto/scrypt"
    "io"
    "bufio"
    "crypto/rand"
    "math/big"
    "io/ioutil"
    "golang.org/x/crypto/ssh/terminal"
    "github.com/howeyc/gopass"
    "github.com/atotto/clipboard"
)

const SCRYPT_N = 32768 // 16384
const SCRYPT_R = 8
const SCRYPT_P = 1

var filenamePtr *string

// === Data structure ===

type Record struct{
    Username string `json:"username,omitempty"`
    EncryptedPassword string `json:"password"`
    Salt string `json:"salt"`
    Url string `json:"url,omitempty"`
}

type PWData struct {
    Records map[string]Record `json:"records"`
    Settings struct {
        
    } `json:"settings,omitempty"`
    KeySalt string `json:"keysalt"`
    KeyHash string `json:"keyhash"`
}

// === Encryption ===

// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	// key := []byte(keyText)
	plaintext := []byte(text)
 
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
 
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
 
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
 
	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}
 
// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)
 
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
 
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
 
	stream := cipher.NewCFBDecrypter(block, iv)
 
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
 
	return fmt.Sprintf("%s", ciphertext)
}

// === Salt and Hash ===

func GenerateSalt() []byte{
    salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}
    return salt
}

func GenerateHash(key []byte, salt []byte) []byte {
    hash, err := scrypt.Key(key, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32)
    if err != nil {
        panic(err)
    }
    return hash
}
func GenerateKey_HashNSalt(key []byte) ([]byte, []byte) {
    salt := GenerateSalt()
    hash := GenerateHash(key, salt)
    return hash, salt
}

func ValidateKey( key []byte, validhashstr string,saltstr string) bool {
    validhash, err := base64.URLEncoding.DecodeString(validhashstr)
    if err != nil{
        panic(err)
    }
    salt, err := base64.URLEncoding.DecodeString(saltstr)
    if err != nil{
        panic(err)
    }
    newhash, err := scrypt.Key(key, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32)
    if err != nil {
        panic(err)
    }
    return string(validhash) == string(newhash)
}

func Confirm(confirmstr string) bool{
    stdinReader := bufio.NewReader(os.Stdin)
    line, _, err := stdinReader.ReadLine()
    if err != nil {
        panic(err)
    }
    return string(line) == confirmstr
}

func GetPasswd() []byte{
    key, err := terminal.ReadPassword(int(os.Stdin.Fd()))
    if err != nil {
        panic(err)
    }
    return key
}

// === Generate Random Password ===
func GenerateRandomPassword(ncharacters uint, usesymbols bool) string {
    if ncharacters > 255 {
        fmt.Println("Invalid Password Size")
        return ""
    }
    password := make([]byte, ncharacters)
    var palette string
    base := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    symbols := " !\"#$%&'()*+,/:;<=>?@[\\]^_`{|}~"
    if usesymbols {
        palette = base + symbols
    } else {
        palette = base
    }
    for i := uint(0); i < ncharacters; i++ {
        n, err := rand.Int(rand.Reader, big.NewInt(int64(len(palette))))
        if err != nil {
            panic(err)
        }
        password[i] = palette[n.Int64()]
    }
    return string(password)
}

// === Load and save data from/to data file ===

func loadPWData() (*PWData, error) {
    var pwd PWData
    out, err := ioutil.ReadFile(*filenamePtr)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(out, &pwd)
    if err != nil {
        return nil, err
    }
    return &pwd, nil
}

func savePWData(pwd *PWData) (error) {
    out, err := json.MarshalIndent(pwd, "", "    ")
    if err != nil {
        return err
    }
    err = ioutil.WriteFile(*filenamePtr+".tmp", out, 0600)
    if err != nil {
        return err
    }
    os.Remove(*filenamePtr)
    err = os.Rename(*filenamePtr+".tmp", *filenamePtr)
    if err != nil {
        return err
    }
    return nil
}

// === Important Functions ===

func GeneratePasswordFile() {
    if _, err := os.Stat(*filenamePtr); !os.IsNotExist(err) {
        fmt.Printf("File %s already exists. \nWrite YES (capital) if you want to overwrite it\n", *filenamePtr)
        if !Confirm("YES") {
            fmt.Println("Exiting file generation")
            return
        }
    }
    var pwd PWData
    pwd.Records = make(map[string]Record)
    fmt.Println("Enter encryption password")
    hash, salt := GenerateKey_HashNSalt(gopass.GetPasswd())
    pwd.KeySalt = base64.URLEncoding.EncodeToString(salt)
    pwd.KeyHash = base64.URLEncoding.EncodeToString(hash)
    savePWData(&pwd)
}


func SetPassword(name string, username string, url string, length uint, useSymbols bool ) {
    pwd, err := loadPWData()
    if err != nil {
        fmt.Println(err)
        return
    }
    if name == ""{
        fmt.Println("no name specified (use -n NAME)")
        return
    }
    _, ok := pwd.Records[name]
    if ok {
        fmt.Printf("An entry for %s already exists, are  you sure you want to overwrite it?\n", name)
        fmt.Println("Write YES (capital) to continue")
        if !Confirm("YES") {
            fmt.Println("Exiting file generation")
            return
        }
    }
    fmt.Println("Enter encryption password")
    key := gopass.GetPasswd()
    if !ValidateKey(key, pwd.KeyHash, pwd.KeySalt) {
        fmt.Println("Invalid password")
        return
    }
    hash, salt := GenerateKey_HashNSalt(key)
    // == Generate Random Password ===
    password := GenerateRandomPassword(length, useSymbols)
    if password == "" {
        return
    }
    clipboard.WriteAll(password)
    pwd.Records[name] = Record{ Username: username,
                                Url: url,
                                EncryptedPassword: encrypt(hash, password),
                                Salt: base64.URLEncoding.EncodeToString(salt),
                               }
    err = savePWData(pwd)
    if err != nil{
        fmt.Println(err)
        return
    }
}

func GetPassword(name string) {
    pwd, err := loadPWData()
    if err != nil {
        fmt.Println(err)
        return
    }
    rec, ok := pwd.Records[name]
    if !ok {
        fmt.Println("No such record")
        return
    }
    if rec.Url != "" {
        fmt.Println("Url:", rec.Url)
    }
    if rec.Username != "" {
        fmt.Println("Username:", rec.Username)
    }
    fmt.Println("Enter encryption password")
    key := gopass.GetPasswd()
    if !ValidateKey(key, pwd.KeyHash, pwd.KeySalt) {
        fmt.Println("Invalid password")
        return
    }
    fmt.Println("Accepted Password, Starting Decryption")
    salt, err := base64.URLEncoding.DecodeString(rec.Salt)
    if err != nil{
        panic(err)
    }
    hash := GenerateHash(key, salt)
    clipboard.WriteAll(decrypt(hash, rec.EncryptedPassword))
    fmt.Println("Password Copied to Clipboard")
}

func ListPasswordEntries() {
    pwd, err := loadPWData()
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Printf("List of Entries(%d):\n", len(pwd.Records))
    for key, _ := range pwd.Records {
        fmt.Println(key)
    }
}

func main() {
    usr, err := user.Current()
    if err != nil {
        panic(err)
    }
    filenamePtr = flag.String("f", usr.HomeDir+"/blakey.json", "filename (optional)")
    if len(os.Args) < 2 {
        fmt.Println("Valid Commands: \ngenfile\ngenpw\nget\nlist")
        return
    }
    cmd := os.Args[1]
    switch cmd {
    case "genfile":
        GeneratePasswordFile()
    case "set":
        if len(os.Args) < 3 {
            fmt.Println("Not enough arguments, a label is required")
            return
        }
        name := os.Args[2]
        usrPtr := flag.String("u", "", "username (optional)")
        urlPtr := flag.String("url", "", "url (optional)")
        lenPtr := flag.Uint("l", 64, "password length (optional)")
        nosymPtr := flag.Bool("nosymbols", false, "makes the password not contain symbols")
        err := flag.CommandLine.Parse(os.Args[3:])
        if err != nil {
            fmt.Println("RIP")
            return
        }
        SetPassword(name, *usrPtr, *urlPtr, *lenPtr, !*nosymPtr)
    case "get":
        if len(os.Args) < 3 {
            fmt.Println("Not enough arguments")
            return
        }
        name := os.Args[2]
        GetPassword(name)
    case "list":
        ListPasswordEntries()
    default:
        fmt.Println("Invalid command.")
    }
}
