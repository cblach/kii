package main
import(
    "crypto/rand"
    "encoding/base64"
    "flag"
    "fmt"
    "github.com/atotto/clipboard"
    "github.com/howeyc/gopass"
    "bufio"
    "log"
    "math/big"
    "os"
    "os/user"
    "sort"
)

type Opts struct {
    keyPath    string
    username   string
    url        string
    length     uint
    isCustomPW bool
    noSymbols  bool
}

/* Ask for confirmation string */
func confirm(confirmStr string) bool{
    stdinReader := bufio.NewReader(os.Stdin)
    line, _, err := stdinReader.ReadLine()
    if err != nil {
        log.Fatalln(err)
    }
    return string(line) == confirmStr
}

// === Generate Random Password ===
func genPassword(ncharacters uint, usesymbols bool) string {
    if ncharacters > 255 {
        log.Fatalln("Invalid Password Size")
    }
    password := make([]byte, ncharacters)
    palette := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    symbols := " !\"#$%&'()*+,/:;<=>?@[\\]^_`{|}~"
    if usesymbols {
        palette += symbols
    }
    for i := uint(0); i < ncharacters; i++ {
        n, err := rand.Int(rand.Reader, big.NewInt(int64(len(palette))))
        if err != nil {
            log.Fatalln(err)
        }
        password[i] = palette[n.Int64()]
    }
    return string(password)
}

func setPassword(name string, opts *Opts) {
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
        if !confirm("YES") {
            fmt.Println("Exiting file generation")
            return
        }
    }
    fmt.Println("Enter encryption password")
    masterpw, err := gopass.GetPasswd()
    if err != nil {
        log.Fatalln(err)
    }
    if !validateMasterPassword(masterpw, pwd.KeyHash, pwd.KeySalt) {
        fmt.Println("Invalid password")
        return
    }
    hash, salt := genEncryptionHashSalt(masterpw)
    var password string
    if opts.isCustomPW {
        fmt.Println("Enter custom password for record", name)
        passwordBin, err := gopass.GetPasswd()
        if err != nil {
            log.Fatalln(err)
        }
        password = string(passwordBin)
    } else {
        password = genPassword(opts.length, !opts.noSymbols)
    }
    clipboard.Primary = true
    clipboard.WriteAll(password)
    clipboard.Primary = false
    clipboard.WriteAll(password)

    pwd.Records[name] = Record {
                                Username: opts.username,
                                Url: opts.url,
                                EncryptedPassword: encrypt(hash, password),
                                Salt: base64.URLEncoding.EncodeToString(salt),
                             }
    if err := savePWData(pwd); err != nil{
        log.Fatalln("failed to save file:", err)
    }
}

func getPassword(name string) {
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
    key, err := gopass.GetPasswd()
    if err != nil {
        log.Fatalln(err)
    }
    salt, err := base64.URLEncoding.DecodeString(rec.Salt)
    if err != nil{
        panic(err)
    }
    hash := getEncryptionHash(key, salt)
    password := decrypt(hash, rec.EncryptedPassword)
    clipboard.Primary = true
    clipboard.WriteAll(password)
    clipboard.Primary = false
    clipboard.WriteAll(password)
    fmt.Println("Password Copied to Clipboard")
}

func list() {
    pwd, err := loadPWData()
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Printf("List of Entries(%d):\n", len(pwd.Records))
    recs := make([]string, 0, len(pwd.Records))
    for key, _ := range pwd.Records {
        recs = append(recs, key)
    }
    sort.Strings(recs)
    for _, v := range recs {
        fmt.Println(v)
    }
}

func rekey() {
    pwd, err := loadPWData()
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println("Enter old encryption password")
    oldPass, err := gopass.GetPasswd()
    if err != nil {
        fmt.Println("failed to get old password from input:", err)
        return
    }
    if !validateMasterPassword(oldPass, pwd.KeyHash, pwd.KeySalt) {
        fmt.Println("Invalid password")
        return
    }
    fmt.Println("Enter new encryption password")
    newPass, err := gopass.GetPasswd()
    if err != nil {
        fmt.Println("failed to get new password from input:", err)
        return
    }
    fmt.Println("Repeat new encryption password")
    newPassRepeat, err := gopass.GetPasswd()
    if err != nil {
        fmt.Println("failed to get repeat password from input:", err)
        return
    }
    if string(newPass) != string(newPassRepeat) {
        fmt.Println("Repeated password does not match")
        return
    }
    hash, salt := genValidationHashSalt(newPass)
    pwd.KeySalt = base64.URLEncoding.EncodeToString(salt)
    pwd.KeyHash = base64.URLEncoding.EncodeToString(hash)
    for name, oldRec := range pwd.Records {
        fmt.Printf("Rekeying %s...\n", name)
        oldSalt, err := base64.URLEncoding.DecodeString(oldRec.Salt)
        if err != nil{
            fmt.Println("failed to base64 decode salt in record", name)
            return
        }
        oldHash := getEncryptionHash(oldPass, oldSalt)
        p := decrypt(oldHash, oldRec.EncryptedPassword)
        newHash, newSalt := genEncryptionHashSalt(newPass)
        newRec := oldRec
        newRec.Salt = base64.URLEncoding.EncodeToString(newSalt)
        newRec.EncryptedPassword = encrypt(newHash, p)
        pwd.Records[name] = newRec
    }
    p := keyPath
    keyPath = p + ".tmp"
    fmt.Println("Saving to temporary file", keyPath)
    if err := savePWData(pwd); err != nil{
        fmt.Println("failed to save data:", err)
        os.Remove(keyPath)
        return
    }
    fmt.Println("Succesfully rekeyed passwords to tmpfile. Moving tmpfile to", p)
    if err := os.Rename(keyPath, p); err != nil {
        fmt.Println("failed to move tmpfile:", err)
        os.Remove(keyPath)
        return
    }
    fmt.Println("Success")
}


func main() {
    opts := Opts{}
    flag.StringVar(&opts.keyPath, "f", "", "kii file path")
    flag.StringVar(&opts.username, "u", "", "username")
    flag.StringVar(&opts.url, "url", "", "url")
    flag.UintVar(&opts.length, "l", 64, "password length")
    flag.BoolVar(&opts.isCustomPW, "p", false, "set custom password")
    flag.BoolVar(&opts.noSymbols, "noSymbols", false, "password contains no symbols")
    flag.Parse()

    var err error
    usr, err = user.Current()
    if err != nil {
        fmt.Println("error getting current user:", err)
        return
    }
    validCommands := "Valid Commands: genfile, set, get, list, rekey"
    args := flag.Args()
    if len(args) < 1 {
        fmt.Println(validCommands)
        return
    }
    switch args[0] {
    case "genfile":
        if keyPath == "" {
            keyPath = usr.HomeDir + "/kii.json"
        }
        generatePasswordFile()
    case "set":
        err := setKeyFilePath()
        if err != nil {
            fmt.Println(err)
            return
        }
        if len(args) < 2 {
            fmt.Println("Usage: kii set $name\nFlags:")
            flag.PrintDefaults()
            return
        }
        fmt.Println("Using", keyPath)
        setPassword(args[1], &opts)
    case "get":
        err := setKeyFilePath();
        if err != nil {
            fmt.Println(err)
            return
        }
        if len(args) < 2 {
            fmt.Println("Usage: kii set $name\nFlags:")
            flag.PrintDefaults()
            return
        }
        fmt.Println("Using", keyPath)
        getPassword(args[1])
    case "list":
        err := setKeyFilePath();
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Using", keyPath)
        list()
    case "rekey":
        err := setKeyFilePath();
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Using", keyPath)
        rekey()
    default:
        fmt.Println("Invalid command")
        fmt.Println(validCommands)
    }
}
