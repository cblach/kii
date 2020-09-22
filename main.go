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
    username   *string
    url        *string
    length     *uint
    isCustomPW *bool
    noSymbols  *bool
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
    if *opts.isCustomPW {
        fmt.Println("Enter custom password for record", name)
        passwordBin, err := gopass.GetPasswd()
        if err != nil {
            log.Fatalln(err)
        }
        password = string(passwordBin)
    } else {
        password = genPassword(*opts.length, !*opts.noSymbols)
    }
    clipboard.Primary = true
    clipboard.WriteAll(password)
    clipboard.Primary = false
    clipboard.WriteAll(password)

    pwd.Records[name] = Record {
                                Username: *opts.username,
                                Url: *opts.url,
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
        log.Fatalln(err)
    }
    if !validateMasterPassword(oldPass, pwd.KeyHash, pwd.KeySalt) {
        fmt.Println("Invalid password")
        return
    }
    fmt.Println("Enter new encryption password")
    newPass, err := gopass.GetPasswd()
    if err != nil {
        log.Fatalln(err)
    }
    fmt.Println("Repeat new encryption password")
    newPassRepeat, err := gopass.GetPasswd()
    if err != nil {
        log.Fatalln(err)
    }
    if string(newPass) != string(newPassRepeat) {
        fmt.Println("Repeated password does not match")
        return
    }
    tmp := *keyFile
    *keyFile += ".backup"
    fmt.Printf("Saving backup to %s\n", keyFile)
    if err := savePWData(pwd); err != nil {
        log.Fatalln("Failed to save backup:", err)
    }
    *keyFile = tmp
    hash, salt := genValidationHashSalt(newPass)
    pwd.KeySalt = base64.URLEncoding.EncodeToString(salt)
    pwd.KeyHash = base64.URLEncoding.EncodeToString(hash)
    for name, oldRec := range pwd.Records {
        fmt.Printf("Rekeying %s...\n", name)
        oldSalt, err := base64.URLEncoding.DecodeString(oldRec.Salt)
        if err != nil{
            log.Fatalln("failed to base64 decode salt in record", name)
        }
        oldHash := getEncryptionHash(oldPass, oldSalt)
        p := decrypt(oldHash, oldRec.EncryptedPassword)
        newHash, newSalt := genEncryptionHashSalt(newPass)
        newRec := oldRec
        newRec.Salt = base64.URLEncoding.EncodeToString(newSalt)
        newRec.EncryptedPassword = encrypt(newHash, p)
        pwd.Records[name] = newRec
    }
    if err := savePWData(pwd); err != nil{
        log.Fatalln("failed to save file:", err)
    }
    fmt.Println("Success")
}


func main() {
    var err error
    usr, err = user.Current()
    if err != nil {
        panic(err)
    }
    keyFile = flag.String("f", "", "keyFile (optional)")
    if len(os.Args) < 2 {
        fmt.Println("Valid Commands: \ngenfile\ngenpw\nget\nlist")
        return
    }
    switch os.Args[1] {
    case "genfile":
        flag.CommandLine.Parse(os.Args[2:])
        if *keyFile == "" {
            *keyFile = usr.HomeDir + "/kii.json"
        }
        generatePasswordFile()
    case "set":
        opts := Opts {
            username:   flag.String("u", "", "username"),
            url:        flag.String("url", "", "url"),
            length:     flag.Uint("l", 64, "password length"),
            isCustomPW: flag.Bool("p", false, "set custom password"),
            noSymbols:  flag.Bool("nosymbols", false, "password contains no symbols"),
        }
        flag.CommandLine.Parse(os.Args[2:])
        err := setKeyFilePath()
        if err != nil {
            fmt.Println(err)
            return
        }
        if len(flag.Args()) == 0 {
            fmt.Println("Usage: kii set $name\nFlags:")
            flag.PrintDefaults()
            return
        }
        fmt.Println("Using", *keyFile)
        setPassword(flag.Args()[0], &opts)
    case "get":
        flag.CommandLine.Parse(os.Args[2:])
        err := setKeyFilePath();
        if err != nil {
            fmt.Println(err)
            return
        }
        if len(flag.Args()) == 0 {
            fmt.Println("Usage: kii set $name\nFlags:")
            flag.PrintDefaults()
            return
        }
        fmt.Println("Using", *keyFile)
        getPassword(flag.Args()[0])
    case "list":
        flag.CommandLine.Parse(os.Args[2:])
        err := setKeyFilePath();
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Using", *keyFile)
        list()
    case "rekey":
        flag.CommandLine.Parse(os.Args[2:])
        err := setKeyFilePath();
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Using", *keyFile)
        rekey()
    default:
        fmt.Println("Invalid command.")
    }
}
