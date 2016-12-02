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
    username   string
    url        string
    length     uint
    customPW   bool
    useSymbols bool
}

/* Ask for confirmation string */
func Confirm(confirmstr string) bool{
    stdinReader := bufio.NewReader(os.Stdin)
    line, _, err := stdinReader.ReadLine()
    if err != nil {
        log.Fatalln(err)
    }
    return string(line) == confirmstr
}

// === Generate Random Password ===
func GenerateRandomPassword(ncharacters uint, usesymbols bool) string {
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
        if !Confirm("YES") {
            fmt.Println("Exiting file generation")
            return
        }
    }
    fmt.Println("Enter encryption password")
    masterpw, err := gopass.GetPasswd()
    if err != nil {
        log.Fatalln(err)
    }
    if !ValidateMasterPassword(masterpw, pwd.KeyHash, pwd.KeySalt) {
        fmt.Println("Invalid password")
        return
    }
    hash, salt := genEncryptionHashSalt(masterpw)
    var password string
    if opts.customPW {
        fmt.Println("Enter custom password for record", name)
        passwordBin, err := gopass.GetPasswd()
        if err != nil {
            log.Fatalln(err)
        }
        password = string(passwordBin)
    } else {
        password = GenerateRandomPassword(opts.length, opts.useSymbols)
        if password == "" {
            return
        }
    }
    clipboard.WriteAll(password)
    pwd.Records[name] = Record {
                                Username: opts.username,
                                Url: opts.url,
                                EncryptedPassword: encrypt(hash, password),
                                Salt: base64.URLEncoding.EncodeToString(salt),
                             }
    err = savePWData(pwd)
    if err != nil{
        fmt.Println(err)
        return
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
    hash := genEncryptionHash(key, salt)
    clipboard.WriteAll(decrypt(hash, rec.EncryptedPassword))
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




func main() {
    var err error
    usr, err = user.Current()
    if err != nil {
        panic(err)
    }
    if len(os.Args) < 2 {
        fmt.Println("Valid Commands: \ngenfile\ngenpw\nget\nlist")
        return
    }
    cmd := os.Args[1]
    switch cmd {
    case "genfile":
        filenamePtr = flag.String("f", usr.HomeDir + "/kii.json", "filename (optional)")
        flag.CommandLine.Parse(os.Args[2:])
        GeneratePasswordFile()
    case "set":
        if len(os.Args) < 3 {
            fmt.Println("Not enough arguments, a label is required")
            return
        }
        err := SetKeyFilePath();
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Using", *filenamePtr)
        usrPtr := flag.String("u", "", "username (optional)")
        urlPtr := flag.String("url", "", "url (optional)")
        lenPtr := flag.Uint("l", 64, "password length (optional)")
        customPwPtr := flag.Bool("p", false, "set custom password (optional)")
        nosymPtr := flag.Bool("nosymbols", false, "makes the password not contain symbols")
        flag.CommandLine.Parse(os.Args[3:])
        opts := Opts {
            username:   *usrPtr,
            url:        *urlPtr,
            length:     *lenPtr,
            customPW:   *customPwPtr,
            useSymbols: !*nosymPtr,
        }
        setPassword(os.Args[2], &opts)
    case "get":
        err := SetKeyFilePath();
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Using", *filenamePtr)
        if len(os.Args) < 3 {
            fmt.Println("Not enough arguments")
            return
        }
        flag.CommandLine.Parse(os.Args[3:])
        name := os.Args[2]
        getPassword(name)
    case "list":
        err := SetKeyFilePath();
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Using", *filenamePtr)
        flag.CommandLine.Parse(os.Args[2:])
        list()
    default:
        fmt.Println("Invalid command.")
    }
}
