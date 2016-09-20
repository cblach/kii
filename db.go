package main
import(
    "encoding/json"
    "encoding/base64"
    "errors"
    "flag"
    "fmt"
    "github.com/howeyc/gopass"
    "io/ioutil"
    "log"
    "os"
    "os/user"
    "path/filepath"
    "runtime"
)

var filenamePtr *string
var usr *user.User
// === Data structure ===

type Record struct{
    Username          string `json:"username,omitempty"`
    EncryptedPassword string `json:"password"`
    Salt              string `json:"salt"`
    Url               string `json:"url,omitempty"`
}

type PWData struct {
    Records map[string]Record `json:"records"`
    Settings struct {
        
    } `json:"settings,omitempty"`
    KeySalt string `json:"keysalt"`
    KeyHash string `json:"keyhash"`
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
    pass, err := gopass.GetPasswd()
    if err != nil {
        log.Fatalln(err)
    }
    hash, salt := genValidationHashSalt(pass)
    pwd.KeySalt = base64.URLEncoding.EncodeToString(salt)
    pwd.KeyHash = base64.URLEncoding.EncodeToString(hash)
    savePWData(&pwd)
}

func GetDropboxPath() string{
    type DropboxInfo struct {
        Personal struct{
            Path string `json:"path"`
        } `json:"personal"`
    }
    var info DropboxInfo
    var infoFile string
    if runtime.GOOS == "windows" {
        infoFile = usr.HomeDir + "/AppData/Roaming/Dropbox/info.json"
    } else {
        infoFile = usr.HomeDir + "/.dropbox/info.json"
    }
    out, err := ioutil.ReadFile(infoFile)
    if err != nil {
        fmt.Println(err, infoFile)
        return ""
    }
    err = json.Unmarshal(out, &info)
    if err != nil {
        fmt.Println(err)
        return ""
    }
    return filepath.ToSlash(info.Personal.Path)
}

func SetKeyFilePath() ( error) {
    usr, err := user.Current()
    if err != nil {
        panic(err)
    }
    default_path := "PLACEHOLDER_PATH"
    filenamePtr = flag.String("f", default_path, "filename (optional)")
    if *filenamePtr != default_path {
        if _, err := os.Stat(*filenamePtr); os.IsNotExist(err) {
            return errors.New("Unable to find path")
        }
        return nil
    }
    dropboxPath := GetDropboxPath()
    if dropboxPath != "" {
        if _, err = os.Stat(dropboxPath+"/kii.json"); !os.IsNotExist(err) {
            *filenamePtr = dropboxPath+"/kii.json"
            return nil
        }
    }
    if _, err = os.Stat(usr.HomeDir+"/kii.json"); !os.IsNotExist(err) {
        *filenamePtr = usr.HomeDir+"/kii.json"
        return nil
    }
    return errors.New("Unable to find file")
}
