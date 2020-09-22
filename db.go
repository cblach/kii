package main
import(
    "encoding/json"
    "encoding/base64"
    "errors"
    "fmt"
    "github.com/howeyc/gopass"
    "io/ioutil"
    "log"
    "os"
    "os/user"
    "path/filepath"
    "runtime"
)

var keyFile *string
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

func loadPWData() (*PWData, error) {
    var pwd PWData
    out, err := ioutil.ReadFile(*keyFile)
    if err != nil {
        return nil, err
    }
    if err := json.Unmarshal(out, &pwd); err != nil {
        return nil, err
    }
    return &pwd, nil
}

func savePWData(pwd *PWData) error {
    out, err := json.MarshalIndent(pwd, "", "    ")
    if err != nil {
        return err
    }
    if err := ioutil.WriteFile(*keyFile + ".tmp", out, 0600); err != nil {
        return err
    }
    if err := os.Rename(*keyFile + ".tmp", *keyFile); err != nil {
        return err
    }
    return nil
}

func generatePasswordFile() {
    if _, err := os.Stat(*keyFile); !os.IsNotExist(err) {
        fmt.Printf("File %s already exists. \nWrite YES (capital) if you want to overwrite it\n", *keyFile)
        if !confirm("YES") {
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
    if err := savePWData(&pwd); err != nil {
        fmt.Println("Failed to save password data:", err)
    }
}

func getDropboxPath() string{
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
        if os.IsNotExist(err) {
            return ""
        }
        log.Fatalln("failed to read dropbox kii file: ", err)
    }
    err = json.Unmarshal(out, &info)
    if err != nil {
        log.Fatalln("failed to unmarshal dropbox kii file: ", err)
    }
    return filepath.ToSlash(info.Personal.Path)
}

func setKeyFilePath() error {
    usr, err := user.Current()
    if err != nil {
        panic(err)
    }
    if *keyFile != "" {
        if _, err := os.Stat(*keyFile); os.IsNotExist(err) {
            return errors.New("Unable to find path")
        }
        return nil
    }
    dropboxPath := getDropboxPath()
    if dropboxPath != "" {
        if _, err = os.Stat(dropboxPath+"/kii.json"); !os.IsNotExist(err) {
            *keyFile = dropboxPath+"/kii.json"
            return nil
        }
    }
    if _, err = os.Stat(usr.HomeDir+"/kii.json"); !os.IsNotExist(err) {
        *keyFile = usr.HomeDir+"/kii.json"
        return nil
    }
    return errors.New("Unable to find file")
}
