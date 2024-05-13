package main

/*
# decrypt-dbvis ~ Stephan Hradek
# DbVisualizer uses PBEWithMD5AndDES with a static key to store passwords.
# This is a quick hack to extract and decrypt credentials from DbVisualizer config files.
# Tested against DbVisualizer Free 9.0.9 and 9.1.6, as well as Pro 24.1.4

[2024-05-13 14:10:30][not-the-sea workspace]$ decrypt-dbvis
DbVisualizer Password Extractor and Decryptor (@Skeeve)
Additional Usage Options:
    security/p/gerry/misc/decrypt_dbvis.py <config filename>
    security/p/gerry/misc/decrypt_dbvis.py <encrypted password>
Extracting credentials from /Users/jack/.dbvis/config70/dbvis.xml

+-------------+---------------+-------------+--------------------+----------------------------------------+
| Driver      | Name          | User        | Password           | Connection_info                        |
+-------------+---------------+-------------+--------------------+----------------------------------------+
| Proxy       | Default Proxy | myproxyuser | somesecretpassword | socks://127.0.0.1:1234                 |
| Vertica 6.1 | vertica-prod  | admin       | password1          | jdbc:vertica://127.0.0.1:5434/userdata |
| PostgreSQL  | PGTest        | pg_user     | pg_pass            | Server=localhost,Port=5432,Database=   |
| SQLite      | Doodie        | sqlituser   | sqpasdf            | Database file name=~/mysqlite.db       |
| SSH         | Doodie        | root        | s1qpa              | localhost:22                           |
+-------------+---------------+-------------+--------------------+----------------------------------------+

Done. Have Fun!
*/

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

type Credentials struct {
	Driver          string
	Name            string
	User            string
	Password        string
	Connection_info string
}

type DbVisConfig struct {
	XMLName   xml.Name   `xml:"DbVisualizer"`
	Databases []Database `xml:"Databases>Database"`
	General   General    `xml:"General"`
}

type SshSettings struct {
	SshPassword string
	SshHost     string
	SshPort     string
	SshUserid   string
}

type General struct {
	ProxyHost        string
	ProxyPassword    string
	ProxyPort        string
	ProxyType        string
	ProxyUseSettings string
	ProxyUser        string
}

type Database struct {
	Alias        string
	Driver       string
	Userid       string
	Password     string
	Url          string
	UrlVariables []Driver    `xml:"UrlVariables>Driver>UrlVariable"`
	SshSettings  SshSettings `xml:"SshSettings"`
}

type Driver struct {
	Variable string `xml:"UrlVariableName,attr"`
	Value    string `xml:",chardata"`
}

const ITERATIONS = 10
const SALT = "\x8E\x129\x9C\aroZ" // 142, 18, 57, 156, 7, 114, 111, 90
const PASSWORD = "qinda"

type PBEWithMD5AndDES struct {
	key []byte
	iv  []byte
}

func NewPBEWithMD5AndDES(password, salt string, iterations int) (self PBEWithMD5AndDES) {
	key := []byte(self.generate_key(password, salt, iterations, 16))
	self.key = key[0:8]
	self.iv = key[8:16]
	return self
}

func (self PBEWithMD5AndDES) generate_key(key, salt string, count, length int) string {
	data := make([]byte, len(key)+len(salt), length)
	copy(data, key+salt)
	for i := 0; i < count; i++ {
		run := md5.Sum(data)
		data = run[:length]
	}
	return string(data)
}

func (self PBEWithMD5AndDES) decrypt(ciphertext []byte) string {
	block, err := des.NewCipher(self.key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, self.iv)
	plainbuf := make([]byte, len(ciphertext))
	mode.CryptBlocks(plainbuf, ciphertext)
	// Cut off padding
	// The padding character's byte code is the amount of
	// characters padded. So padding of 4 will be "\x04\x04\x04\x04"
	// If password length was a multiple of 8, there will
	// be 8 characters padded.
	return string(plainbuf[:len(plainbuf)-int(plainbuf[len(plainbuf)-1])])
}

func decrypt_password(password string) string {
	pbe := NewPBEWithMD5AndDES(PASSWORD, SALT, ITERATIONS)
	ciphertext, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		panic(err)
	}
	return pbe.decrypt(ciphertext)
}

func extract_credentials(config_file string) (creds []Credentials) {
	xmlFile, err := os.Open(config_file)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer xmlFile.Close()

	b, _ := io.ReadAll(xmlFile)

	var dbv DbVisConfig
	xml.Unmarshal(b, &dbv)

	//fmt.Printf("%#v\n", dbv)
	pbe := NewPBEWithMD5AndDES(PASSWORD, SALT, ITERATIONS)

	// Get any global proxy if it exists.
	proxy_user := dbv.General.ProxyUser
	proxy_pass := dbv.General.ProxyPassword
	if proxy_pass != "" {
		pwd, _ := base64.StdEncoding.DecodeString(proxy_pass)
		proxy_pass = pbe.decrypt(pwd)
	}
	proxy_host := dbv.General.ProxyHost
	proxy_port := dbv.General.ProxyPort
	proxy_type := dbv.General.ProxyType
	conn_info := fmt.Sprintf("%s://%s:%s", proxy_type, proxy_host, proxy_port)

	if proxy_user != "" && proxy_pass != "" && conn_info != "://:" {
		creds = append(creds, Credentials{
			Name:            "Default Proxy",
			User:            proxy_user,
			Password:        proxy_pass,
			Connection_info: conn_info,
			Driver:          "Proxy",
		})
	}

	//*/
	// Grab and decrypt each DB password along with any SSh servers
	cred := Credentials{}
	for _, db := range dbv.Databases {
		cred.Name = db.Alias
		cred.User = db.Userid
		if db.Password != "" {
			pwd, _ := base64.StdEncoding.DecodeString(db.Password)
			cred.Password = pbe.decrypt(pwd)
			cred.Driver = db.Driver
			conn_info := db.Url
			if conn_info == "" {
				sep := ""
				for _, v := range db.UrlVariables {
					conn_info += fmt.Sprintf("%s%s=%s", sep, v.Variable, v.Value)
					sep = ","
				}
			}
			cred.Connection_info = conn_info

			// Note: I haven't tested anything related to ssh info extraction... no test cases
			ssh_password := db.SshSettings.SshPassword
			if ssh_password != "" {
				host := db.SshSettings.SshHost
				port := db.SshSettings.SshPort
				if port == "" {
					port = "22"
				}
				pwd, _ := base64.StdEncoding.DecodeString(ssh_password)
				ssh_password = pbe.decrypt(pwd)
				ssh_cred := Credentials{
					Driver:          "SSH",
					Name:            cred.Name,
					User:            db.SshSettings.SshUserid,
					Password:        ssh_password,
					Connection_info: fmt.Sprintf("%s:%s", host, port),
				}
				creds = append(creds, ssh_cred)
			}
		}
		creds = append(creds, cred)
	}
	return
}

func print_table(rows []Credentials) {
	t := table.NewWriter()
	t.Style().Format.Header = text.FormatDefault
	t.SetOutputMirror(os.Stdout)

	val := reflect.ValueOf(rows[0])
	var row table.Row
	row = make([]interface{}, val.NumField())
	for i := 0; i < val.NumField(); i++ {
		row[i] = val.Type().Field(i).Name
	}
	t.AppendHeader(row)
	for _, r := range rows {
		row := make([]interface{}, val.NumField())
		val := reflect.ValueOf(r)
		for i := 0; i < val.NumField(); i++ {
			row[i] = val.Field(i).Interface()
		}
		t.AppendRow(row)
	}
	t.Render()
}

func main() {
	var dbvis_config string
	fmt.Println("DbVisualizer Password Extractor and Decryptor (@Skeeve)")
	if len(os.Args) == 2 {
		if _, err := os.Stat(os.Args[1]); err == nil {
			dbvis_config = os.Args[1]
		}
	} else {
		fmt.Println("Additional Usage Options: ")
		fmt.Printf("    %s <config filename>\n", os.Args[0])
		fmt.Printf("    %s <encrypted password>\n", os.Args[0])
		homeDir, _ := os.UserHomeDir()
		dbvis_config = fmt.Sprintf("%s/.dbvis/config70/dbvis.xml", homeDir)
	}

	if dbvis_config == "" {
		password := os.Args[1]
		fmt.Printf("Decrypting: %s\n", password)
		fmt.Printf("Plain Text: %s\n", decrypt_password(password))
		//except Exception, e:
		//	fmt.Printf("[!] Error decrypting! %s", (e,))
		os.Exit(0)
	}
	fmt.Printf("Extracting credentials from %s\n\n", dbvis_config)
	print_table(extract_credentials(dbvis_config))
	fmt.Println("\nDone. Have Fun!")
}
