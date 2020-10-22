package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"./lib/aes_cfb"
	"./lib/mariadb_lib"
	"./lib/sqlitedb_lib"
	"github.com/BurntSushi/toml"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sevlyar/go-daemon"
)

var DeviceOSFlag int
var ControlServerFlag int
var Node_Flag int
var Node_Change_Client_IP_Mode int
var ProxyIPStrArray []string
var NICInfoArray []NICInformation
var ControlServerIP, ControlServerPort, ControlServerSendInterval string
var RowCountPerPage = 25
var MaxPageCountInPage = 5

var LoginTimeout = 60 * 30 /* sec */
var SqliteDB = "./db/traffic.db"
var DBPath, DBName string
var UpdateLock = &sync.Mutex{}
var ProcessLogFileName = "stat_web_server.log"
var Login = "SELECT COUNT(*) FROM Users WHERE ID=? AND PASSWORD=?"

var Stat_Serv_Common_ID int64
var Stat_Serv_Data_ID int64
var Stat_Clint_Common_ID int64
var Stat_Clint_Data_ID int64

var db_cfg_path = "./cfg/db.cfg"

const (
	DB_RET_SUCC = 0
	DB_RET_FAIL = -1
)

const CooKie_FAIL = -1
const (
	IP_FLAG = iota
	PORT_FLAG
	UUID_FLAG
	TIME_FLAG
)
const (
	Node_FLAG_NONE = iota
	Node_FLAG_CLIENT
	Node_FLAG_SERVER
	Node_FLAG_CLIENT_AND_SERVER
	Node_LICENSE
)

const (
	ENABLE = iota + 1
	DISABLE
)

const (
	DEVICE_OS = iota + 1
	GENERAL_OS
)

const (
	ENC_NONE = iota
	ENC_AES128
	ENC_AES256
	ENC_RC4
)

const (
	Node_MODE_NONE   = 0
	Node_MODE_CLIENT = 0x0001
	Node_MODE_SERVER = 0x0002
)

const (
	SortTime_ASC = iota
	SortBridgeID_ASC
	SortNodeID_ASC
	SortProxyIP_ASC
	SortNodeIP_ASC
	SortServerIP_ASC
	SortClientIP_ASC
	SortTime_DESC = iota + 5
	SortBridgeID_DESC
	SortNodeID_DESC
	SortProxyIP_DESC
	SortNodeIP_DESC
	SortServerIP_DESC
	SortClientIP_DESC
)

type tomlinfo struct {
	UserKey UserKey
	NodeID  NodeID
}

type UserKey struct {
	UserID         string
	UserKey        string
	NodeID_Total   string
	NodeID_Current string
	EndDateYear    string
	EndateMonth    string
	EndateDay      string
}

type NodeID struct {
	NodeID []string
}

type LicenseMagementPageInfo struct {
	NodeClientStatMenu template.HTML
	NodeServerStatMenu template.HTML
	LicenseManagement  template.HTML

	No           template.HTML
	NodeID       template.HTML
	LastConnTime template.HTML
	ETC          template.HTML

	FirstPage template.HTML
	PrevPage  template.HTML
	NextPage  template.HTML
	LastPage  template.HTML

	LicInfo     []LicenseData
	PageNumInfo []PageNumInfo
}
type LicenseData struct {
	TrInfo       TableRowInfo
	No           int
	NodeID       string
	LastConnTime string
	ETC          string
}
type DBconfig struct {
	DB DBcfgData
}
type DBcfgData struct {
	ID       string
	PASSWORD string
	IP       string
	PORT     string
	DBNAME   string
}

type TableRowInfo struct {
	Style       string
	DataGroupID string
	DataFirst   string
}

type PageNumInfo struct {
	TagStart template.HTML
	PageNum  int
	TagEnd   template.HTML
}

type SettingPageInfo struct {
	NodeClientStatMenu template.HTML
	NodeServerStatMenu template.HTML
	LicenseManagement  template.HTML

	Password          string
	VerifyingPassword string
	Max_Conn          int
	Recv_Buffer_Size  int
	Send_Buffer_Size  int
	Timeout_Connect   int
	Timeout_Client    int
	Timeout_Server    int

	Disk_Limit    int
	Max_Size      int
	Log           string
	LogFileName   string
	Error         string
	ErrorFileName string

	StatSelectHTMLList           []HTMLType
	Interval                     int
	Control_Server_IP            string
	Control_Server_Port          int
	Control_Server_Send_Interval int

	ModeSelectHTMLList     []HTMLType
	Buffer_Size            int
	EncModeSelectHTMLList  []HTMLType
	ChangeIPSelectHTMLList []HTMLType

	Node_ID string

	KMS_Address string
	KMS_Port    int

	FrontBackHTMLList []HTMLType
	NICNAMEHTMLList   []HTMLType

	FrontendNodeMode template.HTML
}

type ServerStatisticData struct {
	OverlapID      int64
	ID             int64
	Client_IP_Int  uint32
	Client_IP_Str  string
	Client_IP_HTML template.HTML
	Inbound        int
	Inbound_HTML   template.HTML
	Outbound       int
	Outbound_HTML  template.HTML
}

type ServerStatisticCommon struct {
	TrInfo             TableRowInfo
	ID                 int64
	Time               string
	Bridge_ID_Str      string
	Proxy_IP_Int       uint32
	Proxy_IP_Str       string
	Node_IP_Int        uint32
	Node_IP_Str        string
	Node_Listen_Port   int
	Server_IP_Int      uint32
	Server_IP_Str      string
	Server_Listen_Port int
}

type ServerStatisticInfo struct {
	StatCommon ServerStatisticCommon
	StatData   ServerStatisticData
}

type ProxyIPHTML struct {
	ProxyIP_HTML template.HTML
}

type NICIPHTML struct {
	NICIP_HTML template.HTML
}

type NICNAMEHTML struct {
	NICNAME_HTML template.HTML
}

type EnableSelectHTML struct {
	Value_HTML template.HTML
}

type HTMLType struct {
	Value_HTML template.HTML
}

type ServerStatisticPageInfo struct {
	NodeClientStatMenu template.HTML
	NodeServerStatMenu template.HTML
	LicenseManagement  template.HTML

	ProxyIPHTMLList []ProxyIPHTML
	NICIPHTMLList   []NICIPHTML

	SearchStartTime  string
	SearchEndTime    string
	SearchBridgeID   string
	SearchProxyIP    string
	SearchNICIP      string
	SearchNICPort    string
	SearchServerIP   string
	SearchServerPort string
	SearchClientIP   template.HTML

	SortTime       template.HTML
	SortBridgeID   template.HTML
	SortProxyIP    template.HTML
	SortNodeIP     template.HTML
	SortNodePort   template.HTML
	SortServerIP   template.HTML
	SortServerPort template.HTML
	SortClientIP   template.HTML
	FirstPage      template.HTML
	PrevPage       template.HTML
	NextPage       template.HTML
	LastPage       template.HTML

	StatInfo    []ServerStatisticInfo
	PageNumInfo []PageNumInfo
}

type ClientStatisticData struct {
	OverlapID         int64
	ID                int64
	Proxy_IP_Int      uint32
	Proxy_IP_Str      string
	Proxy_Listen_Port int
	Inbound           int
	Outbound          int
}

type ClientStatisticCommon struct {
	TrInfo           TableRowInfo
	ID               int64
	Time             string
	Node_ID_Str      string
	Client_IP_Int    uint32
	Client_IP_Str    string
	Node_IP_Int      uint32
	Node_IP_Str      string
	Node_Listen_Port int
	StatData         []ClientStatisticData
}

type ClientStatisticInfo struct {
	StatCommon ClientStatisticCommon
	StatData   ClientStatisticData
}

type ClientStatisticPageInfo struct {
	NodeClientStatMenu template.HTML
	NodeServerStatMenu template.HTML

	ProxyIPHTMLList []ProxyIPHTML
	NICIPHTMLList   []NICIPHTML

	SearchStartTime string
	SearchEndTime   string
	SearchNodeID    string
	SearchClientIP  string
	SearchNICIP     string
	SearchNICPort   string
	SearchProxyIP   string
	SearchProxyPort string

	SortTime     template.HTML
	SortNodeID   template.HTML
	SortClientIP template.HTML
	SortNodeIP   template.HTML
	SortProxyIP  template.HTML
	FirstPage    template.HTML
	PrevPage     template.HTML
	NextPage     template.HTML
	LastPage     template.HTML

	StatInfo    []ClientStatisticInfo
	PageNumInfo []PageNumInfo
}

type LeftInboundSession struct {
	Total_Connection_Count int
	time                   int
	Date                   string
}

type CtoM struct {
	ClientIP     string
	TotalTraffic uint64
}

type TotalInboundLeftPerNIC struct {
	NICName          string
	TotalConnections int
}

type InboundLeftPerNIC struct {
	NICName      string
	TotalTraffic int
}

type InboundLeftPerNIC_Client struct {
	NICName      string
	ClientIP     string
	TotalTraffic int
}

type NICInformation struct {
	Name string
	IP   string
}

type SettingsInformation struct {
	Password                      string
	VerifyingPassword             string
	Maximum_ConnectionCount       string
	Recv_Buf_Size                 string
	Send_Buf_Size                 string
	Connection_Timeout            string
	Client_Reconnect_Timeout      string
	Server_Reconnect_Timeout      string
	Limit_Size_Log_Storage        string
	Maxsize_Per_Logfile           string
	Logfile_Path                  string
	Err_Logfile_Path              string
	Statistic_Send_Control_Server string
	Statistic_Collection_Cycle    string
	Statistic_Server_Ip           string
	Statistic_Server_Port         string
	Statistic_Send_Cycle          string
	Bridge_Used                   string
	Bridge_Buf_Size               string
	Encrypt_Mode                  string
	Change_Client_IP              string
	Node_ID                       string
	KMS_Address                   string
	KMS_Port                      string
	SiteList                      []FrontendInformation
}

type FrontendInformation struct {
	Frontendsymbol string
	FrontendPort   string
	NodeMode       string
	Backend        []BackendInformationList
}

type BackendInformationList struct {
	LAN_Interface string
	BackendIP     string
	BackendPort   string
}

var (
	key   = []byte("abcdefgabcdefg1234567890abcdefgh")
	store = sessions.NewCookieStore(key)
)

var (
	aes_key = []byte{109, 56, 85, 44, 248, 44, 18, 128, 236, 116, 13, 250, 243, 45, 122, 133, 199, 241, 124, 188, 188, 93, 65, 153, 214, 193, 127, 85, 132, 147, 193, 68}
	iv      = []byte{89, 93, 106, 165, 128, 137, 36, 38, 122, 121, 249, 59, 151, 133, 155, 148}

	base32_alphabet = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79}
)

func SigHandler() {
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGSEGV)

	signal := <-sigs
	switch signal {
	case syscall.SIGHUP:
		fmt.Printf("SIGHUP\n")
		panic(signal)
	case syscall.SIGINT:
		fmt.Printf("SIGINT\n")
		panic(signal)
	case syscall.SIGTERM:
		fmt.Printf("SIGTERM\n")
		panic(signal)
	case syscall.SIGSEGV:
		fmt.Printf("SIGSEGV\n")
		panic(signal)
	}
}

func StrtoIP(ipaddr string) uint32 {
	var (
		ip                 = strings.Split(ipaddr, ".")
		ip1, ip2, ip3, ip4 uint64
		ret                uint32
	)
	if len(ip) == 4 {
		ip1, _ = strconv.ParseUint(ip[0], 10, 8)
		ip2, _ = strconv.ParseUint(ip[1], 10, 8)
		ip3, _ = strconv.ParseUint(ip[2], 10, 8)
		ip4, _ = strconv.ParseUint(ip[3], 10, 8)
		ret = uint32(ip1)<<24 + uint32(ip2)<<16 + uint32(ip3)<<8 + uint32(ip4)
		return ret
	} else {
		return 0
	}
}

func StrtoUUID(uuid string) uint32 {
	var (
		id = strings.Split(uuid, "-")
	)

	if len(id) == 5 && len(id[4]) == 12 {
		log.Println("len id[4] : ", len(id[4]))
		return 1
	} else {
		return 0
	}
}
func GetCipherText(PlainText string) string {
	block, err := aes.NewCipher([]byte(aes_key))
	if err != nil {
		log.Println("NewCipher err:", err)
		return ""
	}

	nonce := make([]byte, 12)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("NewGCM err:", err)
		return ""

	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(PlainText), nil)
	log.Printf("PlainText %s -> %x\n", PlainText, ciphertext)

	return fmt.Sprintf("%x", ciphertext)
}

func IPtoStr(ipaddr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ipaddr>>24), byte(ipaddr>>16), byte(ipaddr>>8), byte(ipaddr))
}

func WebServer_Login(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	var tmpl *template.Template
	var err error
	defer req.Body.Close()

	if ControlServerFlag == 0 {
		log.Println("Local Web Server", req.Method)
		tmpl, err = template.ParseFiles("./pages/Login.html")
		if err != nil {
			log.Println("failed to template.ParseFiles")
			return
		}

	} else {
		log.Println("Control Web Server", req.Method)
		tmpl, err = template.ParseFiles("./pages/Control_Login.html")
		if err != nil {
			log.Println("failed to template.ParseFiles")
			return
		}
	}
	tmpl.Execute(w, nil)
}

func Cookie_Check(w http.ResponseWriter, req *http.Request) int {
	cookies := req.Cookies()
	log.Println(cookies)

	if len(cookies) == 0 {
		log.Println("No Cookies")
		WebServer_Redirect(w, req, "/login")
		return -1
	}

	for i := range cookies {
		session, _ := store.Get(req, cookies[i].Name)
		log.Println("Cookies Name:", cookies[i].Name)
		if session != nil {
			auth, ok := session.Values["authenticated"].(bool)
			if !ok || !auth {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return -1
			}
			session.Options.MaxAge = LoginTimeout
			session.Save(req, w)
		}
	}

	return 0
}

func UpdateConfigFile(Database *sql.DB) (int32, error) {
	var QueryStr, Config_File, Whole_Config_File string
	var Rows *sql.Rows
	var Max_Conn, Recv_Buffer_Size, Send_Buffer_Size, Timeout_Connect, Timeout_Client, Timeout_Server int
	var Disk_Limit, Logfile_Max_Size int
	var Logfile_Location, Logfile_Name, Errorlogfile_Location, Errorlogfile_Name string
	var Statistics_Interval int
	var Bridge_Mode, Node_Buff_Size, Node_Encrypt, Change_IP_Func int
	var Symbol_Name, Server, Bridge_Mode_Str, Node_Mode_Str, Change_IP_Func_Str, Node_Encrypt_Str string
	var KMS_Address string
	var KMS_Port int
	var EncText string
	var Bind, Node_Mode int
	var err error
	var fd *os.File

	err = os.MkdirAll("./cfg", 0644)
	if err != nil {
		return DB_RET_FAIL, err
	}

	fd, err = os.Create("./cfg/app.cfg")
	if err != nil {
		return DB_RET_FAIL, err
	}
	defer fd.Close()

	{ /* Global */
		QueryStr = fmt.Sprintf("SELECT Global FROM Config_File")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Config_File)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
		}

		QueryStr = fmt.Sprintf("SELECT * FROM Config_Global_Data")

		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}
		for Rows.Next() {
			err = Rows.Scan(&Max_Conn, &Recv_Buffer_Size, &Send_Buffer_Size, &Timeout_Connect, &Timeout_Client, &Timeout_Server)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
			Config_File = strings.Replace(Config_File, "<MAX_CONN>", strconv.Itoa(Max_Conn), -1)
			Config_File = strings.Replace(Config_File, "<DEFAULT_RECV_BUFF_SIZE>", strconv.Itoa(Recv_Buffer_Size), -1)
			Config_File = strings.Replace(Config_File, "<DEFAULT_SEND_BUFF_SIZE>", strconv.Itoa(Send_Buffer_Size), -1)
			Config_File = strings.Replace(Config_File, "<TIMEOUT_CONNECT>", strconv.Itoa(Timeout_Connect), -1)
			Config_File = strings.Replace(Config_File, "<TIMEOUT_CLIENT>", strconv.Itoa(Timeout_Client), -1)
			Config_File = strings.Replace(Config_File, "<TIMEOUT_SERVER>", strconv.Itoa(Timeout_Server), -1)

			Whole_Config_File += Config_File
		}
		Rows.Close()
	}

	{ /* LogFile */
		QueryStr = fmt.Sprintf("SELECT LogFile FROM Config_File")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Config_File)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
		}

		QueryStr = fmt.Sprintf("SELECT * FROM Config_Logfile_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Disk_Limit, &Logfile_Max_Size, &Logfile_Location, &Logfile_Name, &Errorlogfile_Location, &Errorlogfile_Name)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
			Config_File = strings.Replace(Config_File, "<DISK_LIMIT>", strconv.Itoa(Disk_Limit), -1)
			Config_File = strings.Replace(Config_File, "<LOGFILE_MAX_SIZE>", strconv.Itoa(Logfile_Max_Size), -1)
			Config_File = strings.Replace(Config_File, "<LOGFILE_LOCATION>", Logfile_Location+"/"+Logfile_Name, -1)
			Config_File = strings.Replace(Config_File, "<ERRORLOGFILE_LOCATION>", Errorlogfile_Location+"/"+Errorlogfile_Name, -1)

			Whole_Config_File += Config_File
		}
		Rows.Close()
	}

	{ /* Statistics */
		QueryStr = fmt.Sprintf("SELECT Statistics FROM Config_File")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Config_File)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
		}
		Rows.Close()

		QueryStr = fmt.Sprintf("SELECT Interval FROM Config_Statistics_Data")

		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Statistics_Interval)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
			Config_File = strings.Replace(Config_File, "<STATISTICS_INTERVAL>", strconv.Itoa(Statistics_Interval), -1)

			Whole_Config_File += Config_File
		}
		Rows.Close()
	}

	{ /* Node */
		QueryStr = fmt.Sprintf("SELECT Node FROM Config_File")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Config_File)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
		}
		Rows.Close()

		QueryStr = fmt.Sprintf("SELECT * FROM Config_Node_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Bridge_Mode, &Node_Buff_Size, &Node_Encrypt, &Change_IP_Func)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}

			if Bridge_Mode == ENABLE {
				Bridge_Mode_Str = "enable"
			} else {
				Bridge_Mode_Str = "disable"
			}
			log.Println("Bridge_Mode", Bridge_Mode, "Bridge_Mode_Str", Bridge_Mode_Str)
			Config_File = strings.Replace(Config_File, "<Bridge_MODE>", Bridge_Mode_Str, -1)
			Config_File = strings.Replace(Config_File, "<Node_BUFF_SIZE>", strconv.Itoa(Node_Buff_Size), -1)
			if Node_Encrypt == ENC_NONE {
				Node_Encrypt_Str = "none"
			} else if Node_Encrypt == ENC_AES128 {
				Node_Encrypt_Str = "aes128"
			} else if Node_Encrypt == ENC_AES256 {
				Node_Encrypt_Str = "aes256"
			} else if Node_Encrypt == ENC_RC4 {
				Node_Encrypt_Str = "rc4"
			}
			Config_File = strings.Replace(Config_File, "<Node_ENCRYPT>", Node_Encrypt_Str, -1)
			if Change_IP_Func == ENABLE {
				Change_IP_Func_Str = "enable"
			} else {
				Change_IP_Func_Str = "disable"
			}
			Config_File = strings.Replace(Config_File, "<CHANGE_IP_FUNC>", Change_IP_Func_Str, -1)

			Whole_Config_File += Config_File
		}
		Rows.Close()
	}
	{ /* KMS Address */
		QueryStr = fmt.Sprintf("SELECT KMS FROM Config_File")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Config_File)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
		}
		Rows.Close()

		QueryStr = fmt.Sprintf("SELECT * FROM Config_KMS_Data")

		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&KMS_Address, &KMS_Port)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}

			if KMS_Address == "" {
				Config_File = strings.Replace(Config_File, "<KMS_ADDR_PORT>", "", -1)

			} else {
				Config_File = strings.Replace(Config_File, "<KMS_ADDR_PORT>", "http://"+KMS_Address+":"+strconv.Itoa(KMS_Port), -1)
			}

			Whole_Config_File += Config_File
		}
		Rows.Close()
	}

	var Frontend_Config_File, Backend_Config_File, Frontend_Config, Backend_Config string

	Frontend_Config = "[frontend]\n"
	Backend_Config = "[backend]\n"
	{ /* Frontend */
		QueryStr = fmt.Sprintf("SELECT Frontend, Backend FROM Config_File")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Frontend_Config_File, &Backend_Config_File)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
		}
		Rows.Close()

		QueryStr = fmt.Sprintf("SELECT * FROM Config_Frontend_Backend_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Symbol_Name, &Bind, &Node_Mode, &Server)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}

			TempConfig_File := Frontend_Config_File

			TempConfig_File = strings.Replace(TempConfig_File, "<SYMBOL_NAME>", Symbol_Name, -1)
			TempConfig_File = strings.Replace(TempConfig_File, "<FRONTEND_BIND>", strconv.Itoa(Bind), -1)
			if Node_Mode == Node_MODE_CLIENT {
				Node_Mode_Str = "client"
			} else {
				Node_Mode_Str = "server"
			}
			TempConfig_File = strings.Replace(TempConfig_File, "<Node_MODE>", Node_Mode_Str, -1)

			Frontend_Config += TempConfig_File

			TempConfig_File = Backend_Config_File
			TempConfig_File = strings.Replace(TempConfig_File, "<SYMBOL_NAME>", Symbol_Name, -1)
			TempConfig_File = strings.Replace(TempConfig_File, "<LANID_SERVER_IP_PORT>", Server, -1)

			Backend_Config += TempConfig_File
		}
		Rows.Close()
	}
	Whole_Config_File += Frontend_Config
	Whole_Config_File += Backend_Config

	EncryptEncodingStr(Whole_Config_File, &EncText)

	_, err = fd.Write([]byte("COD$_"))
	if err != nil {
		log.Println(" Write err:", err)
		return DB_RET_FAIL, err
	}

	_, err = fd.Write([]byte(EncText))
	if err != nil {
		log.Println(" Write err:", err)
		return DB_RET_FAIL, err
	}

	log.Println("Whole Config File\n", Whole_Config_File)
	return DB_RET_SUCC, nil
}

func UpdateNodeFile(Database *sql.DB) (int32, error) {
	var QueryStr, Node_File, Whole_Node_File, Node_ID string
	var err error
	var EncText string
	var Rows *sql.Rows
	var fd *os.File

	err = os.MkdirAll("./cfg", 0644)
	if err != nil {
		return DB_RET_FAIL, err
	}

	fd, err = os.Create("./cfg/nodeid.key")
	if err != nil {
		return DB_RET_FAIL, err
	}
	defer fd.Close()

	{ /* NodeID */
		QueryStr = fmt.Sprintf("SELECT NodeID FROM Config_File")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Node_File)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}
		}
		Rows.Close()

		QueryStr = fmt.Sprintf("SELECT * FROM Config_NodeID_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return DB_RET_FAIL, err
		}

		for Rows.Next() {
			err = Rows.Scan(&Node_ID)
			if err != nil {
				log.Println(" data Scan error:", err)
				return DB_RET_FAIL, err
			}

			Node_File = strings.Replace(Node_File, "<NODE_ID>", Node_ID, -1)

			Whole_Node_File += Node_File
			EncryptEncodingStr(Whole_Node_File, &EncText)

			_, err = fd.Write([]byte("COD$_"))
			if err != nil {
				log.Println(" Write err:", err)
				return DB_RET_FAIL, err
			}

			_, err = fd.Write([]byte(EncText))
			if err != nil {
				log.Println(" Write err:", err)
				return DB_RET_FAIL, err
			}

		}
		Rows.Close()
	}

	log.Println("EncText\n", EncText)
	return DB_RET_SUCC, nil
}
func WebServer_Update_Setting(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()

	var Settings SettingsInformation
	var err error

	log.Println("Update", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	r := json.NewDecoder(req.Body)
	err = r.Decode(&Settings)
	if err != io.EOF {
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Settings value:", Settings)
	}

	log.Println("783/Try Lock")
	UpdateLock.Lock()
	log.Println("785/Take Lock")
	err = SqliteDBUpdateSetting(Database, Settings)
	if err != nil {
		log.Println("Sqlite DB Update Fail:", err)
		UpdateLock.Unlock()
		return
	}
	_, err = GetProxyInfo(Database)
	if err != nil {
		log.Println("GetProxyInfo err:", err)
		UpdateLock.Unlock()
		return
	}
	_, err = GetNodeMode(Database)
	if err != nil {
		log.Println("GetNodeMode err:", err)
		UpdateLock.Unlock()
		return
	}

	_, err = UpdateConfigFile(Database)
	if err != nil {
		log.Println("UpdateConfigFile err:", err)
		UpdateLock.Unlock()
		return
	}

	_, err = UpdateNodeFile(Database)
	if err != nil {
		log.Println("UpdateNodeFile err:", err)
		UpdateLock.Unlock()
		return
	}

	UpdateLock.Unlock()
	return
	log.Println("791/Release Lock")
}

func WebServer_Setting(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()

	var QueryStr string
	var tmpl *template.Template
	var SetPageInfo SettingPageInfo
	var TempStr string
	var Rows *sql.Rows
	var err error

	log.Println("Setting", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	log.Println("812/Try Lock")
	UpdateLock.Lock()
	log.Println("814/Take Lock")

	if ControlServerFlag == 0 {
		if Node_Flag == Node_FLAG_CLIENT {
			TempStr = fmt.Sprintf("<li><a href=\"/statistics/client/\">Client Statistics</a></li>")
			SetPageInfo.NodeClientStatMenu = template.HTML(TempStr)
			SetPageInfo.NodeServerStatMenu = ""
		} else if Node_Flag == Node_FLAG_SERVER {
			TempStr = fmt.Sprintf("<li><a href=\"/statistics/server/\">Server Statistics</a></li>")
			SetPageInfo.NodeServerStatMenu = template.HTML(TempStr)
			SetPageInfo.NodeClientStatMenu = ""
			TempStr = fmt.Sprintf("<li><a href=\"/license/\">License Management</a></li>")
			SetPageInfo.LicenseManagement = template.HTML(TempStr)
		} else if Node_Flag == Node_FLAG_CLIENT_AND_SERVER {
			TempStr = fmt.Sprintf("<li><a href=\"/statistics/client/\">Client Statistics</a></li>")
			SetPageInfo.NodeClientStatMenu = template.HTML(TempStr)
			TempStr = fmt.Sprintf("<li><a href=\"/statistics/server/\">Server Statistics</a></li>")
			SetPageInfo.NodeServerStatMenu = template.HTML(TempStr)
		}

		QueryStr = fmt.Sprintf("SELECT * FROM Config_Global_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			UpdateLock.Unlock()
			return
		}

		for Rows.Next() {
			err = Rows.Scan(&SetPageInfo.Max_Conn, &SetPageInfo.Recv_Buffer_Size, &SetPageInfo.Send_Buffer_Size, &SetPageInfo.Timeout_Connect, &SetPageInfo.Timeout_Client, &SetPageInfo.Timeout_Server)
			if err != nil {
				log.Println(" data Scan error:", err)
				UpdateLock.Unlock()
				log.Println("838/Release Lock")
				return
			}
		}
		Rows.Close()

		QueryStr = fmt.Sprintf("SELECT * FROM Config_Logfile_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return
		}

		for Rows.Next() {
			err = Rows.Scan(&SetPageInfo.Disk_Limit, &SetPageInfo.Max_Size, &SetPageInfo.Log, &SetPageInfo.LogFileName, &SetPageInfo.Error, &SetPageInfo.ErrorFileName)
			if err != nil {
				log.Println(" data Scan error:", err)
				UpdateLock.Unlock()
				log.Println("851/Release Lock")
				return
			}
		}
		Rows.Close()

		QueryStr = fmt.Sprintf("SELECT Interval, Stat_Send_Flag, Control_Server_IP, Control_Server_Port, Control_Server_Send_Interval FROM Config_Statistics_Data")
		Rows, err = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			UpdateLock.Unlock()
			return
		}

		var StatSendFlag int
		var TempHTML HTMLType
		for Rows.Next() {
			err = Rows.Scan(&SetPageInfo.Interval, &StatSendFlag, &SetPageInfo.Control_Server_IP, &SetPageInfo.Control_Server_Port, &SetPageInfo.Control_Server_Send_Interval)
			if err != nil {
				log.Println(" data Scan error:", err)
				UpdateLock.Unlock()
				log.Println("866/Release Lock")
				return
			}
			if StatSendFlag == ENABLE {
				TempStr = "<option selected=\"selected\">Enable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.StatSelectHTMLList = append(SetPageInfo.StatSelectHTMLList, TempHTML)
				TempStr = "<option>Disable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.StatSelectHTMLList = append(SetPageInfo.StatSelectHTMLList, TempHTML)
			} else {
				TempStr = "<option selected=\"selected\">Disable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.StatSelectHTMLList = append(SetPageInfo.StatSelectHTMLList, TempHTML)
				TempStr = "<option>Enable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.StatSelectHTMLList = append(SetPageInfo.StatSelectHTMLList, TempHTML)
			}
		}
		Rows.Close()

		QueryStr = fmt.Sprintf("SELECT * FROM Config_Node_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			UpdateLock.Unlock()
			return
		}

		var UseBridge, UseEnc, UseChangeIP int
		for Rows.Next() {
			err = Rows.Scan(&UseBridge, &SetPageInfo.Buffer_Size, &UseEnc, &UseChangeIP)
			if err != nil {
				log.Println(" data Scan error:", err)
				UpdateLock.Unlock()
				log.Println("895/Release Lock")
				return
			}
			if UseBridge == ENABLE {
				TempStr = "<option selected=\"selected\">Enable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.ModeSelectHTMLList = append(SetPageInfo.ModeSelectHTMLList, TempHTML)
				TempStr = "<option>Disable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.ModeSelectHTMLList = append(SetPageInfo.ModeSelectHTMLList, TempHTML)
			} else {
				TempStr = "<option selected=\"selected\">Disable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.ModeSelectHTMLList = append(SetPageInfo.ModeSelectHTMLList, TempHTML)
				TempStr = "<option>Enable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.ModeSelectHTMLList = append(SetPageInfo.ModeSelectHTMLList, TempHTML)
			}

			if UseEnc == ENC_NONE {
				TempStr = "<option selected=\"selected\">None</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>AES_128</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>AES_256</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>RC4</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
			} else if UseEnc == ENC_AES128 {
				TempStr = "<option selected=\"selected\">AES_128</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>None</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>AES_256</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>RC4</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
			} else if UseEnc == ENC_AES256 {
				TempStr = "<option selected=\"selected\">AES_256</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>None</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>AES_128</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>RC4</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
			} else if UseEnc == ENC_RC4 {
				TempStr = "<option selected=\"selected\">RC4</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>None</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>AES_128</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
				TempStr = "<option>AES_256</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
			}

			if UseChangeIP == ENABLE {
				TempStr = "<option selected=\"selected\">Enable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.ChangeIPSelectHTMLList = append(SetPageInfo.ChangeIPSelectHTMLList, TempHTML)
				TempStr = "<option>Disable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.ChangeIPSelectHTMLList = append(SetPageInfo.ChangeIPSelectHTMLList, TempHTML)
			} else {
				TempStr = "<option selected=\"selected\">Disable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.ChangeIPSelectHTMLList = append(SetPageInfo.ChangeIPSelectHTMLList, TempHTML)
				TempStr = "<option>Enable</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.ChangeIPSelectHTMLList = append(SetPageInfo.ChangeIPSelectHTMLList, TempHTML)
			}
		}

		QueryStr = fmt.Sprintf("SELECT * FROM Config_NodeID_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			UpdateLock.Unlock()
			return
		}

		for Rows.Next() {
			err = Rows.Scan(&SetPageInfo.Node_ID)
			if err != nil {
				log.Println(" data Scan error:", err)
				UpdateLock.Unlock()
				log.Println("851/Release Lock")
				return
			}
		}
		Rows.Close()

		QueryStr = fmt.Sprintf("SELECT * FROM Config_KMS_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			UpdateLock.Unlock()
			return
		}

		for Rows.Next() {
			err = Rows.Scan(&SetPageInfo.KMS_Address, &SetPageInfo.KMS_Port)
			if err != nil {
				log.Println(" data Scan error:", err)
				UpdateLock.Unlock()
				log.Println("851/Release Lock")
				return
			}
		}
		Rows.Close()

		var FrontBack_Data_Count int

		QueryStr = fmt.Sprintf("SELECT COUNT(*) FROM Config_Frontend_Backend_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			UpdateLock.Unlock()
			return
		}

		for Rows.Next() {
			err = Rows.Scan(&FrontBack_Data_Count)
			if err != nil {
				log.Println(" data Scan error:", err)
				UpdateLock.Unlock()
				log.Println("995/Release Lock")
				return
			}
		}

		QueryStr = fmt.Sprintf("SELECT * FROM Config_Frontend_Backend_Data")
		Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			UpdateLock.Unlock()
			return
		}

		var Symbol_Name, Server string
		var Bind, Node_Mode int
		var OptionStr string
		var count int
		var BackendList, IDTagStart, IDTagEnd, HRTag, Button string

		var NICName, ProxyIP, ProxyPort string
		var NIC_Name_Len, ProxyIP_Len, ProxyPort_Len int

		for Rows.Next() {
			count++
			err = Rows.Scan(&Symbol_Name, &Bind, &Node_Mode, &Server)
			if err != nil {
				log.Println(" data Scan error:", err)
				UpdateLock.Unlock()
				log.Println("1018/Release Lock")
				return
			}

			SplitStr := strings.Split(Server, ",")
			log.Println(SplitStr)
			BackendList = ""
			for i := range SplitStr {
				SplitStr[i] = strings.TrimSpace(SplitStr[i])
				log.Println(SplitStr[i])

				NIC_Name_Len = strings.Index(SplitStr[i], "/")
				NICName = SplitStr[i][1:NIC_Name_Len]
				SplitStr[i] = SplitStr[i][NIC_Name_Len+1:]

				ProxyIP_Len = strings.Index(SplitStr[i], ":")
				ProxyIP = SplitStr[i][0:ProxyIP_Len]
				SplitStr[i] = SplitStr[i][ProxyIP_Len+1:]

				ProxyPort_Len = strings.Index(SplitStr[i], "\"")
				ProxyPort = SplitStr[i][0:ProxyPort_Len]

				OptionStr = ""
				for j := range NICInfoArray {
					if NICInfoArray[j].Name == NICName {
						OptionStr += fmt.Sprintf("<option selected=\"selected\" value=\"%s\">%s</option>", NICInfoArray[j].Name, NICInfoArray[j].Name)
					} else {
						OptionStr += fmt.Sprintf("<option value=\"%s\">%s</option>", NICInfoArray[j].Name, NICInfoArray[j].Name)
					}
				}

				BackendList += fmt.Sprintf("<tr><th>Server</th><td><select class=\"s100\" LAN_interface><option value=\"OS_Default\">OS Default</option>%s</select></td><td><input type=\"text\" class=\"s100\" placeholder=\"IP Address\" BackendIP reserve=\"ipv4\" min=\"7\" max=\"15\" msg=\"IP만 입력이 가능 합니다.\" group=\"all\" value=\"%s\"/></td><td><input type=\"text\" class=\"s100\" placeholder=\"Bind Port\"  BackendPort reserve=\"between\" min=\"1\" max=\"65535\" msg=\"PORT만 입력이 가능 합니다.\" group=\"all\" value=\"%s\"/></td></tr>", OptionStr, ProxyIP, ProxyPort)
			}

			if Node_Mode == Node_MODE_NONE {
				OptionStr = fmt.Sprintf("<option selected=\"selected\" value=\"%d\">선택해주세요</option>", Node_MODE_NONE)
				OptionStr += fmt.Sprintf("<option value=\"%d\">Node Client</option>", Node_MODE_CLIENT)
				if DeviceOSFlag == GENERAL_OS {
					OptionStr += fmt.Sprintf("<option value=\"%d\">Node Server</option>", Node_MODE_SERVER)
				}
			} else if Node_Mode == Node_MODE_CLIENT {
				OptionStr = fmt.Sprintf("<option value=\"%d\">선택해주세요</option>", Node_MODE_NONE)
				OptionStr += fmt.Sprintf("<option selected=\"selected\" value=\"%d\">Node Client</option>", Node_MODE_CLIENT)
				if DeviceOSFlag == GENERAL_OS {
					OptionStr += fmt.Sprintf("<option value=\"%d\">Node Server</option>", Node_MODE_SERVER)
				}
			} else {
				OptionStr = fmt.Sprintf("<option value=\"%d\">선택해주세요</option><option value=\"%d\">Node Client</option><option selected=\"selected\" value=\"%d\">Node Server</option>", Node_MODE_NONE, Node_MODE_CLIENT, Node_MODE_SERVER)
			}

			if count == 1 {
				IDTagStart = "<div id=\"Frontend\">"
				if FrontBack_Data_Count == 1 {
					IDTagEnd = "</div>"
				} else if FrontBack_Data_Count > 1 {
					IDTagEnd = ""
				}
				HRTag = ""
				Button = "<button type=\"button\" class=\"green\" act=\"btnFrontendAdd\">Add</button>"
			} else {
				IDTagStart = ""
				if count == FrontBack_Data_Count {
					IDTagEnd = "</div>"
				}
				HRTag = "<hr />"
				Button = "<button type=\"button\" act=\"btnFrontEndRemove\">Delete</button>"
			}
			// from here
			TempStr = fmt.Sprintf("%s<div data-SiteType=\"1\">%s<h2>Frontend<div>%s</div></h2><table class=\"input\"><colgroup><col width=\"250\"><col></colgroup><tbody><tr><th>Symbol</th><td><input type=\"text\" class=\"s100\" Frontendsymbol reserve=\"ko en number space length\" min=\"2\" max=\"32\" msg=\"글자 2 - 32 까지만 입력이 가능 합니다.\" group=\"all\" value=\"%s\"></td></tr><tr><th>Bind Port</th><td><input type=\"text\" class=\"s100\" FrontendPort reserve=\"between\" min=\"1\" max=\"65535\" msg=\"숫자 1 - 65535 까지만 입력이 가능 합니다.\" group=\"all\" value=\"%d\"/></td></tr><tr><th>Node Mode</th><td><select Node_Mode>%s</select><button type=\"button\" act=\"btnFrontendConfirm\" >Confirm</button></td></tr></tbody></table>", IDTagStart, HRTag, Button, Symbol_Name, Bind, OptionStr)

			if Node_Mode == Node_MODE_CLIENT {
				TempStr += fmt.Sprintf("<div data-SiteType=\"2\" Node_mode=\"%d\"><h2>Backend<div><button type=\"button\" act=\"btnBackEndAdd\" class=\"green\">+</button><button type=\"button\" act=\"btnBackEndDelete\">-</button></div></h2><table class=\"input\"><colgroup><col width=\"250\"><col width=\"210\"><col><col width=\"150\"></colgroup><tbody>%s</tbody></table></div></div>%s", Node_MODE_CLIENT, BackendList, IDTagEnd)
			} else if Node_Mode == Node_MODE_SERVER {
				TempStr += fmt.Sprintf("<div data-SiteType=\"2\" Node_mode=\"%d\"><h2>Backend</h2><table class=\"input\"><colgroup><col width=\"250\"><col width=\"210\"><col><col width=\"150\"></colgroup><tbody>%s</tbody></table></div></div>%s", Node_MODE_SERVER, BackendList, IDTagEnd)
			}

			TempHTML.Value_HTML = template.HTML(TempStr)
			SetPageInfo.FrontBackHTMLList = append(SetPageInfo.FrontBackHTMLList, TempHTML)
		}
		Rows.Close()

		NodeModeStr := fmt.Sprintf("<option selected=\"selected\" value=\"%d\">선택해주세요</option>", Node_MODE_NONE)
		NodeModeStr += fmt.Sprintf("<option value=\"%d\">Node Client</option>", Node_MODE_CLIENT)
		if DeviceOSFlag == GENERAL_OS {
			NodeModeStr += fmt.Sprintf("<option value=\"%d\">Node Server</option>", Node_MODE_SERVER)
		}
		SetPageInfo.FrontendNodeMode = template.HTML(NodeModeStr)

		if count == 0 {
			TempStr = fmt.Sprintf("<div id=\"Frontend\"><div data-SiteType=\"1\"><h2>Frontend<div><button type=\"button\" class=\"green\" act=\"btnFrontendAdd\">Add</button></div></h2><table class=\"input\"><colgroup><col width=\"250\"><col></colgroup><tbody><tr><th>Symbol</th><td><input type=\"text\" class=\"s100\" Frontendsymbol reserve=\"ko en number space length\" min=\"2\" max=\"32\" msg=\"글자 2 - 32 까지만 입력이 가능 합니다.\" group=\"all\" value=\"\"></td></tr><tr><th>Bind Port</th><td><input type=\"text\" class=\"s100\" FrontendPort reserve=\"between\" min=\"1\" max=\"65535\" msg=\"숫자 1 - 65535 까지만 입력이 가능 합니다.\" group=\"all\" value=\"\"/></td></tr><tr><th>Node Mode</th><td><select Node_Mode>%s</select><button type=\"button\" act=\"btnFrontendConfirm\" >Confirm</button></td></tr></tbody></table></div></div>", NodeModeStr)
			TempHTML.Value_HTML = template.HTML(TempStr)
			SetPageInfo.FrontBackHTMLList = append(SetPageInfo.FrontBackHTMLList, TempHTML)
		}

		for i := 0; i < len(NICInfoArray); i++ {
			var NICNAMEHTML HTMLType

			TempStr := fmt.Sprintf("<option>%s</option>", NICInfoArray[i].Name)
			NICNAMEHTML.Value_HTML = template.HTML(TempStr)
			SetPageInfo.NICNAMEHTMLList = append(SetPageInfo.NICNAMEHTMLList, NICNAMEHTML)
		}

		tmpl, err = template.ParseFiles("./pages/Node_Setting.html")
		if err != nil {
			log.Println("failed to template.ParseFiles")
			UpdateLock.Unlock()
			log.Println("1124/Release Lock")
			return
		}
		tmpl.Execute(w, SetPageInfo)

		UpdateLock.Unlock()
		log.Println("1130/Release Lock")
	}
}

func WebServer_Forbidden(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	http.Error(w, "Forbidden", http.StatusForbidden)
	return
}

func WebServer_Server_Statistics(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()

	var tmpl *template.Template
	var StatInfo ServerStatisticInfo
	var PageNumInfo PageNumInfo
	var StatPageInfo ServerStatisticPageInfo
	var CommonIDs string
	var CommonRows *sql.Rows
	var CommonRowsCount, PageIndexStart, LastPageNumber, PageNumber, SortNumber, PrevPageNumber, NextPageNumber, PageCount int
	var SortTime, SortBridgeID, SortProxyIP, SortNodeIP, SortServerIP, SortClientIP int
	var FirstStatInfoIndex, TotalInbound, TotalOutbound int
	var err error
	var OrderBy string
	var Params string
	var QueryStr, QueryCommonCondition, QueryDataCondition, StartTime, EndTime, ClientIP, NICIP, NICPort, BridgeID, ProxyIP, ServerIP, ServerPort string
	var TempStr string
	var ConditionArray []interface{}
	var ConditionCount int

	log.Println("Server Statistics", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}
	if ControlServerFlag == 0 {

		if Node_Flag == Node_FLAG_NONE {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		} else if Node_Flag == Node_FLAG_CLIENT {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		} else if Node_Flag == Node_FLAG_SERVER {
			TempStr = fmt.Sprintf("<li class=\"current\"><a href=\"/statistics/server/\">Server Statistics</a></li>")
			StatPageInfo.NodeServerStatMenu = template.HTML(TempStr)
			StatPageInfo.NodeClientStatMenu = ""
			TempStr = fmt.Sprintf("<li><a href=\"/license/\">License Management</a></li>")
			StatPageInfo.LicenseManagement = template.HTML(TempStr)
		} else if Node_Flag == Node_FLAG_CLIENT_AND_SERVER {
			TempStr = fmt.Sprintf("<li><a href=\"/statistics/client/\">Client Statistics</a></li>")
			StatPageInfo.NodeClientStatMenu = template.HTML(TempStr)
			TempStr = fmt.Sprintf("<li class=\"current\"><a href=\"/statistics/server/\">Server Statistics</a></li>")
			StatPageInfo.NodeServerStatMenu = template.HTML(TempStr)
		}

		Param_PageNumber, ok := req.URL.Query()["page_num"]
		if !ok || len(Param_PageNumber) < 1 {
			WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
			return
		}

		Param_Sort, ok := req.URL.Query()["sort"]
		if !ok || len(Param_Sort) < 1 {
			WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
			return
		}

		if req.Method == "GET" {
			Param_StartTime, ok := req.URL.Query()["stime"]
			if ok {
				StartTime = fmt.Sprintf("%s", Param_StartTime)
				StartTime = strings.Replace(StartTime, "[", "", -1)
				StartTime = strings.Replace(StartTime, "]", "", -1)
				StartTime = strings.TrimSpace(StartTime)
				if Time_Validate_Check(StartTime) == false {
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchStartTime = StartTime

				Param_EndTime, ok := req.URL.Query()["etime"]
				if ok {
					EndTime = fmt.Sprintf("%s", Param_EndTime)
					EndTime = strings.Replace(EndTime, "[", "", -1)
					EndTime = strings.Replace(EndTime, "]", "", -1)
					EndTime = strings.TrimSpace(EndTime)
					if Time_Validate_Check(EndTime) == false {
						WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
						return
					}

					StatPageInfo.SearchEndTime = EndTime
				} else {
					EndTime, _ = SqliteDBGetServerDate(Database, 0)
					StatPageInfo.SearchEndTime = EndTime
				}
			} else {
				Param_EndTime, ok := req.URL.Query()["etime"]
				if ok {
					EndTime = fmt.Sprintf("%s", Param_EndTime)
					EndTime = strings.Replace(EndTime, "[", "", -1)
					EndTime = strings.Replace(EndTime, "]", "", -1)
					EndTime = strings.TrimSpace(EndTime)
					if Time_Validate_Check(EndTime) == false {
						WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
						return
					}
					StatPageInfo.SearchEndTime = EndTime

					StartTime, _ = SqliteDBGetServerDate(Database, 1)
					StatPageInfo.SearchStartTime = StartTime
				}
			}

			Param_ProxyIP, ok := req.URL.Query()["pip"]
			if ok {
				ProxyIP = fmt.Sprintf("%s", Param_ProxyIP)
				ProxyIP = strings.Replace(ProxyIP, "[", "", -1)
				ProxyIP = strings.Replace(ProxyIP, "]", "", -1)
				ProxyIP = strings.TrimSpace(ProxyIP)
				if IP_Validate_Check(ProxyIP) == false {
					log.Println("Invalid ProxyIP")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchProxyIP = ProxyIP
			}
			for i := 0; i < len(ProxyIPStrArray); i++ {
				var ProxyIPHTML ProxyIPHTML

				if len(ProxyIP) > 0 && ProxyIPStrArray[i] == ProxyIP {
					TempStr = fmt.Sprintf("<option selected=\"selected\">%s</option>", ProxyIPStrArray[i])
				} else {
					TempStr = fmt.Sprintf("<option>%s</option>", ProxyIPStrArray[i])
				}
				ProxyIPHTML.ProxyIP_HTML = template.HTML(TempStr)
				StatPageInfo.ProxyIPHTMLList = append(StatPageInfo.ProxyIPHTMLList, ProxyIPHTML)
			}

			Param_NICIP, ok := req.URL.Query()["nip"]
			if ok {
				NICIP = fmt.Sprintf("%s", Param_NICIP)
				NICIP = strings.Replace(NICIP, "[", "", -1)
				NICIP = strings.Replace(NICIP, "]", "", -1)
				NICIP = strings.TrimSpace(NICIP)
				if IP_Validate_Check(NICIP) == false {
					log.Println("Invalid NICIP")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchNICIP = NICIP
			}
			for i := 0; i < len(NICInfoArray); i++ {
				var NICIPHTML NICIPHTML

				if len(NICIP) > 0 && NICInfoArray[i].IP == NICIP {
					TempStr = fmt.Sprintf("<option selected=\"selected\">%s</option>", NICInfoArray[i].IP)
				} else {
					TempStr = fmt.Sprintf("<option>%s</option>", NICInfoArray[i].IP)
				}
				NICIPHTML.NICIP_HTML = template.HTML(TempStr)
				StatPageInfo.NICIPHTMLList = append(StatPageInfo.NICIPHTMLList, NICIPHTML)
			}

			Param_NICPort, ok := req.URL.Query()["nport"]
			if ok {
				NICPort = fmt.Sprintf("%s", Param_NICPort)
				NICPort = strings.Replace(NICPort, "[", "", -1)
				NICPort = strings.Replace(NICPort, "]", "", -1)
				NICPort = strings.TrimSpace(NICPort)
				if Port_Validate_Check(NICPort) == false {
					log.Println("Invalid NICPort")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchNICPort = NICPort
			}

			Param_ServerIP, ok := req.URL.Query()["sip"]
			if ok {
				ServerIP = fmt.Sprintf("%s", Param_ServerIP)
				ServerIP = strings.Replace(ServerIP, "[", "", -1)
				ServerIP = strings.Replace(ServerIP, "]", "", -1)
				ServerIP = strings.TrimSpace(ServerIP)
				StatPageInfo.SearchServerIP = ServerIP
				if IP_Validate_Check(ServerIP) == false {
					log.Println("Invalid ServerIP")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}

			}

			Param_ServerPort, ok := req.URL.Query()["sport"]
			if ok {
				ServerPort = fmt.Sprintf("%s", Param_ServerPort)
				ServerPort = strings.Replace(ServerPort, "[", "", -1)
				ServerPort = strings.Replace(ServerPort, "]", "", -1)
				ServerPort = strings.TrimSpace(ServerPort)
				if Port_Validate_Check(ServerPort) == false {
					log.Println("Invalid ServerPort")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchServerPort = ServerPort
			}

			Param_ClientIP, ok := req.URL.Query()["cip"]
			if ok {
				ClientIP = fmt.Sprintf("%s", Param_ClientIP)
				ClientIP = strings.Replace(ClientIP, "[", "", -1)
				ClientIP = strings.Replace(ClientIP, "]", "", -1)
				if IP_Validate_Check(ClientIP) == false {
					log.Println("Invalid ClientIP")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}

				ClientIP = strings.TrimSpace(ClientIP)

				TempStr = fmt.Sprintf("<div class=\"item\"><span class=\"title\">Client</span><span class=\"condition\"><input type=\"text\" name=\"client_ip\" style=\"width: 120px\" value=\"%s\" onBlur=\"ipCheckValidation(this);\"/></span></div>", ClientIP)
				StatPageInfo.SearchClientIP = template.HTML(TempStr)
			} else {
				if Node_Change_Client_IP_Mode == ENABLE {
					TempStr = fmt.Sprintf("<div class=\"item\"><span class=\"title\">Client</span><span class=\"condition\"><input type=\"text\" name=\"client_ip\" style=\"width: 120px\" value=\"\" onBlur=\"ipCheckValidation(this);\"/></span></div>")
					StatPageInfo.SearchClientIP = template.HTML(TempStr)
				}
			}
		} else {
			req.ParseForm()

			StartTime = fmt.Sprintf("%s", req.Form["start_time"])
			StartTime = strings.Replace(StartTime, "[", "", -1)
			StartTime = strings.Replace(StartTime, "]", "", -1)
			StartTime = strings.TrimSpace(StartTime)

			EndTime = fmt.Sprintf("%s", req.Form["end_time"])
			EndTime = strings.Replace(EndTime, "[", "", -1)
			EndTime = strings.Replace(EndTime, "]", "", -1)
			EndTime = strings.TrimSpace(EndTime)

			ProxyIP = fmt.Sprintf("%s", req.Form["proxy_ip"])
			ProxyIP = strings.Replace(ProxyIP, "[", "", -1)
			ProxyIP = strings.Replace(ProxyIP, "]", "", -1)
			ProxyIP = strings.TrimSpace(ProxyIP)

			NICIP = fmt.Sprintf("%s", req.Form["nic_ip"])
			NICIP = strings.Replace(NICIP, "[", "", -1)
			NICIP = strings.Replace(NICIP, "]", "", -1)
			NICIP = strings.TrimSpace(NICIP)

			NICPort = fmt.Sprintf("%s", req.Form["nic_port"])
			NICPort = strings.Replace(NICPort, "[", "", -1)
			NICPort = strings.Replace(NICPort, "]", "", -1)
			NICPort = strings.TrimSpace(NICPort)

			ServerIP = fmt.Sprintf("%s", req.Form["server_ip"])
			ServerIP = strings.Replace(ServerIP, "[", "", -1)
			ServerIP = strings.Replace(ServerIP, "]", "", -1)
			ServerIP = strings.TrimSpace(ServerIP)

			ServerPort = fmt.Sprintf("%s", req.Form["server_port"])
			ServerPort = strings.Replace(ServerPort, "[", "", -1)
			ServerPort = strings.Replace(ServerPort, "]", "", -1)
			ServerPort = strings.TrimSpace(ServerPort)

			ClientIP = fmt.Sprintf("%s", req.Form["client_ip"])
			ClientIP = strings.Replace(ClientIP, "[", "", -1)
			ClientIP = strings.Replace(ClientIP, "]", "", -1)
			ClientIP = strings.TrimSpace(ClientIP)
		}

		if len(StartTime) > 0 {
			Params += fmt.Sprintf("&stime=%s", StartTime)
		}

		if len(EndTime) > 0 {
			Params += fmt.Sprintf("&etime=%s", EndTime)
		}

		if len(StartTime) > 0 && len(EndTime) > 0 {
			QueryCommonCondition += fmt.Sprintf("AND (Time BETWEEN ? AND ?)")
			ConditionArray = append(ConditionArray, StartTime, EndTime)
			ConditionCount += 2

		}

		if len(ProxyIP) > 0 && ProxyIP != "All" {
			Params += fmt.Sprintf("&pip=%s", ProxyIP)
			if StrtoIP(ProxyIP) != 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Proxy_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ProxyIP)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Proxy_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ProxyIP+"%")
				ConditionCount++

			}
		}

		if len(NICIP) > 0 && NICIP != "All" {
			Params += fmt.Sprintf("&nip=%s", NICIP)
			if StrtoIP(NICIP) != 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, NICIP)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, NICIP+"%")
				ConditionCount++

			}
		}

		if len(NICPort) > 0 {
			Params += fmt.Sprintf("&nport=%s", NICPort)
			TempInt, _ := strconv.Atoi(NICPort)
			if TempInt > 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Node_Listen_Port=?)")
			}
			ConditionArray = append(ConditionArray, TempInt)
			ConditionCount++

		}

		if len(ServerIP) > 0 {
			Params += fmt.Sprintf("&sip=%s", ServerIP)
			if StrtoIP(NICIP) != 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Server_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ServerIP)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Server_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ServerIP+"%")
				ConditionCount++

			}
		}

		if len(ServerPort) > 0 {
			Params += fmt.Sprintf("&sport=%s", ServerPort)
			TempInt, _ := strconv.Atoi(ServerPort)
			if TempInt > 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Server_Listen_Port=?)")
			}
			ConditionArray = append(ConditionArray, TempInt)
			ConditionCount++

		}

		if len(ClientIP) > 0 {
			Params += fmt.Sprintf("&cip=%s", ClientIP)
			if StrtoIP(NICIP) != 0 {
				QueryDataCondition += fmt.Sprintf("AND (Client_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ClientIP)
				ConditionCount++

			} else {
				QueryDataCondition += fmt.Sprintf("AND (Client_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ClientIP+"%")
				ConditionCount++

			}
		}

		if req.Method == "POST" {
			StatURL := "/statistics/server/?page_num=1&sort=0"
			if len(Params) > 0 {
				StatURL += Params
			}

			WebServer_Redirect(w, req, StatURL)
			return
		}

		PageNumberStr := fmt.Sprintf("%s", Param_PageNumber)
		PageNumberStr = strings.Replace(PageNumberStr, "[", "", -1)
		PageNumberStr = strings.Replace(PageNumberStr, "]", "", -1)

		SortStr := fmt.Sprintf("%s", Param_Sort)
		SortStr = strings.Replace(SortStr, "[", "", -1)
		SortStr = strings.Replace(SortStr, "]", "", -1)

		PageNumber, err = strconv.Atoi(PageNumberStr)
		if err != nil {
			log.Println("failed to strconv.Atoi PageNamber")
			return
		}
		log.Println("alskdjflksajdflkjsalfdkjsladkfjlaskdjflksjadfl:", PageNumber)
		SortNumber, err = strconv.Atoi(SortStr)
		if err != nil {
			log.Println("failed to strconv.Atoi")
			return
		}

		DESC_Dir := "▼"
		ASC_Dir := "▲"
		NONE_Dir := "-"

		SortTime = SortTime_ASC
		SortProxyIP = SortProxyIP_ASC
		SortNodeIP = SortNodeIP_ASC
		SortServerIP = SortServerIP_ASC
		SortClientIP = SortClientIP_ASC

		SortTimeDir := NONE_Dir
		SortProxyIPDir := NONE_Dir
		SortNodeIPDir := NONE_Dir
		SortServerIPDir := NONE_Dir
		SortClientIPDir := NONE_Dir

		switch SortNumber {
		case SortTime_ASC:
			SortTime = SortTime_DESC
			SortTimeDir = DESC_Dir

			OrderBy = "Time DESC"
		case SortProxyIP_ASC:
			SortProxyIP = SortProxyIP_DESC
			SortProxyIPDir = DESC_Dir

			OrderBy = "Proxy_IP_INT DESC"
		case SortNodeIP_ASC:
			SortNodeIP = SortNodeIP_DESC
			SortNodeIPDir = DESC_Dir

			OrderBy = "Node_IP_INT DESC"
		case SortServerIP_ASC:
			SortServerIP = SortServerIP_DESC
			SortServerIPDir = DESC_Dir

			OrderBy = "Server_IP_INT DESC"
		case SortClientIP_ASC:
			SortClientIP = SortClientIP_DESC
			SortClientIPDir = DESC_Dir

			OrderBy = "Time DESC, B.Client_IP_INT DESC"
		case SortTime_DESC:
			SortTime = SortTime_ASC
			SortTimeDir = ASC_Dir

			OrderBy = "Time ASC"
		case SortProxyIP_DESC:
			SortProxyIP = SortProxyIP_ASC
			SortProxyIPDir = ASC_Dir

			OrderBy = "Proxy_IP_INT ASC"
		case SortNodeIP_DESC:
			SortNodeIP = SortNodeIP_ASC
			SortNodeIPDir = ASC_Dir

			OrderBy = "Node_IP_INT ASC"
		case SortServerIP_DESC:
			SortServerIP = SortServerIP_ASC
			SortServerIPDir = ASC_Dir

			OrderBy = "Server_IP_INT ASC"
		case SortClientIP_DESC:
			SortClientIP = SortClientIP_ASC
			SortClientIPDir = ASC_Dir

			OrderBy = "Time DESC, B.Client_IP_INT ASC"
		}

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Collection Time %s</a></th>", SortTime, Params, SortTimeDir)
		StatPageInfo.SortTime = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Proxy IP %s</a></th>", SortProxyIP, Params, SortProxyIPDir)
		StatPageInfo.SortProxyIP = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Node Server IP %s</a></th>", SortNodeIP, Params, SortNodeIPDir)
		StatPageInfo.SortNodeIP = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Server IP %s</a></th>", SortServerIP, Params, SortServerIPDir)
		StatPageInfo.SortServerIP = template.HTML(TempStr)

		if Node_Change_Client_IP_Mode == ENABLE {
			TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Client IP %s</a></th>", SortClientIP, Params, SortClientIPDir)
			StatPageInfo.SortClientIP = template.HTML(TempStr)
		}

		tmpl, err = template.ParseFiles("./pages/Node_Server_Statistics.html")
		if err != nil {
			log.Println("failed to template.ParseFiles")
			return
		}

		NextRowOffset := (PageNumber - 1) * RowCountPerPage

		QueryStr = fmt.Sprintf("SELECT COUNT(DISTINCT A.ID) FROM (SELECT * FROM Server_Statistics_Common GROUP BY Time, Proxy_IP_INT, Node_IP_INT, Node_Listen_Port, Server_IP_INT) as A JOIN Server_Statistics_Data as B ON B.ID = A.ID WHERE 1=1 %s AND 1=1 %s", QueryCommonCondition, QueryDataCondition)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}

		for CommonRows.Next() {
			err := CommonRows.Scan(&CommonRowsCount)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}
		}
		CommonRows.Close()

		PageCount = int(math.Ceil(float64(CommonRowsCount) / float64(RowCountPerPage)))
		if PageNumber < PageCount {
			NextPageNumber = PageNumber + 1
		} else {
			NextPageNumber = PageCount
		}

		CommonID := 0
		PrevCommonID := 0
		OverlapID := 0

		QueryStr = fmt.Sprintf("SELECT distinct A.ID  FROM ( SELECT * FROM Server_Statistics_Common WHERE 1=1 %s GROUP BY Time, Proxy_IP_INT, Node_IP_INT, Node_Listen_Port, Server_IP_INT) A JOIN ( SELECT * FROM Server_Statistics_Data WHERE 1=1 %s) B ON A.ID = B.ID ORDER BY %s LIMIT %d OFFSET %d", QueryCommonCondition, QueryDataCondition, OrderBy, RowCountPerPage, NextRowOffset)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}
		for CommonRows.Next() {
			err := CommonRows.Scan(&CommonID)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}
			if len(CommonIDs) > 0 {
				CommonIDs += ","
			}
			CommonIDs += fmt.Sprintf("%d", CommonID)
		}
		CommonRows.Close()

		if len(CommonIDs) == 0 {
			tmpl.Execute(w, StatPageInfo)
			return
		}

		data_group_id := 0
		data_first := 0
		index := 0

		QueryStr = fmt.Sprintf("SELECT * FROM ( SELECT * FROM Server_Statistics_Common WHERE 1=1 %s GROUP BY Time, Proxy_IP_INT, Node_IP_INT, Node_Listen_Port, Server_IP_INT ) A JOIN ( SELECT * FROM Server_Statistics_Data WHERE 1=1 %s) B ON A.ID = B.ID WHERE A.ID IN (%s) ORDER BY %s", QueryCommonCondition, QueryDataCondition, CommonIDs, OrderBy)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}
		for CommonRows.Next() {
			err := CommonRows.Scan(&CommonID, &StatInfo.StatCommon.Time, &StatInfo.StatCommon.Bridge_ID_Str, &StatInfo.StatCommon.Proxy_IP_Int, &StatInfo.StatCommon.Proxy_IP_Str, &StatInfo.StatCommon.Node_IP_Int, &StatInfo.StatCommon.Node_IP_Str, &StatInfo.StatCommon.Node_Listen_Port, &StatInfo.StatCommon.Server_IP_Int, &StatInfo.StatCommon.Server_IP_Str, &StatInfo.StatCommon.Server_Listen_Port, &OverlapID, &CommonID, &StatInfo.StatData.Client_IP_Int, &StatInfo.StatData.Client_IP_Str, &StatInfo.StatData.Inbound, &StatInfo.StatData.Outbound)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}

			if PrevCommonID == 0 {
				PrevCommonID = CommonID
				data_first = 1
			} else if PrevCommonID != CommonID {
				StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound = TotalInbound
				StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound = TotalOutbound

				TempStr = fmt.Sprintf("<td>%d</td>", StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound)
				StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound_HTML = template.HTML(TempStr)
				TempStr = fmt.Sprintf("<td>%d</td>", StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound)
				StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound_HTML = template.HTML(TempStr)

				TotalInbound = 0
				TotalOutbound = 0

				data_first = 1
				PrevCommonID = CommonID
				data_group_id++
			}

			StatInfo.StatCommon.TrInfo.DataGroupID = strconv.Itoa(data_group_id)

			if data_first == 1 {
				StatInfo.StatCommon.TrInfo.DataFirst = strconv.Itoa(data_first)
				StatInfo.StatCommon.TrInfo.Style = "view"
				data_first = 0
				if Node_Change_Client_IP_Mode == ENABLE {
					TempStr = fmt.Sprintf("<td></td>")
					StatInfo.StatData.Client_IP_HTML = template.HTML(TempStr)
				} else {
					StatInfo.StatData.Client_IP_HTML = ""
				}

				StatPageInfo.StatInfo = append(StatPageInfo.StatInfo, StatInfo)
				FirstStatInfoIndex = index
				index++
			}

			if Node_Change_Client_IP_Mode == ENABLE {
				TempStr = fmt.Sprintf("<td>%d</td>", StatInfo.StatData.Inbound)
				StatInfo.StatData.Inbound_HTML = template.HTML(TempStr)
				TempStr = fmt.Sprintf("<td>%d</td>", StatInfo.StatData.Outbound)
				StatInfo.StatData.Outbound_HTML = template.HTML(TempStr)

			} else {
				StatInfo.StatData.Inbound_HTML = ""
				StatInfo.StatData.Outbound_HTML = ""
			}

			TotalInbound += StatInfo.StatData.Inbound
			TotalOutbound += StatInfo.StatData.Outbound
			StatInfo.StatCommon.TrInfo.DataFirst = strconv.Itoa(data_first)
			StatInfo.StatCommon.TrInfo.Style = "none"
			if Node_Change_Client_IP_Mode == ENABLE {
				TempStr = fmt.Sprintf("<td>%s</td>", StatInfo.StatData.Client_IP_Str)
				StatInfo.StatData.Client_IP_HTML = template.HTML(TempStr)
			} else {
				StatInfo.StatData.Client_IP_HTML = ""
			}

			StatPageInfo.StatInfo = append(StatPageInfo.StatInfo, StatInfo)
			index++
		}
		CommonRows.Close()
		StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound = TotalInbound
		StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound = TotalOutbound
		TempStr = fmt.Sprintf("<td>%d</td>", StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound)
		StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound_HTML = template.HTML(TempStr)
		TempStr = fmt.Sprintf("<td>%d</td>", StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound)
		StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound_HTML = template.HTML(TempStr)

		if PageNumber > 1 {
			PrevPageNumber = PageNumber - 1
		} else {
			PrevPageNumber = 1
		}

		TempStr = fmt.Sprintf("/statistics/server/?page_num=%d&sort=%d%s", 1, SortNumber, Params)
		StatPageInfo.FirstPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/server/?page_num=%d&sort=%d%s", PrevPageNumber, SortNumber, Params)
		StatPageInfo.PrevPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/server/?page_num=%d&sort=%d%s", NextPageNumber, SortNumber, Params)
		StatPageInfo.NextPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/server/?page_num=%d&sort=%d%s", PageCount, SortNumber, Params)
		StatPageInfo.LastPage = template.HTML(TempStr)

		PageIndexStart = (((PageNumber - 1) / MaxPageCountInPage) * MaxPageCountInPage) + 1

		if PageCount > MaxPageCountInPage {
			LastPageNumber = PageIndexStart + (MaxPageCountInPage - 1)
		} else {
			LastPageNumber = PageCount
		}

		if LastPageNumber > PageCount {
			LastPageNumber = PageCount
		}

		for page_index := PageIndexStart; page_index <= LastPageNumber; page_index++ {
			PageNumInfo.PageNum = page_index
			if PageNumInfo.PageNum == PageNumber {
				PageNumInfo.TagStart = "<strong>"
				PageNumInfo.TagEnd = "</strong>"
			} else {
				TempTag := fmt.Sprintf("<a href=\"/statistics/server/?page_num=%d&sort=%d%s\">", PageNumInfo.PageNum, SortNumber, Params)
				PageNumInfo.TagStart = template.HTML(TempTag)
				PageNumInfo.TagEnd = "</a>"
			}

			StatPageInfo.PageNumInfo = append(StatPageInfo.PageNumInfo, PageNumInfo)
		}
	} else {

		TempStr = fmt.Sprintf("<li><a href=\"/statistics/client/\">Client Statistics</a></li>")
		StatPageInfo.NodeClientStatMenu = template.HTML(TempStr)
		TempStr = fmt.Sprintf("<li class=\"current\"><a href=\"/statistics/server/\">Server Statistics</a></li>")
		StatPageInfo.NodeServerStatMenu = template.HTML(TempStr)

		Param_PageNumber, ok := req.URL.Query()["page_num"]
		if !ok || len(Param_PageNumber) < 1 {
			log.Println("Parma_PageNumber:", Param_PageNumber)
			WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
			return
		}

		Param_Sort, ok := req.URL.Query()["sort"]
		if !ok || len(Param_Sort) < 1 {
			log.Println("Param_Sort:", Param_Sort)
			WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
			return
		}

		if req.Method == "GET" {

			log.Println("here is Server Statistics Get Type !!!! ")
			Param_StartTime, ok := req.URL.Query()["stime"]
			if ok {
				StartTime = fmt.Sprintf("%s", Param_StartTime)
				StartTime = strings.Replace(StartTime, "[", "", -1)
				StartTime = strings.Replace(StartTime, "]", "", -1)
				StartTime = strings.TrimSpace(StartTime)

				if Time_Validate_Check(StartTime) == false {
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchStartTime = StartTime

				Param_EndTime, ok := req.URL.Query()["etime"]
				if ok {
					EndTime = fmt.Sprintf("%s", Param_EndTime)
					EndTime = strings.Replace(EndTime, "[", "", -1)
					EndTime = strings.Replace(EndTime, "]", "", -1)
					EndTime = strings.TrimSpace(EndTime)
					if Time_Validate_Check(EndTime) == false {
						WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
						return
					}
					StatPageInfo.SearchEndTime = EndTime
				} else {
					EndTime = MariaDBGetServerDate(Database, 0)
					StatPageInfo.SearchEndTime = EndTime
				}
			} else {
				Param_EndTime, ok := req.URL.Query()["etime"]

				if ok {
					EndTime = fmt.Sprintf("%s", Param_EndTime)
					EndTime = strings.Replace(EndTime, "[", "", -1)
					EndTime = strings.Replace(EndTime, "]", "", -1)
					EndTime = strings.TrimSpace(EndTime)
					if Time_Validate_Check(EndTime) == false {
						WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
						return
					}

					StatPageInfo.SearchEndTime = EndTime

					StartTime = MariaDBGetServerDate(Database, 1)
					StatPageInfo.SearchStartTime = StartTime
				}
			}

			Param_BridgeID, ok := req.URL.Query()["Bridgeid"]
			if ok {
				BridgeID = fmt.Sprintf("%s", Param_BridgeID)
				BridgeID = strings.Replace(BridgeID, "[", "", -1)
				BridgeID = strings.Replace(BridgeID, "]", "", -1)
				BridgeID = strings.TrimSpace(BridgeID)
				if UUID_Validate_Check(BridgeID) == false {
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchBridgeID = BridgeID
			}

			Param_ProxyIP, ok := req.URL.Query()["pip"]
			if ok {
				ProxyIP = fmt.Sprintf("%s", Param_ProxyIP)
				ProxyIP = strings.Replace(ProxyIP, "[", "", -1)
				ProxyIP = strings.Replace(ProxyIP, "]", "", -1)
				ProxyIP = strings.TrimSpace(ProxyIP)
				if IP_Validate_Check(ProxyIP) == false {
					log.Println("Invalid ProxyIP")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchProxyIP = ProxyIP
			}

			Param_NICIP, ok := req.URL.Query()["nip"]
			if ok {
				NICIP = fmt.Sprintf("%s", Param_NICIP)
				NICIP = strings.Replace(NICIP, "[", "", -1)
				NICIP = strings.Replace(NICIP, "]", "", -1)
				NICIP = strings.TrimSpace(NICIP)
				if IP_Validate_Check(NICIP) == false {
					log.Println("Invalid NICIP")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchNICIP = NICIP
			}

			Param_NICPort, ok := req.URL.Query()["nport"]
			if ok {
				NICPort = fmt.Sprintf("%s", Param_NICPort)
				NICPort = strings.Replace(NICPort, "[", "", -1)
				NICPort = strings.Replace(NICPort, "]", "", -1)
				NICPort = strings.TrimSpace(NICPort)
				if Port_Validate_Check(NICPort) == false {
					log.Println("Invalid NICPort")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchNICPort = NICPort
			}

			Param_ServerIP, ok := req.URL.Query()["sip"]
			if ok {
				ServerIP = fmt.Sprintf("%s", Param_ServerIP)
				ServerIP = strings.Replace(ServerIP, "[", "", -1)
				ServerIP = strings.Replace(ServerIP, "]", "", -1)
				ServerIP = strings.TrimSpace(ServerIP)
				if IP_Validate_Check(ServerIP) == false {
					log.Println("Invalid ServerIP")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchServerIP = ServerIP
			}

			Param_ServerPort, ok := req.URL.Query()["sport"]
			if ok {
				ServerPort = fmt.Sprintf("%s", Param_ServerPort)
				ServerPort = strings.Replace(ServerPort, "[", "", -1)
				ServerPort = strings.Replace(ServerPort, "]", "", -1)
				ServerPort = strings.TrimSpace(ServerPort)
				if Port_Validate_Check(ServerPort) == false {
					log.Println("Invalid ServerPort")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchServerPort = ServerPort
			}

			Param_ClientIP, ok := req.URL.Query()["cip"]
			if ok {
				ClientIP = fmt.Sprintf("%s", Param_ClientIP)
				ClientIP = strings.Replace(ClientIP, "[", "", -1)
				ClientIP = strings.Replace(ClientIP, "]", "", -1)
				if IP_Validate_Check(ClientIP) == false {
					log.Println("Invalid ClientIP")
					WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
					return
				}
				ClientIP = strings.TrimSpace(ClientIP)

				TempStr = fmt.Sprintf("<div class=\"item\"><span class=\"title\">Client</span><span class=\"condition\"><input type=\"text\" name=\"client_ip\" style=\"width: 120px\" value=\"%s\" onBlur=\"ipCheckValidation(this);\"/></span></div>", ClientIP)
				StatPageInfo.SearchClientIP = template.HTML(TempStr)
			} else {
				/*if Node_Change_Client_IP_Mode == ENABLE {
					TempStr = fmt.Sprintf("<div class=\"item\"><span class=\"title\">Client</span><span class=\"condition\"><input type=\"text\" name=\"client_ip\" style=\"width: 120px\" value=\"\" onBlur=\"ipCheckValidation(this);\"/></span></div>")
					StatPageInfo.SearchClientIP = template.HTML(TempStr)
				  }*/
				TempStr = fmt.Sprintf("<div class=\"item\"><span class=\"title\">Client</span><span class=\"condition\"><input type=\"text\" name=\"client_ip\" style=\"width: 120px\" value=\"\" onBlur=\"ipCheckValidation(this);\"/></span></div>")
				StatPageInfo.SearchClientIP = template.HTML(TempStr)

			}
		} else {
			req.ParseForm()

			StartTime = fmt.Sprintf("%s", req.Form["start_time"])
			StartTime = strings.Replace(StartTime, "[", "", -1)
			StartTime = strings.Replace(StartTime, "]", "", -1)
			StartTime = strings.TrimSpace(StartTime)

			EndTime = fmt.Sprintf("%s", req.Form["end_time"])
			EndTime = strings.Replace(EndTime, "[", "", -1)
			EndTime = strings.Replace(EndTime, "]", "", -1)
			EndTime = strings.TrimSpace(EndTime)

			BridgeID = fmt.Sprintf("%s", req.Form["Bridge_id"])
			BridgeID = strings.Replace(BridgeID, "[", "", -1)
			BridgeID = strings.Replace(BridgeID, "]", "", -1)
			BridgeID = strings.TrimSpace(BridgeID)

			ProxyIP = fmt.Sprintf("%s", req.Form["proxy_ip"])
			ProxyIP = strings.Replace(ProxyIP, "[", "", -1)
			ProxyIP = strings.Replace(ProxyIP, "]", "", -1)
			ProxyIP = strings.TrimSpace(ProxyIP)

			NICIP = fmt.Sprintf("%s", req.Form["nic_ip"])
			NICIP = strings.Replace(NICIP, "[", "", -1)
			NICIP = strings.Replace(NICIP, "]", "", -1)
			NICIP = strings.TrimSpace(NICIP)

			NICPort = fmt.Sprintf("%s", req.Form["nic_port"])
			NICPort = strings.Replace(NICPort, "[", "", -1)
			NICPort = strings.Replace(NICPort, "]", "", -1)
			NICPort = strings.TrimSpace(NICPort)

			ServerIP = fmt.Sprintf("%s", req.Form["server_ip"])
			ServerIP = strings.Replace(ServerIP, "[", "", -1)
			ServerIP = strings.Replace(ServerIP, "]", "", -1)
			ServerIP = strings.TrimSpace(ServerIP)

			ServerPort = fmt.Sprintf("%s", req.Form["server_port"])
			ServerPort = strings.Replace(ServerPort, "[", "", -1)
			ServerPort = strings.Replace(ServerPort, "]", "", -1)
			ServerPort = strings.TrimSpace(ServerPort)

			ClientIP = fmt.Sprintf("%s", req.Form["client_ip"])
			ClientIP = strings.Replace(ClientIP, "[", "", -1)
			ClientIP = strings.Replace(ClientIP, "]", "", -1)
			ClientIP = strings.TrimSpace(ClientIP)
		}

		if len(StartTime) > 0 {
			Params += fmt.Sprintf("&stime=%s", StartTime)
		}

		if len(EndTime) > 0 {
			Params += fmt.Sprintf("&etime=%s", EndTime)
		}

		if len(StartTime) > 0 && len(EndTime) > 0 {
			QueryCommonCondition += fmt.Sprintf("AND (Time BETWEEN ? AND ?)")
			ConditionArray = append(ConditionArray, StartTime, EndTime)
			ConditionCount += 2
		}

		if len(BridgeID) > 0 && BridgeID != "All" {
			Params += fmt.Sprintf("&Bridgeid=%s", BridgeID)
			if StrtoUUID(BridgeID) != 0 {

				QueryCommonCondition += fmt.Sprintf("AND (Bridge_ID_TEXT=?)")
				ConditionArray = append(ConditionArray, BridgeID)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Bridge_ID_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, BridgeID+"%")
				ConditionCount++
			}
		}

		if len(ProxyIP) > 0 && ProxyIP != "All" {
			Params += fmt.Sprintf("&pip=%s", ProxyIP)
			if StrtoIP(ProxyIP) != 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Proxy_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ProxyIP)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Proxy_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ProxyIP+"%")
				ConditionCount++

			}
		}

		if len(NICIP) > 0 && NICIP != "All" {
			Params += fmt.Sprintf("&nip=%s", NICIP)
			if StrtoIP(NICIP) != 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, NICIP)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, NICIP+"%")
				ConditionCount++

			}
		}

		if len(NICPort) > 0 {
			Params += fmt.Sprintf("&nport=%s", NICPort)
			TempInt, _ := strconv.Atoi(NICPort)
			if TempInt > 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Node_Listen_Port=?)")
			}
			ConditionArray = append(ConditionArray, TempInt)
			ConditionCount++
		}

		if len(ServerIP) > 0 {
			Params += fmt.Sprintf("&sip=%s", ServerIP)
			if StrtoIP(NICIP) != 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Server_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ServerIP)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Server_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ServerIP+"%")
				ConditionCount++

			}
		}

		if len(ServerPort) > 0 {
			Params += fmt.Sprintf("&sport=%s", ServerPort)
			TempInt, _ := strconv.Atoi(ServerPort)
			if TempInt > 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Server_Listen_Port=?)")
			}
			ConditionArray = append(ConditionArray, TempInt)
			ConditionCount++
		}

		if len(ClientIP) > 0 {
			Params += fmt.Sprintf("&cip=%s", ClientIP)
			if StrtoIP(NICIP) != 0 {
				QueryDataCondition += fmt.Sprintf("AND (Client_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ClientIP)
				ConditionCount++

			} else {
				QueryDataCondition += fmt.Sprintf("AND (Client_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ClientIP+"%")
				ConditionCount++

			}
		}

		if req.Method == "POST" {
			StatURL := "/statistics/server/?page_num=1&sort=0"
			if len(Params) > 0 {
				StatURL += Params
			}

			WebServer_Redirect(w, req, StatURL)
			return
		}

		PageNumberStr := fmt.Sprintf("%s", Param_PageNumber)
		PageNumberStr = strings.Replace(PageNumberStr, "[", "", -1)
		PageNumberStr = strings.Replace(PageNumberStr, "]", "", -1)

		SortStr := fmt.Sprintf("%s", Param_Sort)
		SortStr = strings.Replace(SortStr, "[", "", -1)
		SortStr = strings.Replace(SortStr, "]", "", -1)

		PageNumber, err = strconv.Atoi(PageNumberStr)
		if err != nil {
			log.Println("failed to strconv.Atoi")
			StatURL := "/statistics/server/?page_num=1&sort=0"
			WebServer_Redirect(w, req, StatURL)
			return
		}

		SortNumber, err = strconv.Atoi(SortStr)
		if err != nil {
			log.Println("failed to strconv.Atoi")
			StatURL := "/statistics/server/?page_num=1&sort=0"
			WebServer_Redirect(w, req, StatURL)
			return
		}

		DESC_Dir := "▼"
		ASC_Dir := "▲"
		NONE_Dir := "-"

		SortTime = SortTime_ASC
		SortBridgeID = SortBridgeID_ASC
		SortProxyIP = SortProxyIP_ASC
		SortNodeIP = SortNodeIP_ASC
		SortServerIP = SortServerIP_ASC
		SortClientIP = SortClientIP_ASC

		SortTimeDir := NONE_Dir
		SortBridgeIDDir := NONE_Dir
		SortProxyIPDir := NONE_Dir
		SortNodeIPDir := NONE_Dir
		SortServerIPDir := NONE_Dir
		SortClientIPDir := NONE_Dir

		switch SortNumber {
		case SortTime_ASC:
			SortTime = SortTime_DESC
			SortTimeDir = DESC_Dir

			OrderBy = "Time DESC"
		case SortBridgeID_ASC:
			SortBridgeID = SortBridgeID_DESC
			SortBridgeIDDir = DESC_Dir

			OrderBy = "Bridge_ID_TEXT DESC"
		case SortProxyIP_ASC:
			SortProxyIP = SortProxyIP_DESC
			SortProxyIPDir = DESC_Dir

			OrderBy = "Proxy_IP_INT DESC"
		case SortNodeIP_ASC:
			SortNodeIP = SortNodeIP_DESC
			SortNodeIPDir = DESC_Dir

			OrderBy = "Node_IP_INT DESC"
		case SortServerIP_ASC:
			SortServerIP = SortServerIP_DESC
			SortServerIPDir = DESC_Dir

			OrderBy = "Server_IP_INT DESC"
		case SortClientIP_ASC:
			SortClientIP = SortClientIP_DESC
			SortClientIPDir = DESC_Dir

			OrderBy = "Time DESC, B.Client_IP_INT DESC"
		case SortTime_DESC:
			SortTime = SortTime_ASC
			SortTimeDir = ASC_Dir

			OrderBy = "Time ASC"
		case SortBridgeID_DESC:
			SortBridgeID = SortBridgeID_ASC
			SortBridgeIDDir = ASC_Dir

			OrderBy = "Bridge_ID_TEXT ASC"
		case SortProxyIP_DESC:
			SortProxyIP = SortProxyIP_ASC
			SortProxyIPDir = ASC_Dir

			OrderBy = "Proxy_IP_INT ASC"
		case SortNodeIP_DESC:
			SortNodeIP = SortNodeIP_ASC
			SortNodeIPDir = ASC_Dir

			OrderBy = "Node_IP_INT ASC"
		case SortServerIP_DESC:
			SortServerIP = SortServerIP_ASC
			SortServerIPDir = ASC_Dir

			OrderBy = "Server_IP_INT ASC"
		case SortClientIP_DESC:
			SortClientIP = SortClientIP_ASC
			SortClientIPDir = ASC_Dir

			OrderBy = "Time DESC, B.Client_IP_INT ASC"
		}

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Collection Time %s</a></th>", SortTime, Params, SortTimeDir)
		StatPageInfo.SortTime = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Bridge ID %s</a></th>", SortBridgeID, Params, SortBridgeIDDir)
		StatPageInfo.SortBridgeID = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Proxy IP %s</a></th>", SortProxyIP, Params, SortProxyIPDir)
		StatPageInfo.SortProxyIP = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Node Server IP %s</a></th>", SortNodeIP, Params, SortNodeIPDir)
		StatPageInfo.SortNodeIP = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Server IP %s</a></th>", SortServerIP, Params, SortServerIPDir)
		StatPageInfo.SortServerIP = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/server/?page_num=1&sort=%d%s\">Client IP %s</a></th>", SortClientIP, Params, SortClientIPDir)
		StatPageInfo.SortClientIP = template.HTML(TempStr)

		tmpl, err = template.ParseFiles("./pages/Control_Node_Server_Statistics.html")
		if err != nil {
			log.Println("failed to template.ParseFiles")
			return
		}

		NextRowOffset := (PageNumber - 1) * RowCountPerPage

		QueryStr = fmt.Sprintf("SELECT COUNT(DISTINCT A.ID) FROM (SELECT * FROM SERVER_STATISTICS_COMMON GROUP BY Time, Bridge_ID_TEXT, Proxy_IP_INT, Node_IP_INT, Node_Listen_Port, Server_IP_INT) as A JOIN SERVER_STATISTICS_DATA as B ON B.ID = A.ID WHERE 1=1 %s AND 1=1 %s", QueryCommonCondition, QueryDataCondition)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}

		for CommonRows.Next() {
			err := CommonRows.Scan(&CommonRowsCount)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}
		}
		CommonRows.Close()

		PageCount = int(math.Ceil(float64(CommonRowsCount) / float64(RowCountPerPage)))
		if PageNumber < PageCount {
			NextPageNumber = PageNumber + 1
		} else {
			NextPageNumber = PageCount
		}

		CommonID := 0
		PrevCommonID := 0
		OverlapID := 0
		QueryStr = fmt.Sprintf("SELECT distinct A.ID  FROM ( SELECT * FROM SERVER_STATISTICS_COMMON WHERE 1=1 %s GROUP BY Time,Bridge_ID_TEXT, Proxy_IP_INT, Node_IP_INT, Node_Listen_Port, Server_IP_INT) A JOIN ( SELECT * FROM SERVER_STATISTICS_DATA WHERE 1=1 %s) B ON A.ID = B.ID ORDER BY %s LIMIT %d OFFSET %d", QueryCommonCondition, QueryDataCondition, OrderBy, RowCountPerPage, NextRowOffset)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}
		for CommonRows.Next() {
			err := CommonRows.Scan(&CommonID)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}
			if len(CommonIDs) > 0 {
				CommonIDs += ","
			}
			CommonIDs += fmt.Sprintf("%d", CommonID)
		}
		CommonRows.Close()

		if len(CommonIDs) == 0 {
			tmpl.Execute(w, StatPageInfo)
			return
		}

		data_group_id := 0
		data_first := 0
		index := 0

		QueryStr = fmt.Sprintf("SELECT * FROM ( SELECT * FROM SERVER_STATISTICS_COMMON WHERE 1=1 %s GROUP BY Time,Bridge_ID_TEXT, Proxy_IP_INT, Node_IP_INT, Node_Listen_Port, Server_IP_INT ) A JOIN ( SELECT * FROM SERVER_STATISTICS_DATA WHERE 1=1 %s) B ON A.ID = B.ID WHERE A.ID IN (%s) ORDER BY %s", QueryCommonCondition, QueryDataCondition, CommonIDs, OrderBy)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}
		for CommonRows.Next() {
			err := CommonRows.Scan(&CommonID, &StatInfo.StatCommon.Time, &StatInfo.StatCommon.Bridge_ID_Str, &StatInfo.StatCommon.Proxy_IP_Int, &StatInfo.StatCommon.Proxy_IP_Str, &StatInfo.StatCommon.Node_IP_Int, &StatInfo.StatCommon.Node_IP_Str, &StatInfo.StatCommon.Node_Listen_Port, &StatInfo.StatCommon.Server_IP_Int, &StatInfo.StatCommon.Server_IP_Str, &StatInfo.StatCommon.Server_Listen_Port, &OverlapID, &CommonID, &StatInfo.StatData.Client_IP_Int, &StatInfo.StatData.Client_IP_Str, &StatInfo.StatData.Inbound, &StatInfo.StatData.Outbound)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}

			if PrevCommonID == 0 {
				PrevCommonID = CommonID
				data_first = 1
			} else if PrevCommonID != CommonID {
				StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound = TotalInbound
				StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound = TotalOutbound

				TempStr = fmt.Sprintf("<td>%d</td>", StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound)
				StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound_HTML = template.HTML(TempStr)
				TempStr = fmt.Sprintf("<td>%d</td>", StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound)
				StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound_HTML = template.HTML(TempStr)

				TotalInbound = 0
				TotalOutbound = 0

				data_first = 1
				PrevCommonID = CommonID
				data_group_id++
			}

			StatInfo.StatCommon.TrInfo.DataGroupID = strconv.Itoa(data_group_id)

			if data_first == 1 {
				StatInfo.StatCommon.TrInfo.DataFirst = strconv.Itoa(data_first)
				StatInfo.StatCommon.TrInfo.Style = "view"
				data_first = 0
				TempStr = fmt.Sprintf("<td></td>")
				StatInfo.StatData.Client_IP_HTML = template.HTML(TempStr)
				StatPageInfo.StatInfo = append(StatPageInfo.StatInfo, StatInfo)
				FirstStatInfoIndex = index
				index++
			}

			TempStr = fmt.Sprintf("<td>%d</td>", StatInfo.StatData.Inbound)
			StatInfo.StatData.Inbound_HTML = template.HTML(TempStr)
			TempStr = fmt.Sprintf("<td>%d</td>", StatInfo.StatData.Outbound)
			StatInfo.StatData.Outbound_HTML = template.HTML(TempStr)

			TotalInbound += StatInfo.StatData.Inbound
			TotalOutbound += StatInfo.StatData.Outbound
			StatInfo.StatCommon.TrInfo.DataFirst = strconv.Itoa(data_first)
			StatInfo.StatCommon.TrInfo.Style = "none"

			TempStr = fmt.Sprintf("<td>%s</td>", StatInfo.StatData.Client_IP_Str)
			StatInfo.StatData.Client_IP_HTML = template.HTML(TempStr)

			StatPageInfo.StatInfo = append(StatPageInfo.StatInfo, StatInfo)
			index++
		}
		CommonRows.Close()
		StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound = TotalInbound
		StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound = TotalOutbound

		TempStr = fmt.Sprintf("<td>%d</td>", StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound)
		StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Inbound_HTML = template.HTML(TempStr)
		TempStr = fmt.Sprintf("<td>%d</td>", StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound)
		StatPageInfo.StatInfo[FirstStatInfoIndex].StatData.Outbound_HTML = template.HTML(TempStr)

		if PageNumber > 1 {
			PrevPageNumber = PageNumber - 1
		} else {
			PrevPageNumber = 1
		}

		TempStr = fmt.Sprintf("/statistics/server/?page_num=%d&sort=%d%s", 1, SortNumber, Params)
		StatPageInfo.FirstPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/server/?page_num=%d&sort=%d%s", PrevPageNumber, SortNumber, Params)
		StatPageInfo.PrevPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/server/?page_num=%d&sort=%d%s", NextPageNumber, SortNumber, Params)
		StatPageInfo.NextPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/server/?page_num=%d&sort=%d%s", PageCount, SortNumber, Params)
		StatPageInfo.LastPage = template.HTML(TempStr)

		PageIndexStart = (((PageNumber - 1) / MaxPageCountInPage) * MaxPageCountInPage) + 1

		if PageCount > MaxPageCountInPage {
			LastPageNumber = PageIndexStart + (MaxPageCountInPage - 1)
		} else {
			LastPageNumber = PageCount
		}

		if LastPageNumber > PageCount {
			LastPageNumber = PageCount
		}

		for page_index := PageIndexStart; page_index <= LastPageNumber; page_index++ {
			PageNumInfo.PageNum = page_index
			if PageNumInfo.PageNum == PageNumber {
				PageNumInfo.TagStart = "<strong>"
				PageNumInfo.TagEnd = "</strong>"
			} else {
				TempTag := fmt.Sprintf("<a href=\"/statistics/server/?page_num=%d&sort=%d%s\">", PageNumInfo.PageNum, SortNumber, Params)
				PageNumInfo.TagStart = template.HTML(TempTag)
				PageNumInfo.TagEnd = "</a>"
			}

			StatPageInfo.PageNumInfo = append(StatPageInfo.PageNumInfo, PageNumInfo)
		}
	}
	tmpl.Execute(w, StatPageInfo)
}

//------------------------------------------------------------------------- [ WEB API:gkwon ] {--------//
func WebServer_Web_Auth_API_Provisioning_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlTemplate *template.Template
	var err error

	log.Println("Web Server - WebServer_Web_Auth_API_Test_Input", req.Method)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	HtmlTemplate, err = template.ParseFiles("./pages/WEB_API_Auth_Provisioning_Input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./pages/WEB_API_Auth_Provisioning_Input.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, "")
}

func WebServer_Web_Auth_API_Statistics_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlTemplate *template.Template
	var err error

	log.Println("Web Server - WebServer_Web_Auth_API_Test_Input", req.Method)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	HtmlTemplate, err = template.ParseFiles("./pages/WEB_API_Auth_Statistics_Input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./pages/WEB_API_Auth_Statistics_Input.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, "")
}

type jsonInputWebAPIEncodeValue struct {
	InputValue string `json:"input"`
}

type jsonOutputWebAPIEncodeValue struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	InputValue  string `json:"input"`
	OutputValue string `json:"output"`
}

func AESEncryptEncodingValue(InputText string) string {
	var AES_KEY = []byte{109, 56, 85, 44, 248, 44, 18, 128, 236, 116, 13, 250, 243, 45, 122, 133, 199, 241, 124, 188, 188, 93, 65, 153, 214, 193, 127, 85, 132, 147, 193, 68}
	var IV = []byte{89, 93, 106, 165, 128, 137, 36, 38, 122, 121, 249, 59, 151, 133, 155, 148}
	var BASE32_ALPHABET = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79}
	var EncryptEncodeText string

	encrypt := make([]byte, len(InputText))
	err := aes_cfb.EncAES_CFB8_256(encrypt, []byte(InputText), []byte(string(AES_KEY)), []byte(string(IV)))
	if err != nil {
		log.Println("aes cfb8 encrypt error: ", err)
		return ""
	}

	new_encoder := base32.NewEncoding(string(BASE32_ALPHABET))
	new_encoder = new_encoder.WithPadding(base32.NoPadding)
	EncryptEncodeText = new_encoder.EncodeToString(encrypt)

	//log.Printf("Encript and Base43 : [%s] -> [%x] -> [%s]", InputText, encrypt, EncryptEncodeText)
	return EncryptEncodeText
}

func AESDecryptDecodeValue(InputText string) string {
	var AES_KEY = []byte{109, 56, 85, 44, 248, 44, 18, 128, 236, 116, 13, 250, 243, 45, 122, 133, 199, 241, 124, 188, 188, 93, 65, 153, 214, 193, 127, 85, 132, 147, 193, 68}
	var IV = []byte{89, 93, 106, 165, 128, 137, 36, 38, 122, 121, 249, 59, 151, 133, 155, 148}
	var BASE32_ALPHABET = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79}
	var DecryptDecodeText string

	new_decoder := base32.NewEncoding(string(BASE32_ALPHABET))
	new_decoder = new_decoder.WithPadding(base32.NoPadding)
	encrypt, err := new_decoder.DecodeString(InputText)
	if err != nil {
		log.Println("base32 decode error: ", err)
		return ""
	}

	decrypt := make([]byte, len(InputText))
	err = aes_cfb.DecAES_CFB8_256(decrypt, encrypt, AES_KEY, IV)
	if err != nil {
		log.Println("aes cfb8 decrypt error: ", err)
		return ""
	}

	/*--------------------------------------------------------------------------------------------------------------------------------------------------------
	  tmpValue := "vnUpaEeT-00000003-GbETk-TchXy-r5M3zQgjwQ6j"
	  DecryptDecodeText = string(decrypt)
	  - string cmp checking
	     1. log.Println(tmpValue)         : vnUpaEeT-00000003-GbETk-TchXy-r5M3zQgjwQ6j
	     2. log.Println(DecryptDecodeText): vnUpaEeT-00000003-GbETk-TchXy-r5M3zQgjwQ6j
	     1-1 String to Hex : 766e5570614565542d30303030303030332d476245546b2d54636858792d72354d337a51676a7751366a0000000000000000000000000000000000000000000000000000
	     2-1 String to Hex : 766e5570614565542d30303030303030332d476245546b2d54636858792d72354d337a51676a7751366a
	  --------------------------------------------------------------------------------------------------------------------------------------------------------*/
	//DecryptDecodeText = string(decrypt)
	DecryptDecodeText = strings.Trim(string(decrypt), "\x00")

	//log.Printf("Decrypt and Base32 : [%s] -> [%x] -> [%s]", InputText, encrypt, DecryptDecodeText)
	return DecryptDecodeText
}

func WebServer_Web_Auth_API_Encode_Value(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var InputData jsonInputWebAPIEncodeValue
	var OutputData jsonOutputWebAPIEncodeValue
	var OutputBody string
	var EncryptValue string
	var DecryptValue string
	var err error

	log.Println("WebServer_Web_Auth_API_Encode_Value", req.Method)

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		OutputData.Code = "600"
		OutputData.Message = "fail"
		OutputData.InputValue = ""
		OutputData.OutputValue = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		log.Println("WebServer_Web_Auth_API_Encode_Value", req.Method)
		return
	}

	log.Println("Input Value:" + InputData.InputValue)

	EncryptValue = AESEncryptEncodingValue(InputData.InputValue)
	if EncryptValue == "" {
		log.Println("WebServer_Web_Auth_API_Encode_Value", req.Method)
		OutputData.Code = "400"
		OutputData.Message = "failed to AESEncryptEncodingValue"
		OutputData.InputValue = InputData.InputValue
		OutputData.OutputValue = EncryptValue

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	log.Println("WebServer_Web_Auth_API_Encode_Value", req.Method)

	DecryptValue = AESDecryptDecodeValue(EncryptValue)
	if DecryptValue == "" {
		OutputData.Code = "400"
		OutputData.Message = "failed to AESDecryptDecodeValue"
		OutputData.InputValue = InputData.InputValue
		OutputData.OutputValue = EncryptValue

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	log.Println("Input Value:" + InputData.InputValue + ", EncryptValue:" + EncryptValue + ", DecryptValue:" + DecryptValue)

	OutputData.Code = "200"
	OutputData.Message = "success"
	OutputData.InputValue = InputData.InputValue
	OutputData.OutputValue = EncryptValue

	jstrbyte, _ := json.Marshal(OutputData)
	OutputBody = string(jstrbyte)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(OutputBody))
	return
}

func Product_rand_key(size int) string {
	var alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var seededRand *rand.Rand = rand.New(
		rand.NewSource(time.Now().UnixNano()))

	buffer := make([]byte, size)
	for i := 0; i < size; i++ {
		buffer[i] = alpha[seededRand.Intn(len(alpha))]
	}

	return string(buffer)
}

func WEBAuthGenerateAuthKey(NodeID string) string {
	var TmpGenerateKey string

	if NodeID == "" {
		log.Println("NodeID - invalid argument")
		return ""
	}

	NodeKeyBuffer := bytes.Buffer{}

	TmpGenerateKey = Product_rand_key(12)
	NodeKeyBuffer.WriteString(TmpGenerateKey)
	TmpGenerateKey = fmt.Sprintf("%08s", NodeID)
	NodeKeyBuffer.WriteString(TmpGenerateKey)

	return NodeKeyBuffer.String()
}

type jsonInputWebAPIAuthProvisioningPack struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	MessageType string `json:"msgtype"`
	UserKey     string `json:"userkey"`
	AuthKey     string `json:"authkey"`
	AuthToken   string `json:"authtoken"`
	Data        string `json:"data"`
}

type jsonOutputWebAPIAuthProvisioningPack struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	MsgType     string `json:"msgtype"`
	Code        string `json:"code"`
	Message     string `json:"msg"`
	AuthKey     string `json:"authkey"`
	ExpireTime  string `json:"expiretime"`
	Data        string `json:"data"`
}

var AuthProvisioningSeqNo = 1
var AuthStatisticsSeqNo = 1

func WebServer_Web_Auth_API_Provisioning_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	//var Database *sql.DB
	//var ResultSetRows *sql.Rows
	//var QueryString string
	var InputData jsonInputWebAPIAuthProvisioningPack
	var OutputData jsonOutputWebAPIAuthProvisioningPack
	var OutputBody string
	var DecryptUserKey string
	var GenerateAuthKey string
	var DBAuthUserKey string
	var OEMAuthExpiretimeInterval int
	var DBAuthKey string
	var DBAuthToken string
	var DBAuthExpireTime uint64
	var DBAuthNOWTime uint64
	var HashingText string
	var HA1 string
	var HA2 string
	var Response string
	var EventValue string
	var err error

	log.Println("WebServer_Web_Auth_API_Provisioning_Proc", req.Method)

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		OutputData.Version = ""     // (security enhancement: tracking prevention)
		OutputData.Method = ""      // (security enhancement: tracking prevention)
		OutputData.SessionType = "" // (security enhancement: tracking prevention)
		OutputData.MsgType = ""     // (security enhancement: tracking prevention)
		OutputData.Code = "610"
		OutputData.Message = "json parameter parsing error (simplify Information)"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	if req.Method != "POST" {
		OutputData.Version = ""     // (security enhancement: tracking prevention)
		OutputData.Method = ""      // (security enhancement: tracking prevention)
		OutputData.SessionType = "" // (security enhancement: tracking prevention)
		OutputData.MsgType = ""     // (security enhancement: tracking prevention)
		OutputData.Code = "610"
		OutputData.Message = "json parameter parsing error (simplify Information for security enhancement)"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", authtoken:" + InputData.AuthToken + ", data:" + InputData.Data + "]")

	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.MessageType == "" || InputData.UserKey == "" {
		log.Println("invalid parmeter value: null")

		OutputData.Version = ""     // (security enhancement: tracking prevention)
		OutputData.Method = ""      // (security enhancement: tracking prevention)
		OutputData.SessionType = "" // (security enhancement: tracking prevention)
		OutputData.MsgType = ""     // (security enhancement: tracking prevention)
		OutputData.Code = "611"
		OutputData.Message = "json parameter is null (simplify Information for security enhancement)"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	if InputData.Version != "1.0" || InputData.Method != "Auth" || (InputData.SessionType != "ConfigData" && InputData.SessionType != "QueryData") || InputData.MessageType != "request" {
		log.Println("invalid parmeter value: not supported value")

		OutputData.Version = ""     // (security enhancement: tracking prevention)
		OutputData.Method = ""      // (security enhancement: tracking prevention)
		OutputData.SessionType = "" // (security enhancement: tracking prevention)
		OutputData.MsgType = ""     // (security enhancement: tracking prevention)
		OutputData.Code = "612"
		OutputData.Message = "json parameter is invalid (simplify Information for security enhancement)"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	DecryptUserKey = AESDecryptDecodeValue(InputData.UserKey)
	if DecryptUserKey == "" {
		log.Println("invalid parmeter value: user key decrypt error")

		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "620"
		OutputData.Message = "json parameter decript error"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}
	//log.Printf("WEB API Auth - UserKey Decrypt Value [%s] -> [%s]", InputData.UserKey, DecryptUserKey)
	InputData.UserKey = DecryptUserKey

	//-----------------------------------------------------------{
	//----[For Testing : Hardcodeing]----//
	DBAuthUserKey = "TC7rcr8v-00000002-aeLlO-CzqAk-N3WJmTTRV0Bu"
	OEMAuthExpiretimeInterval = 10
	DBAuthKey = "VARyK5Tc9ELW00000001"
	DBAuthToken = "9807e3b63b54616e664b85d38e8f6c8d"
	DBAuthExpireTime = 100000
	DBAuthNOWTime = 9999
	//-----------------------------------------------------------}

	if InputData.UserKey != DBAuthUserKey {
		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "630"
		OutputData.Message = "db processing error"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

		return
	}

	if InputData.AuthKey == "" && InputData.AuthToken == "" {

		AuthProvisioningSeqNo += 1

		if AuthProvisioningSeqNo >= 100000 {
			AuthProvisioningSeqNo = 1
		}

		GenerateAuthKey = WEBAuthGenerateAuthKey(strconv.Itoa(AuthProvisioningSeqNo))
		//-----------------------------------------------------------{
		//----[For Testing : Hardcodeing]----//
		GenerateAuthKey = DBAuthKey
		//-----------------------------------------------------------}
		if GenerateAuthKey == "" {
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "643"
			OutputData.Message = "failed to generate auth key"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
			return
		}

		hashing_algorithm := md5.New()
		HashingText = InputData.UserKey + ":" + OutputData.SessionType
		hashing_algorithm.Write([]byte(HashingText))
		HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		EventValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

		hashing_algorithm = md5.New()
		HashingText = InputData.Method + ":" + "/auth_api/provisioning/v1.0/"
		hashing_algorithm.Write([]byte(HashingText))
		HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		EventValue += "[" + HashingText + " >> HA2:" + HA2 + "]"

		hashing_algorithm = md5.New()
		HashingText = HA1 + ":" + GenerateAuthKey + ":" + HA2
		hashing_algorithm.Write([]byte(HA1 + ":" + GenerateAuthKey + ":" + HA2))
		Response = hex.EncodeToString(hashing_algorithm.Sum(nil))
		EventValue += "[" + HashingText + " >> Response:" + Response + "]"

		//log.Println("WEB API Auth Information -> ", EventValue)

		if Response != "" {

			/*--------------------------------------------------------------
			  QueryString = ""
			  // DB Query Processing
			  --------------------------------------------------------------*/

			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "200"
			OutputData.Message = "auth success"
			OutputData.AuthKey = GenerateAuthKey
			OutputData.ExpireTime = strconv.Itoa(OEMAuthExpiretimeInterval)
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s] [code:%s, msg:%s, description:%s (expiretime sec:%d, authkey:%s, authtoken:%s)]", InputData.UserKey, OutputData.Code, OutputData.Message, "create new authkey and authtoken", OEMAuthExpiretimeInterval, GenerateAuthKey, Response)
			return
		} else {
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "644"
			OutputData.Message = "failed to generate auth token"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
			return
		}

	} else if InputData.AuthKey != "" && InputData.AuthToken != "" {

		/*--------------------------------------------------------------
		  QueryString = ""
		  // DB Query Processing
		  --------------------------------------------------------------*/

		if DBAuthToken == "" {
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "641"
			OutputData.Message = "auth error"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
			return
		}

		if InputData.AuthToken != DBAuthToken {
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "642"
			OutputData.Message = "auth error"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
			return
		}

		//log.Println("WEB API Auth Expiretime(DBAuthExpireTime:", DBAuthExpireTime, ", DBAuthNOWTime:", DBAuthNOWTime, ")")

		if DBAuthExpireTime < DBAuthNOWTime {
			/*------------------------------------------------------------------------------------------------------------------------
			  QueryString = ""
			  // DB Query Processing
			  ------------------------------------------------------------------------------------------------------------------------*/

			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "643"
			OutputData.Message = "212 auth error"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s] [code:%s, msg:%s] %d, %d", InputData.UserKey, OutputData.Code, OutputData.Message, DBAuthExpireTime, DBAuthNOWTime)
			return
		}

		/*------------------------------------------------------------------------------------------------------------------------
		  QueryString = ""
		  // DB Query Processing
		  ------------------------------------------------------------------------------------------------------------------------*/

		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "200"
		OutputData.Message = "auth success"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = strconv.Itoa(0)
		//-----------------------------------------------------------{
		//----[For Testing : Hardcodeing]----//
		OutputData.Data = "Response-" + InputData.Data
		//-----------------------------------------------------------}

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

		log.Printf("web api response [userkey:%s] [code:%s, msg:%s, description:%s (expiretime sec:%d, authtoken:%s)]", InputData.UserKey, OutputData.Code, OutputData.Message, "expiretime update", OEMAuthExpiretimeInterval, InputData.AuthToken)
		return
	} else {
		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "641"
		OutputData.Message = "auth error"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

		log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
		return
	}
}

type jsonInputWebAPIAuthStatisticsPack struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	MessageType string `json:"msgtype"`
	UserKey     string `json:"userkey"`
	NodeID      string `json:"nodeid"`
	AuthKey     string `json:"authkey"`
	AuthToken   string `json:"authtoken"`
	Data        string `json:"data"`
}

type jsonOutputWebAPIAuthStatisticsPack struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	MsgType     string `json:"msgtype"`
	Code        string `json:"code"`
	Message     string `json:"msg"`
	AuthKey     string `json:"authkey"`
	ExpireTime  string `json:"expiretime"`
	Data        string `json:"data"`
}

func WebServer_Web_Auth_API_Statistics_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	//var Database *sql.DB
	//var ResultSetRows *sql.Rows
	//var QueryString string
	var InputData jsonInputWebAPIAuthStatisticsPack
	var OutputData jsonOutputWebAPIAuthStatisticsPack
	var OutputBody string
	var DecryptUserKey string
	var DecryptNodeID string
	var GenerateAuthKey string
	var DBAuthUserKey string
	var DBAuthNodeID string
	var OEMAuthExpiretimeInterval int
	var DBAuthKey string
	var DBAuthToken string
	var DBAuthExpireTime uint64
	var DBAuthNOWTime uint64
	var HashingText string
	var HA1 string
	var HA2 string
	var Response string
	var EventValue string
	var err error

	log.Println("WebServer_Web_Auth_API_Statistics_Proc", req.Method)

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		OutputData.Version = ""     // (security enhancement: tracking prevention)
		OutputData.Method = ""      // (security enhancement: tracking prevention)
		OutputData.SessionType = "" // (security enhancement: tracking prevention)
		OutputData.MsgType = ""     // (security enhancement: tracking prevention)
		OutputData.Code = "610"
		OutputData.Message = "json parameter parsing error (simplify Information)"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	if req.Method != "POST" {
		OutputData.Version = ""     // (security enhancement: tracking prevention)
		OutputData.Method = ""      // (security enhancement: tracking prevention)
		OutputData.SessionType = "" // (security enhancement: tracking prevention)
		OutputData.MsgType = ""     // (security enhancement: tracking prevention)
		OutputData.Code = "610"
		OutputData.Message = "json parameter parsing error (simplify Information for security enhancement)"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", authtoken:" + InputData.AuthToken + ", data:" + InputData.Data + "]")

	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.MessageType == "" || InputData.UserKey == "" || InputData.NodeID == "" {
		log.Println("invalid parmeter value: null")

		OutputData.Version = ""     // (security enhancement: tracking prevention)
		OutputData.Method = ""      // (security enhancement: tracking prevention)
		OutputData.SessionType = "" // (security enhancement: tracking prevention)
		OutputData.MsgType = ""     // (security enhancement: tracking prevention)
		OutputData.Code = "611"
		OutputData.Message = "json parameter is null (simplify Information for security enhancement)"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	if InputData.Version != "1.0" || InputData.Method != "Auth" || InputData.SessionType != "Statistics" || InputData.MessageType != "request" {
		log.Println("invalid parmeter value: not supported value")

		OutputData.Version = ""     // (security enhancement: tracking prevention)
		OutputData.Method = ""      // (security enhancement: tracking prevention)
		OutputData.SessionType = "" // (security enhancement: tracking prevention)
		OutputData.MsgType = ""     // (security enhancement: tracking prevention)
		OutputData.Code = "612"
		OutputData.Message = "json parameter is invalid (simplify Information for security enhancement)"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	DecryptUserKey = AESDecryptDecodeValue(InputData.UserKey)
	if DecryptUserKey == "" {
		log.Println("invalid parmeter value: user key decrypt error")

		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "620"
		OutputData.Message = "json parameter decript error"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}
	//log.Printf("WEB API Auth - UserKey Decrypt Value [%s] -> [%s]", InputData.UserKey, DecryptUserKey)
	InputData.UserKey = DecryptUserKey

	DecryptNodeID = AESDecryptDecodeValue(InputData.NodeID)
	if DecryptNodeID == "" {
		log.Println("invalid parmeter value: node id decrypt error")

		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "620"
		OutputData.Message = "json parameter decript error"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}
	//log.Printf("WEB API Auth - UserKey Decrypt Value [%s] -> [%s]", InputData.UserKey, DecryptNodeID)
	InputData.NodeID = DecryptNodeID

	//-----------------------------------------------------------{
	//----[For Testing : Hardcodeing]----//
	DBAuthUserKey = "TC7rcr8v-00000002-aeLlO-CzqAk-N3WJmTTRV0Bu"
	DBAuthNodeID = "N7y8VbI8-00000001-hWJeh-AUCXS-mA0IhNYm2B4M"
	OEMAuthExpiretimeInterval = 10
	DBAuthKey = "VARyK5Tc9ELW00000001"
	DBAuthToken = "69c35a7c2dfa4edf8b3b29e12a681a0f"
	DBAuthExpireTime = 100000
	DBAuthNOWTime = 9999
	//-----------------------------------------------------------}

	if InputData.UserKey != DBAuthUserKey || InputData.NodeID != DBAuthNodeID {
		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "630"
		OutputData.Message = "db processing error"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

		return
	}

	if InputData.AuthKey == "" && InputData.AuthToken == "" {

		AuthStatisticsSeqNo += 1

		if AuthStatisticsSeqNo >= 100000 {
			AuthStatisticsSeqNo = 1
		}

		GenerateAuthKey = WEBAuthGenerateAuthKey(strconv.Itoa(AuthStatisticsSeqNo))
		//-----------------------------------------------------------{
		//----[For Testing : Hardcodeing]----//
		GenerateAuthKey = DBAuthKey
		//-----------------------------------------------------------}
		if GenerateAuthKey == "" {
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "643"
			OutputData.Message = "failed to generate auth key"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message)
			return
		}

		hashing_algorithm := md5.New()
		HashingText = InputData.UserKey + ":" + InputData.NodeID
		hashing_algorithm.Write([]byte(HashingText))
		HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		EventValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

		hashing_algorithm = md5.New()
		HashingText = InputData.Method + ":" + InputData.SessionType + ":" + "/auth_api/provisioning/v1.0/"
		hashing_algorithm.Write([]byte(HashingText))
		HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		EventValue += "[" + HashingText + " >> HA2:" + HA2 + "]"

		hashing_algorithm = md5.New()
		HashingText = HA1 + ":" + GenerateAuthKey + ":" + HA2
		hashing_algorithm.Write([]byte(HA1 + ":" + GenerateAuthKey + ":" + HA2))
		Response = hex.EncodeToString(hashing_algorithm.Sum(nil))
		EventValue += "[" + HashingText + " >> Response:" + Response + "]"

		//log.Println("WEB API Auth Information -> ", EventValue)

		if Response != "" {

			/*--------------------------------------------------------------
			  QueryString = ""
			  // DB Query Processing
			  --------------------------------------------------------------*/

			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "200"
			OutputData.Message = "auth success"
			OutputData.AuthKey = GenerateAuthKey
			OutputData.ExpireTime = strconv.Itoa(OEMAuthExpiretimeInterval)
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s, description:%s (expiretime sec:%d, authkey:%s, authtoken:%s)]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message, "create new authkey and authtoken", OEMAuthExpiretimeInterval, GenerateAuthKey, Response)
			return
		} else {
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "644"
			OutputData.Message = "failed to generate auth token"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message)
			return
		}

	} else if InputData.AuthKey != "" && InputData.AuthToken != "" {

		/*--------------------------------------------------------------
		  QueryString = ""
		  // DB Query Processing
		  --------------------------------------------------------------*/

		if DBAuthKey == "" || DBAuthToken == "" {
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "641"
			OutputData.Message = "auth error"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message)
			return
		}

		if InputData.AuthKey != DBAuthKey || InputData.AuthToken != DBAuthToken {
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "642"
			OutputData.Message = "auth error"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message)
			return
		}

		//log.Println("WEB API Auth Expiretime(DBAuthExpireTime:", DBAuthExpireTime, ", DBAuthNOWTime:", DBAuthNOWTime, ")")

		if DBAuthExpireTime < DBAuthNOWTime {
			/*------------------------------------------------------------------------------------------------------------------------
			  QueryString = ""
			  // DB Query Processing
			  ------------------------------------------------------------------------------------------------------------------------*/

			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "643"
			OutputData.Message = "212 auth error"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s] %d, %d", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message, DBAuthExpireTime, DBAuthNOWTime)
			return
		}

		/*------------------------------------------------------------------------------------------------------------------------
		  QueryString = ""
		  // DB Query Processing
		  ------------------------------------------------------------------------------------------------------------------------*/

		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "200"
		OutputData.Message = "auth success"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = strconv.Itoa(0)
		//-----------------------------------------------------------{
		//----[For Testing : Hardcodeing]----//
		OutputData.Data = "Response-" + InputData.Data
		//-----------------------------------------------------------}

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

		log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s, description:%s (expiretime sec:%d, authtoken:%s)]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message, "expiretime update", OEMAuthExpiretimeInterval, InputData.AuthToken)
		return
	} else {
		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "641"
		OutputData.Message = "auth error"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

		log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message)
		return
	}
}

//------------------------------------------------------------------------- [ WEB API:gkwon ] }--------//

func ConditionQuery_Stmt(stmt *sql.Stmt, ConditionCount int, ConditionArray []interface{}) *sql.Rows {
	var Rows *sql.Rows
	var err error

	switch ConditionCount {

	case 1:
		Rows, err = stmt.Query(ConditionArray[0])
	case 2:
		Rows, err = stmt.Query(ConditionArray[0], ConditionArray[1])
	case 3:
		Rows, err = stmt.Query(ConditionArray[0], ConditionArray[1], ConditionArray[2])
	case 4:
		Rows, err = stmt.Query(ConditionArray[0], ConditionArray[1], ConditionArray[2], ConditionArray[3])
	case 5:
		Rows, err = stmt.Query(ConditionArray[0], ConditionArray[1], ConditionArray[2], ConditionArray[3], ConditionArray[4])
	case 6:
		Rows, err = stmt.Query(ConditionArray[0], ConditionArray[1], ConditionArray[2], ConditionArray[3], ConditionArray[4], ConditionArray[5])
	case 7:
		Rows, err = stmt.Query(ConditionArray[0], ConditionArray[1], ConditionArray[2], ConditionArray[3], ConditionArray[4], ConditionArray[5], ConditionArray[6])
	case 8:
		Rows, err = stmt.Query(ConditionArray[0], ConditionArray[1], ConditionArray[2], ConditionArray[3], ConditionArray[4], ConditionArray[5], ConditionArray[6], ConditionArray[7])

	}
	if err != nil {
		return nil
	}

	return Rows
}
func ConditionQuery_DB(Database *sql.DB, QueryStr string) *sql.Rows {

	Rows, err := Database.Query(QueryStr)
	if err != nil {
		log.Println(" Database Query error in ConditionQuery:", err)
		return nil
	}
	return Rows
}

func WebServer_Client_Statistics(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()

	var tmpl *template.Template
	var StatInfo ClientStatisticInfo
	var PageNumInfo PageNumInfo
	var StatPageInfo ClientStatisticPageInfo
	var CommonIDs string
	var CommonRows *sql.Rows
	var CommonRowsCount, PageIndexStart, LastPageNumber, PageNumber, SortNumber, PrevPageNumber, NextPageNumber, PageCount int
	var SortTime, SortNodeID, SortProxyIP, SortNodeIP, SortClientIP int
	var err error
	var OrderBy string
	var Params string
	var QueryStr, QueryCommonCondition, QueryDataCondition, StartTime, EndTime, NodeID, ClientIP, NICIP, NICPort, ProxyIP, ProxyPort string
	var TempStr string

	var ConditionCount int
	var ConditionArray []interface{}

	log.Println("Client Statistics", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}
	if ControlServerFlag == 0 {
		if Node_Flag == Node_FLAG_NONE {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		} else if Node_Flag == Node_FLAG_CLIENT {
			TempStr := fmt.Sprintf("<li class=\"current\"><a href=\"/statistics/client/\">Client Statistics</a></li>")
			StatPageInfo.NodeClientStatMenu = template.HTML(TempStr)
			StatPageInfo.NodeServerStatMenu = ""
		} else if Node_Flag == Node_FLAG_SERVER {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		} else if Node_Flag == Node_FLAG_CLIENT_AND_SERVER {
			TempStr := fmt.Sprintf("<li class=\"current\"><a href=\"/statistics/client/\">Client Statistics</a></li>")
			StatPageInfo.NodeClientStatMenu = template.HTML(TempStr)
			TempStr = fmt.Sprintf("<li><a href=\"/statistics/server/\">Server Statistics</a></li>")
			StatPageInfo.NodeServerStatMenu = template.HTML(TempStr)
		}

		Param_PageNumber, ok := req.URL.Query()["page_num"]
		if !ok || len(Param_PageNumber) < 1 {
			WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
			return
		}

		Param_Sort, ok := req.URL.Query()["sort"]
		if !ok || len(Param_Sort) < 1 {
			WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
			return
		}

		if req.Method == "GET" {
			Param_StartTime, ok := req.URL.Query()["stime"]
			if ok {
				StartTime = fmt.Sprintf("%s", Param_StartTime)
				StartTime = strings.Replace(StartTime, "[", "", -1)
				StartTime = strings.Replace(StartTime, "]", "", -1)
				StartTime = strings.TrimSpace(StartTime)
				if Time_Validate_Check(StartTime) == false {
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					log.Println("Invalid Time")
					return
				}

				StatPageInfo.SearchStartTime = StartTime

				Param_EndTime, ok := req.URL.Query()["etime"]
				if ok {

					EndTime = fmt.Sprintf("%s", Param_EndTime)
					EndTime = strings.Replace(EndTime, "[", "", -1)
					EndTime = strings.Replace(EndTime, "]", "", -1)
					EndTime = strings.TrimSpace(EndTime)
					if Time_Validate_Check(EndTime) == false {
						WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
						log.Println("Invalid Time")
						return
					}
					StatPageInfo.SearchEndTime = EndTime
				} else {
					EndTime, _ = SqliteDBGetServerDate(Database, 0)
					StatPageInfo.SearchEndTime = EndTime
				}
			} else {
				Param_EndTime, ok := req.URL.Query()["etime"]
				if ok {
					EndTime = fmt.Sprintf("%s", Param_EndTime)
					EndTime = strings.Replace(EndTime, "[", "", -1)
					EndTime = strings.Replace(EndTime, "]", "", -1)
					EndTime = strings.TrimSpace(EndTime)
					if Time_Validate_Check(EndTime) == false {
						WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
						log.Println("Invalid Time")
						return
					}
					StatPageInfo.SearchEndTime = EndTime

					StartTime, _ = SqliteDBGetServerDate(Database, 1)
					StatPageInfo.SearchStartTime = StartTime
				}
			}
			log.Println("StartTime ", StartTime, "EndTime ", EndTime)

			Param_ClientIP, ok := req.URL.Query()["cip"]
			if ok {
				ClientIP = fmt.Sprintf("%s", Param_ClientIP)
				ClientIP = strings.Replace(ClientIP, "[", "", -1)
				ClientIP = strings.Replace(ClientIP, "]", "", -1)
				ClientIP = strings.TrimSpace(ClientIP)
				if IP_Validate_Check(ClientIP) == false {
					log.Println("Invalid ClientIP")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchClientIP = ClientIP
			}

			Param_NICIP, ok := req.URL.Query()["nip"]
			if ok {
				NICIP = fmt.Sprintf("%s", Param_NICIP)
				NICIP = strings.Replace(NICIP, "[", "", -1)
				NICIP = strings.Replace(NICIP, "]", "", -1)
				NICIP = strings.TrimSpace(NICIP)
				if IP_Validate_Check(NICIP) == false {
					log.Println("Invalid NICIP")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchNICIP = NICIP
			}
			for i := 0; i < len(NICInfoArray); i++ {
				var NICIPHTML NICIPHTML

				if len(NICIP) > 0 && NICInfoArray[i].IP == NICIP {
					TempStr = fmt.Sprintf("<option selected=\"selected\">%s</option>", NICInfoArray[i].IP)
				} else {
					TempStr = fmt.Sprintf("<option>%s</option>", NICInfoArray[i].IP)
				}
				NICIPHTML.NICIP_HTML = template.HTML(TempStr)
				StatPageInfo.NICIPHTMLList = append(StatPageInfo.NICIPHTMLList, NICIPHTML)
			}

			Param_NICPort, ok := req.URL.Query()["nport"]
			if ok {
				NICPort = fmt.Sprintf("%s", Param_NICPort)
				NICPort = strings.Replace(NICPort, "[", "", -1)
				NICPort = strings.Replace(NICPort, "]", "", -1)
				NICPort = strings.TrimSpace(NICPort)
				if Port_Validate_Check(NICPort) == false {
					log.Println("Invalid NICPort")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchNICPort = NICPort
			}

			Param_ProxyIP, ok := req.URL.Query()["pip"]
			if ok {
				ProxyIP = fmt.Sprintf("%s", Param_ProxyIP)
				ProxyIP = strings.Replace(ProxyIP, "[", "", -1)
				ProxyIP = strings.Replace(ProxyIP, "]", "", -1)
				ProxyIP = strings.TrimSpace(ProxyIP)
				if IP_Validate_Check(ProxyIP) == false {
					log.Println("Invalid ServerIP")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchProxyIP = ProxyIP
			}
			for i := 0; i < len(ProxyIPStrArray); i++ {
				var ProxyIPHTML ProxyIPHTML

				if len(ProxyIP) > 0 && ProxyIPStrArray[i] == ProxyIP {
					TempStr = fmt.Sprintf("<option selected=\"selected\">%s</option>", ProxyIPStrArray[i])
				} else {
					TempStr = fmt.Sprintf("<option>%s</option>", ProxyIPStrArray[i])
				}
				ProxyIPHTML.ProxyIP_HTML = template.HTML(TempStr)
				StatPageInfo.ProxyIPHTMLList = append(StatPageInfo.ProxyIPHTMLList, ProxyIPHTML)
			}

			Param_ProxyPort, ok := req.URL.Query()["pport"]
			if ok {
				ProxyPort = fmt.Sprintf("%s", Param_ProxyPort)
				ProxyPort = strings.Replace(ProxyPort, "[", "", -1)
				ProxyPort = strings.Replace(ProxyPort, "]", "", -1)
				ProxyPort = strings.TrimSpace(ProxyPort)
				if Port_Validate_Check(ProxyPort) == false {
					log.Println("Invalid ServerPort")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchProxyPort = ProxyPort
			}
		} else {
			req.ParseForm()

			StartTime = fmt.Sprintf("%s", req.Form["start_time"])
			StartTime = strings.Replace(StartTime, "[", "", -1)
			StartTime = strings.Replace(StartTime, "]", "", -1)
			StartTime = strings.TrimSpace(StartTime)

			EndTime = fmt.Sprintf("%s", req.Form["end_time"])
			EndTime = strings.Replace(EndTime, "[", "", -1)
			EndTime = strings.Replace(EndTime, "]", "", -1)
			EndTime = strings.TrimSpace(EndTime)

			ClientIP = fmt.Sprintf("%s", req.Form["client_ip"])
			ClientIP = strings.Replace(ClientIP, "[", "", -1)
			ClientIP = strings.Replace(ClientIP, "]", "", -1)
			ClientIP = strings.TrimSpace(ClientIP)

			NICIP = fmt.Sprintf("%s", req.Form["nic_ip"])
			NICIP = strings.Replace(NICIP, "[", "", -1)
			NICIP = strings.Replace(NICIP, "]", "", -1)
			NICIP = strings.TrimSpace(NICIP)

			NICPort = fmt.Sprintf("%s", req.Form["nic_port"])
			NICPort = strings.Replace(NICPort, "[", "", -1)
			NICPort = strings.Replace(NICPort, "]", "", -1)
			NICPort = strings.TrimSpace(NICPort)

			ProxyIP = fmt.Sprintf("%s", req.Form["proxy_ip"])
			ProxyIP = strings.Replace(ProxyIP, "[", "", -1)
			ProxyIP = strings.Replace(ProxyIP, "]", "", -1)
			ProxyIP = strings.TrimSpace(ProxyIP)

			ProxyPort = fmt.Sprintf("%s", req.Form["proxy_port"])
			ProxyPort = strings.Replace(ProxyPort, "[", "", -1)
			ProxyPort = strings.Replace(ProxyPort, "]", "", -1)
			ProxyPort = strings.TrimSpace(ProxyPort)
		}

		if len(StartTime) > 0 {
			Params += fmt.Sprintf("&stime=%s", StartTime)
		}

		if len(EndTime) > 0 {
			Params += fmt.Sprintf("&etime=%s", EndTime)
		}

		if len(StartTime) > 0 && len(EndTime) > 0 {
			//QueryCommonCondition += fmt.Sprintf("AND (Time BETWEEN \"%s\" AND \"%s\")", StartTime, EndTime)
			QueryCommonCondition += fmt.Sprintf("AND (Time BETWEEN ? AND ? )")
			ConditionArray = append(ConditionArray, StartTime, EndTime)
			ConditionCount += 2

		}

		if len(ClientIP) > 0 {
			Params += fmt.Sprintf("&cip=%s", ClientIP)
			if StrtoIP(ClientIP) != 0 {
				//	QueryCommonCondition += fmt.Sprintf("AND (Client_IP_TEXT=\"%s\")", ClientIP)
				QueryCommonCondition += fmt.Sprintf("AND (Client_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ClientIP)
				ConditionCount++

			} else {
				//	QueryCommonCondition += fmt.Sprintf("AND (Client_IP_TEXT LIKE \"%s%%\")", ClientIP)
				QueryCommonCondition += fmt.Sprintf("AND (Client_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ClientIP+"%")
				ConditionCount++

			}
		}

		if len(NICIP) > 0 && NICIP != "All" {
			Params += fmt.Sprintf("&nip=%s", NICIP)
			if StrtoIP(NICIP) != 0 {
				//	QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT=\"%s\")", NICIP)
				QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, NICIP)
				ConditionCount++

			} else {
				//	QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT LIKE \"%s%%\")", NICIP)
				QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, NICIP+"%")
				ConditionCount++

			}
		}

		if len(NICPort) > 0 {
			Params += fmt.Sprintf("&nport=%s", NICPort)
			TempInt, _ := strconv.Atoi(NICPort)
			if TempInt > 0 {
				//QueryCommonCondition += fmt.Sprintf("AND (Node_Listen_Port=%d)", TempInt)
				QueryCommonCondition += fmt.Sprintf("AND (Node_Listen_Port=?)")
				ConditionArray = append(ConditionArray, TempInt)
				ConditionCount++

			}
		}

		if len(ProxyIP) > 0 && ProxyIP != "All" {
			Params += fmt.Sprintf("&pip=%s", ProxyIP)
			if StrtoIP(ProxyIP) != 0 {
				//QueryDataCondition += fmt.Sprintf("AND (Proxy_IP_TEXT=\"%s\")", ProxyIP)
				QueryDataCondition += fmt.Sprintf("AND (Proxy_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ProxyIP)
				ConditionCount++

			} else {
				//QueryDataCondition += fmt.Sprintf("AND (Proxy_IP_TEXT LIKE \"%s%%\")", ProxyIP)
				QueryDataCondition += fmt.Sprintf("AND (Proxy_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ProxyIP+"%")
				ConditionCount++

			}
		}

		if len(ProxyPort) > 0 {
			Params += fmt.Sprintf("&pport=%s", ProxyPort)
			TempInt, _ := strconv.Atoi(ProxyPort)
			if TempInt > 0 {
				//QueryDataCondition += fmt.Sprintf("AND (Proxy_Listen_Port=%d)", TempInt)
				QueryDataCondition += fmt.Sprintf("AND (Proxy_Listen_Port=?)")
				ConditionArray = append(ConditionArray, TempInt)
				ConditionCount++

			}
		}

		if req.Method == "POST" {
			StatURL := "/statistics/client/?page_num=1&sort=0"
			if len(Params) > 0 {
				StatURL += Params
			}

			WebServer_Redirect(w, req, StatURL)
			return
		}

		PageNumberStr := fmt.Sprintf("%s", Param_PageNumber)
		PageNumberStr = strings.Replace(PageNumberStr, "[", "", -1)
		PageNumberStr = strings.Replace(PageNumberStr, "]", "", -1)

		SortStr := fmt.Sprintf("%s", Param_Sort)
		SortStr = strings.Replace(SortStr, "[", "", -1)
		SortStr = strings.Replace(SortStr, "]", "", -1)

		PageNumber, err = strconv.Atoi(PageNumberStr)
		if err != nil {
			log.Println("failed to PageNumber Atoi")
			return
		}

		SortNumber, err = strconv.Atoi(SortStr)
		if err != nil {
			log.Println("failed to SortNumber strconv.Atoi")
			return
		}

		DESC_Dir := "▼"
		ASC_Dir := "▲"
		NONE_Dir := "-"

		SortTime = SortTime_ASC
		SortProxyIP = SortProxyIP_ASC
		SortNodeIP = SortNodeIP_ASC
		SortClientIP = SortClientIP_ASC

		SortTimeDir := NONE_Dir
		SortProxyIPDir := NONE_Dir
		SortNodeIPDir := NONE_Dir
		SortClientIPDir := NONE_Dir

		switch SortNumber {
		case SortTime_ASC:
			SortTime = SortTime_DESC
			SortTimeDir = DESC_Dir

			OrderBy = "Time DESC"
		case SortClientIP_ASC:
			SortClientIP = SortClientIP_DESC
			SortClientIPDir = DESC_Dir

			OrderBy = "Client_IP_INT  DESC"
		case SortNodeIP_ASC:
			SortNodeIP = SortNodeIP_DESC
			SortNodeIPDir = DESC_Dir

			OrderBy = "Node_IP_INT DESC"
		case SortProxyIP_ASC:
			SortProxyIP = SortProxyIP_DESC
			SortProxyIPDir = DESC_Dir

			OrderBy = "Time DESC, B.Proxy_IP_INT DESC"
		case SortTime_DESC:
			SortTime = SortTime_ASC
			SortTimeDir = ASC_Dir

			OrderBy = "Time ASC"
		case SortClientIP_DESC:
			SortClientIP = SortClientIP_ASC
			SortClientIPDir = ASC_Dir

			OrderBy = "Client_IP_INT ASC"
		case SortNodeIP_DESC:
			SortNodeIP = SortNodeIP_ASC
			SortNodeIPDir = ASC_Dir

			OrderBy = "Node_IP_INT ASC"
		case SortProxyIP_DESC:
			SortProxyIP = SortProxyIP_ASC
			SortProxyIPDir = ASC_Dir

			OrderBy = "Time DESC, B.Proxy_IP_INT ASC"
		}

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/client/?page_num=1&sort=%d%s\">Collection Time %s</a></th>", SortTime, Params, SortTimeDir)
		StatPageInfo.SortTime = template.HTML(TempStr)

		fmt.Println("TempStr:", TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/client/?page_num=1&sort=%d%s\">Client IP %s</a></th>", SortClientIP, Params, SortClientIPDir)
		StatPageInfo.SortClientIP = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/client/?page_num=1&sort=%d%s\">Node Client IP %s</a></th>", SortNodeIP, Params, SortNodeIPDir)
		StatPageInfo.SortNodeIP = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/client/?page_num=1&sort=%d%s\">Proxy IP %s</a></th>", SortProxyIP, Params, SortProxyIPDir)
		StatPageInfo.SortProxyIP = template.HTML(TempStr)

		tmpl, err = template.ParseFiles("./pages/Node_Client_Statistics.html")
		if err != nil {
			log.Println("failed to template.ParseFiles")
			return
		}

		NextRowOffset := (PageNumber - 1) * RowCountPerPage

		QueryStr = fmt.Sprintf("SELECT COUNT(DISTINCT A.ID) FROM Client_Statistics_Common as A JOIN Client_Statistics_Data as B ON B.ID = A.ID WHERE 1=1 %s AND 1=1 %s", QueryCommonCondition, QueryDataCondition)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}

		for CommonRows.Next() {
			err = CommonRows.Scan(&CommonRowsCount)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}
		}
		CommonRows.Close()

		PageCount = int(math.Ceil(float64(CommonRowsCount) / float64(RowCountPerPage)))
		if PageNumber < PageCount {
			NextPageNumber = PageNumber + 1
		} else {
			NextPageNumber = PageCount
		}

		CommonID := 0
		PrevCommonID := 0

		QueryStr = fmt.Sprintf("SELECT distinct A.ID  FROM ( SELECT * FROM Client_Statistics_Common WHERE 1=1 %s) A JOIN ( SELECT * FROM Client_Statistics_Data WHERE 1=1 %s) B ON A.ID = B.ID ORDER BY %s LIMIT %d OFFSET %d", QueryCommonCondition, QueryDataCondition, OrderBy, RowCountPerPage, NextRowOffset)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}

		for CommonRows.Next() {
			err = CommonRows.Scan(&CommonID)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}
			if len(CommonIDs) > 0 {
				CommonIDs += ","
			}
			CommonIDs += fmt.Sprintf("%d", CommonID)
		}
		CommonRows.Close()

		if len(CommonIDs) == 0 {
			tmpl.Execute(w, StatPageInfo)
			return
		}

		data_group_id := 0
		data_first := 0

		QueryStr = fmt.Sprintf("SELECT * FROM ( SELECT * FROM Client_Statistics_Common WHERE 1=1 %s) A JOIN ( SELECT ID, Proxy_IP_INT, Proxy_IP_TEXT, Proxy_Listen_Port, SUM(Inbound), SUM(Outbound) FROM Client_Statistics_Data WHERE 1=1 %s GROUP BY ID, Proxy_IP_INT, Proxy_Listen_Port ) B ON A.ID = B.ID WHERE A.ID IN (%s) ORDER BY %s", QueryCommonCondition, QueryDataCondition, CommonIDs, OrderBy)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}

		for CommonRows.Next() {
			err = CommonRows.Scan(&CommonID, &StatInfo.StatCommon.Time, &StatInfo.StatCommon.Node_ID_Str, &StatInfo.StatCommon.Client_IP_Int, &StatInfo.StatCommon.Client_IP_Str, &StatInfo.StatCommon.Node_IP_Int, &StatInfo.StatCommon.Node_IP_Str, &StatInfo.StatCommon.Node_Listen_Port, &CommonID, &StatInfo.StatData.Proxy_IP_Int, &StatInfo.StatData.Proxy_IP_Str, &StatInfo.StatData.Proxy_Listen_Port, &StatInfo.StatData.Inbound, &StatInfo.StatData.Outbound)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}

			if PrevCommonID == 0 {
				PrevCommonID = CommonID
				data_first = 1
			} else if PrevCommonID != CommonID {
				data_first = 1
				PrevCommonID = CommonID
				data_group_id++
			}

			StatInfo.StatCommon.TrInfo.DataGroupID = strconv.Itoa(data_group_id)
			StatInfo.StatCommon.TrInfo.DataFirst = strconv.Itoa(data_first)

			if data_first == 1 {
				StatInfo.StatCommon.TrInfo.Style = "view"
				data_first = 0
			} else {
				StatInfo.StatCommon.TrInfo.Style = "none"
			}

			StatPageInfo.StatInfo = append(StatPageInfo.StatInfo, StatInfo)
		}
		CommonRows.Close()

		if PageNumber > 1 {
			PrevPageNumber = PageNumber - 1
		} else {
			PrevPageNumber = 1
		}

		TempStr = fmt.Sprintf("/statistics/client/?page_num=%d&sort=%d%s", 1, SortNumber, Params)
		StatPageInfo.FirstPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/client/?page_num=%d&sort=%d%s", PrevPageNumber, SortNumber, Params)
		StatPageInfo.PrevPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/client/?page_num=%d&sort=%d%s", NextPageNumber, SortNumber, Params)
		StatPageInfo.NextPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/client/?page_num=%d&sort=%d%s", PageCount, SortNumber, Params)
		StatPageInfo.LastPage = template.HTML(TempStr)

		PageIndexStart = (((PageNumber - 1) / MaxPageCountInPage) * MaxPageCountInPage) + 1

		if PageCount > MaxPageCountInPage {
			LastPageNumber = PageIndexStart + (MaxPageCountInPage - 1)
		} else {
			LastPageNumber = PageCount
		}

		if LastPageNumber > PageCount {
			LastPageNumber = PageCount
		}

		for page_index := PageIndexStart; page_index <= LastPageNumber; page_index++ {
			PageNumInfo.PageNum = page_index
			if PageNumInfo.PageNum == PageNumber {
				PageNumInfo.TagStart = "<strong>"
				PageNumInfo.TagEnd = "</strong>"
			} else {
				TempTag := fmt.Sprintf("<a href=\"/statistics/client/?page_num=%d&sort=%d%s\">", PageNumInfo.PageNum, SortNumber, Params)
				PageNumInfo.TagStart = template.HTML(TempTag)
				PageNumInfo.TagEnd = "</a>"
			}

			StatPageInfo.PageNumInfo = append(StatPageInfo.PageNumInfo, PageNumInfo)
		}
	} else {

		TempStr := fmt.Sprintf("<li class=\"current\"><a href=\"/statistics/client/\">Client Statistics</a></li>")
		StatPageInfo.NodeClientStatMenu = template.HTML(TempStr)
		TempStr = fmt.Sprintf("<li><a href=\"/statistics/server/\">Server Statistics</a></li>")
		StatPageInfo.NodeServerStatMenu = template.HTML(TempStr)

		Param_PageNumber, ok := req.URL.Query()["page_num"]
		if !ok || len(Param_PageNumber) < 1 {
			WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
			return
		}

		Param_Sort, ok := req.URL.Query()["sort"]
		if !ok || len(Param_Sort) < 1 {
			WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
			return
		}

		if req.Method == "GET" {
			log.Println("Client Statistics GET")
			Param_StartTime, ok := req.URL.Query()["stime"]
			if ok {
				StartTime = fmt.Sprintf("%s", Param_StartTime)
				StartTime = strings.Replace(StartTime, "[", "", -1)
				StartTime = strings.Replace(StartTime, "]", "", -1)
				StartTime = strings.TrimSpace(StartTime)

				if Time_Validate_Check(StartTime) == false {
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchStartTime = StartTime

				Param_EndTime, ok := req.URL.Query()["etime"]
				if ok {
					log.Println("Parma_EndTime :", Param_EndTime)
					EndTime = fmt.Sprintf("%s", Param_EndTime)
					EndTime = strings.Replace(EndTime, "[", "", -1)
					EndTime = strings.Replace(EndTime, "]", "", -1)
					EndTime = strings.TrimSpace(EndTime)

					if Time_Validate_Check(EndTime) == false {
						WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
						return
					}
					StatPageInfo.SearchEndTime = EndTime
				} else {
					EndTime = MariaDBGetServerDate(Database, 0)
					StatPageInfo.SearchEndTime = EndTime
				}
			} else {
				Param_EndTime, ok := req.URL.Query()["etime"]
				if ok {
					EndTime = fmt.Sprintf("%s", Param_EndTime)
					EndTime = strings.Replace(EndTime, "[", "", -1)
					EndTime = strings.Replace(EndTime, "]", "", -1)
					EndTime = strings.TrimSpace(EndTime)
					StatPageInfo.SearchEndTime = EndTime

					if Time_Validate_Check(EndTime) == false {
						WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
						return
					}

					StartTime = MariaDBGetServerDate(Database, 1)
					StatPageInfo.SearchStartTime = StartTime
				}
			}
			log.Println("StartTime ", StartTime, "EndTime ", EndTime)

			Param_NodeID, ok := req.URL.Query()["Nodeid"]
			if ok {
				NodeID = fmt.Sprintf("%s", Param_NodeID)
				NodeID = strings.Replace(NodeID, "[", "", -1)
				NodeID = strings.Replace(NodeID, "]", "", -1)
				NodeID = strings.TrimSpace(NodeID)

				if UUID_Validate_Check(NodeID) == false {
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchNodeID = NodeID
			}

			Param_ClientIP, ok := req.URL.Query()["cip"]
			if ok {
				ClientIP = fmt.Sprintf("%s", Param_ClientIP)
				ClientIP = strings.Replace(ClientIP, "[", "", -1)
				ClientIP = strings.Replace(ClientIP, "]", "", -1)
				ClientIP = strings.TrimSpace(ClientIP)

				if IP_Validate_Check(ClientIP) == false {
					log.Println("Invalid ClientIP")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchClientIP = ClientIP
			}

			Param_NICIP, ok := req.URL.Query()["nip"]
			if ok {
				NICIP = fmt.Sprintf("%s", Param_NICIP)
				NICIP = strings.Replace(NICIP, "[", "", -1)
				NICIP = strings.Replace(NICIP, "]", "", -1)
				NICIP = strings.TrimSpace(NICIP)

				if IP_Validate_Check(NICIP) == false {
					log.Println("Invalid NICIP")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchNICIP = NICIP
			}

			Param_NICPort, ok := req.URL.Query()["nport"]
			if ok {
				NICPort = fmt.Sprintf("%s", Param_NICPort)
				NICPort = strings.Replace(NICPort, "[", "", -1)
				NICPort = strings.Replace(NICPort, "]", "", -1)
				NICPort = strings.TrimSpace(NICPort)
				if Port_Validate_Check(NICPort) == false {
					log.Println("Invalid NICPort")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchNICPort = NICPort
			}

			Param_ProxyIP, ok := req.URL.Query()["pip"]
			if ok {
				ProxyIP = fmt.Sprintf("%s", Param_ProxyIP)
				ProxyIP = strings.Replace(ProxyIP, "[", "", -1)
				ProxyIP = strings.Replace(ProxyIP, "]", "", -1)
				ProxyIP = strings.TrimSpace(ProxyIP)
				if IP_Validate_Check(ProxyIP) == false {
					log.Println("Invalid ServerIP")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}
				StatPageInfo.SearchProxyIP = ProxyIP
			}

			Param_ProxyPort, ok := req.URL.Query()["pport"]
			if ok {
				ProxyPort = fmt.Sprintf("%s", Param_ProxyPort)
				ProxyPort = strings.Replace(ProxyPort, "[", "", -1)
				ProxyPort = strings.Replace(ProxyPort, "]", "", -1)
				ProxyPort = strings.TrimSpace(ProxyPort)
				if Port_Validate_Check(ProxyPort) == false {
					log.Println("Invalid ServerPort")
					WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
					return
				}

				StatPageInfo.SearchProxyPort = ProxyPort
			}
		} else {
			log.Println("Client Statistics POST")
			req.ParseForm()

			StartTime = fmt.Sprintf("%s", req.Form["start_time"])
			StartTime = strings.Replace(StartTime, "[", "", -1)
			StartTime = strings.Replace(StartTime, "]", "", -1)
			StartTime = strings.TrimSpace(StartTime)

			EndTime = fmt.Sprintf("%s", req.Form["end_time"])
			EndTime = strings.Replace(EndTime, "[", "", -1)
			EndTime = strings.Replace(EndTime, "]", "", -1)
			EndTime = strings.TrimSpace(EndTime)

			NodeID = fmt.Sprintf("%s", req.Form["Node_id"])
			NodeID = strings.Replace(NodeID, "[", "", -1)
			NodeID = strings.Replace(NodeID, "]", "", -1)
			NodeID = strings.TrimSpace(NodeID)

			ClientIP = fmt.Sprintf("%s", req.Form["client_ip"])
			ClientIP = strings.Replace(ClientIP, "[", "", -1)
			ClientIP = strings.Replace(ClientIP, "]", "", -1)
			ClientIP = strings.TrimSpace(ClientIP)

			NICIP = fmt.Sprintf("%s", req.Form["nic_ip"])
			NICIP = strings.Replace(NICIP, "[", "", -1)
			NICIP = strings.Replace(NICIP, "]", "", -1)
			NICIP = strings.TrimSpace(NICIP)

			NICPort = fmt.Sprintf("%s", req.Form["nic_port"])
			NICPort = strings.Replace(NICPort, "[", "", -1)
			NICPort = strings.Replace(NICPort, "]", "", -1)
			NICPort = strings.TrimSpace(NICPort)

			ProxyIP = fmt.Sprintf("%s", req.Form["proxy_ip"])
			ProxyIP = strings.Replace(ProxyIP, "[", "", -1)
			ProxyIP = strings.Replace(ProxyIP, "]", "", -1)
			ProxyIP = strings.TrimSpace(ProxyIP)

			ProxyPort = fmt.Sprintf("%s", req.Form["proxy_port"])
			ProxyPort = strings.Replace(ProxyPort, "[", "", -1)
			ProxyPort = strings.Replace(ProxyPort, "]", "", -1)
			ProxyPort = strings.TrimSpace(ProxyPort)
		}

		if len(StartTime) > 0 {
			Params += fmt.Sprintf("&stime=%s", StartTime)
		}

		if len(EndTime) > 0 {
			Params += fmt.Sprintf("&etime=%s", EndTime)
		}

		if len(StartTime) > 0 && len(EndTime) > 0 {
			// QueryCommonCondition += fmt.Sprintf("AND (Time BETWEEN \"%s\" AND \"%s\")", StartTime, EndTime)
			QueryCommonCondition += fmt.Sprintf("AND (Time BETWEEN ? AND ? )")
			ConditionArray = append(ConditionArray, StartTime, EndTime)
			ConditionCount += 2
		}

		if len(NodeID) > 0 {
			Params += fmt.Sprintf("&Nodeid=%s", NodeID)
			if StrtoUUID(NodeID) != 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Node_ID_TEXT=?)")
				ConditionArray = append(ConditionArray, NodeID)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Node_ID_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, NodeID+"%")
				ConditionCount++

			}
		}

		if len(ClientIP) > 0 {
			Params += fmt.Sprintf("&cip=%s", ClientIP)
			if StrtoIP(ClientIP) != 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Client_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ClientIP)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Client_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ClientIP+"%")
				ConditionCount++
			}
		}

		if len(NICIP) > 0 && NICIP != "All" {
			Params += fmt.Sprintf("&nip=%s", NICIP)
			if StrtoIP(NICIP) != 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, NICIP)
				ConditionCount++

			} else {
				QueryCommonCondition += fmt.Sprintf("AND (Node_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, NICIP+"%")
				ConditionCount++

			}

		}

		if len(NICPort) > 0 {
			Params += fmt.Sprintf("&nport=%s", NICPort)
			TempInt, _ := strconv.Atoi(NICPort)
			if TempInt > 0 {
				QueryCommonCondition += fmt.Sprintf("AND (Node_Listen_Port=?)")
				ConditionArray = append(ConditionArray, TempInt)
				ConditionCount++
			}
		}

		if len(ProxyIP) > 0 && ProxyIP != "All" {
			Params += fmt.Sprintf("&pip=%s", ProxyIP)
			if StrtoIP(ProxyIP) != 0 {
				QueryDataCondition += fmt.Sprintf("AND (Proxy_IP_TEXT=?)")
				ConditionArray = append(ConditionArray, ProxyIP)
				ConditionCount++

			} else {
				QueryDataCondition += fmt.Sprintf("AND (Proxy_IP_TEXT LIKE ?)")
				ConditionArray = append(ConditionArray, ProxyIP+"%")
				ConditionCount++

			}
		}

		if len(ProxyPort) > 0 {
			Params += fmt.Sprintf("&pport=%s", ProxyPort)
			TempInt, _ := strconv.Atoi(ProxyPort)
			if TempInt > 0 {
				QueryDataCondition += fmt.Sprintf("AND (Proxy_Listen_Port=?)")
				ConditionArray = append(ConditionArray, TempInt)
				ConditionCount++
			}
		}

		if req.Method == "POST" {
			StatURL := "/statistics/client/?page_num=1&sort=0"
			if len(Params) > 0 {
				StatURL += Params
			}

			WebServer_Redirect(w, req, StatURL)
			return
		}

		PageNumberStr := fmt.Sprintf("%s", Param_PageNumber)
		PageNumberStr = strings.Replace(PageNumberStr, "[", "", -1)
		PageNumberStr = strings.Replace(PageNumberStr, "]", "", -1)

		SortStr := fmt.Sprintf("%s", Param_Sort)
		SortStr = strings.Replace(SortStr, "[", "", -1)
		SortStr = strings.Replace(SortStr, "]", "", -1)

		PageNumber, err = strconv.Atoi(PageNumberStr)
		if err != nil {
			log.Println("failed to strconv.Atoi")
			StatURL := "/statistics/client/?page_num=1&sort=0"
			WebServer_Redirect(w, req, StatURL)
			return
		}

		SortNumber, err = strconv.Atoi(SortStr)
		if err != nil {
			log.Println("failed to strconv.Atoi")
			StatURL := "/statistics/client/?page_num=1&sort=0"
			WebServer_Redirect(w, req, StatURL)
			return
		}

		DESC_Dir := "▼"
		ASC_Dir := "▲"
		NONE_Dir := "-"

		SortTime = SortTime_ASC
		SortNodeID = SortNodeID_ASC
		SortProxyIP = SortProxyIP_ASC
		SortNodeIP = SortNodeIP_ASC
		SortClientIP = SortClientIP_ASC

		SortTimeDir := NONE_Dir
		SortNodeIDDir := NONE_Dir
		SortProxyIPDir := NONE_Dir
		SortNodeIPDir := NONE_Dir
		SortClientIPDir := NONE_Dir

		switch SortNumber {
		case SortTime_ASC:
			SortTime = SortTime_DESC
			SortTimeDir = DESC_Dir

			OrderBy = "Time DESC"
		case SortNodeID_ASC:
			SortNodeID = SortNodeID_DESC
			SortNodeIDDir = DESC_Dir

			OrderBy = "Node_ID_TEXT DESC"
		case SortClientIP_ASC:
			SortClientIP = SortClientIP_DESC
			SortClientIPDir = DESC_Dir

			OrderBy = "Client_IP_INT DESC"
		case SortNodeIP_ASC:
			SortNodeIP = SortNodeIP_DESC
			SortNodeIPDir = DESC_Dir

			OrderBy = "Node_IP_INT DESC"
		case SortProxyIP_ASC:
			SortProxyIP = SortProxyIP_DESC
			SortProxyIPDir = DESC_Dir

			OrderBy = "Time DESC, B.Proxy_IP_INT DESC"
		case SortTime_DESC:
			SortTime = SortTime_ASC
			SortTimeDir = ASC_Dir

			OrderBy = "Time ASC"
		case SortNodeID_DESC:
			SortNodeID = SortNodeID_ASC
			SortNodeIDDir = ASC_Dir

			OrderBy = "Node_ID_TEXT ASC"
		case SortClientIP_DESC:
			SortClientIP = SortClientIP_ASC
			SortClientIPDir = ASC_Dir

			OrderBy = "Client_IP_INT ASC"
		case SortNodeIP_DESC:
			SortNodeIP = SortNodeIP_ASC
			SortNodeIPDir = ASC_Dir

			OrderBy = "Node_IP_INT ASC"
		case SortProxyIP_DESC:
			SortProxyIP = SortProxyIP_ASC
			SortProxyIPDir = ASC_Dir

			OrderBy = "Time DESC, B.Proxy_IP_INT ASC"
		}

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/client/?page_num=1&sort=%d%s\">Collection Time %s</a></th>", SortTime, Params, SortTimeDir)
		StatPageInfo.SortTime = template.HTML(TempStr)

		log.Println("TempStr:", TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/client/?page_num=1&sort=%d%s\">Node ID %s</a></th>", SortNodeID, Params, SortNodeIDDir)
		StatPageInfo.SortNodeID = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/client/?page_num=1&sort=%d%s\">Client IP %s</a></th>", SortClientIP, Params, SortClientIPDir)
		StatPageInfo.SortClientIP = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/client/?page_num=1&sort=%d%s\">Node Client IP %s</a></th>", SortNodeIP, Params, SortNodeIPDir)
		StatPageInfo.SortNodeIP = template.HTML(TempStr)

		TempStr = fmt.Sprintf("<th><a href=\"/statistics/client/?page_num=1&sort=%d%s\">Proxy IP %s</a></th>", SortProxyIP, Params, SortProxyIPDir)
		StatPageInfo.SortProxyIP = template.HTML(TempStr)

		tmpl, err = template.ParseFiles("./pages/Control_Node_Client_Statistics.html")
		if err != nil {
			log.Println("failed to template.ParseFiles")
			return
		}

		NextRowOffset := (PageNumber - 1) * RowCountPerPage
		QueryStr = fmt.Sprintf("SELECT COUNT(DISTINCT A.ID) FROM CLIENT_STATISTICS_COMMON as A JOIN CLIENT_STATISTICS_DATA as B ON B.ID = A.ID WHERE 1=1 %s AND 1=1 %s", QueryCommonCondition, QueryDataCondition)
		log.Println("ConditionCount :", ConditionCount, "CommonCondition : [", QueryCommonCondition, "] QueryDataConditon : [", QueryDataCondition, "]")

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}
		for CommonRows.Next() {
			err := CommonRows.Scan(&CommonRowsCount)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}
		}

		CommonRows.Close()

		PageCount = int(math.Ceil(float64(CommonRowsCount) / float64(RowCountPerPage)))
		if PageNumber < PageCount {
			NextPageNumber = PageNumber + 1
		} else {
			NextPageNumber = PageCount
		}

		CommonID := 0
		PrevCommonID := 0

		QueryStr = fmt.Sprintf("SELECT distinct A.ID  FROM ( SELECT * FROM CLIENT_STATISTICS_COMMON  WHERE 1=1 %s) A JOIN ( SELECT * FROM CLIENT_STATISTICS_DATA WHERE 1=1 %s) B ON A.ID = B.ID ORDER BY %s LIMIT %d OFFSET %d", QueryCommonCondition, QueryDataCondition, OrderBy, RowCountPerPage, NextRowOffset)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}
		for CommonRows.Next() {
			err := CommonRows.Scan(&CommonID)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}
			if len(CommonIDs) > 0 {
				CommonIDs += ","
			}
			CommonIDs += fmt.Sprintf("%d", CommonID)
		}
		CommonRows.Close()

		if len(CommonIDs) == 0 {
			tmpl.Execute(w, StatPageInfo)
			return
		}

		data_group_id := 0
		data_first := 0

		QueryStr = fmt.Sprintf("SELECT * FROM ( SELECT * FROM CLIENT_STATISTICS_COMMON WHERE 1=1 %s) A JOIN ( SELECT ID, Proxy_IP_INT, Proxy_IP_TEXT, Proxy_Listen_Port, SUM(Inbound), SUM(Outbound) FROM CLIENT_STATISTICS_DATA WHERE 1=1 %s GROUP BY ID, Proxy_IP_INT, Proxy_Listen_Port ) B ON A.ID = B.ID WHERE A.ID IN (%s) ORDER BY %s", QueryCommonCondition, QueryDataCondition, CommonIDs, OrderBy)

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}
		for CommonRows.Next() {
			err := CommonRows.Scan(&CommonID, &StatInfo.StatCommon.Time, &StatInfo.StatCommon.Node_ID_Str, &StatInfo.StatCommon.Client_IP_Int, &StatInfo.StatCommon.Client_IP_Str, &StatInfo.StatCommon.Node_IP_Int, &StatInfo.StatCommon.Node_IP_Str, &StatInfo.StatCommon.Node_Listen_Port, &CommonID, &StatInfo.StatData.Proxy_IP_Int, &StatInfo.StatData.Proxy_IP_Str, &StatInfo.StatData.Proxy_Listen_Port, &StatInfo.StatData.Inbound, &StatInfo.StatData.Outbound)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}

			if PrevCommonID == 0 {
				PrevCommonID = CommonID
				data_first = 1
			} else if PrevCommonID != CommonID {
				data_first = 1
				PrevCommonID = CommonID
				data_group_id++
			}

			StatInfo.StatCommon.TrInfo.DataGroupID = strconv.Itoa(data_group_id)
			StatInfo.StatCommon.TrInfo.DataFirst = strconv.Itoa(data_first)

			if data_first == 1 {
				StatInfo.StatCommon.TrInfo.Style = "view"
				data_first = 0
			} else {
				StatInfo.StatCommon.TrInfo.Style = "none"
			}

			StatPageInfo.StatInfo = append(StatPageInfo.StatInfo, StatInfo)
		}
		CommonRows.Close()

		if PageNumber > 1 {
			PrevPageNumber = PageNumber - 1
		} else {
			PrevPageNumber = 1
		}

		TempStr = fmt.Sprintf("/statistics/client/?page_num=%d&sort=%d%s", 1, SortNumber, Params)
		StatPageInfo.FirstPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/client/?page_num=%d&sort=%d%s", PrevPageNumber, SortNumber, Params)
		StatPageInfo.PrevPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/client/?page_num=%d&sort=%d%s", NextPageNumber, SortNumber, Params)
		StatPageInfo.NextPage = template.HTML(TempStr)

		TempStr = fmt.Sprintf("/statistics/client/?page_num=%d&sort=%d%s", PageCount, SortNumber, Params)
		StatPageInfo.LastPage = template.HTML(TempStr)

		PageIndexStart = (((PageNumber - 1) / MaxPageCountInPage) * MaxPageCountInPage) + 1

		if PageCount > MaxPageCountInPage {
			LastPageNumber = PageIndexStart + (MaxPageCountInPage - 1)
		} else {
			LastPageNumber = PageCount
		}

		if LastPageNumber > PageCount {
			LastPageNumber = PageCount
		}

		for page_index := PageIndexStart; page_index <= LastPageNumber; page_index++ {
			PageNumInfo.PageNum = page_index
			if PageNumInfo.PageNum == PageNumber {
				PageNumInfo.TagStart = "<strong>"
				PageNumInfo.TagEnd = "</strong>"
			} else {
				TempTag := fmt.Sprintf("<a href=\"/statistics/client/?page_num=%d&sort=%d%s\">", PageNumInfo.PageNum, SortNumber, Params)
				PageNumInfo.TagStart = template.HTML(TempTag)
				PageNumInfo.TagEnd = "</a>"
			}

			StatPageInfo.PageNumInfo = append(StatPageInfo.PageNumInfo, PageNumInfo)
		}
	}
	tmpl.Execute(w, StatPageInfo)
}

func WebServer_Redirect(w http.ResponseWriter, req *http.Request, dir string) {
	defer req.Body.Close()

	HostStr := fmt.Sprintf("http://%s%s", req.Host, dir)

	http.Redirect(w, req, HostStr, 302)
}

func SQL_Injection_ID_Check(ID string) bool {
	ID = "admin"

	re := regexp.MustCompile("([?:;`~|!;$%@'\"{}<>(),& /#=+--\r\n])|([A-Z])|([\u4e00-\u9fff])")

	if re.MatchString(ID) == true || strings.Contains(ID, "\\") == true || strings.Contains(ID, ".") == true {
		log.Println("Forbidden String:", true)
		return true
	} else {
		log.Println("Forbidden String:", false)
		return false
	}
}

func SQL_Injection_PW_Check(Password string) bool {

	log.Println(Password)

	re := regexp.MustCompile("([\u4e00-\u9fff])")

	if re.MatchString(Password) == true {

		log.Println("Invalid Password:", Password)

		return true
	} else {

		log.Println("Valid Password:", Password)
		return false
	}
}
func Time_Validate_Check(Time string) bool {

	re := regexp.MustCompile("^([0-9][0-9][0-9][0-9])-(0[0-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$")

	if re.MatchString(Time) == true {
		log.Println("Valid Time:", Time)
		return true
	} else {
		log.Println("Invalid Time:", Time)
		return false
	}

}
func IP_Validate_Check(IP string) bool {

	re := regexp.MustCompile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){1,3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]){0,1}$`)

	if re.MatchString(IP) == true {
		log.Println("Valid IP:", IP)
		return true
	} else {
		log.Println("Invalid IP:", IP)
		return false
	}

}
func UUID_Validate_Check(UUID string) bool {

	re := regexp.MustCompile("^([0-9a-fA-F]{1,9}-[0-9a-fA-F]{1,5}-[0-9a-fA-F]{1,5}-[0-9a-fA-F]{1,5}-[0-9a-fA-F]{1,13})$")

	if re.MatchString(UUID) == true {
		log.Println("Valid UUID:", UUID)
		return true
	} else {
		log.Println("Invalid UUID:", UUID)
		return false
	}

}
func Port_Validate_Check(PortStr string) bool {

	Port, err := strconv.Atoi(PortStr)
	if err == nil {
		log.Println("Valid Port:", Port)
		return true
	} else {
		log.Println("Invalid Port:", Port)
		return false
	}
}

func Change_Spec_Char(Password string) string {

	Password = strings.ReplaceAll(Password, "`", "Ga")
	Password = strings.ReplaceAll(Password, "~", "Ti")
	Password = strings.ReplaceAll(Password, "!", "Em")
	Password = strings.ReplaceAll(Password, "@", "As")
	Password = strings.ReplaceAll(Password, "#", "Ns")
	Password = strings.ReplaceAll(Password, "$", "Da")
	Password = strings.ReplaceAll(Password, "%", "Ps")
	Password = strings.ReplaceAll(Password, "^", "Ca")
	Password = strings.ReplaceAll(Password, "&", "Am")
	Password = strings.ReplaceAll(Password, "*", "Ar")
	Password = strings.ReplaceAll(Password, "(", "Lp")
	Password = strings.ReplaceAll(Password, ")", "Rp")
	Password = strings.ReplaceAll(Password, "_", "Hm")
	Password = strings.ReplaceAll(Password, "-", "Us")
	Password = strings.ReplaceAll(Password, "=", "Es")
	Password = strings.ReplaceAll(Password, "+", "Pl")
	Password = strings.ReplaceAll(Password, "[", "Lb")
	Password = strings.ReplaceAll(Password, "]", "Rb")
	Password = strings.ReplaceAll(Password, "{", "Lc")
	Password = strings.ReplaceAll(Password, "}", "Rc")
	Password = strings.ReplaceAll(Password, "\\", "Ba")
	Password = strings.ReplaceAll(Password, "|", "Vb")
	Password = strings.ReplaceAll(Password, ";", "Sc")
	Password = strings.ReplaceAll(Password, ":", "Cl")
	Password = strings.ReplaceAll(Password, "'", "Ap")
	Password = strings.ReplaceAll(Password, "\"", "Qm")
	Password = strings.ReplaceAll(Password, ",", "Cm")
	Password = strings.ReplaceAll(Password, ".", "Fs")
	Password = strings.ReplaceAll(Password, "<", "Ls")
	Password = strings.ReplaceAll(Password, ">", "Gs")
	Password = strings.ReplaceAll(Password, "/", "So")
	Password = strings.ReplaceAll(Password, "?", "Qm")
	return Password
}

func Trim_Spec_Char(TrimFlag int, Text string) string {

	if TrimFlag != IP_FLAG {
		Text = strings.ReplaceAll(Text, ".", "")
	}
	if TrimFlag != TIME_FLAG {
		Text = strings.ReplaceAll(Text, ":", "")
	}
	if TrimFlag != TIME_FLAG && TrimFlag != UUID_FLAG {
		Text = strings.ReplaceAll(Text, "-", "")
	}

	Text = strings.ReplaceAll(Text, "`", "")
	Text = strings.ReplaceAll(Text, "~", "")
	Text = strings.ReplaceAll(Text, "!", "")
	Text = strings.ReplaceAll(Text, "@", "")
	Text = strings.ReplaceAll(Text, "#", "")
	Text = strings.ReplaceAll(Text, "$", "")
	Text = strings.ReplaceAll(Text, "%", "")
	Text = strings.ReplaceAll(Text, "^", "")
	Text = strings.ReplaceAll(Text, "&", "")
	Text = strings.ReplaceAll(Text, "*", "")
	Text = strings.ReplaceAll(Text, "(", "")
	Text = strings.ReplaceAll(Text, ")", "")
	Text = strings.ReplaceAll(Text, "_", "")
	Text = strings.ReplaceAll(Text, "=", "")
	Text = strings.ReplaceAll(Text, "+", "")
	Text = strings.ReplaceAll(Text, "[", "")
	Text = strings.ReplaceAll(Text, "]", "")
	Text = strings.ReplaceAll(Text, "{", "")
	Text = strings.ReplaceAll(Text, "}", "")
	Text = strings.ReplaceAll(Text, "\\", "")
	Text = strings.ReplaceAll(Text, "|", "")
	Text = strings.ReplaceAll(Text, ";", "")
	Text = strings.ReplaceAll(Text, "'", "")
	Text = strings.ReplaceAll(Text, "\"", "")
	Text = strings.ReplaceAll(Text, ",", "")
	Text = strings.ReplaceAll(Text, "<", "")
	Text = strings.ReplaceAll(Text, ">", "")
	Text = strings.ReplaceAll(Text, "/", "")
	Text = strings.ReplaceAll(Text, "?", "")

	return Text

}

func WebServer_Login_Check(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	log.Println("Login", req.Method)
	defer req.Body.Close()

	var CommonRows *sql.Rows
	var Count int
	var QueryStr string
	var ConditionCount int
	var ConditionArray []interface{}
	//var err error

	if req.Method == "POST" {
		req.ParseForm()

		// check id and passwd if ok keep going
		ID := fmt.Sprintf("%s", req.Form["id"])
		ID = strings.Replace(ID, "[", "", -1)
		ID = strings.Replace(ID, "]", "", -1)

		if SQL_Injection_ID_Check(ID) == true {
			log.Println("Invalid Sql Injection ID")
			WebServer_Redirect(w, req, "/login")
			return
		}

		Pass := fmt.Sprintf("%s", req.Form["pwd"])
		Pass = strings.Replace(Pass, "[", "", -1)
		Pass = strings.Replace(Pass, "]", "", -1)

		if SQL_Injection_PW_Check(Pass) == true {
			log.Println(" Invalid Injection in Password")
			WebServer_Redirect(w, req, "/login")
			return

		} else {
			Pass = Change_Spec_Char(Pass)
		}
		QueryStr = fmt.Sprintf("SELECT COUNT(*) FROM Users WHERE ID=? AND PASSWORD=?")
		ConditionCount = 2
		ConditionArray = append(ConditionArray, ID, GetCipherText(Pass))

		if len(ConditionArray) == 0 {
			CommonRows = ConditionQuery_DB(Database, QueryStr)
		} else {
			stmt, _ := Database.Prepare(QueryStr)
			CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
			stmt.Close()
		}

		for CommonRows.Next() {
			err := CommonRows.Scan(&Count)
			if err != nil {
				log.Println(" data Scan error:", err)
				CommonRows.Close()
				return
			}
			log.Println(" Result count : ", Count)

			if Count != 1 {
				log.Println("no user or wrong password", ID, Pass, GetCipherText(Pass))
				WebServer_Redirect(w, req, "/login")
				CommonRows.Close()
				return
			}

		}

		CommonRows.Close()

		CookieName := ID

		session, err := store.Get(req, CookieName)
		if err != nil {
			log.Println("store.get Error:", err)
		}
		session.Values["authenticated"] = true
		session.Options.MaxAge = LoginTimeout
		session.Save(req, w)
	}

	if ControlServerFlag == 0 {
		if Node_Flag == Node_FLAG_NONE {
			WebServer_Redirect(w, req, "/setting")
		} else if Node_Flag == Node_FLAG_SERVER {
			WebServer_Redirect(w, req, "/statistics/server/?page_num=1&sort=0")
		} else {
			WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
		}
	} else {
		WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
	}
}

func StatServCommon(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	var err error
	var ServerStatCommon []ServerStatisticCommon
	var TempServerStatCommon ServerStatisticCommon
	defer req.Body.Close()

	dec := json.NewDecoder(req.Body)
	for {

		err = dec.Decode(&TempServerStatCommon)
		if err != nil {
			if err == io.EOF {
				w.Write([]byte("ServCommonSucc"))
				break
			} else {
				log.Println(" Decode err:", err)
				w.Write([]byte("Fail"))
				return
			}
		}
		ServerStatCommon = append(ServerStatCommon, TempServerStatCommon)

	}
	for i := range ServerStatCommon {
		for {
			_, err = MariaDBInsertServerCommon(Database, ServerStatCommon[i])
			if err != nil {
				log.Println("Fail")
				continue
			} else {
				break
			}
		}
	}
	log.Println("StatServ Common Success!")
}

func StatServData(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	var err error
	defer req.Body.Close()
	var ServerStatData []ServerStatisticData
	var TempServerStatData ServerStatisticData

	dec := json.NewDecoder(req.Body)
	for {
		err = dec.Decode(&TempServerStatData)
		if err != nil {
			if err == io.EOF {
				w.Write([]byte("ServDataSucc"))
				break
			} else {
				log.Println(" Decode err:", err)
				w.Write([]byte("Fail"))
				return
			}
		}
		ServerStatData = append(ServerStatData, TempServerStatData)
	}

	for i := range ServerStatData {
		for {
			_, err = MariaDBInsertServerData(Database, ServerStatData[i])
			if err != nil {
				log.Println("Fail")
				continue
			} else {
				break
			}
		}
	}
	log.Println("StatServ Data Success!")
}

func StatClntCommon(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	var err error
	defer req.Body.Close()
	var ClientStatCommon []ClientStatisticCommon
	var TempClientStatCommon ClientStatisticCommon

	dec := json.NewDecoder(req.Body)
	for {

		err = dec.Decode(&TempClientStatCommon)
		if err != nil {
			if err == io.EOF {
				w.Write([]byte("ClntCommonSucc"))
				break
			} else {
				log.Println(" Decode err:", err)
				w.Write([]byte("Fail"))
				return
			}
		}
		ClientStatCommon = append(ClientStatCommon, TempClientStatCommon)
	}

	for i := range ClientStatCommon {
		for {
			_, err = MariaDBInsertClientCommon(Database, ClientStatCommon[i])
			if err != nil {
				log.Println("Fail")
				continue
			} else {
				break
			}
		}
	}
	log.Println("StatClient Common Success!")
}

func StatClntData(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	var err error
	var ClientStatData []ClientStatisticData
	var TempClientStatData ClientStatisticData

	defer req.Body.Close()

	dec := json.NewDecoder(req.Body)

	for {

		err = dec.Decode(&TempClientStatData)
		if err != nil {
			if err == io.EOF {
				w.Write([]byte("ClntDataSucc"))
				break
			} else {
				log.Println(" Decode err:", err)
				w.Write([]byte("Fail"))
				return
			}
		}
		ClientStatData = append(ClientStatData, TempClientStatData)
	}

	for i := range ClientStatData {
		for {
			_, err = MariaDBInsertClientData(Database, ClientStatData[i])
			if err != nil {
				log.Println("Fail")
				continue
			} else {
				break
			}
		}
	}
	log.Println("StatClient Data Success!")
}

func HttpListen(TlsFlag int, ListenPort string, ServerCert string, ServerKey string, Handler http.Handler) {
	if TlsFlag == 1 {
		err := http.ListenAndServeTLS(ListenPort, ServerCert, ServerKey, Handler)
		if err != nil {
			log.Fatal("ListenAndServeTLS: ", err)
		}
	} else if TlsFlag == 0 {
		err := http.ListenAndServe(ListenPort, Handler)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}
}

func MariaDBInsertServerCommon(Database *sql.DB, StatCommon ServerStatisticCommon) (int32, error) {
	var DB_Flag int64
	var err error
	InsertDataStr := fmt.Sprintf("INSERT IGNORE INTO SERVER_STATISTICS_COMMON (ID, Time, Bridge_ID_TEXT , Proxy_IP_INT, Proxy_IP_TEXT, Node_IP_INT, Node_IP_TEXT, Node_Listen_Port, Server_IP_INT, Server_IP_TEXT, Server_Listen_Port) VALUES (%d,'%s','%s',%d,'%s',%d,'%s',%d,%d,'%s',%d)", StatCommon.ID, StatCommon.Time, StatCommon.Bridge_ID_Str, StatCommon.Proxy_IP_Int, StatCommon.Proxy_IP_Str, StatCommon.Node_IP_Int, StatCommon.Node_IP_Str, StatCommon.Node_Listen_Port, StatCommon.Server_IP_Int, StatCommon.Server_IP_Str, StatCommon.Server_Listen_Port)

	DB_Flag, err = mariadb_lib.Insert_Data(Database, InsertDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("mariadb Insert Fail!")
		return DB_RET_FAIL, err

	}
	return DB_RET_SUCC, nil

}

func MariaDBInsertServerData(Database *sql.DB, StatData ServerStatisticData) (int32, error) {
	var DB_Flag int64
	var err error
	InsertDataStr := fmt.Sprintf("INSERT IGNORE INTO SERVER_STATISTICS_DATA (OVERLAPID,ID, Client_IP_INT, Client_IP_TEXT, Inbound, Outbound) VALUES (%d,%d,%d,'%s',%d,%d)", StatData.OverlapID, StatData.ID, StatData.Client_IP_Int, StatData.Client_IP_Str, StatData.Inbound, StatData.Outbound)

	DB_Flag, _ = mariadb_lib.Insert_Data(Database, InsertDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("mariadb Insert Fail!")
		return DB_RET_FAIL, err
	}
	return DB_RET_SUCC, nil
}

func MariaDBInsertClientCommon(Database *sql.DB, StatCommon ClientStatisticCommon) (int32, error) {
	var DB_Flag int64
	var err error
	InsertDataStr := fmt.Sprintf("INSERT  IGNORE INTO CLIENT_STATISTICS_COMMON (ID,Time, Node_ID_TEXT, Client_IP_INT, Client_IP_TEXT, Node_IP_INT, Node_IP_TEXT, Node_Listen_Port) VALUES (%d,'%s','%s',%d,'%s',%d,'%s',%d)", StatCommon.ID, StatCommon.Time, StatCommon.Node_ID_Str, StatCommon.Client_IP_Int, StatCommon.Client_IP_Str, StatCommon.Node_IP_Int, StatCommon.Node_IP_Str, StatCommon.Node_Listen_Port)

	DB_Flag, _ = mariadb_lib.Insert_Data(Database, InsertDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("mariadb Insert Fail!")
		return DB_RET_FAIL, err
	}
	return DB_RET_SUCC, nil
}

func MariaDBInsertClientData(Database *sql.DB, StatData ClientStatisticData) (int32, error) {
	var DB_Flag int64
	var err error

	InsertDataStr := fmt.Sprintf("INSERT IGNORE INTO CLIENT_STATISTICS_DATA (OVERLAPID,ID, Proxy_IP_INT, Proxy_IP_TEXT, Proxy_Listen_Port, Inbound, Outbound) VALUES (%d,%d,%d,'%s',%d,%d,%d)", StatData.OverlapID, StatData.ID, StatData.Proxy_IP_Int, StatData.Proxy_IP_Str, StatData.Proxy_Listen_Port, StatData.Inbound, StatData.Outbound)

	DB_Flag, _ = mariadb_lib.Insert_Data(Database, InsertDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("mariadb Insert Fail!")
		return DB_RET_FAIL, err
	}
	return DB_RET_SUCC, nil
}

func MariaDBOpen(Id string, Passwd string, DbAddr string, DbPort string, DbName string) (*sql.DB, error) {

	Database, err := mariadb_lib.Connection_DB(Id, Passwd, DbAddr, DbPort, DbName)
	if Database == nil {
		log.Println("Maria DB Open Fail!")
		return Database, err
	}
	return Database, nil
}

func MariaDBInit(Id string, Passwd string, DbAddr string, DbPort string, DbName string) {

	var DB_Flag int32

	Database, _ := mariadb_lib.Connection_DB(Id, Passwd, DbAddr, DbPort, DbName)
	if Database == nil {
		log.Println("Connection MariaDB Fail!")
		return
	}

	DB_Flag, _ = mariadb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Users (ID Text, Password Text)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	DB_Flag, _ = mariadb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS SERVER_STATISTICS_COMMON(ID INTEGER PRIMARY KEY AUTO_INCREMENT, Time TEXT, Bridge_ID_TEXT TEXT, Proxy_IP_INT BIGINT, Proxy_IP_TEXT TEXT, Node_IP_INT BIGINT, Node_IP_TEXT TEXT, Node_Listen_Port BIGINT, Server_IP_INT BIGINT, Server_IP_TEXT TEXT, Server_Listen_Port BIGINT);")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	DB_Flag, _ = mariadb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS SERVER_STATISTICS_DATA(OVERLAPID INTEGER PRIMARY KEY AUTO_INCREMENT,ID BIGINT, Client_IP_INT BIGINT, Client_IP_TEXT TEXT, Inbound BIGINT, Outbound BIGINT);")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	DB_Flag, _ = mariadb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS CLIENT_STATISTICS_COMMON (ID INTEGER PRIMARY KEY AUTO_INCREMENT, Time text, Node_ID_TEXT TEXT, Client_IP_INT BIGINT, Client_IP_TEXT TEXT, Node_IP_INT BIGINT, Node_IP_TEXT TEXT, Node_Listen_Port BIGINT);")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	DB_Flag, _ = mariadb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS CLIENT_STATISTICS_DATA (OVERLAPID INTEGER PRIMARY KEY AUTO_INCREMENT,ID BIGINT, Proxy_IP_INT BIGINT, Proxy_IP_TEXT TEXT, Proxy_Listen_Port BIGINT, Inbound BIGINT, Outbound BIGINT);")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	DB_Flag, _ = mariadb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Global_Data (Max_Conn INT, Recv_Buffer_Size INT, Send_Buffer_Size INT, Timeout_Connect INT, Timeout_Client INT, Timeout_Server INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	DB_Flag, _ = mariadb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Logfile_Data (Disk_Limit INT, Max_Size INT, Log TEXT, LogName TEXT, Error TEXT, ErrorName TEXT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	DB_Flag, _ = mariadb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Delete (Del_Time INT, Cyc_Time INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

}
func MariaDBGetServerDate(Database *sql.DB, First int) string {

	var QueryStr string
	var CommonDate string
	var CommonRows *sql.Rows
	var err error

	if First == 1 {
		QueryStr = fmt.Sprintf("SELECT Time FROM SERVER_STATISTICS_COMMON ORDER BY Time ASC LIMIT 1")
	} else {
		QueryStr = fmt.Sprintf("SELECT Time FROM SERVER_STATISTICS_COMMON ORDER BY Time DESC LIMIT 1")
	}

	CommonRows, err = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if CommonRows != nil {
			CommonRows.Close()
		}
	}()
	if CommonRows == nil {
		return CommonDate
	}

	for CommonRows.Next() {
		err = CommonRows.Scan(&CommonDate)
		if err != nil {
			log.Println(" data Scan error:", err)
			return CommonDate
		}

		log.Println("Common Date", CommonDate)
		CommonRows.Close()
		return CommonDate
	}
	CommonRows.Close()

	return CommonDate
}

func RunControlWebServer() {
	log.Print("Run Control Web Server..\n")
	var db_cfg_info DBconfig

	if _, err := toml.DecodeFile(db_cfg_path, &db_cfg_info); err != nil {
		log.Fatal(err)
	}

	db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME = Decrypt_dbcfginfo(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)

	MariaDBInit(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)

	WebServerMux := http.NewServeMux()

	WebServerMux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Redirect(w, req, "/login/")
	})

	WebServerMux.HandleFunc("/login/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		WebServer_Login(w, req, Database)
		Database.Close()
	})

	WebServerMux.HandleFunc("/logging/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		WebServer_Login_Check(w, req, Database)
		Database.Close()
	})

	WebServerMux.HandleFunc("/setting/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		WebServer_Setting(w, req, Database)
		Database.Close()
	})

	WebServerMux.HandleFunc("/statistics/server/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		WebServer_Server_Statistics(w, req, Database)
		Database.Close()
	})

	WebServerMux.HandleFunc("/statistics/client/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		WebServer_Client_Statistics(w, req, Database)
		Database.Close()
	})

	WebServerMux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		WebServer_Forbidden(w, req, Database)
		Database.Close()
	})

	WebServerMux.Handle("/pages/", http.StripPrefix("/pages/", http.FileServer(http.Dir("pages"))))

	StatServerMux := http.NewServeMux()
	StatServerMux.HandleFunc("/Serv_Stat_Common/", func(w http.ResponseWriter, req *http.Request) {

		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		StatServCommon(w, req, Database)
		Database.Close()
	})

	StatServerMux.HandleFunc("/Serv_Stat_Data/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		StatServData(w, req, Database)
		Database.Close()
	})

	StatServerMux.HandleFunc("/Clnt_Stat_Common/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		StatClntCommon(w, req, Database)
		Database.Close()
	})

	StatServerMux.HandleFunc("/Clnt_Stat_Data/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		StatClntData(w, req, Database)
		Database.Close()
	})

	//------------------------------------------------------------------------- [ WEB API:gkwon ] {--------//
	WebServerMux.HandleFunc("/auth_api_input/provisioning/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Provisioning_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_input/statistics/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Statistics_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_encode_value/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Encode_Value(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/provisioning/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Provisioning_Proc(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/statistics/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Statistics_Proc(w, req)
	})
	//------------------------------------------------------------------------- [ WEB API ] }--------//

	go HttpListen(1, ":443", "server.crt", "server.key", StatServerMux)
	go HttpListen(0, ":8080", "", "", WebServerMux)

	//go Delete_Client_Statistics(Database)
	//go Delete_Server_Statistics(Database)

}

func SendStat(Database *sql.DB) {

	var SendIntervalTime time.Duration
	var StatSendFlag int
	var CtrlServIP, CtrlServPort, CtrlServInfo string
	var StatCfgRows *sql.Rows
	var Serv_StartID int64
	var Serv_FinishID int64
	var Clint_StartID int64
	var Clint_FinishID int64
	var Clint_first_send bool
	var Serv_first_send bool

	var err error
	var QueryStr string

	for {
		timer := time.NewTimer(time.Second * time.Duration(SendIntervalTime))
		<-timer.C

		QueryStr = "SELECT Stat_Send_Flag,Control_Server_IP, Control_Server_Port,Control_Server_Send_Interval FROM Config_Statistics_Data;"
		StatCfgRows, err = sqlitedb_lib.Query_DB(Database, QueryStr)
		if StatCfgRows == nil {
			log.Println("StatCfgRows Error:", err)
		} else {
			for StatCfgRows.Next() {
				err := StatCfgRows.Scan(&StatSendFlag, &CtrlServIP, &CtrlServPort, &SendIntervalTime)
				if err != nil {
					log.Println("StatCfgRows Scan Error:", err)
				}
			}
			CtrlServInfo = CtrlServIP + ":" + CtrlServPort
			StatCfgRows.Close()
		}

		log.Println("CtrlServInfo:", CtrlServInfo)

		if StatSendFlag == ENABLE {
			Server_SendStat(Database, CtrlServInfo, CtrlServIP, CtrlServPort, &Serv_StartID, &Serv_FinishID, &Serv_first_send)
			Client_SendStat(Database, CtrlServInfo, CtrlServIP, CtrlServPort, &Clint_StartID, &Clint_FinishID, &Clint_first_send)
		}
	}
}

func Server_SendStat(Database *sql.DB, CtrlServInfo string, CtrlServIP string, CtrlServPort string, Serv_StartID *int64, Serv_FinishID *int64, Serv_first_send *bool) {
	var ServerStatCommon ServerStatisticCommon
	var ServerStatData ServerStatisticData
	var StatCfgRows *sql.Rows
	var QueryStr string
	var IsSuccData []byte
	var err error
	Buff := new(bytes.Buffer)

	for {
		if *Serv_first_send == true {
			QueryStr = "SELECT ID, Time, Bridge_ID_TEXT, Proxy_IP_INT , Proxy_IP_TEXT , Node_IP_INT, Node_IP_TEXT, Node_Listen_Port, Server_IP_INT, Server_IP_TEXT , Server_Listen_Port  FROM Server_Statistics_Common;"
			*Serv_first_send = false
		} else {
			QueryStr = "SELECT ID, Time, Bridge_ID_TEXT, Proxy_IP_INT , Proxy_IP_TEXT , Node_IP_INT, Node_IP_TEXT, Node_Listen_Port, Server_IP_INT, Server_IP_TEXT , Server_Listen_Port  FROM Server_Statistics_Common WHERE ID > " + strconv.FormatInt(*Serv_StartID, 10) + ";"
		}

		rows_servcommon, _ := sqlitedb_lib.Query_DB(Database, QueryStr)
		if rows_servcommon == nil {
			log.Println("rows_servcommon Error:", err)
			continue
		} else {
			for rows_servcommon.Next() {
				err = rows_servcommon.Scan(&ServerStatCommon.ID, &ServerStatCommon.Time, &ServerStatCommon.Bridge_ID_Str, &ServerStatCommon.Proxy_IP_Int, &ServerStatCommon.Proxy_IP_Str, &ServerStatCommon.Node_IP_Int, &ServerStatCommon.Node_IP_Str, &ServerStatCommon.Node_Listen_Port, &ServerStatCommon.Server_IP_Int, &ServerStatCommon.Server_IP_Str, &ServerStatCommon.Server_Listen_Port)
				if err != nil {
					log.Println(" data Scan error:", err)
					rows_servcommon.Close()
					Buff.Truncate(0)
					continue
				} else {
					json.NewEncoder(Buff).Encode(ServerStatCommon)
				}
			}

			if Buff.Len() != 0 {
				*Serv_FinishID = ServerStatCommon.ID
				// Https
				client := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
				}
				for {
					res, err := client.Post("https://"+CtrlServInfo+"/Serv_Stat_Common/", "application/json", Buff)
					if err != nil {
						log.Println("Post err:", err.Error())
						StatCfgRows, err = sqlitedb_lib.Query_DB(Database, "SELECT Control_Server_IP, Control_Server_Port FROM Config_Statistics_Data;")
						if StatCfgRows == nil {
							log.Println("StatCfgRows Error:", err)

						} else {
							for StatCfgRows.Next() {
								err := StatCfgRows.Scan(&CtrlServIP, &CtrlServPort)
								if err != nil {
									log.Println("StatCfgRows Scan Error:", err)
								}
							}
							CtrlServInfo = CtrlServIP + ":" + CtrlServPort
							log.Println("CtrlServInfo:", CtrlServInfo)
							StatCfgRows.Close()
						}
						time.Sleep(time.Second * 3)
						continue
					}
					IsSuccData, err = ioutil.ReadAll(res.Body)
					log.Println("IsSuccData:", string(IsSuccData))
					if string(IsSuccData) == "Fail" {
						res.Body.Close()
						continue
					} else {
						res.Body.Close()
						break
					}
				}
			}

			Buff.Truncate(0)
			rows_servcommon.Close()
			break
		}
	}

	if *Serv_StartID != *Serv_FinishID {
		for {
			QueryStr = "SELECT * FROM  SERVER_STATISTICS_DATA WHERE ID BETWEEN " + strconv.FormatInt(*Serv_StartID, 10) + " AND " + strconv.FormatInt(*Serv_FinishID, 10) + ";"

			rows_servdata, _ := sqlitedb_lib.Query_DB(Database, QueryStr)
			if rows_servdata == nil {
				log.Println("row_servdate Error:", err)
				continue
			} else {
				for rows_servdata.Next() {
					err := rows_servdata.Scan(&ServerStatData.OverlapID, &ServerStatData.ID, &ServerStatData.Client_IP_Int, &ServerStatData.Client_IP_Str, &ServerStatData.Inbound, &ServerStatData.Outbound)
					if err != nil {
						log.Println(" data Scan error:", err)
						rows_servdata.Close()
						Buff.Truncate(0)
						continue
					} else {
						json.NewEncoder(Buff).Encode(ServerStatData)
					}

				}
				if Buff.Len() != 0 {
					// Https
					client := &http.Client{
						Transport: &http.Transport{
							TLSClientConfig: &tls.Config{
								InsecureSkipVerify: true,
							},
						},
					}
					for {
						res, err := client.Post("https://"+CtrlServInfo+"/Serv_Stat_Data/", "application/json", Buff)
						if err != nil {
							log.Println("Post err:", err.Error())
							StatCfgRows, err = sqlitedb_lib.Query_DB(Database, "SELECT Control_Server_IP, Control_Server_Port FROM Config_Statistics_Data;")
							if StatCfgRows == nil {
								log.Println("StatCfgRows Error:", err)

							} else {
								for StatCfgRows.Next() {
									err := StatCfgRows.Scan(&CtrlServIP, &CtrlServPort)
									if err != nil {
										log.Println("StatCfgRows Scan Error:", err)
									}
								}
								CtrlServInfo = CtrlServIP + ":" + CtrlServPort
								log.Println("CtrlServInfo:", CtrlServInfo)
								StatCfgRows.Close()
							}
							time.Sleep(time.Second * 3)
							continue
						}
						IsSuccData, err = ioutil.ReadAll(res.Body)
						log.Println("IsSuccData:", string(IsSuccData))
						if string(IsSuccData) == "Fail" {
							res.Body.Close()
							continue
						} else {
							res.Body.Close()
							break
						}
					}
				}
				Buff.Truncate(0)
				rows_servdata.Close()
				break
			}
		}
		*Serv_StartID = *Serv_FinishID
	}

}

func Client_SendStat(Database *sql.DB, CtrlServInfo string, CtrlServIP string, CtrlServPort string, Clint_StartID *int64, Clint_FinishID *int64, Clint_first_send *bool) {
	var ClientStatCommon ClientStatisticCommon
	var ClientStatData ClientStatisticData
	var StatCfgRows *sql.Rows
	var QueryStr string
	var IsSuccData []byte
	var err error
	Buff := new(bytes.Buffer)

	for {
		if *Clint_first_send == true {
			QueryStr = "SELECT ID, Time ,Node_ID_TEXT, Client_IP_INT , Client_IP_TEXT , Node_IP_INT , Node_IP_TEXT , Node_Listen_Port  FROM CLIENT_STATISTICS_COMMON;"
			*Clint_first_send = false
		} else {
			QueryStr = "SELECT ID, Time ,Node_ID_TEXT ,Client_IP_INT , Client_IP_TEXT , Node_IP_INT , Node_IP_TEXT , Node_Listen_Port  FROM CLIENT_STATISTICS_COMMON WHERE ID >" + strconv.FormatInt(*Clint_StartID, 10) + ";"
		}

		rows_clntcommon, _ := sqlitedb_lib.Query_DB(Database, QueryStr)
		if rows_clntcommon == nil {
			log.Println("rows_clntcommon Scan Error:", err)
			continue
		} else {
			for rows_clntcommon.Next() {
				err := rows_clntcommon.Scan(&ClientStatCommon.ID, &ClientStatCommon.Time, &ClientStatCommon.Node_ID_Str, &ClientStatCommon.Client_IP_Int, &ClientStatCommon.Client_IP_Str, &ClientStatCommon.Node_IP_Int, &ClientStatCommon.Node_IP_Str, &ClientStatCommon.Node_Listen_Port)

				if err != nil {
					log.Println(" data Scan error:", err)
					rows_clntcommon.Close()
					Buff.Truncate(0)
					continue
				} else {
					json.NewEncoder(Buff).Encode(ClientStatCommon)
				}
			}
			if Buff.Len() != 0 {
				*Clint_FinishID = ClientStatCommon.ID
				// Https
				client := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
				}
				for {
					res, err := client.Post("https://"+CtrlServInfo+"/Clnt_Stat_Common/", "application/json", Buff)
					if err != nil {
						log.Println("Post err:", err.Error())
						StatCfgRows, err = sqlitedb_lib.Query_DB(Database, "SELECT Control_Server_IP, Control_Server_Port FROM Config_Statistics_Data;")
						if StatCfgRows == nil {
							log.Println("StatCfgRows Error:", err)
						} else {
							for StatCfgRows.Next() {
								err := StatCfgRows.Scan(&CtrlServIP, &CtrlServPort)
								if err != nil {
									log.Println("StatCfgRows Scan Error:", err)
								}
							}
							CtrlServInfo = CtrlServIP + ":" + CtrlServPort
							log.Println("CtrlServInfo:", CtrlServInfo)
							StatCfgRows.Close()
						}
						time.Sleep(time.Second * 3)
						continue
					}
					IsSuccData, err = ioutil.ReadAll(res.Body)
					log.Println("IsSuccData:", string(IsSuccData))
					if string(IsSuccData) == "Fail" {
						res.Body.Close()
						continue
					} else {
						res.Body.Close()
						break
					}
				}
			}
			Buff.Truncate(0)
			rows_clntcommon.Close()
			break
		}
	}

	if *Clint_StartID != *Clint_FinishID {
		for {
			QueryStr = "SELECT * FROM  CLIENT_STATISTICS_DATA WHERE ID BETWEEN " + strconv.FormatInt(*Clint_StartID, 10) + " AND " + strconv.FormatInt(*Clint_FinishID, 10) + ";"
			rows_clntdata, _ := sqlitedb_lib.Query_DB(Database, QueryStr)

			if rows_clntdata == nil {
				log.Println(" rows_clntdata error:", err)
			} else {
				for rows_clntdata.Next() {
					err := rows_clntdata.Scan(&ClientStatData.OverlapID, &ClientStatData.ID, &ClientStatData.Proxy_IP_Int, &ClientStatData.Proxy_IP_Str, &ClientStatData.Proxy_Listen_Port, &ClientStatData.Inbound, &ClientStatData.Outbound)
					if err != nil {
						log.Println(" data Scan error:", err)
						Buff.Truncate(0)
						rows_clntdata.Close()
						continue
					} else {
						json.NewEncoder(Buff).Encode(ClientStatData)
					}
				}
				if Buff.Len() != 0 {
					// Https
					client := &http.Client{
						Transport: &http.Transport{
							TLSClientConfig: &tls.Config{
								InsecureSkipVerify: true,
							},
						},
					}
					for {
						res, err := client.Post("https://"+CtrlServInfo+"/Clnt_Stat_Data/", "application/json", Buff)
						if err != nil {
							log.Println("Post err:", err.Error())
							StatCfgRows, err = sqlitedb_lib.Query_DB(Database, "SELECT Control_Server_IP, Control_Server_Port FROM Config_Statistics_Data;")
							if StatCfgRows == nil {
								log.Println("StatCfgRows Error:", err)
							} else {
								for StatCfgRows.Next() {
									err := StatCfgRows.Scan(&CtrlServIP, &CtrlServPort)
									if err != nil {
										log.Println("StatCfgRows Scan Error:", err)
									}
								}
								CtrlServInfo = CtrlServIP + ":" + CtrlServPort
								log.Println("CtrlServInfo:", CtrlServInfo)
								StatCfgRows.Close()
							}
							time.Sleep(time.Second * 3)
							continue
						}
						IsSuccData, err = ioutil.ReadAll(res.Body)
						log.Println("IsSuccData:", string(IsSuccData))
						if string(IsSuccData) == "Fail" {
							res.Body.Close()
							continue
						} else {
							res.Body.Close()
							break
						}
					}
				}
				Buff.Truncate(0)
				rows_clntdata.Close()
				break
			}
		}
		*Clint_StartID = *Clint_FinishID
	}

}
func SqliteDBInsertUsers(Database *sql.DB, ID string, Password string) {
	var DB_Flag int64

	InsertDataStr := fmt.Sprintf("INSERT INTO Users (ID, Password) VALUES ('%s','%s')", ID, GetCipherText(Password))

	log.Println("Insert Configure", InsertDataStr)

	DB_Flag, _ = sqlitedb_lib.Insert_Data(Database, InsertDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("sqlitedb Insert Fail!")
	}
}

func SqliteDBInsertConfig(Database *sql.DB, ConfGlobal string, ConfLogFile string, ConfStatistics string, ConfNode string, ConfNodeID string, ConfKMS string, ConfFrontend string, ConfBackend string) {
	var DB_Flag int64
	InsertDataStr := fmt.Sprintf("INSERT INTO Config_File (Global, LogFile, Statistics, Node,NodeID, KMS, Frontend, Backend) VALUES ('%s','%s','%s','%s','%s','%s','%s','%s')", ConfGlobal, ConfLogFile, ConfStatistics, ConfNode, ConfNodeID, ConfKMS, ConfFrontend, ConfBackend)

	log.Println("Insert Configure", InsertDataStr)

	DB_Flag, _ = sqlitedb_lib.Insert_Data(Database, InsertDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("sqlitedb Insert Fail!")
	}
}

func SqliteDBUpdateSetting(Database *sql.DB, Settings SettingsInformation) error {
	var StatSendFlag, BridgeUseFlag, ChangeClientIPUseFlag, Encrypt_Mode, i, j int
	var UpdateDataStr, BackendList string
	var DB_Flag int64
	var stmt *sql.Stmt
	var tx *sql.Tx
	var err error

	tx, err = Database.Begin()
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return err
	}

	defer sqlitedb_lib.DB_Rollback(tx)
	if len(Settings.Password) > 5 {

		UpdateDataStr = "UPDATE Users SET Password=? WHERE ID=?"

		stmt, err = tx.Prepare(UpdateDataStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		defer stmt.Close()

		_, err = stmt.Exec(GetCipherText(Settings.Password), "admin")
		if err != nil {
			log.Println("Exec Fail!:", err)
			return err
		}
	}

	UpdateDataStr = "UPDATE Config_Global_Data SET Max_Conn=?, Recv_Buffer_Size=?, Send_Buffer_Size=?, Timeout_Connect=?, Timeout_Client=?, Timeout_Server=?"
	stmt, err = tx.Prepare(UpdateDataStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return err
	}

	_, err = stmt.Exec(Settings.Maximum_ConnectionCount, Settings.Recv_Buf_Size, Settings.Send_Buf_Size, Settings.Connection_Timeout, Settings.Client_Reconnect_Timeout, Settings.Server_Reconnect_Timeout)
	if err != nil {
		log.Println("Exec Fail!:", err)
		return err
	}

	UpdateDataStr = "UPDATE Config_Logfile_Data SET Disk_Limit=?, Max_Size=?, Log=?, Error=?"
	stmt, err = tx.Prepare(UpdateDataStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return err
	}

	_, err = stmt.Exec(Settings.Limit_Size_Log_Storage, Settings.Maxsize_Per_Logfile, Settings.Logfile_Path, Settings.Err_Logfile_Path)
	if err != nil {
		log.Println("Exec Fail!:", err)
		return err
	}

	if Settings.Statistic_Send_Control_Server == "Enable" {
		StatSendFlag = ENABLE
	} else {
		StatSendFlag = DISABLE
	}

	UpdateDataStr = "UPDATE Config_Statistics_Data SET Interval=?, Stat_Send_Flag=?"
	if StatSendFlag == ENABLE {
		UpdateDataStr += ", Control_Server_IP=?, Control_Server_Port=?, Control_Server_Send_Interval=?"
	}

	stmt, err = tx.Prepare(UpdateDataStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return err
	}
	if StatSendFlag == ENABLE {
		_, err = stmt.Exec(Settings.Statistic_Collection_Cycle, StatSendFlag, Settings.Statistic_Server_Ip, Settings.Statistic_Server_Port, Settings.Statistic_Send_Cycle)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return err
		}
	} else {
		_, err = stmt.Exec(Settings.Statistic_Collection_Cycle, StatSendFlag)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return err
		}
	}

	if Settings.Bridge_Used == "Enable" {
		BridgeUseFlag = ENABLE
	} else {
		BridgeUseFlag = DISABLE
	}

	if Settings.Change_Client_IP == "Enable" {
		ChangeClientIPUseFlag = ENABLE
	} else {
		ChangeClientIPUseFlag = DISABLE
	}
	Node_Change_Client_IP_Mode = ChangeClientIPUseFlag

	if Settings.Encrypt_Mode == "None" {
		Encrypt_Mode = ENC_NONE
	} else if Settings.Encrypt_Mode == "AES_128" {
		Encrypt_Mode = ENC_AES128
	} else if Settings.Encrypt_Mode == "AES_256" {
		Encrypt_Mode = ENC_AES256
	} else if Settings.Encrypt_Mode == "RC4" {
		Encrypt_Mode = ENC_RC4
	}

	UpdateDataStr = "UPDATE Config_Node_Data SET Use_Syncnoti=?, Buffer_Size=?, Encrypt=?, CP_Tunneling=?"
	stmt, err = tx.Prepare(UpdateDataStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return err
	}

	_, err = stmt.Exec(BridgeUseFlag, Settings.Bridge_Buf_Size, Encrypt_Mode, ChangeClientIPUseFlag)
	if err != nil {
		log.Println("Exec Fail!:", err)
		return err
	}

	UpdateDataStr = "UPDATE Config_NodeID_Data SET Node_ID=?"
	stmt, err = tx.Prepare(UpdateDataStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return err
	}

	_, err = stmt.Exec(Settings.Node_ID)
	if err != nil {
		log.Println("Exec Fail!:", err)
		return err
	}

	if Settings.KMS_Address != "" && Settings.KMS_Port != "" {
		UpdateDataStr = "UPDATE Config_KMS_Data SET KMS_Address=?, KMS_Port=?"
		stmt, err = tx.Prepare(UpdateDataStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		_, err = stmt.Exec(Settings.KMS_Address, Settings.KMS_Port)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return err
		}
	} else if Settings.KMS_Address == "" && Settings.KMS_Port == "" {
		UpdateDataStr = "UPDATE Config_KMS_Data SET KMS_Address=?, KMS_Port=?"
		stmt, err = tx.Prepare(UpdateDataStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		_, err = stmt.Exec("", 8080)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return err
		}
	}

	err = sqlitedb_lib.DB_Commit(tx)
	if err != nil {
		log.Println("Commit Fail!:", err)
		return err
	}

	tx, err = Database.Begin()

	if err != nil {
		return err
	}

	defer sqlitedb_lib.DB_Rollback(tx)

	DB_Flag, _ = sqlitedb_lib.Drop_Table(Database, "Config_Frontend_Backend_Data")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Drop Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Frontend_Backend_Data (Symbol_Name TEXT, Bind INT, Node_Mode INT, Server TEXT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	for i = range Settings.SiteList {
		BackendList = ""
		for j = range Settings.SiteList[i].Backend {
			if len(BackendList) > 0 {
				BackendList += ", "
			}
			if Settings.SiteList[i].Backend[j].LAN_Interface == "OS_Default" {
				Settings.SiteList[i].Backend[j].LAN_Interface = ""
			}
			BackendList += "\"" + Settings.SiteList[i].Backend[j].LAN_Interface + "/" + Settings.SiteList[i].Backend[j].BackendIP + ":" + Settings.SiteList[i].Backend[j].BackendPort + "\""
		}

		UpdateDataStr = "INSERT INTO Config_Frontend_Backend_Data (Symbol_Name, Bind, Node_Mode, Server) VALUES (?,?,?,?)"
		stmt, err = tx.Prepare(UpdateDataStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		_, err = stmt.Exec(Settings.SiteList[i].Frontendsymbol, Settings.SiteList[i].FrontendPort, Settings.SiteList[i].NodeMode, BackendList)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return err
		}
	}
	err = sqlitedb_lib.DB_Commit(tx)
	if err != nil {
		log.Println("Commit Fail!:", err)
		return err
	}
	return nil
}

func SqliteDBDelData(Database *sql.DB, Id int) {
	DelDataStr := fmt.Sprint("DELETE FROM FullData WHERE id=%d", Id)

	DB_Flag, _ := sqlitedb_lib.Delete_Data(Database, DelDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("sqlitedb Delete error!")
	}

}

func SqliteDBGetServerDate(Database *sql.DB, First int) (string, error) {
	var QueryStr string
	var CommonDate string
	var CommonRows *sql.Rows
	var err error
	if First == 1 {
		QueryStr = fmt.Sprintf("SELECT Time FROM Server_Statistics_Common ORDER BY Time ASC LIMIT 1")
	} else {
		QueryStr = fmt.Sprintf("SELECT Time FROM Server_Statistics_Common ORDER BY Time DESC LIMIT 1")
	}

	CommonRows, err = sqlitedb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if CommonRows != nil {
			CommonRows.Close()
		}
	}()
	if CommonRows == nil {
		return CommonDate, err
	}

	for CommonRows.Next() {
		err := CommonRows.Scan(&CommonDate)
		if err != nil {
			log.Println(" data Scan error:", err)
			return CommonDate, err
		}
		log.Println("Common Date", CommonDate)
	}
	return CommonDate, nil
}

func SqliteDBInit(DbName string) *sql.DB {
	var Database *sql.DB
	var RowCount int32
	var DB_Flag int64
	Database, _ = sqlitedb_lib.Create_DB(DbName)

	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Users (ID Text, Password Text)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Server_Statistics_Common (ID INTEGER PRIMARY KEY AUTOINCREMENT, Time Text,Bridge_ID_TEXT, Proxy_IP_INT INT, Proxy_IP_TEXT TEXT, Node_IP_INT INT, Node_IP_TEXT TEXT, Node_Listen_Port INT, Server_IP_INT INT, Server_IP_TEXT TEXT, Server_Listen_Port INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Server_Statistics_Data (OVERLAPID INTEGER PRIMARY KEY AUTOINCREMENT,ID INT, Client_IP_INT INT, Client_IP_TEXT TEXT, Inbound INT, Outbound INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Client_Statistics_Common (ID INTEGER PRIMARY KEY AUTOINCREMENT, Time Text, Node_ID_TEXT TEXT,Client_IP_INT INT, Client_IP_TEXT TEXT, Node_IP_INT INT, Node_IP_TEXT TEXT, Node_Listen_Port INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Client_Statistics_Data (OVERLAPID INTEGER PRIMARY KEY AUTOINCREMENT,ID INT, Proxy_IP_INT INT, Proxy_IP_TEXT TEXT, Proxy_Listen_Port INT, Inbound INT, Outbound INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_File (Global TEXT, LogFile TEXT, Statistics TEXT, Node TEXT,NodeID TEXT,KMS TEXT, Frontend TEXT, Backend TEXT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Global_Data (Max_Conn INT, Recv_Buffer_Size INT, Send_Buffer_Size INT, Timeout_Connect INT, Timeout_Client INT, Timeout_Server INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Logfile_Data (Disk_Limit INT, Max_Size INT, Log TEXT, LogName TEXT, Error TEXT, ErrorName TEXT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Statistics_Data (Interval INT, Stat_Send_Flag INT, Control_Server_IP TEXT, Control_Server_Port INT, Control_Server_Send_Interval INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Node_Data (Use_Syncnoti INT, Buffer_Size INT, Encrypt INT, CP_Tunneling INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_NodeID_Data (Node_ID TEXT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_KMS_Data (KMS_Address TEXT, KMS_Port INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Delete (Del_Time INT, Cyc_Time INT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Config_Frontend_Backend_Data (Symbol_Name TEXT, Bind INT, Node_Mode INT, Server TEXT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	RowCount, _ = sqlitedb_lib.RowCount(Database, "Users")
	if RowCount == 0 {
		SqliteDBInsertUsers(Database, "admin", "admin123")
	}

	RowCount, _ = sqlitedb_lib.RowCount(Database, "Config_File")
	if RowCount == 0 {
		/* Insert Config Files */
		var ConfGlobal, ConfLogFile, ConfStatistics, ConfNode, ConfNodeID, ConfKMS, ConfFrontend, ConfBackend string
		ConfGlobal = "[global]\n"
		ConfGlobal += "max_conn = \"<MAX_CONN>\"\n"
		ConfGlobal += "recv_buffer_size = \"<DEFAULT_RECV_BUFF_SIZE>\"\n"
		ConfGlobal += "send_buffer_size = \"<DEFAULT_SEND_BUFF_SIZE>\"\n"
		ConfGlobal += "timeout_connect = \"<TIMEOUT_CONNECT>\"\n"
		ConfGlobal += "timeout_client = \"<TIMEOUT_CLIENT>\"\n"
		ConfGlobal += "timeout_server = \"<TIMEOUT_SERVER>\"\n"
		ConfGlobal += "\n"

		ConfLogFile = "[logfile]\n"
		ConfLogFile += "disk_limit = \"<DISK_LIMIT>\"\n"
		ConfLogFile += "max_size = \"<LOGFILE_MAX_SIZE>MB\"\n"
		ConfLogFile += "log = \"<LOGFILE_LOCATION>\"\n"
		ConfLogFile += "error = \"<ERRORLOGFILE_LOCATION>\"\n"
		ConfLogFile += "\n"

		ConfStatistics = "[statistics]\n"
		ConfStatistics += "use = \"enable\"\n"
		ConfStatistics += "interval = \"<STATISTICS_INTERVAL>\"\n"
		ConfStatistics += "dbpath = \"./db/traffic.db\"\n"
		ConfStatistics += "\n"

		ConfNode = "[node]\n"
		ConfNode += "position = \"wan\"\n"
		ConfNode += "interval_retry = \"5s\"\n"
		ConfNode += "sync_timeout = \"10s\"\n"
		ConfNode += "use_syncnoti = \"<Bridge_MODE>\"\n"
		ConfNode += "buffer_size = \"<Node_BUFF_SIZE>\"\n"
		ConfNode += "encrypt = \"<Node_ENCRYPT>\"\n"
		ConfNode += "cp_tunneling = \"<CHANGE_IP_FUNC>\"\n"
		ConfNode += "\n"

		ConfNodeID += "[NodeID]\n"
		ConfNodeID += "NodeID = \"<NODE_ID>\"\n"
		ConfNodeID += "\n"

		ConfKMS += "[kms]\n"
		ConfKMS += "url = \"<KMS_ADDR_PORT>\"\n"
		ConfKMS += "\n"

		ConfFrontend += "[frontend.<SYMBOL_NAME>]\n"
		ConfFrontend += "bind = \"<FRONTEND_BIND>\"\n"
		ConfFrontend += "backend = \"<SYMBOL_NAME>\"\n"
		ConfFrontend += "node_mode = \"<Node_MODE>\"\n"
		ConfFrontend += "\n"

		ConfBackend += "[backend.<SYMBOL_NAME>]\n"
		ConfBackend += "server = [<LANID_SERVER_IP_PORT>]\n"
		ConfBackend += "\n"

		SqliteDBInsertConfig(Database, ConfGlobal, ConfLogFile, ConfStatistics, ConfNode, ConfNodeID, ConfKMS, ConfFrontend, ConfBackend)

		log.Println("Insert Config\n", ConfGlobal, "\n", ConfLogFile, "\n", ConfStatistics, "\n", ConfNode, "\n", ConfKMS, "\n", ConfFrontend, "\n", ConfBackend, "\n")
	}

	RowCount, _ = sqlitedb_lib.RowCount(Database, "Config_Global_Data")
	if RowCount == 0 {
		InsertDataStr := "INSERT INTO Config_Global_Data (Max_Conn, Recv_Buffer_Size, Send_Buffer_Size, Timeout_Connect, Timeout_Client, Timeout_Server) VALUES (2048,16384,16384,5,30,30)"
		DB_Flag, _ = sqlitedb_lib.Insert_Data(Database, InsertDataStr)
		if DB_RET_FAIL == DB_Flag {
			log.Println("sqlitedb Insert Fail!")
		}
	}

	RowCount, _ = sqlitedb_lib.RowCount(Database, "Config_Logfile_Data")
	if RowCount == 0 {
		InsertDataStr := "INSERT INTO Config_Logfile_Data (Disk_Limit, Max_Size, Log, LogName, Error, ErrorName) VALUES (90, 150, './logs', 'app.log', './logs', 'app_err.log')"
		DB_Flag, _ = sqlitedb_lib.Insert_Data(Database, InsertDataStr)
		if DB_RET_FAIL == DB_Flag {
			log.Println("sqlitedb Insert Fail!")
		}
	}

	RowCount, _ = sqlitedb_lib.RowCount(Database, "Config_Statistics_Data")
	if RowCount == 0 {
		InsertDataStr := "INSERT INTO Config_Statistics_Data (Interval, Stat_Send_Flag, Control_Server_IP, Control_Server_Port, Control_Server_Send_Interval) VALUES (1, 2, '192.168.122.128', 443,60)"
		DB_Flag, _ = sqlitedb_lib.Insert_Data(Database, InsertDataStr)
		if DB_RET_FAIL == DB_Flag {
			log.Println("sqlitedb Insert Fail!")
		}
	}

	RowCount, _ = sqlitedb_lib.RowCount(Database, "Config_Node_Data")
	if RowCount == 0 {
		InsertDataStr := "INSERT INTO Config_Node_Data (Use_Syncnoti, Buffer_Size, Encrypt, CP_Tunneling) VALUES (2, 2097152, 0, 2)"
		Flag, _ := sqlitedb_lib.Insert_Data(Database, InsertDataStr)
		if DB_RET_FAIL == Flag {
			log.Println("sqlitedb Insert Fail!")
		}
	}

	RowCount, _ = sqlitedb_lib.RowCount(Database, "Config_NodeID_Data")
	if RowCount == 0 {
		InsertDataStr := "INSERT INTO Config_NodeID_Data (Node_ID) VALUES ('')"
		Flag, _ := sqlitedb_lib.Insert_Data(Database, InsertDataStr)
		if DB_RET_FAIL == Flag {
			log.Println("sqlitedb Insert Fail!")
		}
	}

	RowCount, _ = sqlitedb_lib.RowCount(Database, "Config_KMS_Data")
	if RowCount == 0 {
		InsertDataStr := "INSERT INTO Config_KMS_Data (KMS_Address,KMS_Port) VALUES ('',8080)"
		Flag, _ := sqlitedb_lib.Insert_Data(Database, InsertDataStr)
		if DB_RET_FAIL == Flag {
			log.Println("sqlitedb Insert Fail!")
		}
	}

	RowCount, _ = sqlitedb_lib.RowCount(Database, "Config_Delete")
	if RowCount == 0 {
		InsertDataStr := "INSERT INTO Config_Delete (Del_Time, Cyc_Time) VALUES (3,30)"
		Flag, _ := sqlitedb_lib.Insert_Data(Database, InsertDataStr)
		if DB_RET_FAIL == Flag {
			log.Println("sqlitedb Insert Fail!")
		}
	}
	return Database
}

func RunLocalWebServer() {
	log.Print("Run Local Web Server..\n")

	PrepareSqliteDB()

	Database := SqliteDBInit(SqliteDB)

	GetProxyInfo(Database)
	GetNodeMode(Database)

	Node_Change_Client_IP_Mode, _ = GetChangeClientIPMode(Database)

	WebServerMux := http.NewServeMux()

	WebServerMux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Redirect(w, req, "/login/")
	})

	WebServerMux.HandleFunc("/login/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Login(w, req, Database)
	})

	WebServerMux.HandleFunc("/logging/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Login_Check(w, req, Database)
	})

	WebServerMux.HandleFunc("/setting/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Setting(w, req, Database)
	})

	WebServerMux.HandleFunc("/update_setting/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Update_Setting(w, req, Database)
	})

	WebServerMux.HandleFunc("/statistics/client/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Client_Statistics(w, req, Database)
	})

	WebServerMux.HandleFunc("/statistics/server/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Server_Statistics(w, req, Database)
	})

	WebServerMux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Forbidden(w, req, Database)
	})

	//------------------------------------------------------------------------- [ WEB API:gkwon ] {--------//
	WebServerMux.HandleFunc("/auth_api_input/provisioning/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Provisioning_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_input/statistics/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Statistics_Input(w, req)
	})

	WebServerMux.HandleFunc("/license/", func(w http.ResponseWriter, req *http.Request) {
		Read_License(w, req, Database)
	})

	//------------------------------------------------------------------------- [ WEB API ] }--------//

	WebServerMux.Handle("/pages/", http.StripPrefix("/pages/", http.FileServer(http.Dir("pages"))))

	go HttpListen(0, ":8080", "", "", WebServerMux)
	go SendStat(Database)

	go Delete_Client_Statistics(Database)
	go Delete_Server_Statistics(Database)

}
func Read_License(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()
	var tmpl *template.Template
	var TempStr string
	var LicensePageInfo LicenseMagementPageInfo
	var LicInfo LicenseData
	var PageNumInfo PageNumInfo
	//var TEXT string
	var err error
	var PageIndexStart, PageNumber, PageCount, NextPageNumber, PrevPageNumber, SortNumber, LastPageNumber int
	//var fd *os.File
	var tomldata tomlinfo
	var RowsCount int
	//var index int64

	log.Println("Server Statistics", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	// fd, err = os.Create("./example.toml")
	// if err != nil {
	// 	return
	// }
	// defer fd.Close()

	if Node_Flag == Node_FLAG_SERVER {
		TempStr = fmt.Sprintf("<li><a href=\"/statistics/server/\">Server Statistics</a></li>")
		LicensePageInfo.NodeServerStatMenu = template.HTML(TempStr)
		LicensePageInfo.NodeClientStatMenu = ""
		TempStr = fmt.Sprintf("<li class=\"current\"><a href=\"/license/\">License Management</a></li>")
		LicensePageInfo.LicenseManagement = template.HTML(TempStr)
	}
	Param_PageNumber, ok := req.URL.Query()["page_num"]
	if !ok || len(Param_PageNumber) < 1 {
		WebServer_Redirect(w, req, "/license/?page_num=1&sort=0")
		return
	}
	log.Println("param_PageNumber:", Param_PageNumber)
	Param_Sort, ok := req.URL.Query()["sort"]
	if !ok || len(Param_Sort) < 1 {
		WebServer_Redirect(w, req, "/license/?page_num=1&sort=0")
		return
	}
	TempStr = fmt.Sprintf("<th><a href=\"/license/?page_num=1\">No</a></th>")
	LicensePageInfo.No = template.HTML(TempStr)

	TempStr = fmt.Sprintf("<th><a href=\"/license/?page_num=1\">Node ID</a></th>")
	LicensePageInfo.NodeID = template.HTML(TempStr)

	TempStr = fmt.Sprintf("<th><a href=\"/license/?page_num=1\">Last Connection Time</a></th>")
	LicensePageInfo.LastConnTime = template.HTML(TempStr)

	TempStr = fmt.Sprintf("<th><a href=\"/license/?page_num=1\">ETC</a></th>")
	LicensePageInfo.ETC = template.HTML(TempStr)

	tmpl, err = template.ParseFiles("./pages/Node_Server_License_Dashboard.html")
	if err != nil {
		log.Println("failed to template.ParseFiles")
		return
	}
	// licensestr := "fp5v5kuaqftciw7di1accj7vpy4575vvkeq6yfna5giyaeeh3mkjxw1yhqkvt4t4nrer81bsdfwfvub6s5q1ys6hr3uaqy6ygvytwar3xjcy2haf6wi7qeeq8j5dfyxus266vxqq5fwa1aaic8ladhtu1ck3fxcgmdt5w8lwha33dhv3lvs58685ersawhapdmdam8nmgt1fslmul4tp8313n1utlgtxetj24li3tl2wsybhswvvvbnlb6ysy5mkfvyj7vcf3gafj8fblie85xeaemub1j2lxbsjstwke3ukbf5w8akm56xx1rtguw8ityhwfqefgpya7434mjq1r1nedq427v5b16cayp3aglg364jxjwmtf7awa64jsyj5xb6qhrjbmqvvx75c2nmw1wsayses3t5382flgsncpnfym26s7wgxmbtw5edicn8q1cjd8s4pdekx3fqf4cnhgvby5dqs1vpwaq8yhfn2h22yt7aw5x3aiksiea1yaltikejk6sj6etrlnddspr6h37l868pgy7eiht5it7gx8t65iswcx2x6bda8gmw4xvmcx1g72qadbn8rf2abdfkc3ubmpwenw42fuamgqvxijex2fudtscwk64bnnfcptfsay6lpp37wfpsfqnnjd6x1qq3hksyihdmrpm4jt28u25ipgx8dp61qmfshjbxwhtschuksessrmdaiyukxcmv6m7gekxnab7w4hdu3pbb2dwpg7f7ml1n166jp"

	// DecryptDecodingStr(licensestr, &TEXT)
	// log.Println(TEXT)
	// _, err = fd.Write([]byte(TEXT))
	// if err != nil {
	// 	log.Println(" Write err:", err)
	// }
	PageNumberStr := fmt.Sprintf("%s", Param_PageNumber)
	PageNumberStr = strings.Replace(PageNumberStr, "[", "", -1)
	PageNumberStr = strings.Replace(PageNumberStr, "]", "", -1)
	PageNumber, err = strconv.Atoi(PageNumberStr)
	if err != nil {
		log.Println("failed to strconv.Atoi PageNamber")
		return
	}

	SortStr := fmt.Sprintf("%s", Param_Sort)
	SortStr = strings.Replace(SortStr, "[", "", -1)
	SortStr = strings.Replace(SortStr, "]", "", -1)

	/*---------------------------------
	  read licensefile


	  ------------------------------------*/

	if PageNumber > 1 {
		PrevPageNumber = PageNumber - 1
	} else {
		PrevPageNumber = 1
	}

	if _, err := toml.DecodeFile("./example.toml", &tomldata); err != nil {
		log.Println("failed to template.ParseFiles")
	}

	for j := range tomldata.NodeID.NodeID {
		RowsCount = j + 1
	}
	log.Println("RowsCount:", RowsCount)
	var startindex int

	log.Println("PageNumber:", PageNumber)
	if PageNumber == 1 {
		startindex = 1
	} else {
		startindex = (PageNumber-1)*RowCountPerPage + 1
	}
	log.Println("startindex:", startindex)
	for i := range tomldata.NodeID.NodeID {
		if startindex <= i+1 && i+1 < startindex+RowCountPerPage {
			LicInfo.No = i + 1
			LicInfo.NodeID = tomldata.NodeID.NodeID[i]
			LicInfo.LastConnTime = "2020-01-01 10:10:1" + strconv.Itoa(i)
			LicInfo.ETC = ""
			LicensePageInfo.LicInfo = append(LicensePageInfo.LicInfo, LicInfo)
		}
	}

	// err = os.Remove("example.toml")
	// if err != nil {
	// 	log.Println(err)
	// }
	//NextRowOffset := (PageNumber - 1) * RowCountPerPage

	PageCount = int(math.Ceil(float64(RowsCount) / float64(RowCountPerPage)))
	log.Println("PageCount:", PageCount)
	if PageNumber < PageCount {
		NextPageNumber = PageNumber + 1
	} else {
		NextPageNumber = PageCount
		log.Println("NexPageNumber:", NextPageNumber)
	}
	/*
		data_group_id := 0
		data_first := 0
		index := 0

		if data_first == 1 {

		}
	*/
	log.Println("MaxPageCountInPage:", MaxPageCountInPage)
	PageIndexStart = (((PageNumber - 1) / MaxPageCountInPage) * MaxPageCountInPage) + 1

	TempStr = fmt.Sprintf("/license/?page_num=%d&sort=%d", 1)
	LicensePageInfo.FirstPage = template.HTML(TempStr)

	TempStr = fmt.Sprintf("/license/?page_num=%d&sort=%d", PrevPageNumber)
	LicensePageInfo.PrevPage = template.HTML(TempStr)

	TempStr = fmt.Sprintf("/license/?page_num=%d&sort=%d", NextPageNumber)
	LicensePageInfo.NextPage = template.HTML(TempStr)

	TempStr = fmt.Sprintf("/license/?page_num=%d&sort=%d", PageCount)
	LicensePageInfo.LastPage = template.HTML(TempStr)

	log.Println("PageCount:", PageCount)
	log.Println("PageIndexStart:", PageIndexStart)

	if PageCount > MaxPageCountInPage {
		LastPageNumber = PageIndexStart + (MaxPageCountInPage - 1)
	} else {
		LastPageNumber = PageCount
	}

	if LastPageNumber > PageCount {
		LastPageNumber = PageCount
	}

	for page_index := PageIndexStart; page_index <= LastPageNumber; page_index++ {
		PageNumInfo.PageNum = page_index
		if PageNumInfo.PageNum == PageNumber {
			PageNumInfo.TagStart = "<strong>"
			PageNumInfo.TagEnd = "</strong>"
		} else {
			log.Println("SortNumber:", SortNumber)
			TempTag := fmt.Sprintf("<a href=\"/license/?page_num=%d&sort=%d\">", PageNumInfo.PageNum, SortNumber)
			PageNumInfo.TagStart = template.HTML(TempTag)
			PageNumInfo.TagEnd = "</a>"
		}

		LicensePageInfo.PageNumInfo = append(LicensePageInfo.PageNumInfo, PageNumInfo)
	}

	tmpl.Execute(w, LicensePageInfo)
}
func GetNICInfo() []NICInformation {
	var NICInfo NICInformation

	NICInfoArray = nil

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Print(err)
		return NICInfoArray
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Print(err)
			continue
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				TempStr := fmt.Sprintf("%v", v)

				if strings.Contains(TempStr, ".") == true {
					if i.Name != "lo" && strings.Contains(i.Name, "virbr") == false {
						NICInfo.Name = i.Name
						NICInfo.IP = fmt.Sprintf("%v", v)
						IP := strings.Split(NICInfo.IP, "/")
						NICInfo.IP = IP[0]

						log.Println("NIC Name :", NICInfo.Name, "NIC IP :", NICInfo.IP)

						NICInfoArray = append(NICInfoArray, NICInfo)
					}
				}
			}
		}
	}
	return NICInfoArray
}

func Delete_Client_Statistics(db *sql.DB) {
	var Select_Standard_ID_SQL string
	var Select_Del_And_Cyc_Time_SQL string
	var timer *time.Timer
	var Del_Time, Cyc_Time int
	var Del_Time_Str string
	var Rows *sql.Rows
	var err error

	log.Println("here is in Delete_Client_Statistics")

	Select_Del_And_Cyc_Time_SQL = "Select Del_Time, Cyc_Time from Config_Delete"
	Rows, _ = sqlitedb_lib.Query_DB(db, Select_Del_And_Cyc_Time_SQL)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		log.Println("Rows Delete err:", err)
	}

	for Rows.Next() {
		err = Rows.Scan(&Del_Time, &Cyc_Time)
		if err != nil {
			log.Println("data Scan error:", err)
		}
	}
	log.Println("Del_Time:", Del_Time)
	log.Println("Cyc_Time:", Cyc_Time)
	Del_Time_Str = strconv.Itoa(Del_Time)

	Select_Standard_ID_SQL = "SELECT ID FROM Client_Statistics_Common where datetime('now','localtime','-" + Del_Time_Str + " days') = Time"
	for {
		timer = time.NewTimer(time.Minute * time.Duration(Cyc_Time))
		<-timer.C

		err = DB_Clnt_Delete_Transaction(db, Select_Standard_ID_SQL)
		if err != nil {
			log.Println("DB Client Delete Fail!")
		}
	}

}

func DB_Clnt_Delete_Transaction(db *sql.DB, Select_Standard_ID_SQL string) error {
	var Rows *sql.Rows
	var tx *sql.Tx
	var err error
	var Standard_ID int64

	log.Println("here is in DB_Clnt_Delete_Transaction")
	Rows, _ = sqlitedb_lib.Query_DB(db, Select_Standard_ID_SQL)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		log.Println("Select Standard ID Fail!")
		return err
	}

	for Rows.Next() {
		err = Rows.Scan(&Standard_ID)
		if err != nil {
			log.Println("data Scan error:", err)
			return err
		}
	}

	tx, _ = sqlitedb_lib.DB_Begin(db)
	if tx == nil {
		log.Println(" transaction Begin Fail!")
		return err
	}
	defer sqlitedb_lib.DB_Rollback(tx)

	log.Println("Standard ID:", Standard_ID)
	_, err = sqlitedb_lib.DB_Exec(tx, "DELETE FROM Client_Statistics_Common WHERE "+strconv.FormatInt(Standard_ID, 10)+">ID")
	if err != nil {
		log.Println("Delete Client_Statistics_Common Fail! ", err)
		return err
	}

	_, err = sqlitedb_lib.DB_Exec(tx, "DELETE FROM Client_Statistics_Data WHERE "+strconv.FormatInt(Standard_ID, 10)+">ID")
	if err != nil {
		log.Println("Delete Client_Statistics_Common Fail!")
		return err
	}

	sqlitedb_lib.DB_Commit(tx)

	return nil
}

func Delete_Server_Statistics(db *sql.DB) {
	var Select_Standard_ID_SQL string
	var Select_Del_And_Cyc_Time_SQL string
	var timer *time.Timer
	var Del_Time, Cyc_Time int
	var Del_Time_Str string
	var Rows *sql.Rows
	var err error

	log.Println("here is in Delete_Client_Statistics")

	Select_Del_And_Cyc_Time_SQL = "Select Del_Time, Cyc_Time from Config_Delete"
	Rows, _ = sqlitedb_lib.Query_DB(db, Select_Del_And_Cyc_Time_SQL)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
	}

	for Rows.Next() {
		err = Rows.Scan(&Del_Time, &Cyc_Time)
		if err != nil {
			log.Println("data Scan error:", err)
		}
	}
	Del_Time_Str = strconv.Itoa(Del_Time)

	Select_Standard_ID_SQL = "SELECT ID FROM Server_Statistics_Common where datetime('now','localtime','-" + Del_Time_Str + " days') = Time"
	for {
		timer = time.NewTimer(time.Minute * time.Duration(Cyc_Time))
		<-timer.C

		err = DB_Serv_Delete_Transaction(db, Select_Standard_ID_SQL)
		if err != nil {
			log.Println("DB Server Delete Fail!")
		}
	}

}

func DB_Serv_Delete_Transaction(db *sql.DB, Select_Standard_ID_SQL string) error {
	var Rows *sql.Rows
	var tx *sql.Tx
	var err error
	var Standard_ID int64

	log.Println("here is in DB_Serv_Delete_Transaction")

	Rows, _ = sqlitedb_lib.Query_DB(db, Select_Standard_ID_SQL)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		log.Println("Select Standard ID Fail!")
		return err
	}

	for Rows.Next() {
		err = Rows.Scan(&Standard_ID)
		if err != nil {
			log.Println("data Scan error:", err)
			return err
		}
	}

	tx, _ = sqlitedb_lib.DB_Begin(db)
	if tx == nil {
		log.Println(" transaction Begin Fail!")
		return err
	}
	defer sqlitedb_lib.DB_Rollback(tx)

	_, err = sqlitedb_lib.DB_Exec(tx, "DELETE FROM Server_Statistics_Common WHERE "+strconv.FormatInt(Standard_ID, 10)+">ID")
	if err != nil {
		log.Println("Delete Client_Statistics_Common Fail!")
		return err
	}

	_, err = sqlitedb_lib.DB_Exec(tx, "DELETE FROM Server_Statistics_Data WHERE "+strconv.FormatInt(Standard_ID, 10)+">ID")
	if err != nil {
		log.Println("Delete Client_Statistics_Common Fail!")
		return err
	}

	sqlitedb_lib.DB_Commit(tx)
	return nil

}

func PrepareSqliteDB() {
	var err error

	SplitStr := strings.Split(SqliteDB, "/")
	for i := range SplitStr {
		DBName = SplitStr[i]
	}

	DBPath = strings.Replace(SqliteDB, DBName, "", -1)
	log.Println("DBPATH", DBPath, "DBName", DBName)

	err = os.MkdirAll(DBPath, 0644)
	if err != nil {
		log.Println("Mkdir DBPath err:", err)
		return
	}
}

func GetProxyInfo(Database *sql.DB) (int32, error) {
	var QueryStr string
	var Rows *sql.Rows
	var err error
	var Symbol_Name, Server string
	var Bind, Node_Mode int
	var ProxyIP string
	var NIC_Name_Len, ProxyIP_Len int

	ProxyIPStrArray = nil

	QueryStr = fmt.Sprintf("SELECT * FROM Config_Frontend_Backend_Data")
	Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return DB_RET_FAIL, err
	}

	for Rows.Next() {
		err = Rows.Scan(&Symbol_Name, &Bind, &Node_Mode, &Server)
		if err != nil {
			log.Println(" data Scan error:", err)
			return DB_RET_FAIL, err
		}
		if Node_Mode == Node_MODE_SERVER {
			continue
		}

		SplitStr := strings.Split(Server, ",")
		for i := range SplitStr {

			NIC_Name_Len = strings.Index(SplitStr[i], "/")
			SplitStr[i] = SplitStr[i][NIC_Name_Len+1:]
			ProxyIP_Len = strings.Index(SplitStr[i], ":")
			ProxyIP = SplitStr[i][0:ProxyIP_Len]
			SplitStr[i] = SplitStr[i][ProxyIP_Len+1:]

			ProxyIPStrArray = append(ProxyIPStrArray, ProxyIP)
			log.Println("Proxy IP : ", ProxyIP)
		}
	}
	return DB_RET_SUCC, nil
}

func GetNodeMode(Database *sql.DB) (int32, error) {
	var QueryStr string
	var Rows *sql.Rows
	var err error
	var Node_Mode, TempNodeMode int

	TempNodeMode = Node_FLAG_NONE
	QueryStr = fmt.Sprintf("SELECT Node_Mode FROM Config_Frontend_Backend_Data GROUP BY Node_Mode")
	log.Println(QueryStr)
	Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return DB_RET_FAIL, err
	}

	for Rows.Next() {
		err = Rows.Scan(&Node_Mode)
		if err != nil {
			log.Println(" data Scan error:", err)
			return DB_RET_FAIL, err
		}
		TempNodeMode |= Node_Mode
	}
	Rows.Close()

	switch TempNodeMode {
	case Node_MODE_NONE:
		Node_Flag = Node_FLAG_NONE

	case Node_MODE_CLIENT:
		Node_Flag = Node_FLAG_CLIENT

	case Node_MODE_SERVER:
		Node_Flag = Node_FLAG_SERVER

	case Node_MODE_CLIENT | Node_MODE_SERVER:
		Node_Flag = Node_FLAG_CLIENT_AND_SERVER
	}

	if Node_Flag == Node_FLAG_NONE {
		log.Println("Node_Flag : Node_FLAG_NONE")
	} else if Node_Flag == Node_FLAG_CLIENT {
		log.Println("Node_Flag : Node_FLAG_CLIENT")
	} else if Node_Flag == Node_FLAG_SERVER {
		log.Println("Node_Flag : Node_FLAG_SERVER")
	} else if Node_Flag == Node_FLAG_CLIENT_AND_SERVER {
		log.Println("Node_Flag : Node_FLAG_CLIENT_AND_SERVER")
	}
	return DB_RET_SUCC, nil
}

func GetChangeClientIPMode(Database *sql.DB) (int, error) {
	var QueryStr string
	var Rows *sql.Rows
	var Bridge_Mode, Node_Buff_Size, Node_Encrypt, Change_IP_Func int
	var err error

	QueryStr = fmt.Sprintf("SELECT * FROM Config_Node_Data")
	Rows, _ = sqlitedb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return DB_RET_FAIL, err
	}

	for Rows.Next() {
		err = Rows.Scan(&Bridge_Mode, &Node_Buff_Size, &Node_Encrypt, &Change_IP_Func)
		if err != nil {
			log.Println(" data Scan error:", err)
			return DB_RET_FAIL, err
		}
	}

	return Change_IP_Func, nil
}

func GetDevOSFlag() int {
	var found bool

	fd, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return GENERAL_OS
	}

	scanner := bufio.NewScanner(fd)

	for scanner.Scan() {
		found = strings.Contains(scanner.Text(), "Atheros")
		if found == true {
			fd.Close()
			return DEVICE_OS
		}

		found = strings.Contains(scanner.Text(), "TP-LINK")
		if found == true {
			fd.Close()
			return DEVICE_OS
		}

		found = strings.Contains(scanner.Text(), "MIPS")
		if found == true {
			fd.Close()
			return DEVICE_OS
		}
	}
	fd.Close()

	return GENERAL_OS
}

func ShowHelpCommand() {
	log.Println("Usage: ./stat_web_server [Arg] [Options]")
	log.Println(" Available Args")
	log.Println(" -c	Run as Control Web Server")
	log.Println(" -l	Run as Local Web Server")
	log.Println("")
	log.Println(" Available Options")
	log.Println(" -d	Run as Daemon")
	log.Println("")
}

func EncryptEncodingStr(PlainText string, RetText *string) {
	encrypt := make([]byte, len(PlainText))
	err := aes_cfb.EncAES_CFB8_256(encrypt, []byte(PlainText), aes_key, iv)
	if err != nil {
		log.Println("EncAES err:", err)
		return

	}
	new_encoder := base32.NewEncoding(string(base32_alphabet))
	new_encoder = new_encoder.WithPadding(base32.NoPadding)
	*RetText = new_encoder.EncodeToString(encrypt)

	//log.Printf("Enc %s -> %x \nEncode %s\n", PlainText, encrypt, *RetText)
}

func DecryptDecodingStr(EncryptEncodingText string, RetText *string) {

	new_decoder := base32.NewEncoding(string(base32_alphabet))
	new_decoder = new_decoder.WithPadding(base32.NoPadding)
	encrypt, err := new_decoder.DecodeString(EncryptEncodingText)
	if err != nil {
		log.Println("Decoding err:", err)
		return
	}

	PlainText := make([]byte, len(encrypt))

	err = aes_cfb.DecAES_CFB8_256(PlainText, encrypt, aes_key, iv)
	if err != nil {
		log.Println("DecAES err:", err)
		return
	}
	*RetText = string(PlainText)
	//log.Printf("Dec %s -> %x Decode %s\n", EncryptEncodingText, encrypt, string(PlainText))
}

func Decrypt_dbcfginfo(id string, pw string, ip string, port string, dbname string) (string, string, string, string, string) {
	var ID string
	var PASSWORD string
	var IP string
	var PORT string
	var DBNAME string

	DecryptDecodingStr(id, &ID)
	DecryptDecodingStr(pw, &PASSWORD)
	DecryptDecodingStr(ip, &IP)
	DecryptDecodingStr(port, &PORT)
	DecryptDecodingStr(dbname, &DBNAME)

	return ID, PASSWORD, IP, PORT, DBNAME

}

func CheckLogFile() {
	for {
		timer := time.NewTimer(time.Second * 1)
		<-timer.C
		if _, err := os.Stat(ProcessLogFileName); err != nil {
			if os.IsNotExist(err) {
				f, err := os.OpenFile(ProcessLogFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
				if err != nil {
					log.Fatal(err)
				}
				log.SetOutput(f)
			}
		}
	}
}

func main() {
	var MaxArgs, MaxOptions, DaemonFlag, i int
	var WebServerFlag string

	MaxArgs = 1
	MaxOptions = 1

	if len(os.Args) < MaxArgs+1 || len(os.Args) > MaxArgs+MaxOptions+1 {
		ShowHelpCommand()
		return
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)

	for i = 0; i < MaxArgs; i++ {
		switch os.Args[i+1] {
		case "-c":
			ControlServerFlag = 1
			WebServerFlag = os.Args[i+1]

		case "-l":
			ControlServerFlag = 0
			WebServerFlag = os.Args[i+1]

		default:
			ShowHelpCommand()
			return
		}
	}

	if len(os.Args) > MaxArgs+1 {
		for i = 0; i < MaxOptions; i++ {
			switch os.Args[i+MaxArgs+1] {
			case "-d":
				DaemonFlag = 1

			default:
				ShowHelpCommand()
				return
			}
		}
	}

	if DaemonFlag == 1 {
		context := &daemon.Context{
			PidFileName: "stat_web_server.pid",
			PidFilePerm: 0644,
			LogFileName: ProcessLogFileName,
			LogFilePerm: 0640,
			WorkDir:     "./",
			Umask:       027,
			Args:        []string{"./stat_web_server", WebServerFlag},
		}

		child, err := context.Reborn()
		if err != nil {
			log.Fatal("Unable to run: ", err)
		}

		if child != nil {
			return
		}
		defer context.Release()
	}

	go SigHandler()
	go CheckLogFile()

	GetNICInfo()
	DeviceOSFlag = GetDevOSFlag()
	if DeviceOSFlag == DEVICE_OS {
		log.Println("OS : Device OS")
	} else if DeviceOSFlag == GENERAL_OS {
		log.Println("OS : General OS")
	}

	if ControlServerFlag == 1 {
		RunControlWebServer()
	} else {
		RunLocalWebServer()
	}

	log.Println("test log 4")
	finish := make(chan bool)
	log.Println("test log 5")
	<-finish
	log.Println("test log 6")
}
