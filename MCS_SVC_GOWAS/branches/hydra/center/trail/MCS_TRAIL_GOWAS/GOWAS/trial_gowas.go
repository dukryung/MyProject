package main

import (
	//"MCS_SERVICE_GOWAS/library/db/mariadb_lib"
	//"MCS_SERVICE_GOWAS/library/db/msdb_lib"

	//"crypto/aes"
	//"crypto/cipher"
	"crypto/md5"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/BurntSushi/toml"
	_ "github.com/denisenkom/go-mssqldb"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/mitchellh/mapstructure"
	"github.com/sevlyar/go-daemon"
	"gopkg.in/natefinch/lumberjack.v2"

	"bufio"
	"bytes"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"./library/db/mariadb_lib"
	"./library/db/msdb_lib"
	"./library/security/aes_cfb"
	"./library/utility/disk"
	"./library/utility/product_rand_key"
)

var DeviceOSFlag int
var ControlServerFlag int
var CommonIDArray []int
var ProxyIPStrArray []string
var NICInfoArray []NICInformation
var ControlServerIP, ControlServerPort, ControlServerSendInterval string
var RowCountPerPage = 25
var MaxPageCountInPage = 10
var LoginTimeout = 60 * 30 /* sec */
var DBPath, DBName string
var UpdateLock = &sync.Mutex{}
var ProcessLogFileName = "./log/trial_gowas.log"

var PackageLockTable *PackageMapTable
var AuthProvisioningSeqNo = 1
var AuthStatisticsSeqNo = 1
var AuthAssocationSeqNo = 1
var AuthPackageSeqNo = 1

var StatCycleTime = 60

var DBIP = ""
var DBPORT = ""
var DBNAME = ""
var DBUSER = ""
var DBUSERPW = ""

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
	DB_RET_SUCC = 0
	DB_RET_FAIL = -1
)

//-----{ defined struct } -----// {
var RET_INT_SUCC = 1
var RET_INT_FAIL = 0

/*-------------------------------------------------------------------------
type kms_response_pack struct {
  code int
  message string
}

var kms_response_class []kms_response_pack {
  kms_response_pack {code: 1000, message: "Cookie expiretime timed out"},
  kms_response_pack {code: 1000, message: "Cookie expiretime timed out"},
  kms_response_pack {code: 1010, message: "Not Exist UserID"},
  kms_response_pack {code: 1011, message: "Exist UserID"},
  kms_response_pack {code: 1000, message: "Cookie expiretime timed out"},
  kms_response_pack {code: 1080, message: "failed to db processing"},
  kms_response_pack {code: 1081, message: "error db data"},
  kms_response_pack {code: 1090, message: "No access authority"},
  kms_response_pack {code: 1100, message: "Cookie expiretime timed out"},
}
-------------------------------------------------------------------------*/

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

type CookiesUserData struct {
	CookieUserID       string
	CookieUserProperty string
}

/*
type PreparedStatementValue union {
  int32
  int64
  uint32
  uint64
  //float32
  //float64
  //ufloat32
  //ufloat64
}
*/

type PreparedStatementObject func() *PreparedStatementPack
type PreparedStatementSetInt32 func(*PreparedStatementPack, int, int32)
type PreparedStatementSetInt64 func(*PreparedStatementPack, int, int64)
type PreparedStatementSetUInt32 func(*PreparedStatementPack, int, uint32)
type PreparedStatementSetUInt64 func(*PreparedStatementPack, int, uint64)
type PreparedStatementSetString func(*PreparedStatementPack, int, string)
type PreparedStatementExecuteQuery func(*PreparedStatementPack) *sql.Rows
type PreparedStatementExecuteCMD func(*PreparedStatementPack) int
type PreparedStatementClose func(*PreparedStatementPack)

type PreparedStatementPack struct {
	SQLQuery string

	ArgumentCnt    int
	ArgumentArrary []string

	SetInt32  PreparedStatementSetInt32
	SetInt64  PreparedStatementSetInt64
	SetUInt32 PreparedStatementSetUInt32
	SetUInt64 PreparedStatementSetUInt64
	SetString PreparedStatementSetString

	ExecuteQuery PreparedStatementExecuteQuery
	ExecuteCMD   PreparedStatementExecuteCMD

	Close PreparedStatementClose
}

type ExceptionPage struct {
	ExceptionCode    int
	ExceptionURL     string
	ExceptionContent string
	ExceptionAction  string
}

type SVCHtmlMainMenu struct {
	Setup      template.HTML
	Statistics template.HTML
}

type HtmlPageListComponent struct {
	ParamPageNumItem   string
	ParamPageNumString string
	ParamPageNum       int

	ParamPageSortItem   string
	ParamPageSortString string
	ParamPageSort       int

	MaxPageCount    int
	MaxRowCountPage int
	PageCount       int
	RowCountTotal   int
	RowOffset       int

	PageIndexStart int
	PageBeginNum   int
	PageEndNum     int
	PrevPageNum    int
	NextPageNum    int

	TempleteViewBeginPage template.HTML   // <<
	TempleteViewEndPage   template.HTML   // >>
	TempleteViewPrevPage  template.HTML   // <
	TempleteViewNextPage  template.HTML   // >
	TempleteViewPageList  []template.HTML // ...
	PageLinkURL           string
	PageAdditionParams    string

	returnCode int

	errPage ExceptionPage
}

type OEMInformation struct {
	OEMName        string
	OEMWEBHeadInfo string
	OEMWEBTailInfo string
}

type CommonHTML struct {
	CookiesData CookiesUserData
	MainMenu    SVCHtmlMainMenu
	OEMData     OEMInformation

	SQLQuery          string
	SQLQueryCondition string
}

type jsonInputWebAPIEncodeValue struct {
	InputValue string `json:"input"`
}

type jsonInputWebAPIHashDerivationValue struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	Seperator   string `json:"seperator"`
	MessageType string `json:"msgtype"`
	UserKeyID   string `json:"user_key_id"`
	UserKey     string `json:"user_key"`
	DeviceID    string `json:"device_id"`
	NodeID      string `json:"mcse_id"`
	AuthKey     string `json:"auth_key"`
}

type jsonOutputWebAPIEncodeValue struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	InputValue  string `json:"input"`
	OutputValue string `json:"output"`
}

type jsonOutputWebAPIHashDerivationValue struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	OutputValue string `json:"output"`
}

const (
	ProvisionVersion = "1.0"
	ProvisionMethod  = "CFGSET"
)

type SettingsInformation struct {
	Password                      string                `mapstructure:"Password" json:"password"`
	VerifyingPassword             string                `mapstructure:"verif_password" json:"verif_password"`
	Maximum_ConnectionCount       string                `mapstructure:"max_conn" json:"max_conn"`
	Recv_Buf_Size                 string                `mapstructure:"recv_buffer_size" json:"recv_buffer_size"`
	Send_Buf_Size                 string                `mapstructure:"send_buffer_size" json:"send_buffer_size"`
	Connection_Timeout            string                `mapstructure:"timeout_connect" json:"timeout_connect"`
	Client_Reconnect_Timeout      string                `mapstructure:"timeout_client" json:"timeout_client"`
	Server_Reconnect_Timeout      string                `mapstructure:"timeout_server" json:"timeout_server"`
	Limit_Size_Log_Storage        string                `mapstructure:"disk_limit" json:"disk_limit"`
	Maxsize_Per_Logfile           string                `mapstructure:"max_size" json:"max_size"`
	Logfile_Path                  string                `mapstructure:"log_path" json:"log_path"`
	Err_Logfile_Path              string                `mapstructure:"err_path" json:"err_path"`
	Statistic_Send_Control_Server string                `mapstructure:"stat_send_ctrl_srv" json:"stat_send_ctrl_srv"`
	Statistic_Collection_Cycle    string                `mapstructure:"stat_coll_cycle" json:"stat_coll_cycle"`
	Statistic_Server_Ip           string                `mapstructure:"stat_server_ip" json:"stat_server_ip"`
	Statistic_Server_Port         string                `mapstructure:"stat_server_port" json:"stat_server_port"`
	Statistic_Send_Cycle          string                `mapstructure:"stat_data_send_cycle" json:"stat_data_send_cycle"`
	Bridge_Used                   string                `mapstructure:"node_bridage" json:"node_bridage"`
	Bridge_Buf_Size               string                `mapstructure:"node_buffer_size" json:"node_buffer_size"`
	Encrypt_Mode                  string                `mapstructure:"encrypt" json:"encrypt"`
	Change_Client_IP              string                `mapstructure:"ip_client_mode" json:"ip_client_mode"`
	Node_ID                       string                `mapstructure:"nodeid" json:"nodeid"`
	KMS_Address                   string                `mapstructure:"kms_ip" json:"kms_ip"`
	KMS_Port                      string                `mapstructure:"kms_port" json:"kms_port"`
	SiteList                      []FrontendInformation `mapstructure:"frontend" json:"frontend"`
}

type FrontendInformation struct {
	Frontendsymbol string                   `mapstructure:"name" json:"name"`
	FrontendPort   string                   `mapstructure:"bind" json:"bind"`
	NodeMode       string                   `mapstructure:"node_mode" json:"node_mode"`
	Backend        []BackendInformationList `mapstructure:"backend" json:"backend"`
}

type BackendInformationList struct {
	LAN_Interface string `mapstructure:"nic" json:"nic"`
	BackendIP     string `mapstructure:"server_ip" json:"server_ip"`
	BackendPort   string `mapstructure:"server_port" json:"server_port"`
}

type ProvisionHeader struct {
	Version   string `json:"version"`
	Method    string `json:"method"`
	Seperator string `json:"seperator"`
	Msgtype   string `json:"msgtype"`
	Userkey   string `json:"userkey"`
	UserKeyID string `json:"userkeyid"`
	Nodeid    string `json:"nodeid"`
	DeviceID  string `json:"deviceid"`
	CurSeq    int64  `mapstructure:"cur_seq" json:"cur_seq"`
	Seq       int64  `json:"seq"`
}

type ProvisionBody struct {
	Code    int                  `json:"code,omitempty"`    // 0 is ignore
	Message string               `json:"message,omitempty"` // emptry is ignore
	Data    *SettingsInformation `json:"data,omitempty"`
}

type ProvisionProtocol struct {
	Header ProvisionHeader `json:"header"`
	Body   ProvisionBody   `json:"body, omitempty"`
}

type PackageLockData struct {
	//keyID uint64
	keyID             int
	platformUsedCount int

	linuxUsedFlag   int
	linuxMutex      (sync.Mutex)
	windowsUsedFlag int
	windowsMutex    (sync.Mutex)
}

type PackageMapTable struct {
	MutexLock sync.Mutex
	MapTable  map[int]*PackageLockData
}

type jsonOutputWebAPIAuthInvalidAccess struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type jsonInputWebAPIAuthTrialSetupPack struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	Seperator   string `json:"seperator"`
	MessageType string `json:"msgtype"`
	MessageSeq  string `json:"msgseq"`
	SN1         string `json:"sn1"`
	SN2         string `json:"sn2"`
	SN3         string `json:"sn3"`
	AuthKey     string `json:"auth_key"`
	AuthToken   string `json:"auth_token"`
}

type jsonOutputWebAPIAuthTrialSetup struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	Seperator   string `json:"seperator"`
	MessageType string `json:"msgtype"`
	MessageSeq  string `json:"msgseq"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	AuthKey     string `json:"auth_key"`
	Expiretime  string `json:"expiretime"`
	Param       string `json:"param"`
	Event       string `json:"event"`
}

type PackageInformation struct {
	User_id             string `mapstructure:"user_id" json:"user_id"`
	User_key            string `mapstructure:"user_key" json:"user_key"`
	Platform_type       string `mapstructure:"platform_type" json:"platform_type"`
	Mcse_max_count      string `mapstructure:"mcse_max_count" json:"mcse_max_count"`
	Pkg_end_year        string `mapstructure:"pkg_end_year" json:"pkg_end_year"`
	Pkg_end_monty       string `mapstructure:"pkg_end_monty" json:"pkg_end_monty"`
	Pkg_end_day         string `mapstructure:"pkg_end_day" json:"pkg_end_day"`
	Pkg_home_path       string `mapstructure:"pkg_home_path" json:"pkg_home_path"`
	Pkg_unique_sub_path string `mapstructure:"pkg_unique_sub_path" json:"pkg_unique_sub_path"`
	Pkg_filename        string `mapstructure:"pkg_filename" json:"pkg_filename"`
	Pkg_product_name    string `mapstructure:"pkg_product_name" json:"pkg_product_name"`
}

type NICInformation struct {
	Name string
	IP   string
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
type TableRowInfo struct {
	Style       string
	DataGroupID string
	DataFirst   string
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

type jsonInputWebAPIPerformanceMemoryRsp struct {
	InputValue string `json:"input"`
}

//-----{ defined struct } -----// }

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

func InitLogger() {
	logStruct := &lumberjack.Logger{
		Filename:   ProcessLogFileName, // Filename is the file to write logs to
		MaxSize:    100,                // MaxSize is the maximum size in megabytes of the log file before it gets rotated
		MaxBackups: (10 * 5),           // MaxBackups is the maximum number of old log files to retain
		MaxAge:     30,                 // MaxAge is the maximum number of days to retain old log files based on the timestamp encoded in their filename
		LocalTime:  true,               // LocalTime determines if the time used for formatting the timestamps in backup files is the computer's local time (The default is to use UTC time)
		Compress:   false,              // Compress determines if the rotated log files should be compressed using gzip (disabled by default)
	}

	log.SetOutput(logStruct)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)

	go func() {
		for {
			<-c
			logStruct.Rotate()
		}
	}()
}

func Cookie_Check(w http.ResponseWriter, req *http.Request) int {
	cookies := req.Cookies()

	log.Println("Cookie Check:", cookies)

	if len(cookies) == 0 {
		log.Println("Not Exist Cookies")
		//-- WebServer_Redirect(w, req, "/login") --//
		return -1
	}

	for i := range cookies {
		session, _ := store.Get(req, cookies[i].Name)
		if session != nil {
			log.Println("Cookie Check:", session.Values)

			id, ok := session.Values["id"].(string)
			if !ok || len(id) <= 0 {
				//http.Error(w, "Forbidden", http.StatusForbidden)
				log.Println("Exist Cookies")
				return -1
			}

			id, ok = session.Values["id"].(string)
			log.Println("Cookie Information ID:", id)
			session.Options.MaxAge = LoginTimeout
			session.Save(req, w)
		}
	}

	return 0
}

func HTTPReq_ReturnParamValue(req *http.Request, RequestMethodType string, ParamName string) string {

	if RequestMethodType == "" {
		log.Println("invalid Request Method Type:" + RequestMethodType)
		return ""
	}

	if ParamName == "" {
		log.Println("invalid Param Name:" + ParamName)
		return ""
	}

	if RequestMethodType == "GET" {
		SearchParamValue, ok := req.URL.Query()[ParamName]
		if !ok {
			log.Println("not founded Param Value [" + ParamName + "]")
			return ""
		}

		ParamValue := fmt.Sprintf("%s", SearchParamValue)
		ParamValue = strings.Replace(ParamValue, "[", "", -1)
		ParamValue = strings.Replace(ParamValue, "]", "", -1)
		ParamValue = strings.TrimSpace(ParamValue)

		if ParamValue == "" {
			log.Println("not founded Param Value [" + ParamName + "]")
			return ""
		}

		log.Println("GET URL Parameter [" + ParamName + " : " + ParamValue + "]")
		return ParamValue

	} else if RequestMethodType == "POST" {
		req.ParseForm()

		//log.Println(req.Form)

		SearchParamValue := fmt.Sprintf("%s", req.Form[ParamName])
		if SearchParamValue == "" {
			log.Println("not founded Param Value [" + SearchParamValue + "]")
			return ""
		}

		ParamValue := SearchParamValue
		ParamValue = strings.Replace(ParamValue, "[", "", -1)
		ParamValue = strings.Replace(ParamValue, "]", "", -1)
		ParamValue = strings.TrimSpace(ParamValue)

		if ParamValue == "" {
			log.Println("not founded Param Value [" + ParamName + "]")
			return ""
		}

		log.Println("POST FORM Parameter [" + ParamName + " : " + ParamValue + "]")
		return ParamValue

	} else {
		log.Println("invalid Request Method Type:" + RequestMethodType)
		return ""
	}
}

func Cookie_GetValue(req *http.Request, key string) string {
	cookies := req.Cookies()

	if len(cookies) == 0 {
		log.Println("Not Exist Cookies")
		return ""
	}

	for i := range cookies {
		session, _ := store.Get(req, cookies[i].Name)
		if session != nil {
			log.Println("Cookie Check:", session.Values)

			cookie_value, ok := session.Values[key].(string)
			if !ok || len(cookie_value) <= 0 {
				//http.Error(w, "Forbidden", http.StatusForbidden)
				log.Println("Exist Cookies")
				return ""
			} else {
				return cookie_value
			}
		}
	}

	return ""
}

func GetPackageNFSHomePath() string {
	var SVCgoWASHomePath string

	//SVCgoWASHomePath = "/home/kwgwak77/WORKSPACE/PACKAGE_HOME"
	SVCgoWASHomePath = "/home/mcspkg"
	return SVCgoWASHomePath
}

func GetPackageHomePath() string {
	var PackageHomePath string

	ProcessPWD, err := os.Getwd()
	if err != nil {
		log.Println("oem process pwd return value error")
		return ""
	}

	PackageHomePath = ProcessPWD + "/database" + "/package_home/"
	return PackageHomePath
}

func GetAES256EncryptKey() string {
	//var Database *sql.DB
	//var ResultSetRows *sql.Rows
	//var QueryString string
	var EncryptKey string
	var FORCE_FIX_AES_KEY = []byte{109, 56, 85, 44, 248, 44, 18, 128, 236, 116, 13, 250, 243, 45, 122, 133, 199, 241, 124, 188, 188, 93, 65, 153, 214, 193, 127, 85, 132, 147, 193, 68}

	/*------------------------------------------------------------------
		Database = MariaDB_Open()
		defer MariaDB_Close(Database)
		QueryString = "SELECT OEM_PACKAGE_ENCRYPTION_KEY FROM AESInformation"
		ResultSetRows, _ = msdb_lib.Query_DB(Database, QueryString)
		for ResultSetRows.Next() {
			err := ResultSetRows.Scan(&EncryptKey)
			if err != nil {
				ResultSetRows.Close()
				log.Println("oem name data db scan error:", err)

				return ""
			}
		}
		ResultSetRows.Close()
	  ------------------------------------------------------------------*/

	/*--------------------------------------------------------------
	  if len(EncryptKey) == 0 {
	    log.Println("oem name data db return value is empty string")
	    return ""
	  }
	  --------------------------------------------------------------*/

	EncryptKey = string(FORCE_FIX_AES_KEY)
	//log.Println("Force EncryptKey:" + EncryptKey)

	return EncryptKey
}

func GetAES256EncryptIV() string {
	//var Database *sql.DB
	//var ResultSetRows *sql.Rows
	//var QueryString string
	var EncryptIV string
	var FORCE_FIX_IV = []byte{89, 93, 106, 165, 128, 137, 36, 38, 122, 121, 249, 59, 151, 133, 155, 148}

	/*------------------------------------------------------------------
		Database = MariaDB_Open()
		defer MariaDB_Close(Database)
		QueryString = "SELECT OEM_PACKAGE_ENCRYPTION_IV FROM kms_configure"
		ResultSetRows, _ = msdb_lib.Query_DB(Database, QueryString)
		for ResultSetRows.Next() {
			err := ResultSetRows.Scan(&EncryptIV)
			if err != nil {
				ResultSetRows.Close()
				log.Println("oem name data db scan error:", err)

				return ""
			}
		}
		ResultSetRows.Close()
	  ------------------------------------------------------------------*/

	/*--------------------------------------------------------------
	  if len(EncryptIV) == 0 {
	    log.Println("oem name data db return value is empty string")
	    return ""
	  }
	  --------------------------------------------------------------*/

	EncryptIV = string(FORCE_FIX_IV)
	//log.Println("Force EncryptIV:" + EncryptIV)

	return EncryptIV
}

func CreateLicenseFile(OSType string, HomeDirPath string, FilePath string, EncryptFlag bool, EncryptKey string, EncryptIV string, UserID string, UserKey string, NodeIDMaxCount int, NodeIDCount int, EndDateYear string, EndDateMonth string, EndDateDay string, NodeIDArrary []string) bool {
	var LineContextArrary []string
	var LineContextAll string
	var LineContextNodeIDList string
	var LineContent string
	var LineNodeID string
	var CRLF string
	var OutputContext string
	var Result bool

	if OSType == "" || HomeDirPath == "" || FilePath == "" || EncryptKey == "" || EncryptIV == "" || UserID == "" || UserKey == "" || NodeIDMaxCount == 0 || NodeIDCount == 0 || EndDateYear == "" || EndDateMonth == "" || EndDateDay == "" || len(NodeIDArrary) == 0 {
		log.Println("CreateLicenseFile - invalid argument")
		return false
	}

	log.Println("CreateLicenseFile :", FilePath)

	if OSType != "LINUX" && OSType != "WINDOWS" {
		return false
	}

	Result = disk.IsExistDirectoryPath(HomeDirPath)
	if Result != true {
		Result = disk.CreateDirectoryPath(HomeDirPath)
		if Result != true {
			return false
		}
	}

	Result = disk.IsExistFilePath(FilePath)
	if Result == true {
		Result = disk.RemoveFilePath(FilePath)
		if Result != true {
			log.Println("failed to delete exist file (filepath:", FilePath, ")")
		}
	}

	if OSType == "LINUX" {
		CRLF = "\n"
	} else if OSType == "WINDOWS" {
		CRLF = "\r\n"
	}

	LineContextArrary = append(LineContextArrary, "[UserKey]"+CRLF)
	LineContextArrary = append(LineContextArrary, "UserID = \""+UserID+"\""+CRLF)
	LineContextArrary = append(LineContextArrary, "UserKey = \""+UserKey+"\""+CRLF)
	LineContextArrary = append(LineContextArrary, "NodeID_Total = "+strconv.Itoa(NodeIDMaxCount)+CRLF)
	LineContextArrary = append(LineContextArrary, "NodeID_Current = "+strconv.Itoa(NodeIDCount)+CRLF)
	LineContextArrary = append(LineContextArrary, "EndDateYear = "+EndDateYear+CRLF)
	LineContextArrary = append(LineContextArrary, "EndDateMonth = "+EndDateMonth+CRLF)
	LineContextArrary = append(LineContextArrary, "EndDateDay = "+EndDateDay+CRLF)
	LineContextArrary = append(LineContextArrary, CRLF)

	LineContextArrary = append(LineContextArrary, "[NodeID]"+CRLF)

	for _, LineNodeID = range NodeIDArrary {
		LineContextNodeIDList += "\"" + LineNodeID + "\","
	}

	if len(LineContextNodeIDList) > 0 {
		LineContextNodeIDList = strings.TrimRight(LineContextNodeIDList, ",")
		LineContextNodeIDList = "NodeID = [" + LineContextNodeIDList + "]"
		LineContextArrary = append(LineContextArrary, LineContextNodeIDList)
	}

	if EncryptFlag == true {
		for _, LineContent = range LineContextArrary {
			LineContextAll += LineContent
		}

		encrypt := make([]byte, len(LineContextAll))
		err := aes_cfb.EncAES_CFB8_256(encrypt, []byte(LineContextAll), []byte(EncryptKey), []byte(EncryptIV))
		if err != nil {
			return false
		}

		new_encoder := base32.NewEncoding(string(base32_alphabet))
		new_encoder = new_encoder.WithPadding(base32.NoPadding)
		OutputContext = new_encoder.EncodeToString(encrypt)
		//OutputContext = strings.Replace(OutputContext, "=", "", -1)

		OutputContext = "COD$_" + OutputContext

		Result = disk.CreateFileWriteString(FilePath, OutputContext)
	} else {
		Result = disk.CreateFileWriteStringArrary(FilePath, LineContextArrary)
	}

	if Result == false {
		log.Println("failed to license file - (file path:", FilePath, ", user id:", UserID, ", user key:", UserKey, ")")
		return false
	}

	log.Println("success creating license file - (file path:", FilePath, ", user id:", UserID, ", user key:", UserKey, ")")
	return true
}

func GenerateNodeID(DB *sql.DB, NodeKey string) string {
	var Database *sql.DB
	var NodeKeySeq int
	var TmpGenerateKey string
	var ResultSetRows *sql.Rows
	var QueryString string

	if NodeKey == "" {
		log.Println("GenerateNodeID - invalid argument")
		return ""
	}

	if DB == nil {
		Database = MssqlDB_Open()
		defer MssqlDB_Close(Database)
	} else {
		Database = DB
	}

	if Database == nil {
		log.Println("GenerateNodeKey - failed to db connect")
		return ""
	}

	NodeIDBuffer := bytes.Buffer{}

	NodeKeySeq = 0
	QueryString = "SELECT user_key_id_seq FROM user_key WHERE user_key_id = '%s'"
	QueryString = fmt.Sprintf(QueryString, NodeKey)
	log.Println("GenerateNodeID - party key query:", QueryString)

	ResultSetRows, _ = msdb_lib.Query_DB(Database, QueryString)
	for i := 0; ResultSetRows.Next(); i++ {
		err := ResultSetRows.Scan(&(NodeKeySeq))
		if err != nil {
			ResultSetRows.Close()
			log.Println(" data Scan error:", err)
			return ""
		}
	}
	ResultSetRows.Close()

	if NodeKeySeq == 0 {
		log.Println("GenerateNodeID - not founded node_key_id_seq -", NodeKey)
		return ""
	}

	for i := 0; i < 5; i++ {
		if i == 0 {
			TmpGenerateKey = product_rand_key.Product_rand_key(8)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeIDBuffer.WriteString(TmpGenerateKey)
			NodeIDBuffer.WriteString("-")
		} else if i == 1 {
			TmpGenerateKey = fmt.Sprintf("%08d", NodeKeySeq)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeIDBuffer.WriteString(TmpGenerateKey)
			NodeIDBuffer.WriteString("-")
		} else if i == 2 {
			TmpGenerateKey = product_rand_key.Product_rand_key(5)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeIDBuffer.WriteString(TmpGenerateKey)
			NodeIDBuffer.WriteString("-")
		} else if i == 3 {
			TmpGenerateKey = product_rand_key.Product_rand_key(5)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeIDBuffer.WriteString(TmpGenerateKey)
			NodeIDBuffer.WriteString("-")
		} else if i == 4 {
			TmpGenerateKey = product_rand_key.Product_rand_key(12)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeIDBuffer.WriteString(TmpGenerateKey)
		}
	}

	return NodeIDBuffer.String()
}

func DBSetTmpGenerateNodeKey(UserID, TmpGenerateNodeKey string) int {
	var Database *sql.DB
	var QueryString string

	if UserID == "" {
		log.Println("DBSetTmpGenerateNodeKey - invalid argument")
		return 0
	}

	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)

	if Database == nil {
		log.Println("GenerateNodeKey - failed to db connect")
		return 0
	}

	// Update Temp Generator NodeKey of 'user' db table by user_id //
	QueryString = "UPDATE user SET nodekey_generate_tmp_key = '%s' WHERE user_id = '%s'"

	QueryString = fmt.Sprintf(QueryString, TmpGenerateNodeKey, UserID)
	log.Println("DBSetTmpGenerateNodeKey - update query:", QueryString)
	msdb_lib.Update_Data(Database, QueryString)
	// TODO: DB Excxception

	log.Println("DBSetTmpGenerateNodeKey - update TempGenerateNodeID:", TmpGenerateNodeKey)

	return 1
}

func GenerateNodeKey(DB *sql.DB, UserID string) string {
	var Database *sql.DB
	var UserIDSeq int
	var TmpGenerateKey string
	var ResultSetRows *sql.Rows
	var QueryString string

	if UserID == "" {
		log.Println("GenerateNodeKey - invalid argument")
		return ""
	}

	if DB == nil {
		Database = MssqlDB_Open()
		defer MssqlDB_Close(Database)
	} else {
		Database = DB
	}

	if Database == nil {
		log.Println("GenerateNodeKey - failed to db connect")
		return ""
	}

	NodeKeyBuffer := bytes.Buffer{}

	UserIDSeq = 0
	QueryString = "SELECT user_id_seq FROM user WHERE user_id = '%s'"
	QueryString = fmt.Sprintf(QueryString, UserID)
	log.Println("GenerateNodeKey - party key query:", QueryString)

	ResultSetRows, _ = msdb_lib.Query_DB(Database, QueryString)
	for i := 0; ResultSetRows.Next(); i++ {
		err := ResultSetRows.Scan(&(UserIDSeq))
		if err != nil {
			ResultSetRows.Close()
			log.Println(" data Scan error:", err)
			return ""
		}
	}
	ResultSetRows.Close()

	if UserIDSeq == 0 {
		log.Println("GenerateNodeKey - not founded user_id_seq -", UserID)
		return ""
	}

	for i := 0; i < 5; i++ {
		if i == 0 {
			TmpGenerateKey = product_rand_key.Product_rand_key(8)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeKeyBuffer.WriteString(TmpGenerateKey)
			NodeKeyBuffer.WriteString("-")
		} else if i == 1 {
			TmpGenerateKey = fmt.Sprintf("%08d", UserIDSeq)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeKeyBuffer.WriteString(TmpGenerateKey)
			NodeKeyBuffer.WriteString("-")
		} else if i == 2 {
			TmpGenerateKey = product_rand_key.Product_rand_key(5)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeKeyBuffer.WriteString(TmpGenerateKey)
			NodeKeyBuffer.WriteString("-")
		} else if i == 3 {
			TmpGenerateKey = product_rand_key.Product_rand_key(5)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeKeyBuffer.WriteString(TmpGenerateKey)
			NodeKeyBuffer.WriteString("-")
		} else if i == 4 {
			TmpGenerateKey = product_rand_key.Product_rand_key(12)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeKeyBuffer.WriteString(TmpGenerateKey)
		}
	}

	return NodeKeyBuffer.String()
}

func WebServer_Service_Stop(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	var tmpl *template.Template
	var err error

	log.Println("KMS Web Server - Service_Stop", req.Method)

	tmpl, err = template.ParseFiles("./html/kms_error_service_stop.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/kms_error_service_stop.html)")
		panic(err)
	}

	tmpl.Execute(w, nil)
}

func WebServer_Service_Invalid_Access(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	var tmpl *template.Template
	var err error

	log.Println("KMS Web Server - Service_Stop", req.Method)

	tmpl, err = template.ParseFiles("./html/kms_error_invalid_access.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/kms_error_invalid_access.html)")
		panic(err)
	}

	tmpl.Execute(w, nil)
}

func HtmlDataPage(inPack *HtmlPageListComponent, pageNumName string, pageNumString string, pageSortName string, pageSortString string, currentPageNum int, maxCountPage int, maxRowCountPage int, rowCountTotal int, pageLinkURL string, pageAdditionParams string, exceptionURL string, exceptionContent string, exceptionURLAction string) *HtmlPageListComponent {

	var tempString string

	if inPack == nil {
		return nil
	}

	inPack.ParamPageNumItem = pageNumName
	//inPack.ParamPageNumString = fmt.Sprintf("%s", pageNumString)
	//inPack.ParamPageNumString = strings.Replace(inPack.ParamPageNumString, "[", "", -1)
	//inPack.ParamPageNumString = strings.Replace(inPack.ParamPageNumString, "]", "", -1)
	//retInt, errObj := strconv.Atoi(inPack.ParamPageNumString)
	retInt, errObj := strconv.Atoi(pageNumString)
	if errObj != nil {
		log.Println("failed to strconv.Atoi")
		inPack.errPage.ExceptionCode = 500
		inPack.errPage.ExceptionURL = exceptionURL
		inPack.errPage.ExceptionContent = exceptionContent
		inPack.errPage.ExceptionAction = exceptionURLAction
		inPack.returnCode = 500
		return inPack
	}
	inPack.ParamPageNum = retInt

	inPack.ParamPageSortItem = pageSortName
	//inPack.ParamPageSortString = fmt.Sprintf("%s", pageNumString)
	//inPack.ParamPageSortString = strings.Replace(inPack.ParamPageSortString, "[", "", -1)
	//inPack.ParamPageSortString = strings.Replace(inPack.ParamPageSortString, "]", "", -1)
	//retInt, errObj = strconv.Atoi(inPack.ParamPageSortString)
	retInt, errObj = strconv.Atoi(pageNumString)
	if errObj != nil {
		log.Println("failed to strconv.Atoi")
		inPack.errPage.ExceptionCode = 500
		inPack.errPage.ExceptionURL = exceptionURL
		inPack.errPage.ExceptionContent = exceptionContent
		inPack.errPage.ExceptionAction = exceptionURLAction
		inPack.returnCode = 500
		return inPack
	}
	inPack.ParamPageSort = retInt

	inPack.MaxPageCount = maxCountPage
	inPack.MaxRowCountPage = maxRowCountPage
	inPack.RowCountTotal = rowCountTotal
	inPack.PageCount = int(math.Ceil(float64(inPack.RowCountTotal) / float64(inPack.MaxRowCountPage)))
	inPack.RowOffset = (inPack.ParamPageNum - 1) * inPack.MaxRowCountPage

	inPack.PageIndexStart = ((((inPack.ParamPageNum - 1) / inPack.MaxPageCount) * inPack.MaxPageCount) + 1)

	inPack.PageBeginNum = 1

	if inPack.PageCount > inPack.MaxPageCount {
		inPack.PageEndNum = inPack.PageIndexStart + (inPack.MaxPageCount - 1)
		if inPack.PageEndNum > inPack.PageCount {
			inPack.PageEndNum = inPack.PageCount
		}
	} else {
		inPack.PageEndNum = inPack.PageCount
		if inPack.PageEndNum > inPack.PageCount {
			inPack.PageEndNum = inPack.PageCount
		}
	}

	if inPack.ParamPageNum > 1 {
		inPack.PrevPageNum = inPack.ParamPageNum - 1
	} else {
		inPack.PrevPageNum = 1
	}

	if inPack.ParamPageNum < inPack.PageCount {
		inPack.NextPageNum = inPack.ParamPageNum + 1
	} else {
		inPack.NextPageNum = inPack.ParamPageNum
	}

	inPack.PageLinkURL = pageLinkURL

	inPack.PageAdditionParams = pageAdditionParams

	tempString = fmt.Sprintf("%s?page_num=%d&page_sort=%s_%s%s", inPack.PageLinkURL, inPack.PageBeginNum, inPack.ParamPageSortString, inPack.ParamPageSortItem, inPack.PageAdditionParams)
	inPack.TempleteViewBeginPage = template.HTML(tempString)

	tempString = fmt.Sprintf("%s?page_num=%d&page_sort=%s_%s%s", inPack.PageLinkURL, inPack.PageEndNum, inPack.ParamPageSortString, inPack.ParamPageSortItem, inPack.PageAdditionParams)
	inPack.TempleteViewEndPage = template.HTML(tempString)

	tempString = fmt.Sprintf("%s?page_num=%d&page_sort=%s_%s%s", inPack.PageLinkURL, inPack.PrevPageNum, inPack.ParamPageSortString, inPack.ParamPageSortItem, inPack.PageAdditionParams)
	inPack.TempleteViewPrevPage = template.HTML(tempString)

	tempString = fmt.Sprintf("%s?page_num=%d&page_sort=%s_%s%s", inPack.PageLinkURL, inPack.NextPageNum, inPack.ParamPageSortString, inPack.ParamPageSortItem, inPack.PageAdditionParams)
	inPack.TempleteViewNextPage = template.HTML(tempString)

	for i, j := inPack.PageIndexStart, 0; i <= inPack.PageEndNum && j <= inPack.MaxPageCount; i, j = i+1, j+1 {

		if inPack.ParamPageNum == i {
			tempString = fmt.Sprintf("<strong>%d</strong>", i)
			inPack.TempleteViewPageList = append(inPack.TempleteViewPageList, template.HTML(tempString))
		} else {
			tempString = fmt.Sprintf("<a href=\"%s?page_num=%d&page_sort=%s_%s%s\">%d</a>", inPack.PageLinkURL, i, inPack.ParamPageSortString, inPack.ParamPageSortItem, inPack.PageAdditionParams, i)
			inPack.TempleteViewPageList = append(inPack.TempleteViewPageList, template.HTML(tempString))
		}

	}

	log.Println("HtmlPage Information[begin:", inPack.PageBeginNum, ", prev:", inPack.PrevPageNum, ", start idx:", inPack.PageIndexStart, ", current idx", inPack.ParamPageNum, ", next:", inPack.NextPageNum, ", end:", inPack.PageEndNum, "]")

	inPack.returnCode = 200
	return inPack
}

func SessionCookieUserData(cookies *CookiesUserData, req *http.Request) int {
	var TempString string

	if cookies == nil || req == nil {
		log.Println("input argument is invalid")
		return RET_INT_FAIL
	}

	TempString = Cookie_GetValue(req, "id")
	if len(TempString) == 0 {
		return RET_INT_FAIL
	}

	cookies.CookieUserID = TempString

	TempString = Cookie_GetValue(req, "property")
	if len(TempString) == 0 {
		return RET_INT_FAIL
	}

	cookies.CookieUserProperty = TempString

	return RET_INT_SUCC
}

func WebServerMainMenu(MainMenu *SVCHtmlMainMenu, CurrentMenu string) int {
	var TempString string

	if MainMenu == nil {
		log.Println("input argument is invalid")
		return RET_INT_FAIL
	}

	if CurrentMenu == "setup" {
		TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/auth_api/trial_setup/v1.0/input_debugger\">Setup</a></li>")
		MainMenu.Setup = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/trial_statistics/input_debugger/\">Statistics</a></li>")
		MainMenu.Statistics = template.HTML(TempString)
	} else if CurrentMenu == "statistics" {
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/trial_setup/v1.0/input_debugger\">Setup</a></li>")
		MainMenu.Setup = template.HTML(TempString)
		TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/auth_api/trial_statistics/input_debugger/\">Statistics</a></li>")
		MainMenu.Statistics = template.HTML(TempString)
	}

	return RET_INT_SUCC
}

func WebServer_Auth_API_Trial_Setup_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlTrial CommonHTML
	var HtmlTemplate *template.Template
	var err error

	log.Println("WebServer_Auth_API_Trial_Setup_Input", req.Method)

	///*---------------------------------------
		res := Cookie_Check(w, req)
		if res < 0 {
			WebServer_Redirect(w, req, "/login/")
			return
		}
		//SessionCookieUserData(&HtmlPackage.CookiesData, req)
		//WebServerOEMInformation(&HtmlPackage.OEMData)
	//  ----------------------------------------*/
	WebServerMainMenu(&HtmlTrial.MainMenu, "setup")

	HtmlTemplate, err = template.ParseFiles("./html/trial_gowas_auth_setup_input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/trial_gowas_auth_setup_input.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, HtmlTrial)
}

func UpdateDBProvisioningTime(Database *sql.DB, deviceid int) error {

	tx, err := msdb_lib.DB_TX_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return err
	}
	defer tx.Rollback()

	query := "UPDATE MCSE_Info " +
		"SET provisioning_time = GETDATE(), status = '001' " +
		"WHERE device_id = ?"

	stmt, err := Database.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(deviceid)
	if err != nil {
		return err
	}
	tx.Commit()
	return nil
}

func UpdateProvisioningNodeip(Database *sql.DB, deviceid int, nodeip string) error {

	tx, err := msdb_lib.DB_TX_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return err
	}
	defer tx.Rollback()

	query := "Update MCSE_Info\n" +
		"SET  node_ip = '%s'\n" +
		"WHERE device_id = ?"
	query = fmt.Sprintf(query, nodeip)

	stmt, err := Database.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(deviceid)
	if err != nil {
		return err
	}

	tx.Commit()
	return nil

}

func SelectDBConfigData(db *sql.DB, deviceid int) (*SettingsInformation, string, error) {
	var StatisticSendFlag bool

	query := "Select A.user_key , B.password, B.max_connections , B.receive_buffer_size, B.send_buffer_size, B.time_connect, B.time_client, B.time_server\n" +
		", B.limit_size_log , B.max_size_log_file, B.log_file_path_dir,B.log_file_path_name, B.error_log_file_path_dir, B.error_log_file_path_name\n" +
		",B.statistics_yn,B.statistics_cycle,B.statistics_ip,B.statistics_port,B.statistics_data_cycle\n" +
		",B.bridge_yn,B.mcs_size,B.encrypt_mode,B.change_ip_mode\n" +
		",B.kms_addr,B.kms_port\n" +
		",C.symbol,C.port,C.mode\n" +
		",E.nickname,E.addr,E.port\n" +
		"from User_Key AS A \n" +
		"INNER JOIN MCSE_Info AS B \n" +
		"ON A.key_id = B.key_id\n" +
		"AND B.device_id = ?\n" +
		"INNER JOIN MCSE_Frontend AS C \n" +
		"ON B.device_id = C.device_id \n" +
		"INNER JOIN MCSE_Backend AS D \n" +
		"ON C.fe_id = D.fe_id\n" +
		"INNER JOIN MCSE_Backend_Addr AS E \n" +
		"ON D.be_id = E.be_id"

	stmt, err := db.Prepare(query)
	if err != nil {
		log.Println("prepare err", err)
		return nil, "", err
	}
	defer stmt.Close()

	rows, err := stmt.Query(deviceid)
	if err != nil {
		log.Println("Query err", err)
		return nil, "", err
	}
	defer rows.Close()

	settingData := new(SettingsInformation)

	var userkey, logDir, logFileName, errDir, errFileName, frontendName, frontendPort, frontendNodeMode, backendNIC, backendIP, backendPort string
	frontendName1 := ""

	idx := -1
	for rows.Next() {
		err := rows.Scan(&userkey, &settingData.Password,
			&settingData.Maximum_ConnectionCount, &settingData.Recv_Buf_Size, &settingData.Send_Buf_Size, &settingData.Connection_Timeout, &settingData.Client_Reconnect_Timeout, &settingData.Server_Reconnect_Timeout,
			&settingData.Limit_Size_Log_Storage, &settingData.Maxsize_Per_Logfile, &logDir, &logFileName, &errDir, &errFileName,
			&StatisticSendFlag, &settingData.Statistic_Collection_Cycle, &settingData.Statistic_Server_Ip, &settingData.Statistic_Server_Port, &settingData.Statistic_Send_Cycle,
			&settingData.Bridge_Used, &settingData.Bridge_Buf_Size, &settingData.Encrypt_Mode, &settingData.Change_Client_IP,
			&settingData.KMS_Address, &settingData.KMS_Port, &frontendName, &frontendPort, &frontendNodeMode, &backendNIC, &backendIP, &backendPort)
		if err != nil {
			log.Println("scan err", err)
			return nil, "", err
		}
		if StatisticSendFlag == true {
			settingData.Statistic_Send_Control_Server = "Enable"
		} else {
			settingData.Statistic_Send_Control_Server = "Disable"
		}

		if frontendName != frontendName1 {
			frontend := FrontendInformation{}
			settingData.SiteList = append(settingData.SiteList, frontend)
			idx++

			settingData.SiteList[idx].Frontendsymbol = frontendName
			settingData.SiteList[idx].FrontendPort = ":" + frontendPort
			settingData.SiteList[idx].NodeMode = frontendNodeMode
			frontendName1 = frontendName
		}

		backend := BackendInformationList{}
		backend.LAN_Interface = backendNIC
		backend.BackendIP = backendIP
		backend.BackendPort = backendPort
		settingData.SiteList[idx].Backend = append(settingData.SiteList[idx].Backend, backend)
	}

	settingData.Logfile_Path = logDir + "/" + logFileName
	settingData.Err_Logfile_Path = errDir + "/" + errFileName

	return settingData, userkey, nil
}

func SelectDBSyncSeqNo(db *sql.DB, deviceid int) (int64, error) {
	query := "SELECT sync_seq_no " +
		"FROM CWS_Sync_Seq " +
		"WHERE device_id = ? " +
		"AND sync_seq_type = 'ConfigData';"

	stmt, err := db.Prepare(query)
	if err != nil {
		return 0, err
	}

	defer stmt.Close()

	var syncseqno int64
	err = stmt.QueryRow(deviceid).Scan(&syncseqno)
	if err != nil {
		return 0, err
	}

	return syncseqno, nil
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

func GetOEMPackageHomePath() string {
	var PackageHomePath string

	ProcessPWD, err := os.Getwd()
	if err != nil {
		log.Println("oem process pwd return value error")
		return ""
	}

	PackageHomePath = ProcessPWD + "/database" + "/package_home/"
	return PackageHomePath
}

func GetOEMAuthExpiretimeInterval() int {
	var Database *sql.DB
	var ResultSetRows *sql.Rows
	var QueryString string
	var AuthExpiretimeInterval int

	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)

	QueryString = "SELECT OEM_AUTH_EXPIRETIME_INTERVAL FROM kms_configure"

	ResultSetRows, _ = msdb_lib.Query_DB(Database, QueryString)
	for ResultSetRows.Next() {
		err := ResultSetRows.Scan(&AuthExpiretimeInterval)
		if err != nil {
			ResultSetRows.Close()
			log.Println("oem name data db scan error:", err)

			return 0
		}
	}
	ResultSetRows.Close()

	if AuthExpiretimeInterval == 0 {
		log.Println("oem auth expiretime interval is zero")
		return AuthExpiretimeInterval
	}

	return AuthExpiretimeInterval
}

func WebServer_Auth_API_Hashing_Provisioning(UserKeyID string, DeviceID string, Method string, GenerateAuthKey string) string {
	var HashingText string
	var HA1, HA2 string
	var Response string
	var EventValue string

	hashing_algorithm := md5.New()
	HashingText = UserKeyID + ":" + DeviceID
	hashing_algorithm.Write([]byte(HashingText))
	HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
	EventValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

	hashing_algorithm = md5.New()
	HashingText = Method + ":" + "/auth_api/provisioning/v1.0/"
	hashing_algorithm.Write([]byte(HashingText))
	HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))
	EventValue += "[" + HashingText + " >> HA2:" + HA2 + "]"

	hashing_algorithm = md5.New()
	HashingText = HA1 + ":" + GenerateAuthKey + ":" + HA2
	hashing_algorithm.Write([]byte(HashingText))
	Response = hex.EncodeToString(hashing_algorithm.Sum(nil))
	EventValue += "[" + HashingText + " >> Response:" + Response + "]"

	return Response
}

func WebServer_Auth_API_Hashing_Statistic(UserKeyID string, DeviceID string, Method string, GenerateAuthKey string) string {

	var HashingText string
	var HA1, HA2 string
	var Response string
	var EventValue string

	hashing_algorithm := md5.New()
	HashingText = UserKeyID + ":" + DeviceID
	hashing_algorithm.Write([]byte(HashingText))
	HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
	EventValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

	hashing_algorithm = md5.New()
	HashingText = Method + ":" + "/auth_api/statistics/v1.0/"
	hashing_algorithm.Write([]byte(HashingText))
	HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))
	EventValue += "[" + HashingText + " >> HA2:" + HA2 + "]"

	hashing_algorithm = md5.New()
	HashingText = HA1 + ":" + GenerateAuthKey + ":" + HA2
	hashing_algorithm.Write([]byte(HashingText))
	Response = hex.EncodeToString(hashing_algorithm.Sum(nil))
	EventValue += "[" + HashingText + " >> Response:" + Response + "]"

	return Response
}

func WebServer_Auth_API_Trail_Invalid_Access_Response(w http.ResponseWriter, Code string, Message string) {
	var OutputData jsonOutputWebAPIAuthInvalidAccess
	var OutputBody string

	OutputData.Code = Code
	OutputData.Message = Message

	jstrbyte, _ := json.Marshal(OutputData)
	OutputBody = string(jstrbyte)
	/*---------------------------------------------------------------------
	  //-- comment by hyadra proxy web page --//
	  w.Header().Set("Access-Control-Allow-Origin", "*")
	  w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	  w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	  w.Header().Set("Access-Control-Max-Age", "10")
	  w.Header().Set("Content-Type", "application/json")
	  ---------------------------------------------------------------------*/
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(OutputBody))
	return
}

func WebServer_Auth_API_Trail_Setup_Response(w http.ResponseWriter, Version string, Method string, SessionType string, Seperator string, MessageType string, MessageSeq string, Code string, Message string, AuthKey string, Expiretime string, Param string, Event string) {
	var OutputData jsonOutputWebAPIAuthTrialSetup
	var OutputBody string

	OutputData.Version = Version
	OutputData.Method = Method
	OutputData.SessionType = SessionType
	OutputData.Seperator = Seperator
	OutputData.MessageType = MessageType
	OutputData.MessageSeq = MessageSeq
	OutputData.Code = Code
	OutputData.Message = Message
	OutputData.AuthKey = AuthKey
	OutputData.Expiretime = Expiretime
	OutputData.Param = Param
	OutputData.Event = Event

	jstrbyte, _ := json.Marshal(OutputData)
	OutputBody = string(jstrbyte)
	///*---------------------------------------------------------------------
	//-- comment by hyadra proxy web page --//
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "10")
	w.Header().Set("Content-Type", "application/json")
	//  ---------------------------------------------------------------------*/
	//w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(OutputBody))
	return
}

func PackageMapTableInit() *PackageMapTable {
	PkgLockTable := new(PackageMapTable)
	PkgLockTable.MutexLock = sync.Mutex{}
	PkgLockTable.MapTable = make(map[int]*PackageLockData)
	return PkgLockTable
}

func PackagMapTableValueSet(keyID int, platformType string) (int, *sync.Mutex) {
	PackageLockTable.MutexLock.Lock()
	defer PackageLockTable.MutexLock.Unlock()

	log.Printf("PackageMapTbl Set Input Data - keyID:%d, platformType:%s", keyID, platformType)

	value, ok := PackageLockTable.MapTable[keyID]
	if ok == true {
		log.Printf("Exist Key - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, value.platformUsedCount, value.linuxUsedFlag, value.windowsUsedFlag)
		if value.platformUsedCount >= 2 {
			return 0, nil
		}

		if platformType == "linux" {
			if value.linuxUsedFlag == 1 {
				return 0, nil
			} else if value.linuxUsedFlag == 0 {
				value.linuxUsedFlag = 1
				value.platformUsedCount++

				log.Printf("Exist Data - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, value.platformUsedCount, value.linuxUsedFlag, value.windowsUsedFlag)
				return 1, &value.linuxMutex
			} else {
				return 0, nil
			}
		} else if platformType == "windows" {
			if value.windowsUsedFlag == 1 {
				return 0, nil
			} else if value.windowsUsedFlag == 0 {
				value.windowsUsedFlag = 1
				value.platformUsedCount++

				log.Printf("Exist Data - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, value.platformUsedCount, value.linuxUsedFlag, value.windowsUsedFlag)
				return 1, &value.windowsMutex
			} else {
				return 0, nil
			}
		} else {
			return 0, nil
		}
	} else {
		mapData := new(PackageLockData)
		mapData.keyID = keyID
		mapData.platformUsedCount++
		if platformType == "linux" {
			mapData.linuxUsedFlag = 1
			mapData.windowsUsedFlag = 0
			mapData.linuxMutex = sync.Mutex{}
			mapData.windowsMutex = sync.Mutex{}
			PackageLockTable.MapTable[keyID] = mapData
			log.Printf("New Key - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, mapData.platformUsedCount, mapData.linuxUsedFlag, mapData.windowsUsedFlag)

			return 1, &mapData.linuxMutex
		} else if platformType == "windows" {
			mapData.linuxUsedFlag = 0
			mapData.windowsUsedFlag = 1
			mapData.linuxMutex = sync.Mutex{}
			mapData.windowsMutex = sync.Mutex{}
			PackageLockTable.MapTable[keyID] = mapData
			log.Printf("New Key - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, mapData.platformUsedCount, mapData.linuxUsedFlag, mapData.windowsUsedFlag)

			return 1, &mapData.windowsMutex
		} else {
			return 0, nil
		}
	}
}

func PackageMapTableValueDelete(keyID int, platformType string) int {
	PackageLockTable.MutexLock.Lock()
	defer PackageLockTable.MutexLock.Unlock()

	log.Printf("PackageMapTbl Delete Input Data - keyID:%d, platformType:%s", keyID, platformType)

	value, ok := PackageLockTable.MapTable[keyID]
	if ok == true {
		log.Printf("Exist Data - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, value.platformUsedCount, value.linuxUsedFlag, value.windowsUsedFlag)
		if platformType == "linux" {
			if value.linuxUsedFlag == 1 {
				value.linuxUsedFlag = 0
				//value.linuxMutex.Unlock()
				log.Printf("Exist Data - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, value.platformUsedCount, value.linuxUsedFlag, value.windowsUsedFlag)
			}

			if value.platformUsedCount > 0 {
				value.platformUsedCount--
			} else {
				return 0
			}

			log.Printf("Exist Data - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, value.platformUsedCount, value.linuxUsedFlag, value.windowsUsedFlag)
			if value.platformUsedCount == 0 {
				delete(PackageLockTable.MapTable, keyID)
				log.Printf(">>> delete : %d", keyID)
			}

			return 1
		} else if platformType == "windows" {
			if value.windowsUsedFlag == 1 {
				value.windowsUsedFlag = 0
				//value.windowsMutex.Unlock()
				log.Printf("Exist Data - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, value.platformUsedCount, value.linuxUsedFlag, value.windowsUsedFlag)
			}

			if value.platformUsedCount > 0 {
				value.platformUsedCount--
			} else {
				return 0
			}

			log.Printf("Exist Data - keyID:%d, platformUsedCount:%d, linuxUsedFlag:%d, windowsUsedFlag:%d", keyID, value.platformUsedCount, value.linuxUsedFlag, value.windowsUsedFlag)

			if value.platformUsedCount == 0 {
				delete(PackageLockTable.MapTable, keyID)
			}

			return 1
		} else {
			return 0
		}
	} else {
		log.Printf("No Exist Data - keyID:%d", keyID)
		return 0
	}
}

func PackageHashMapSearchSample() {
	var ret int
	var lock *sync.Mutex

	ret, lock = PackagMapTableValueSet(44, "linux")
	if ret == 0 {
		log.Printf("failed to PackagMapTableValueSet, %p", lock)
	} else {
		log.Printf("success PackagMapTableValueSet, %p", lock)
	}
	log.Printf("PackageLockTable Counter : %d", len(PackageLockTable.MapTable))

	ret, lock = PackagMapTableValueSet(44, "windows")
	if ret == 0 {
		log.Printf("failed to PackagMapTableValueSet, %p", lock)
	} else {
		log.Printf("success PackagMapTableValueSet, %p", lock)
	}
	log.Printf("PackageLockTable Counter : %d", len(PackageLockTable.MapTable))

	ret, lock = PackagMapTableValueSet(44, "windows")
	if ret == 0 {
		log.Printf("failed to PackagMapTableValueSet, %p", lock)
	} else {
		log.Printf("success PackagMapTableValueSet, %p", lock)
	}
	log.Printf("PackageLockTable Counter : %d", len(PackageLockTable.MapTable))

	ret = PackageMapTableValueDelete(44, "windows")
	if ret == 0 {
		log.Printf("failed to PackageMapTableValueDelete, %p", lock)
	} else {
		log.Printf("success PackageMapTableValueDelete, %p", lock)
	}
	log.Printf("PackageLockTable Counter : %d", len(PackageLockTable.MapTable))

	ret = PackageMapTableValueDelete(44, "linux")
	if ret == 0 {
		log.Printf("failed to PackageMapTableValueDelete, %p", lock)
	} else {
		log.Printf("success PackageMapTableValueDelete, %p", lock)
	}
	log.Printf("PackageLockTable Counter : %d", len(PackageLockTable.MapTable))

	ret = PackageMapTableValueDelete(44, "linux")
	if ret == 0 {
		log.Printf("failed to PackageMapTableValueDelete, %p", lock)
	} else {
		log.Printf("success PackageMapTableValueDelete, %p", lock)
	}
	log.Printf("PackageLockTable Counter : %d", len(PackageLockTable.MapTable))
}

func WebServer_Auth_API_Trial_Setup_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var Database *sql.DB
	var InputData jsonInputWebAPIAuthTrialSetupPack
	var ResponseMessage string

	var SiteID int
	var AccessClientIP string
	var EncryptSN string
	var DecryptSN1 string
	var DecryptSN2 string
	var DecryptSN3 string
	var HashingText string
	var HashingValue string
	var HA1 string
	var HA2 string
	var GenerateAuthKey string
	var GenerateAuthToken string
	var TrialHashingValue string
	var EncryptValue string

	var AuthExpiretimeInterval int
	var DBSNCount int
	var DBTrialID int

	var DBAuthKey string
	var DBAuthToken string
	var DBAuthExpireTime uint64
	var DBAuthNOWTime uint64

	var QueryString string
	var QuerySubString string
	var QueryTupleCount int
	var ResultSetRows *sql.Rows
	//var stmt *sql.Stmt
	var tx *sql.Tx
	var err error

	forwarded := req.Header.Get("X-FORWARDED-FOR")
	if forwarded != "" {
		AccessClientIP = forwarded
	} else {
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			AccessClientIP = ""
		} else {
			AccessClientIP = ip
		}
	}

	log.Println("WebServer_Auth_API_Trial_Setup_Proc", req.Method, ", Proxy Address:", req.RemoteAddr, ", Client Address:", AccessClientIP)

	SiteID = 1
	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		log.Println("json parsing error:", err)
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error - (simplify Information for security enhancement)"
		WebServer_Auth_API_Trail_Setup_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "", "")
		return
	}

	// comments: checking valid http method
	if req.Method != "POST" {
		log.Println("not supported request method")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error (not support method) - (simplify Information for security enhancement)"
		WebServer_Auth_API_Trail_Setup_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "", "")
		return
	}

	log.Println(">>> Input Data - version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", seperator:" + InputData.Seperator + ", msgtype:" + InputData.MessageType + ", msgseq:" + InputData.MessageSeq + ", SN1:" + InputData.SN1 + ", SN2:" + InputData.SN2 + ", SN3:" + InputData.SN3 + ", authkey:" + InputData.AuthKey + ", authtoken:" + InputData.AuthToken)

	// comments: checking mandatory input value
	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.Seperator == "" || InputData.MessageType == "" || InputData.MessageSeq == "" || InputData.SN1 == "" || InputData.SN2 == "" || InputData.SN3 == "" {
		log.Println("invalid parmeter value: mandatory param is empty")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is empty (simplify Information for security enhancement)"
		WebServer_Auth_API_Trail_Setup_Response(w, "", "", "", "", "", "", "611", ResponseMessage, "", "", "", "")
		return
	}

	// comments: checking validation input value
	if InputData.Version != "1.0" || InputData.Method != "auth" || InputData.SessionType != "register" || InputData.Seperator != "setup" || InputData.MessageType != "request" {
		log.Println("invalid parmeter value: not supported value")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is invalid (simplify Information for security enhancement)"
		WebServer_Auth_API_Trail_Setup_Response(w, "", "", "", "", "", "", "612", ResponseMessage, "", "", "", "")
		return
	}

	// comments: decrypt and base32 input userkey value
	if InputData.SN1 != "" {
		EncryptSN = InputData.SN1
		DecryptSN1 = AESDecryptDecodeValue(EncryptSN)

		if DecryptSN1 == "" {
			log.Println("invalid parmeter value: user key decrypt error")
			ResponseMessage = "json parameter decript error"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "612", ResponseMessage, "", "", "", "")
			return
		}

		log.Printf("WEB API Auth - SN1 Decrypt Value [%s] -> [%s]", InputData.SN1, DecryptSN1)
		if len(DecryptSN1) > 128 {
			log.Println("invalid sn1 parmeter value: over length")
			ResponseMessage = "invalid sn1 parmeter value: over length"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "612", ResponseMessage, "", "", "", "")
			return
		}
	}

	// comments: decrypt and base32 input userkey value
	if InputData.SN2 != "" {
		EncryptSN = InputData.SN2
		DecryptSN2 = AESDecryptDecodeValue(EncryptSN)

		if DecryptSN2 == "" {
			log.Println("invalid parmeter value: user key decrypt error")
			ResponseMessage = "json parameter decript error"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "612", ResponseMessage, "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - SN2 Decrypt Value [%s] -> [%s]", InputData.SN2, DecryptSN2)
		if len(DecryptSN2) > 128 {
			log.Println("invalid sn2 parmeter value: over length")
			ResponseMessage = "invalid sn2 parmeter value: over length"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "612", ResponseMessage, "", "", "", "")
			return
		}
	}

	MACList := strings.Split(DecryptSN2, ",")
	//for i, line := range strings.Split(DecryptSN2, ",") {
	for i, mac_address := range MACList {
		if len(mac_address) > 0 {
			if i == 0 {
				QuerySubString += "'" + mac_address + "'"
			} else if i > 0 && i <= 10 {
				QuerySubString += ", " + "'" + mac_address + "'"
			} else if i > 10 {
				break
			}
		}
		log.Printf("SN2 MAC Address[%d] -> [%s]", i, mac_address)
	}

	log.Printf("MAC List Address : %s", QuerySubString)

	// comments: decrypt and base32 input userkey value
	if InputData.SN3 != "" {
		EncryptSN = InputData.SN3
		DecryptSN3 = AESDecryptDecodeValue(EncryptSN)

		if DecryptSN3 == "" {
			log.Println("invalid parmeter value: user key decrypt error")
			ResponseMessage = "json parameter decript error"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "612", ResponseMessage, "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - SN3 Decrypt Value [%s] -> [%s]", InputData.SN3, DecryptSN3)
	}

	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)
	//msdb_lib.DB_AutoCommit_Enable(Database)

	if Database == nil {
		log.Println("db connection error")
		ResponseMessage = "db connection error"
		WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
		return
	}

	AuthExpiretimeInterval = 60

	//--[Query: Checking UserKey]--------------------{
	/*--------------------------------------------------------------------------
		QueryString = "SELECT count(U.trial_id) as sn_cnt " +
	                "FROM " +
	                "( " +
	                "SELECT trial_id FROM mcs.trial_Key_Machine WHERE sn = '%s' " +
	                "UNION ALL " +
	                "SELECT trial_id FROM mcs.trial_Key_Mac WHERE sn = '%s' " +
	                "UNION ALL " +
	                "SELECT trial_id FROM mcs.trial_Key_Cookie WHERE sn = '%s' " +
	                ") U"
		QueryString = fmt.Sprintf(QueryString, DecryptSN1, DecryptSN2, DecryptSN3)
	  --------------------------------------------------------------------------*/
	QueryString = "SELECT count(U.trial_id) as sn_cnt " +
		"FROM " +
		"( " +
		"SELECT trial_id FROM mcs.trial_Key_Machine WHERE sn = '%s' " +
		"UNION ALL " +
		"SELECT trial_id FROM mcs.trial_Key_Mac WHERE sn in (%s) " +
		") U"
	QueryString = fmt.Sprintf(QueryString, DecryptSN1, QuerySubString)
	log.Println("Auth UserKey Exist Query : ", QueryString)
	//-----------------------------------------------}
	ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
	if err != nil {
		log.Println("db query error (not founded user_key column of User_Key)")
		ResponseMessage = "db query error(not founded user_key column of User_Key)"
		WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
		return
	}

	QueryTupleCount = 0
	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&DBSNCount)
		if err != nil {
			ResultSetRows.Close()
			log.Println("data Scan error:", err)
			ResponseMessage = "db query error(not founded result set row that was key_id, user_key column of User_Key)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}
		QueryTupleCount++
	}
	ResultSetRows.Close()

	if QueryTupleCount > 1 {
		log.Println("db query error(exist trial setup sn)")
		ResponseMessage = "setup creation failed (exist sn)"
		WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "654", ResponseMessage, "", "", "", "")
		return
	}

	if DBSNCount > 0 {
		log.Println("founded of trial history")
		ResponseMessage = "founded trial history"
		WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "654", ResponseMessage, "", "", "", "")
		return
	}

	//------------------------------------------------------------------------------//
	// Transaction - Request Msg (AuthKey)
	//------------------------------------------------------------------------------//
	if InputData.AuthKey == "" && InputData.AuthToken == "" {
		AuthPackageSeqNo += 1
		if AuthPackageSeqNo >= 100000 {
			AuthPackageSeqNo = 1
		}

		GenerateAuthKey = WEBAuthGenerateAuthKey(strconv.Itoa(AuthPackageSeqNo))
		if GenerateAuthKey == "" {
			log.Println("failed to generate auth key")
			ResponseMessage = "failed to generate auth key"
			log.Printf("web api response [code:%s, msg:%s]", "643", ResponseMessage)
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "", "")
			return
		}

		hashing_algorithm := md5.New()
		HashingText = DecryptSN1 + ":" + DecryptSN2
		hashing_algorithm.Write([]byte(HashingText))
		HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

		hashing_algorithm = md5.New()
		HashingText = InputData.Method + ":" + "/auth_api/trial_setup/v1.0/"
		hashing_algorithm.Write([]byte(HashingText))
		HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue += "[" + HashingText + " >> HA2:" + HA2 + "]"

		hashing_algorithm = md5.New()
		HashingText = HA1 + ":" + GenerateAuthKey + ":" + HA2
		hashing_algorithm.Write([]byte(HashingText))
		GenerateAuthToken = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue += "[" + HashingText + " >> GenerateAuthToken:" + GenerateAuthToken + "]"

		log.Println("WEB API Auth Setup Information -> ", HashingValue)

		if GenerateAuthToken != "" {

			/*---------------------------------------------------------------
						//--[Query: Delete Existed AuthKey & AuthToken]--{
						QueryString = "DELETE FROM mcs.CWS_TrialAuth WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' and seperator = '%s' "
						QueryString = fmt.Sprintf(QueryString, DBUserKeySeq, 0, InputData.Method, InputData.SessionType, InputData.Platform_type)
						log.Println("CWS_AuthTbl Delete Query : ", QueryString)
						//-----------------------------------------------}
						_, err = msdb_lib.Delete_Data(Database, QueryString)
						if err != nil {
							log.Println("db processing error (delete CWS_Auth by key_id)")
							ResponseMessage = "db processing error (delete CWS_Auth by key_id)"
							WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
							return
						}
			      ---------------------------------------------------------------*/

			//--[Query: Insert Temp AuthKey & AuthToken]-----{
			QueryString = "INSERT INTO mcs.CWS_TrialAuth (trial_id, ip, method, session_type, seperator, auth_key, auth_token, expiretime, reg_user, reg_date) " +
				"VALUES (%d, '%s', '%s', '%s', '%s', '%s', '%s', DATEADD(second, %d, GETDATE()), %d, GETDATE()) "
			if len(AccessClientIP) >= 64 {
				QueryString = fmt.Sprintf(QueryString, 0, "InvalidIPLength", InputData.Method, InputData.SessionType, InputData.Seperator, GenerateAuthKey, GenerateAuthToken, AuthExpiretimeInterval, 0)
			} else {
				QueryString = fmt.Sprintf(QueryString, 0, AccessClientIP, InputData.Method, InputData.SessionType, InputData.Seperator, GenerateAuthKey, GenerateAuthToken, AuthExpiretimeInterval, 0)
			}
			log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
			//-----------------------------------------------}
			_, err = msdb_lib.Insert_Data(Database, QueryString)
			if err != nil {
				log.Println("db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)")
				ResponseMessage = "db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)"
				WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
				return
			}

			ResponseMessage = "success generation auth key"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "200", ResponseMessage, GenerateAuthKey, strconv.Itoa(AuthExpiretimeInterval), "", "")
			log.Printf("web api response [code:%s, msg:%s, description:%s (expiretime sec:%d, authkey:%s, authtoken:%s)]", "200", ResponseMessage, "create new authkey and authtoken", AuthExpiretimeInterval, GenerateAuthKey, GenerateAuthToken)
			return

		} else {
			log.Println("failed to create auth token:")
			ResponseMessage = "failed to generate auth token"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "644", ResponseMessage, "", "", "", "")
			return
		}

	} else if InputData.AuthKey != "" && InputData.AuthToken != "" {

		//--[Query: Checking Auth Information]-----------{
		QueryString = "SELECT auth_key, auth_token, " +
			"auth_expiretime=((DATEPART(HOUR,expiretime)*3600)+(DATEPART(MINUTE,expiretime)*60)+(DATEPART(Second,expiretime))), " +
			"auth_now=((DATEPART(HOUR,GETDATE())*3600)+(DATEPART(MINUTE,GETDATE())*60)+(DATEPART(Second,GETDATE()))) " +
			"FROM mcs.CWS_TrialAuth " +
			"WHERE trial_id = %d and auth_key = '%s' and auth_token = '%s' and method = '%s' and session_type = '%s' and seperator = '%s' "
		QueryString = fmt.Sprintf(QueryString, 0, InputData.AuthKey, InputData.AuthToken, InputData.Method, InputData.SessionType, InputData.Seperator)
		log.Println("Auth Information Checking Query : ", QueryString)
		//-----------------------------------------------}

		ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			log.Println("db processing error (not founded tuple by key_id, auth_key, auth_token)")
			ResponseMessage = "db processing error (not founded tuple by key_id, auth_key, auth_token)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		QueryTupleCount = 0
		for ResultSetRows.Next() {
			err = ResultSetRows.Scan(&DBAuthKey, &DBAuthToken, &DBAuthExpireTime, &DBAuthNOWTime)
			if err != nil {
				ResultSetRows.Close()
				log.Println("data Scan error:", err)
				ResponseMessage = "db processing error (not founded resultset row of tuple(auth_key, auth_token, expiretime, now))"
				WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
				return
			}
			QueryTupleCount++
		}
		ResultSetRows.Close()

		if QueryTupleCount == 0 {
			log.Println("db query error(auth data of AuthTable not founded)")
			ResponseMessage = "db query error(auth data of AuthTable not founded)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		} else if QueryTupleCount > 1 {
			log.Println("db query error(auth data of AuthTable is multi-tuple)")
			ResponseMessage = "db query error(auth data of AuthTable is multi-tuple)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		//--[Query: Delete Existed AuthKey & AuthToken]--{
		QueryString = "DELETE FROM mcs.CWS_TrialAuth WHERE trial_id = %d and auth_key = '%s' and auth_token = '%s' and method = '%s' and session_type = '%s' and seperator = '%s' "
		QueryString = fmt.Sprintf(QueryString, 0, InputData.AuthKey, InputData.AuthToken, InputData.Method, InputData.SessionType, InputData.Seperator)
		log.Println("CWS_TrialAuth Delete Query : ", QueryString)
		//-----------------------------------------------}
		_, err = msdb_lib.Delete_Data(Database, QueryString)
		if err != nil {
			log.Println("db processing error (delete CWS_Auth by key_id)")
			ResponseMessage = "db processing error (delete CWS_Auth by key_id)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		if DBAuthExpireTime < DBAuthNOWTime {
			ResponseMessage = "auth_key has expired"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "", "")
			log.Printf("web api response [code:%s, msg:%s] %d, %d", "643", ResponseMessage, DBAuthExpireTime, DBAuthNOWTime)
			return
		}

		tx, err = msdb_lib.DB_TX_Begin(Database)
		if err != nil {
			log.Println("Transaction Begin err:", err)
			ResponseMessage = "Transaction Begin error"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "", "")
			log.Printf("web api response [code:%s, msg:%s] %d, %d", "630", ResponseMessage, DBAuthExpireTime, DBAuthNOWTime)
			return
		}

		defer msdb_lib.DB_TX_Rollback(tx)

		//--[Query: Insert Trial_ID ]-----{
		QueryString = "INSERT INTO mcs.Trial_ID (status, access_ip, reg_user, reg_date, upd_user, upd_date, site_id) VALUES ('%s', '%s', %d, GETDATE(), %d, GETDATE(), %d) "
		if len(AccessClientIP) >= 64 {
			QueryString = fmt.Sprintf(QueryString, "enable", "IP="+"InvalidIPLength"+":"+InputData.AuthKey+":"+InputData.AuthToken, 0, 0, SiteID)
		} else {
			QueryString = fmt.Sprintf(QueryString, "enable", "IP="+AccessClientIP+":"+InputData.AuthKey+":"+InputData.AuthToken, 0, 0, SiteID)
		}
		log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
		//--------------------------------}
		//_, err = msdb_lib.Insert_Data(Database, QueryString)
		_, err = tx.Exec(QueryString)
		if err != nil {
			log.Println("db processing error (insert Trial_ID by authkey, authtoken)")
			ResponseMessage = "db processing error (insert Trial_ID by authkey, authtoken)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		//--[Query: Checking trial_id of Trial_ID ]-----------{
		QueryString = "SELECT trial_id FROM mcs.Trial_ID WHERE access_ip = '%s' "
		if len(AccessClientIP) >= 64 {
			QueryString = fmt.Sprintf(QueryString, "IP="+"InvalidIPLength"+":"+InputData.AuthKey+":"+InputData.AuthToken)
		} else {
			QueryString = fmt.Sprintf(QueryString, "IP="+AccessClientIP+":"+InputData.AuthKey+":"+InputData.AuthToken)

		}
		log.Println("Trial_ID Checking Query : ", QueryString)
		//----------------------------------------------------}
		//ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
		ResultSetRow := tx.QueryRow(QueryString)

		QueryTupleCount = 0
		err = ResultSetRow.Scan(&DBTrialID)
		if err != nil {
			//ResultSetRow.Close()
			log.Println("data Scan error:", err)
			ResponseMessage = "db processing error (not founded resultset row of tuple(auth_key, auth_token, expiretime, now))"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}
		QueryTupleCount++
		//ResultSetRow.Close()

		if QueryTupleCount == 0 {
			log.Println("db query error(not founded db trial_id)")
			ResponseMessage = "db query error(not founded db trial_id)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		} else if QueryTupleCount > 1 {
			log.Println("db query error(trial_id data of Trial_ID is multi-tuple)")
			ResponseMessage = "db query error(trial_id data of Trial_ID is multi-tuple)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		//--[Query: Insert Trial_Key_Machine ]-----{
		QueryString = "INSERT INTO mcs.Trial_Key_Machine (trial_id, sn, reg_date, reg_user) VALUES (%d, '%s', GETDATE(), %d) "
		QueryString = fmt.Sprintf(QueryString, DBTrialID, DecryptSN1, 0)
		log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
		//-----------------------------------------}
		//_, err = msdb_lib.Insert_Data(Database, QueryString)
		_, err = tx.Exec(QueryString)
		if err != nil {
			log.Println("db processing error (insert trial_id by SN1)")
			ResponseMessage = "db processing error (insert trial_id by SN1)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		//--[Query: Insert Trial_Key_Mac ]-----{
		for i, mac_address := range MACList {
			QueryString = "INSERT INTO mcs.Trial_Key_Mac (trial_id, sn, reg_date, reg_user) VALUES (%d, '%s', GETDATE(), %d) "
			QueryString = fmt.Sprintf(QueryString, DBTrialID, mac_address, 0)
			log.Println("AuthKey & AuthToken Insert Query ", i, QueryString)
			//-------------------------------------}
			//_, err = msdb_lib.Insert_Data(Database, QueryString)
			_, err = tx.Exec(QueryString)
			if err != nil {
				log.Println("db processing error (insert trial_id by SN2)")
				ResponseMessage = "db processing error (insert trial_id by SN2)"
				WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
				return
			}
		}

		//--[Query: Insert Trial_Key_Cookie ]-----{
		QueryString = "INSERT INTO mcs.Trial_Key_Cookie (trial_id, sn, reg_date, reg_user) VALUES (%d, '%s', GETDATE(), %d) "
		if len(AccessClientIP) >= 64 {
			QueryString = fmt.Sprintf(QueryString, DBTrialID, "Cookies="+"InvalidIPLength"+":"+InputData.AuthKey+":"+InputData.AuthToken+":"+DecryptSN3, 0)
		} else {
			QueryString = fmt.Sprintf(QueryString, DBTrialID, "Cookies="+AccessClientIP+":"+InputData.AuthKey+":"+InputData.AuthToken+":"+DecryptSN3, 0)
		}
		log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
		//-----------------------------------------------}
		//_, err = msdb_lib.Insert_Data(Database, QueryString)
		_, err = tx.Exec(QueryString)
		if err != nil {
			log.Println("db processing error (insert trial_id by SN3)")
			ResponseMessage = "db processing error (insert trial_id by SN3)"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		msdb_lib.DB_TX_Commit(tx)

		//------------------------------------------------------------------------------//
		// Transaction - 200 OK Response  Msg (Validateion Hashing Value)
		//------------------------------------------------------------------------------//
		hashing_algorithm := md5.New()
		HashingText = InputData.AuthKey + ":" + strconv.Itoa(DBTrialID)
		hashing_algorithm.Write([]byte(HashingText))
		TrialHashingValue = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue = HashingText + ":" + TrialHashingValue

		EncryptValue = AESEncryptEncodingValue(HashingValue)
		if EncryptValue == "" {
			log.Println("failed to decrypt decode trial_id pattern")
			ResponseMessage = "failed to decrypt decode trial_id pattern"
			WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "400", ResponseMessage, "", "", "", "")
			return
		}

		ResponseMessage = "success"
		WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "200", ResponseMessage, "", "", EncryptValue, "")
		log.Printf("web api init trial response [trail_id:%d] [code:%s, msg:%s]", DBTrialID, "200", ResponseMessage)
		return

	} else {
		log.Println("not supported auth information case")
		ResponseMessage = "not supported auth information case"
		WebServer_Auth_API_Trail_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "611", ResponseMessage, "", "", "", "")
		return
	}
}

type jsonOutputPack struct {
	MsgType  string // Message Class type
	MsgTitle string // Window Display Title Message
	MsgMsg   string // Window Display Result Message
	MsgCode  string // Processing Result Code
	MsgValue string // Processing Result Value
}

func WEBAuthGenerateAuthKey(NodeID string) string {
	var TmpGenerateKey string

	if NodeID == "" {
		log.Println("NodeID - invalid argument")
		return ""
	}

	NodeKeyBuffer := bytes.Buffer{}

	TmpGenerateKey = product_rand_key.Product_rand_key(12)
	NodeKeyBuffer.WriteString(TmpGenerateKey)
	TmpGenerateKey = fmt.Sprintf("%08s", NodeID)
	NodeKeyBuffer.WriteString(TmpGenerateKey)

	return NodeKeyBuffer.String()
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

func WebServer_Auth_API_Trial_Encode_Value(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var InputData jsonInputWebAPIEncodeValue
	var OutputData jsonOutputWebAPIEncodeValue
	var OutputBody string
	var EncryptValue string
	var DecryptValue string
	var err error

	log.Println("WebServer_Auth_API_Trial_Encode_Value", req.Method)

	/*-------------------------------------------------------
		res := Cookie_Check(w, req)
		if res < 0 {
			OutputData.Code = "600"
			OutputData.Message = "fail (session expiretimed)"
			OutputData.InputValue = ""
			OutputData.OutputValue = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))
			return
		}
	  -------------------------------------------------------*/

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
		return
	}

	log.Println("Input Value:" + InputData.InputValue)

	EncryptValue = AESEncryptEncodingValue(InputData.InputValue)
	if EncryptValue == "" {
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

func WebServer_Auth_API_Trial_AuthToken_Value(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var InputData jsonInputWebAPIHashDerivationValue
	var OutputData jsonOutputWebAPIHashDerivationValue
	var HashingText string
	var HashingValue string
	var HA1 string
	var HA2 string
	var GenerateAuthToken string
	var OutputBody string
	var err error

	log.Println("WebServer_Auth_API_Trial_AuthToken_Value", req.Method)

	/*-------------------------------------------------------
		res := Cookie_Check(w, req)
		if res < 0 {
			OutputData.Code = "600"
			OutputData.Message = "fail (session expiretimed)"
			OutputData.InputValue = ""
			OutputData.OutputValue = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))
			return
		}
	  -------------------------------------------------------*/

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		OutputData.Code = "600"
		OutputData.Message = "fail"
		OutputData.OutputValue = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	hashing_algorithm := md5.New()
	HashingText = InputData.UserKey + ":" // ( + DecryptMcseID)
	hashing_algorithm.Write([]byte(HashingText))
	HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
	HashingValue = "HA1 : [" + HashingText + "] >> [" + HA1 + "], "

	hashing_algorithm = md5.New()
	HashingText = InputData.Method + ":" + "/auth_api/package/v1.0/"
	hashing_algorithm.Write([]byte(HashingText))
	HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))
	HashingValue += "HA2 : [" + HashingText + "] >> [" + HA2 + "], "

	hashing_algorithm = md5.New()
	HashingText = HA1 + ":" + InputData.AuthKey + ":" + HA2
	hashing_algorithm.Write([]byte(HashingText))
	GenerateAuthToken = hex.EncodeToString(hashing_algorithm.Sum(nil))
	HashingValue += "Output : [" + HashingText + "] >> [" + GenerateAuthToken + "]"

	log.Println("Key Derivation Value -> ", HashingValue)

	OutputData.Code = "200"
	OutputData.Message = "success"
	OutputData.OutputValue = GenerateAuthToken

	jstrbyte, _ := json.Marshal(OutputData)
	OutputBody = string(jstrbyte)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(OutputBody))
	return
}

//-------------------------------------------------------------//
//-------------------------------------------------------------//
//-------------------------------------------------------------//

func WebServer_Forbidden(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	http.Error(w, "Forbidden", http.StatusForbidden)
	return
}

func WebServer_Redirect(w http.ResponseWriter, req *http.Request, dir string) {
	defer req.Body.Close()

	HostStr := fmt.Sprintf("http://%s%s", req.Host, dir)
	http.Redirect(w, req, HostStr, 302)
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

func MariaDBInit(Id string, Passwd string, DbAddr string, DbPort string, DbName string) *sql.DB {
	//var sql string

	Database := mariadb_lib.Connection_DB(Id, Passwd, DbAddr, DbPort, DbName)

	/*---------------------------
		sql = "CREATE TABLE IF NOT EXISTS `user` ( " +
			"`user_id_seq` int NOT NULL AUTO_INCREMENT, " +
			"`user_id` varchar(50) NOT NULL, " +
			"`password` varchar(50) NOT NULL, " +
			"`email` varchar(256) NOT NULL, " +
			"`property` varchar(32) NOT NULL, " +
			"`create_date` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
			"`update_date` TIMESTAMP NULL DEFAULT NULL, " +
			"`status` varchar(32) NOT NULL, " +
			"`program_name` varchar(128) NOT NULL, " +
			"`nodekey_generate_tmp_key` text, " +
			"unique index idx__user__user_seq (user_id_seq), " +
			"unique index idx__user__user_id (user_id) " +
			") " +
			"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' " +
			"ENGINE=InnoDB "

		mariadb_lib.Create_Table(Database, sql)

		sql = "CREATE TABLE IF NOT EXISTS `user_key` ( " +
			"`user_key_id_seq` int NOT NULL AUTO_INCREMENT, " +
			"`user_key_id` varchar(256) NOT NULL, " +
			"`node_client_count` int, " +
			"`create_date` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
			"`update_date` TIMESTAMP, " +
			"`pkg_start_date` TIMESTAMP, " +
			"`pkg_end_date` TIMESTAMP, " +
			"`status` varchar(32) NOT NULL, " +
			"`create_user_id` varchar(50) NOT NULL, " +
			"`update_user_id` varchar(50) NOT NULL, " +
			"`package_home_path` text NOT NULL, " +
			"`user_id_seq` int NOT NULL, " +
			"`nodeid_generate_tmp_key` text, " +
			"unique index idx__user_key__user_key_id_seq (user_key_id_seq), " +
			"unique index idx__user_key__user_key_id (user_key_id), " +
			"index idx__user_key__user_id_seq (user_id_seq) " +
			") " +
			"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "

		mariadb_lib.Create_Table(Database, sql)

		sql = "CREATE TABLE IF NOT EXISTS `node_id` ( " +
			"`node_id_seq` int NOT NULL AUTO_INCREMENT, " +
			"`node_id` varchar(256) NOT NULL, " +
			"`create_date` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
			"`user_id_seq` int NOT NULL, " +
			"`create_user_id` varchar(50) NOT NULL, " +
			"`update_user_id` varchar(50) NOT NULL, " +
			"`user_key_id_seq` int NOT NULL, " +
			"`user_key_id` varchar(256) NOT NULL, " +
			"`web_api_auth_key` varchar(256) NOT NULL, " +
			"`web_api_auth_token` varchar(256) NOT NULL, " +
			"`web_api_auth_token_expire_time_date` TIMESTAMP NOT NULL, " +
			"unique index idx__node_id__node_id_seq (node_id_seq), " +
			"unique index idx__node_id__node_id  (node_id), " +
			"index idx__node_id__user_id_seq (user_id_seq), " +
			"index idx__node_id__user_key_id_seq (user_key_id_seq) " +
			") " +
			"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "

		mariadb_lib.Create_Table(Database, sql)

		sql = "CREATE TABLE IF NOT EXISTS `auth_access_node_list` ( " +
			"`seq` int NOT NULL AUTO_INCREMENT, " +
			"`user_id_seq` int NOT NULL, " +
			"`node_id` varchar(256) NOT NULL, " +
			"`node_ip` varchar(128) NOT NULL, " +
			"`auth_date` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
			"`auth_token` varchar(256) NOT NULL, " +
			"`auth_expire_time` int NOT NULL, " +
			"`auth_response_code` varchar(16) NOT NULL, " +
			"`auth_response_message` varchar(256) NOT NULL, " +
			"unique index idx__auth_access_node_list__seq (seq), " +
			"index idx__auth_access_node_list__user_id_seq (user_id_seq), " +
			"index idx__auth_access_node_list__node_id (node_id), " +
			"index idx__auth_access_node_list__node_ip (node_ip), " +
			"index idx__auth_access_node_list__auth_date (auth_date) " +
			") " +
			"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "

		mariadb_lib.Create_Table(Database, sql)

		sql = "CREATE TABLE IF NOT EXISTS `kms_configure` ( " +
			"`OEM_NAME` varchar(256) NOT NULL, " +
			"`OEM_WEB_HEAD_INFORMATION` varchar(256) NOT NULL, " +
			"`OEM_WEB_TAIL_INFORMATION` varchar(256) NOT NULL, " +
			"`OEM_PACKAGE_FILENAME` varchar(256) NOT NULL, " +
			"`OEM_PACKAGE_ENCRYPTION_KEY` varchar(256) NOT NULL, " +
			"`OEM_PACKAGE_ENCRYPTION_IV` varchar(256) NOT NULL, " +
			"`OEM_PACKAGE_HOMEPATH` varchar(256) NOT NULL, " +
			"`OEM_AUTH_EXPIRETIME_INTERVAL` int NOT NULL, " +
			"`OEM_SMTP_SERVER_ADDRESS` text NOT NULL, " +
			"`OEM_SMTP_SERVER_HOST` text NOT NULL, " +
			"`OEM_SMTP_SENDER_EMAIL` text NOT NULL, " +
			"`OEM_SMTP_SENDER_PASSWORD` text NOT NULL " +
			") " +
			"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "

		mariadb_lib.Create_Table(Database, sql)
	---------------------------*/

	return Database
}

func MariaDBInitDataSetup() {
	/*--------------------------------------
		var Database *sql.DB
		var ResultSetRows *sql.Rows
		var QueryString string
		var CheckRowCount int

		log.Println("DB Init Setup")

		Database = MariaDB_Open()
		defer MariaDB_Close(Database)

		CheckRowCount = 0

		QueryString = "SELECT COUNT(user_id) FROM user WHERE user_id = 'admin' "
		//log.Println("MariaDBInitDataSetup Query -> ", QueryString)
		ResultSetRows, _ = mariadb_lib.Query_DB(Database, QueryString)
		for ResultSetRows.Next() {
			err := ResultSetRows.Scan(&CheckRowCount)
			if err != nil {
				ResultSetRows.Close()
				log.Println(" data Scan error:", err)

				return
			}
		}
		ResultSetRows.Close()

		if CheckRowCount == 0 {
			QueryString = "INSERT INTO user " +
				"(user_id, password, email, property, create_date, update_date, program_name, nodekey_generate_tmp_key, status) " +
				"VALUES ('admin', '3697032a353a1f4784d5e9f362f8ce9d1b0f60ca', '', 'admin', NOW(), NOW(), '', '', 'ENABLE') "

			log.Println("MariaDBInitDataSetup Insert Query -> ", QueryString)
			mariadb_lib.Insert_Data(Database, QueryString)
			// TODO: DB Excxception (return cnt)
		}

		CheckRowCount = 0

		QueryString = "SELECT COUNT(*) FROM kms_configure  "
		//log.Println("MariaDBInitDataSetup Query -> ", QueryString)
		ResultSetRows, _ = mariadb_lib.Query_DB(Database, QueryString)
		for ResultSetRows.Next() {
			err := ResultSetRows.Scan(&CheckRowCount)
			if err != nil {
				ResultSetRows.Close()
				log.Println(" data Scan error:", err)

				return
			}
		}
		ResultSetRows.Close()

		if CheckRowCount == 0 {
			QueryString = "INSERT INTO kms_configure " +
				"(OEM_NAME, OEM_WEB_HEAD_INFORMATION, OEM_WEB_TAIL_INFORMATION, OEM_PACKAGE_FILENAME, OEM_PACKAGE_ENCRYPTION_KEY, OEM_PACKAGE_ENCRYPTION_IV, OEM_SMTP_SERVER_ADDRESS, OEM_SMTP_SERVER_HOST, OEM_SMTP_SENDER_EMAIL, OEM_SMTP_SENDER_PASSWORD, OEM_PACKAGE_HOMEPATH, OEM_AUTH_EXPIRETIME_INTERVAL) " +
				"VALUES ('svc_corporation', '', 'Copyright ⓒ 2020 KMS. All right reserved.', 'svc_node', 'SINCE-2020-01-01-SVC_CORPORATION', 'SINCE-20200101IV', 'smtp.gmail.com:587', 'smtp.gmail.com', 'kms_sender@gmail.com', 'test1234', '', 300) "

			log.Println("MariaDBInitDataSetup Insert Query -> ", QueryString)
			mariadb_lib.Insert_Data(Database, QueryString)
			// TODO: DB Excxception (return cnt)
		}
	--------------------------------------*/
}

func MariaDB_Open() (Database *sql.DB) {
	var DBObject *sql.DB

	DBObject = MariaDBInit(DBUSER, DBUSERPW, DBIP, DBPORT, DBNAME)
	if DBObject != nil {
		mariadb_lib.DB_AutoCommit_Enable(DBObject)
	}
	return DBObject
}

func MariaDB_Close(Database *sql.DB) {
	if Database != nil {
		Database.Close()
		Database = nil
	}
}

func MssqlDBInit(UserID string, Passwd string, DBIP string, DBPort string, DBName string) *sql.DB {

	Database, err := msdb_lib.Connection_DB(UserID, Passwd, DBIP, DBPort, DBName)
	if err != nil {
		log.Println("SQL Open Error", err)
		Database.Close()
		return nil
	}

	// TODO : Checking Table List Exist //
	return Database
}

func MssqlDB_Open() (Database *sql.DB) {
	var DBObject *sql.DB

	DBObject = MssqlDBInit(DBUSER, DBUSERPW, DBIP, DBPORT, DBNAME)
	if DBObject != nil {
		//msdb_lib.DB_AutoCommit_Disable(DBObject)
	}
	return DBObject
}

func MssqlDB_Close(Database *sql.DB) {
	if Database != nil {
		Database.Close()
		Database = nil
	}
}

func DBInformationSetup() {
	var db_cfg_path = "./configuration/db.cfg"

	var db_cfg_info DBconfig

	if _, err := toml.DecodeFile(db_cfg_path, &db_cfg_info); err != nil {
		log.Fatal(err)
	}

	db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME = Decrypt_dbcfginfo(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)

	DBIP = db_cfg_info.DB.IP
	DBPORT = db_cfg_info.DB.PORT
	DBNAME = db_cfg_info.DB.DBNAME
	DBUSER = db_cfg_info.DB.ID
	DBUSERPW = db_cfg_info.DB.PASSWORD

	if DBIP == "" {
		log.Print("[error report] invalid db ip data")
		panic("invalid db information")
	}

	if DBPORT == "" {
		log.Print("[error report] invalid db port data")
		panic("invalid db information")
	}

	if DBNAME == "" {
		log.Print("[error report] invalid db name data")
		panic("invalid db information")
	}

	if DBUSER == "" {
		log.Print("[error report] invalid db user data")
		panic("invalid db information")
	}

	if DBUSERPW == "" {
		log.Print("[error report] invalid db user password data")
		panic("invalid db information")
	}

	//log.Print("IP:", DBIP, ", PORT:", DBPORT, ", DBNAME:", DBNAME, ", DBUSER:", DBUSER, ", DBUSERPW:", DBUSERPW)
}

func RunWebContainer(ServicePort string) {
	log.Print("Run Web-Container\n")

	PackageLockTable = PackageMapTableInit()

	DBInformationSetup()

	Database := MssqlDBInit(DBUSER, DBUSERPW, DBIP, DBPORT, DBNAME)
	MssqlDB_Close(Database)
	//MariaDBInitDataSetup()

	WebServerMux := http.NewServeMux()

	WebServerMux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		log.Print("<<--- HTMP URL Not Founded Page --->>\n")
		//WebServer_Redirect(w, req, "/login/")
		WebServer_Auth_API_Trail_Invalid_Access_Response(w, "403", "Forbidden")
	})

	//----- [ Trial Init Auth Processing ] {--------------------//
	WebServerMux.HandleFunc("/auth_api/trial_setup/v1.0/input_debugger/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Trial_Setup_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/trial_setup/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Trial_Setup_Proc(w, req)
	})
	//----- [ Trial Init Auth Processing ] }--------------------//

	//----- [ Trial Statistics Processing ] {--------------------//
	WebServerMux.HandleFunc("/auth_api/trial_traffic/input_debugger/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Trial_Statistics_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/trial_traffic/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Trial_Statistics_Proc(w, req)
	})
	//----- [ Trial Statistics Processing ] }--------------------//

	//----- [ Trial Utililty Processing ] {--------------------//
	WebServerMux.HandleFunc("/auth_api/trial_setup/v1.0/key_encoding/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Trial_Encode_Value(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/trial_setup/v1.0/key_derivation/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Trial_AuthToken_Value(w, req)
	})
	//----- [ Trial Utililty Processing ] }--------------------//

	WebServerMux.Handle("/html/", http.StripPrefix("/html/", http.FileServer(http.Dir("html"))))

	WebServerMux.HandleFunc("/service_stop/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Service_Stop(w, req)
	})

	WebServerMux.HandleFunc("/service_invalid_access/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Service_Invalid_Access(w, req)
	})

	/*--------------------------------------------------------------------------------------------------------
		StatServerMux := http.NewServeMux()
		StatServerMux.HandleFunc("/Serv_Stat_Common/", func(w http.ResponseWriter, req *http.Request) {
			StatServCommon(w, req, Database)
		})
	  --------------------------------------------------------------------------------------------------------*/

	WebServerMux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Forbidden(w, req, Database)
	})

	// Node Status check

	go HttpListen(0, ":"+ServicePort, "", "", WebServerMux)
}

func DecryptDecodingStr(EncryptEncodingText string, RetText *string) {
	new_decoder := base32.NewEncoding(string(base32_alphabet))
	new_decoder = new_decoder.WithPadding(base32.NoPadding)
	encrypt, err := new_decoder.DecodeString(EncryptEncodingText)
	if err != nil {
		panic(err)
	}

	PlainText := make([]byte, len(encrypt))

	err = aes_cfb.DecAES_CFB8_256(PlainText, encrypt, aes_key, iv)
	if err != nil {
		panic(err)
	}

	*RetText = string(PlainText)
	//log.Printf("Dec %s -> %x Decode %s\n", EncryptEncodingText, encrypt, *RetText)
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
	log.Println("Usage: ./kms_service [Arg] [Options]")
	log.Println(" Available Args ")
	log.Println(" -l [port number] : Run as listener port")
	log.Println(" -p [fg or bg]    : Run as foreground process or background process")
	log.Println(" (ex: ./kms_service -l 80 -p bg)")
	log.Println("")
}

func MariaDBOpen(Id string, Passwd string, DbAddr string, DbPort string, DbName string) *sql.DB {

	Database := mariadb_lib.Connection_DB(Id, Passwd, DbAddr, DbPort, DbName)
	if Database == nil {
		log.Println("Maria DB Open Fail!")
		return nil
	}
	return Database
}

//---------------------Statistics Auth--------------------------------
//type jsonInputWebAPIAuthStatisticsPack struct {
type jsonInputWebAPIAuthTrialStatisticsData struct {
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

//----------------------------------------------------------
type jsonInputWebAPIAuthTrialStatisticsPack struct {
	Version     string      `json:"version"`
	Method      string      `json:"method"`
	SessionType string      `json:"sessiontype"`
	Seperator   string      `json:"seperator"`
	MessageType string      `json:"msgtype"`
	MessageSeq  string      `json:"msgseq"`
	TrialID     string      `json:"trialid"`
	AuthKey     string      `json:"auth_key"`
	AuthToken   string      `json:"auth_token"`
	Data        interface{} `json:"data"`
}

type jsonOutputWebAPIAuthTrialStatisticsPack struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	Seperator   string `json:"seperator"`
	MessageType string `json:"msgtype"`
	MessageSeq  string `json:"msgseq"`
	Code        string `json:"code"`
	Message     string `json:"msg"`
	AuthKey     string `json:"auth_key"`
	ExpireTime  string `json:"expiretime"`
	Param       string `json:"param"`
	Event       string `json:"event"`
	Sendcyctime string `json:"sendcyctime "`
}

//----------------------------------------------------------
//-----------------------Statistics Auth------------------------------

type StatisticInformation struct {
	MCSEIP              string `mapstructure:"MCSEIP" json:"mcseip"`
	CurPeerSumTraffic   string `mapstructure:"CurPeerSumTraffic" json:"curpeersumtraffic"`
	CurProxySumTraffic  string `mapstructure:"CurProxySumTraffic" json:"curproxysumtraffic"`
	CurPeerTraffic      string `mapstructure:"CurPeerTraffic" json:"curpeertraffic"`
	CurProxyTraffic     string `mapstructure:"CurProxyTraffic" json:"curproxytraffic"`
	PrevPeerSumTraffic  string `mapstructure:"PrevPeerSumTraffic" json:"prevpeersumtraffic"`
	PrevProxySumTraffic string `mapstructure:"PrevProxySumTraffic" json:"prevproxysumtraffic"`
	ProxyCnt            string `mapstructure:"ProxyCnt" json:"proxycnt"`
	ClientCnt           string `mapstructure:"ClientCnt" json:"clientcnt"`
	ServerCnt           string `mapstructure:"ServerCnt" json:"servercnt"`
	MCSEMode            string `mapstructure:"MCSEMode" json:"mcsemode"`
}

type ServStatInfo struct {
	DeviceID           int
	UserKeyID          int
	Bridge_ID_Text     string
	Time               string
	Server_IP_Text     string
	Server_Listen_Port int
	Node_IP_Text       string
	Node_Listen_Port   int
	Proxy_IP_Text      string
	Client_IP_Text     string
	Inbound            int
	Outbound           int
	SiteType           int
}
type ClntStatInfo struct {
	DeviceID          int
	UserKeyID         int
	Node_ID_Text      string
	Time              string
	Node_IP_Text      string
	Node_Listen_Port  int
	Proxy_IP_Text     string
	Proxy_Listen_Port int
	Client_IP_Text    string
	Inbound           int
	Outbound          int
	SiteType          int
}

func WebServer_Web_Auth_API_Trial_Statistics_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlTrial CommonHTML
	var HtmlTemplate *template.Template
	var err error

	log.Println("WebServer_Web_Auth_API_Trial_Statistics_Input", req.Method)

	///*---------------------------------------
		res := Cookie_Check(w, req)
		if res < 0 {
			WebServer_Redirect(w, req, "/login/")
			return
		}
		//SessionCookieUserData(&HtmlPackage.CookiesData, req)
		//WebServerOEMInformation(&HtmlPackage.OEMData)
	//  ----------------------------------------*/
	WebServerMainMenu(&HtmlTrial.MainMenu, "statistics")

	HtmlTemplate, err = template.ParseFiles("./html/trail_gowas_auth_statistics_input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/trail_gowas_auth_statistics_input.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, HtmlTrial)
}

func WebServer_Auth_API_Trial_Statistic_Response(w http.ResponseWriter, Version string, Method string, SessionType string, Seperator string, MessageType string, MessageSeq string, Code string, Message string, AuthKey string, Expiretime string, Param string, Event string) {
	var OutputData jsonOutputWebAPIAuthTrialStatisticsPack
	var OutputBody string

	OutputData.Version = Version         // (security enhancement: tracking prevention)
	OutputData.Method = Method           // (security enhancement: tracking prevention)
	OutputData.SessionType = SessionType // (security enhancement: tracking prevention)
	OutputData.Seperator = Seperator     // (security enhancement: tracking prevention)
	OutputData.MessageType = MessageType // (security enhancement: tracking prevention)
	OutputData.MessageSeq = MessageSeq   // (security enhancement: tracking prevention)
	OutputData.Code = Code
	OutputData.Message = Message
	OutputData.AuthKey = AuthKey
	OutputData.ExpireTime = Expiretime
	OutputData.Param = Param
	OutputData.Event = Event
	OutputData.Sendcyctime = "60"

	jstrbyte, _ := json.Marshal(OutputData)
	OutputBody = string(jstrbyte)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "10")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(OutputBody))
	return
}

func WebServer_Web_Auth_API_Trial_Statistics_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var Database *sql.DB
	var InputData jsonInputWebAPIAuthTrialStatisticsPack
	var ResponseMessage string

	var LimitExpireDays int
	var TrialID int
	var DBTrialIDCount int
	var DBTrialIDExpiredays int
	var EncryptTrialID string
	var DecryptTrialID string
	var DecryptTrialIDSalt string

	var HashingText string
	var HashingValue string
	var HA1 string
	var HA2 string
	var GenerateAuthKey string
	var GenerateAuthToken string
	var TrialHashingValue string
	var EncryptValue string

	var AuthExpiretimeInterval int
	var DBAuthKey string
	var DBAuthToken string
	var DBAuthExpireTime uint64
	var DBAuthNOWTime uint64

	var QueryString string
	var QueryTupleCount int
	var ResultSetRows *sql.Rows
	var RetValue int
	var err error

	log.Println("WebServer_Web_Auth_API_Trial_Statistics_Proc", req.Method, ", Proxy Address:", req.RemoteAddr)

	LimitExpireDays = 14

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		log.Println("json parsing error:", err)
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error - (simplify Information for security enhancement)"
		WebServer_Auth_API_Trial_Statistic_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "", "")
		return
	}

	if req.Method != "POST" {
		log.Println("not supported request method")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error (not support method) - (simplify Information for security enhancement)"
		WebServer_Auth_API_Trial_Statistic_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "", "")
		return
	}

	log.Println(">>> Input Data - version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", seperator:" + InputData.Seperator + ", msgtype:" + InputData.MessageType + ", msgseq:" + InputData.MessageSeq + ", trialid:" + InputData.TrialID + ", authkey:" + InputData.AuthKey + ", authtoken:" + InputData.AuthToken)

	// comments: checking mandatory input value
	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.Seperator == "" || InputData.MessageType == "" || InputData.MessageSeq == "" || InputData.TrialID == "" {
		log.Println("invalid parmeter value: mandatory param is empty")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is empty (simplify Information for security enhancement)"
		WebServer_Auth_API_Trial_Statistic_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "", "")
		return
	}

	// comments: checking validation input value
	if InputData.Version != "1.0" || InputData.Method != "auth" || InputData.SessionType != "traffic" || (InputData.Seperator != "client" && InputData.Seperator != "server") || InputData.MessageType != "request" {
		log.Println("invalid parmeter value: not supported value")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is invalid (simplify Information for security enhancement)"
		WebServer_Auth_API_Trial_Statistic_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "", "")
		return
	}

	if InputData.TrialID != "" {
		EncryptTrialID = InputData.TrialID
		DecryptTrialID = AESDecryptDecodeValue(EncryptTrialID)
		if DecryptTrialID == "" {
			log.Println("invalid parmeter value: user key decrypt error")
			ResponseMessage = "json parameter decript error"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "", "")
			return
		}

		log.Printf("DecryptTrialIDPattern [%s]", DecryptTrialID)

		PatternLineList := strings.Split(DecryptTrialID, ":")
		for i, line := range PatternLineList {
			if len(line) > 0 {
				if i == 0 {
					DecryptTrialIDSalt = line
				} else if i == 1 {
					DecryptTrialID = line
				} else {
					break
					log.Println("invalid parmeter value: trial capsulation value")
					ResponseMessage = "invalid parmeter value: trial capsulation value"
					WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "", "")
					return
				}
			}
		}

		log.Printf("DecryptTrialIDPattern [%s]", DecryptTrialID)
		log.Printf("Pattern Line List [%s]", PatternLineList)
		log.Printf("DecryptTrialIDSalt [%s]", DecryptTrialIDSalt)

		TrialID, err = strconv.Atoi(DecryptTrialID)
		if err != nil {
			log.Println("failed to Atoi DecryptTrialID")
			ResponseMessage = "invalid DecryptTrialID"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "", "")
			return
		}

		log.Printf("WEB API Auth - TrialID Decrypt Value [%s] -> [%s]", InputData.TrialID, DecryptTrialID)
	}

	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)
	//msdb_lib.DB_AutoCommit_Enable(Database)

	if Database == nil {
		log.Println("db connection error")
		ResponseMessage = "db connection error"
		WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
		return
	}

	AuthExpiretimeInterval = 10
	//Database.SetMaxIdleConns(1000)
	//Database.SetMaxOpenConns(1000)

	/*----------------------------------------------------
		forwarded := req.Header.Get("X-FORWARDED-FOR")
		if forwarded != "" {
			InputData.IP = forwarded
		} else {
			ip, _, err := net.SplitHostPort(req.RemoteAddr)
			if err != nil {
				InputData.IP = ""
			} else {
				InputData.IP = ip
			}
		}
	  ----------------------------------------------------*/

	//--[Query: Checking TrialID]--------------------{
	QueryString = "SELECT trial_id, DATEDIFF(day, reg_date, getdate()) as expiredays FROM mcs.Trial_ID WHERE trial_id = %d "
	QueryString = fmt.Sprintf(QueryString, TrialID)
	log.Println("Auth TrialID Exist Query : ", QueryString)
	//--[Query: Checking TrialID]--------------------}

	ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
	if err != nil {
		log.Println("db query error (not founded trial_id column of Trial_ID)")
		ResponseMessage = "db query error(not founded trial_id column of Trial_ID)"
		WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
		return
	}

	QueryTupleCount = 0
	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&DBTrialIDCount, &DBTrialIDExpiredays)
		if err != nil {
			ResultSetRows.Close()
			log.Println("not founded trial id - data Scan error:", err)
			ResponseMessage = "not founded trial id"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "655", ResponseMessage, "", "", "", "")
			return
		}
		QueryTupleCount++
	}
	ResultSetRows.Close()

	if QueryTupleCount == 0 {
		log.Println("db query error(exist trial id)")
		ResponseMessage = "failed to query (not exist trial id)"
		WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
		return
	} else if QueryTupleCount > 1 {
		log.Println("db query error(multi-tuple trial_id)")
		ResponseMessage = "failed to query (multi-tuple trial_id)"
		WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
		return
	}

	if DBTrialIDExpiredays > LimitExpireDays {
		ResponseMessage = "end of service period"
		WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "652", ResponseMessage, "", "", "", "")
		log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "652", ResponseMessage)
		return
	}

	if InputData.AuthKey == "" && InputData.AuthToken == "" {
		AuthStatisticsSeqNo += 1
		if AuthStatisticsSeqNo >= 100000 {
			AuthStatisticsSeqNo = 1
		}

		GenerateAuthKey = WEBAuthGenerateAuthKey(strconv.Itoa(AuthStatisticsSeqNo))
		if GenerateAuthKey == "" {
			log.Println("failed to generate auth key")
			ResponseMessage = "failed to generate auth key"
			log.Printf("web api response [code:%s, msg:%s]", "643", ResponseMessage)
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "", "")
			return
		}

		hashing_algorithm := md5.New()
		HashingText = "trial_certification_identity" + ":" + DecryptTrialID
		hashing_algorithm.Write([]byte(HashingText))
		HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

		hashing_algorithm = md5.New()
		HashingText = InputData.Method + ":" + "/auth_api/trial_traffic/v1.0/"
		hashing_algorithm.Write([]byte(HashingText))
		HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue += "[" + HashingText + " >> HA2:" + HA2 + "]"

		hashing_algorithm = md5.New()
		HashingText = HA1 + ":" + GenerateAuthKey + ":" + HA2
		hashing_algorithm.Write([]byte(HashingText))
		GenerateAuthToken = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue += "[" + HashingText + " >> GenerateAuthToken:" + GenerateAuthToken + "]"

		log.Println("WEB API Auth Traffic Information -> ", HashingValue)

		//----------------------------------------------------------------//
		//Response = WebServer_Auth_API_Hashing_Statistic(InputData.UserKeyID, InputData.DeviceID, InputData.Method, GenerateAuthKey)
		//log.Println("WEB API Auth Information -> ", EventValue)
		//----------------------------------------------------------------//

		if GenerateAuthToken != "" {

			//--[Query: Delete Existed AuthKey & AuthToken]--{
			QueryString = "DELETE FROM mcs.CWS_TrialAuth WHERE trial_id = %d and method = '%s' and session_type = '%s' and seperator = '%s' "
			QueryString = fmt.Sprintf(QueryString, TrialID, InputData.Method, InputData.SessionType, InputData.Seperator)
			log.Println("CWS_TrialAuth Delete Query : ", QueryString)
			//-----------------------------------------------}
			_, err = msdb_lib.Delete_Data(Database, QueryString)
			if err != nil {
				log.Println("db processing error (delete CWS_TrialAuth by trial_id)")
				ResponseMessage = "db processing error (delete CWS_TrialAuth by trial_id)"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
				return
			}

			//--[Query: Insert Temp AuthKey & AuthToken]-----{
			QueryString = "INSERT INTO mcs.CWS_TrialAuth (trial_id, method, session_type, seperator, auth_key, auth_token, expiretime, reg_date) " +
				"VALUES (%d, '%s', '%s', '%s', '%s', '%s', DATEADD(second, %d, GETDATE()), GETDATE()) "
			QueryString = fmt.Sprintf(QueryString, TrialID, InputData.Method, InputData.SessionType, InputData.Seperator, GenerateAuthKey, GenerateAuthToken, AuthExpiretimeInterval)
			log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
			//-----------------------------------------------}
			_, err = msdb_lib.Insert_Data(Database, QueryString)
			if err != nil {
				log.Println("db processing error (insert CWS_Auth traffic by key_id, auth_key, auth_token)")
				ResponseMessage = "db processing error (insert CWS_Auth traffic by key_id, auth_key, auth_token)"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
				return
			}

			ResponseMessage = "success generation auth key"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "200", ResponseMessage, GenerateAuthKey, strconv.Itoa(AuthExpiretimeInterval), "", "")
			log.Printf("web api response [trial_id:%d] [code:%s, msg:%s, description:%s (expiretime sec:%d, authkey:%s, authtoken:%s)]", TrialID, "200", ResponseMessage, "create new authkey and authtoken", AuthExpiretimeInterval, GenerateAuthKey, GenerateAuthToken)
			return

		} else {
			log.Println("failed to create auth token:")
			ResponseMessage = "failed to generate auth token"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "644", ResponseMessage, "", "", "", "")
			return
		}

	} else if InputData.AuthKey != "" && InputData.AuthToken != "" {

		//--[Query: Checking Auth Information]-----------{
		QueryString = "SELECT auth_key, auth_token, " +
			"auth_expiretime=((DATEPART(HOUR,expiretime)*3600)+(DATEPART(MINUTE,expiretime)*60)+(DATEPART(Second,expiretime))), " +
			"auth_now=((DATEPART(HOUR,GETDATE())*3600)+(DATEPART(MINUTE,GETDATE())*60)+(DATEPART(Second,GETDATE()))) " +
			"FROM mcs.CWS_TrialAuth " +
			"WHERE trial_id = %d and method = '%s' and session_type = '%s' and seperator = '%s' "
		QueryString = fmt.Sprintf(QueryString, TrialID, InputData.Method, InputData.SessionType, InputData.Seperator)
		log.Println("Auth Information Checking Query : ", QueryString)
		//-----------------------------------------------}

		ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			log.Println("db processing error (not founded tuple by trial_id)")
			ResponseMessage = "db processing error (not founded tuple by trial_id)"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		QueryTupleCount = 0
		for ResultSetRows.Next() {
			err = ResultSetRows.Scan(&DBAuthKey, &DBAuthToken, &DBAuthExpireTime, &DBAuthNOWTime)
			if err != nil {
				ResultSetRows.Close()
				log.Println("data Scan error:", err)
				ResponseMessage = "db processing error (not founded resultset row of tuple(trial_id))"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
				return
			}
			QueryTupleCount++
		}
		ResultSetRows.Close()

		if QueryTupleCount == 0 {
			log.Println("db query error(auth data of AuthTable not founded)")
			ResponseMessage = "db query error(auth data of AuthTable not founded)"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		} else if QueryTupleCount > 1 {
			log.Println("db query error(auth data of AuthTable is multi-tuple)")
			ResponseMessage = "db query error(auth data of AuthTable is multi-tuple)"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		//--[Query: Delete Existed AuthKey & AuthToken]--{
		QueryString = "DELETE FROM mcs.CWS_TrialAuth WHERE trial_id = %d and method = '%s' and session_type = '%s' and seperator = '%s' "
		QueryString = fmt.Sprintf(QueryString, TrialID, InputData.Method, InputData.SessionType, InputData.Seperator)
		log.Println("CWS_TrialAuth Delete Query : ", QueryString)
		//-----------------------------------------------}
		_, err = msdb_lib.Delete_Data(Database, QueryString)
		if err != nil {
			log.Println("db processing error (delete CWS_TrialAuth by trial_id)")
			ResponseMessage = "db processing error (delete CWS_TrialAuth by trial_id)"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			return
		}

		if DBAuthExpireTime < DBAuthNOWTime {
			ResponseMessage = "auth_key has expired"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "")
			log.Printf("web api response [code:%s, msg:%s] %d, %d", "643", ResponseMessage, DBAuthExpireTime, DBAuthNOWTime)
			return
		}

		TrafficData := StatisticInformation{}
		if err := mapstructure.Decode(InputData.Data, &TrafficData); err != nil {
			ResponseMessage = "failed to parsing json traffic"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "610", ResponseMessage, "", "", "", "")
			log.Println("failed to parsing json traffic")
			return
		}

		///*-----------------------------------------------------------------------
		log.Println("mcseip:" + TrafficData.MCSEIP)
		log.Println("prevpeertraffic:" + TrafficData.PrevPeerSumTraffic)
		log.Println("prevproxytraffic:" + TrafficData.PrevProxySumTraffic)
		log.Println("curpeertraffic:" + TrafficData.CurPeerTraffic)
		log.Println("curproxytraffic:" + TrafficData.CurProxyTraffic)
		log.Println("peersumtraffic:" + TrafficData.CurPeerSumTraffic)
		log.Println("proxysumtraffic:" + TrafficData.CurProxySumTraffic)
		log.Println("proxycnt:" + TrafficData.ProxyCnt)
		log.Println("clientcnt:" + TrafficData.ClientCnt)
		log.Println("servercnt:" + TrafficData.ServerCnt)
		log.Println("mcsemode:" + TrafficData.MCSEMode)
		//------------------------------------------------------------------------*/

		RetValue = InsertStatisticsDB(Database, TrafficData, TrialID)
		if RetValue < 0 {
			if RetValue == -1 {
				ResponseMessage = "failed to traffic processing (parsing traffic value)"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "610", ResponseMessage, "", "", "", "")
				log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "610", ResponseMessage)
				return
			} else if RetValue == -2 {
				ResponseMessage = "failed to traffic processing (invalid ip address)"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "610", ResponseMessage, "", "", "", "")
				log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "610", ResponseMessage)
				return
			} else if RetValue == -3 {
				ResponseMessage = "failed to traffic processing (not supported mode)"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "610", ResponseMessage, "", "", "", "")
				log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "610", ResponseMessage)
				return
			} else if RetValue == -4 {
				ResponseMessage = "failed to traffic processing (invalid calculate traffic)"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "610", ResponseMessage, "", "", "", "")
				log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "610", ResponseMessage)
				return
			} else if RetValue == -5 {
				ResponseMessage = "product service restrictions"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "653", ResponseMessage, "", "", "", "")
				log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "653", ResponseMessage)
				return
			} else if RetValue == -6 {
				ResponseMessage = "product service restrictions"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "610", ResponseMessage, "", "", "", "")
				log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "610", ResponseMessage)
				return
			} else if RetValue == -10 {
				ResponseMessage = "error db processing"
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "610", ResponseMessage, "", "", "", "")
				log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "610", ResponseMessage)
				return
			} else {
				ResponseMessage = "failed to processing "
				WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "610", ResponseMessage, "", "", "", "")
				log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "610", ResponseMessage)
				return
			}
		}

		hashing_algorithm := md5.New()
		HashingText = InputData.AuthKey + ":" + InputData.TrialID
		hashing_algorithm.Write([]byte(HashingText))
		TrialHashingValue = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue = HashingText + ":" + TrialHashingValue

		EncryptValue = AESEncryptEncodingValue(HashingValue)
		if EncryptValue == "" {
			log.Println("failed to decrypt decode trial_id pattern")
			ResponseMessage = "failed to decrypt decode trial_id pattern"
			WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "400", ResponseMessage, "", "", "", "")
			return
		}

		ResponseMessage = "success"
		WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "200", ResponseMessage, "", strconv.Itoa(0), EncryptValue, "")
		log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "200", ResponseMessage)
		return

	} else {
		ResponseMessage = "auth error"
		WebServer_Auth_API_Trial_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "641", ResponseMessage, "", "", "", "")
		log.Printf("web api response [trail_id:%d] [code:%s, msg:%s]", TrialID, "641", ResponseMessage)
		return
	}
}

func InsertStatisticsDB(Database *sql.DB, Statistics StatisticInformation, TrialID int) int {
	var QueryString string
	var QueryTupleCount int
	var PrevStreamCheckFlag int
	var SiteID int
	var LimitStreamGBytes int64
	var DBPrevPeerStreamSum int64
	var DBPrevProxyStreamSum int64
	var InputPrevPeerStreamSum int64
	var InputPrevProxyStreamSum int64
	var InputCurrPeerStream int64
	var InputCurrProxyStream int64
	var InputSumPeerStream int64
	var InputSumProxyStream int64
	var InputProxyCnt int
	var InputClientCnt int
	var InputServerCnt int
	var ResultSetRows *sql.Rows

	var stmt *sql.Stmt
	var tx *sql.Tx
	var err error

	SiteID = 1
	// calculate giga byte (GB -> B) (1GB : 1073741824 Byte) //
	LimitStreamGBytes = (100 * 1073741824)
	InputPrevPeerStreamSum, err = strconv.ParseInt(Statistics.PrevPeerSumTraffic, 10, 64)
	if err != nil {
		return -1
	}
	InputPrevProxyStreamSum, err = strconv.ParseInt(Statistics.PrevProxySumTraffic, 10, 64)
	if err != nil {
		return -1
	}
	InputCurrPeerStream, err = strconv.ParseInt(Statistics.CurPeerTraffic, 10, 64)
	if err != nil {
		return -1
	}
	InputCurrProxyStream, err = strconv.ParseInt(Statistics.CurProxyTraffic, 10, 64)
	if err != nil {
		return -1
	}
	InputSumPeerStream, err = strconv.ParseInt(Statistics.CurPeerSumTraffic, 10, 64)
	if err != nil {
		return -1
	}
	InputSumProxyStream, err = strconv.ParseInt(Statistics.CurProxySumTraffic, 10, 64)
	if err != nil {
		return -1
	}
	InputProxyCnt, err = strconv.Atoi(Statistics.ProxyCnt)
	if err != nil {
		return -1
	}
	InputClientCnt, err = strconv.Atoi(Statistics.ClientCnt)
	if err != nil {
		return -1
	}
	InputServerCnt, err = strconv.Atoi(Statistics.ServerCnt)
	if err != nil {
		return -1
	}

	if len(Statistics.MCSEIP) == 0 {
		return -2
	}

	if Statistics.MCSEMode != "001" && Statistics.MCSEMode != "002" {
		return -3
	}

	if InputPrevPeerStreamSum+InputCurrPeerStream != InputSumPeerStream {
		return -4
	}

	if InputPrevProxyStreamSum+InputCurrProxyStream != InputSumProxyStream {
		return -4
	}

	if InputSumProxyStream >= LimitStreamGBytes {
		return -5
	}

	tx, err = msdb_lib.DB_TX_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return -10
	}

	defer msdb_lib.DB_TX_Rollback(tx)

	if Statistics.MCSEMode == "001" {
		QueryString = "SELECT peer_stream, proxy_stream " +
			"FROM mcs.Trial_Client_Statistics_Info " +
			"WHERE statistics_id = " +
			" (SELECT max(statistics_id) " +
			" FROM mcs.Trial_Client_Statistics_Info " +
			"  WHERE trial_id = ? ) "
	} else if Statistics.MCSEMode == "002" {
		QueryString = "SELECT peer_stream, proxy_stream " +
			"FROM mcs.Trial_Server_Statistics_Info " +
			"WHERE statistics_id = " +
			" (SELECT max(statistics_id) " +
			" FROM mcs.Trial_Server_Statistics_Info " +
			"  WHERE trial_id = ? ) "
	}
	log.Println("Traffic Query:" + QueryString)

	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Exec Fail!:", err)
		return -10
	}

	ResultSetRows, err = stmt.Query(TrialID)
	if err != nil {
		stmt.Close()
		log.Println("Query:", err)
		return -10
	}

	QueryTupleCount = 0
	for ResultSetRows.Next() {
		err := ResultSetRows.Scan(&DBPrevPeerStreamSum, &DBPrevProxyStreamSum)
		if err != nil {
			log.Println(" data Scan error:", err)
			return -10
		}
		QueryTupleCount++
	}
	ResultSetRows.Close()

	PrevStreamCheckFlag = 0
	if QueryTupleCount == 0 {
		if InputPrevPeerStreamSum == 0 && InputPrevProxyStreamSum == 0 {
			PrevStreamCheckFlag = 1
		} else {
			PrevStreamCheckFlag = 0
		}
	} else if QueryTupleCount == 1 {
		if DBPrevPeerStreamSum == InputPrevPeerStreamSum && DBPrevProxyStreamSum == InputPrevProxyStreamSum {
			PrevStreamCheckFlag = 1
		} else {
			PrevStreamCheckFlag = 0
			log.Printf("Trial_ID [%d] InputPrevPeerSum [%d] InputPrevProxySum [%d] DBPrevPeerSum [%d] DBPrevProxySum [%d]", TrialID, InputPrevPeerStreamSum, InputPrevProxyStreamSum, DBPrevPeerStreamSum, DBPrevProxyStreamSum)
		}
	} else {
		return -10
	}

	if PrevStreamCheckFlag != 1 {
		return -6
	}

	if InputSumProxyStream >= LimitStreamGBytes {
		return -5
	}

	if Statistics.MCSEMode == "001" {
		QueryString = "INSERT INTO mcs.Trial_Client_Statistics_Info " +
			"(trial_id, mcse_ip, client_addr_cnt, proxy_addr_cnt, peer_stream, proxy_stream, reg_user, reg_date, site_id) " +
			"VALUES (?, ?, ?, ?, ?, ?, ?, GETDATE(), ?) "
		log.Println("QueryString", QueryString)

		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return -10
		}

		_, err = stmt.Exec(TrialID, Statistics.MCSEIP, InputClientCnt, InputProxyCnt, InputSumPeerStream, InputSumProxyStream, 0, SiteID)
		if err != nil {
			log.Println("exec Fail!:", err)
			return -10
		}
	} else if Statistics.MCSEMode == "002" {
		QueryString = "INSERT INTO mcs.Trial_Server_Statistics_Info " +
			"(trial_id, mcse_ip, client_addr_cnt, server_addr_cnt, proxy_addr_cnt, peer_stream, proxy_stream, reg_user, reg_date, site_id) " +
			"VALUES (?, ?, ?, ?, ?, ?, ?, ?, GETDATE(), ?) "
		log.Println("QueryString", QueryString)

		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return -10
		}

		_, err = stmt.Exec(TrialID, Statistics.MCSEIP, InputClientCnt, InputServerCnt, InputProxyCnt, InputSumPeerStream, InputSumProxyStream, 0, SiteID)
		if err != nil {
			log.Println("exec Fail!:", err)
			return -10
		}
	}
	stmt.Close()

	msdb_lib.DB_TX_Commit(tx)
	return 0
}

func InsertMcseLog(db *sql.DB, keyid int64, deviceid int, nodeid string, ip string, logType int, logCode int, siteid int) error {
	tx, err := msdb_lib.DB_TX_Begin(db)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := "INSERT INTO MCSE_Logs ( " +
		"key_id, device_id, node_id, ip, log_type, log_code, vision, site_id) VALUES ( " +
		"?, ?, ?, ?, ?, ?, ?, ? ) "

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(keyid, deviceid, nodeid, ip, logType, logCode, 1, siteid)
	if err != nil {
		return err
	}

	tx.Commit()

	return nil
}

func main() {
	//var MinArgs, MinOptions, MaxArgs, MaxOptions int
	//var ListenerPort, DaemonFlag, i int
	//var WebServerFlag string

	var i, MustArgs int
	var ListenerPort string
	var ProcessType string
	var ListenerPortCheck int
	var ProcessTypeCheck int

	MustArgs = 4

	if len(os.Args) != (MustArgs + 1) {
		ShowHelpCommand()

		return
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	InitLogger()

	for i = 0; i < MustArgs; i++ {
		switch os.Args[i] {
		case "-l":
			if ListenerPortCheck != 1 {
				ListenerPort = os.Args[i+1]
				ListenerPortCheck = 1
			}
			break

		case "-p":
			if ProcessTypeCheck != 1 {
				ProcessType = os.Args[i+1]
				ProcessTypeCheck = 1
			}
			break
		}
	}

	if ProcessType == "bg" {
		context := &daemon.Context{
			PidFileName: "innogs_trial_gowas.pid",
			PidFilePerm: 0644,
			LogFileName: ProcessLogFileName,
			LogFilePerm: 0640,
			WorkDir:     "./",
			Umask:       027,
			Args:        []string{"./innogs_trial_gowas", "-l", ListenerPort, "-p", ProcessType},
		}

		child, err := context.Reborn()
		if err != nil {
			log.Fatal("Unable to run: ", err)
		}

		if child != nil {
			log.Fatal("deamon child is not null")
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

	RunWebContainer(ListenerPort)

	finish := make(chan bool)
	<-finish
}
