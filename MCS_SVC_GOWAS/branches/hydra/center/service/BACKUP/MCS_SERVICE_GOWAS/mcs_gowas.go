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
	"./library/make_package"
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
var ProcessLogFileName = "./log/svc_gowas.log"

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
	Provisioning             template.HTML
	Statistics               template.HTML
	Package                  template.HTML
	AuthAssociation          template.HTML
	AuthAssociationDashboard template.HTML
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

type MonitoringNodeAuth struct {
	CookiesData CookiesUserData
	MainMenu    SVCHtmlMainMenu
	OEMData     OEMInformation

	SearchType string

	TempletePage HtmlPageListComponent

	MonitoringItem    []MonitoringNodeAuthItem
	SQLQuery          string
	SQLQueryCondition string
}

type MonitoringNodeAuthItem struct {
	Num                 int
	NodeID              string
	NodeIP              string
	AuthenticationTime  string
	AuthToken           string
	AuthTokenExpiretime int
}

type MonitoringNodeAuthDetail struct {
	CookiesData CookiesUserData
	MainMenu    SVCHtmlMainMenu
	OEMData     OEMInformation

	SearchNodeID string

	TempletePage HtmlPageListComponent

	MonitoringItem    []MonitoringNodeAuthDetailItem
	SQLQuery          string
	SQLQueryCondition string
}

type MonitoringNodeAuthDetailItem struct {
	Num                 int
	NodeID              string
	NodeIP              string
	AuthenticationTime  string
	AuthRspCode         string
	AuthRspMessage      string
	AuthToken           string
	AuthTokenExpiretime int
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

type NodeKeyPackage struct {
	CookiesData CookiesUserData
	MainMenu    SVCHtmlMainMenu
	OEMData     OEMInformation

	TempletePage HtmlPageListComponent

	NodeKeyPackage    NodeKeyPackageItem
	SQLQuery          string
	SQLQueryCondition string
}

type NodeKeyPackageItem struct {
	UserID         string
	NodeKey        string
	NodeIDCount    int
	NodeIDMaxCount int
	ActionMode     string
	ResultMsg      string
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

type jsonInputWebAPIAuthAssociation struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	Seperator   string `json:"seperator"`
	MessageType string `json:"msgtype"`
	MessageSeq  string `json:"msgseq"`
	UserKeyID   string `json:"userkeyid"`
	UserKey     string `json:"userkey"`
	DeviceID    string `json:"deviceid"`
	NodeID      string `json:"nodeid"`
	ViaDeviceID string `json:"via_deviceid"`
	ViaNodeID   string `json:"via_nodeid"`
	AuthKey     string `json:"auth_key"`
	AuthToken   string `json:"auth_token"`
}

type jsonOutputWebAPIAuthAssociation struct {
	Version     string `json:"version"`
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	Seperator   string `json:"seperator"`
	MessageType string `json:"msgtype"`
	MessageSeq  string `json:"msgseq"`
	Code        string `json:"code"`
	Message     string `json:"msg"`
	AuthKey     string `json:"auth_key"`
	Expiretime  string `json:"expiretime"`
	Event       string `json:"event"`
}

type jsonInputWebAPIAuthProvisioningPack struct {
	Version     string      `json:"version"`
	Method      string      `json:"method"`
	SessionType string      `json:"sessiontype"`
	MessageType string      `json:"msgtype"`
	UserKey     string      `json:"userkey"`
	UserKeyID   string      `json:"userkeyid"`
	NodeID      string      `json:"nodeid"`
	DeviceID    string      `json:"deviceid"`
	IP          string      `json:"ip"`
	MACTotal    string      `json:"mactotal"`
	AuthKey     string      `json:"authkey"`
	AuthToken   string      `json:"authtoken"`
	Data        interface{} `json:"data"`
}

type jsonOutputWebAPIAuthProvisioningPack struct {
	Version       string      `json:"version"`
	Method        string      `json:"method"`
	SessionType   string      `json:"sessiontype"`
	MsgType       string      `json:"msgtype"`
	Code          string      `json:"code"`
	Message       string      `json:"msg"`
	UserkeyID     string      `json:"userkeyid"`
	DeviceID      string      `json:"deviceid"`
	AuthKey       string      `json:"authkey"`
	ExpireTime    string      `json:"expiretime"`
	StatCycleTime string      `json:"statcycletime"`
	Data          interface{} `json:"data"`
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

type jsonInputWebAPIAuthPackagePack struct {
	Version       string      `json:"version"`
	Method        string      `json:"method"`
	SessionType   string      `json:"sessiontype"`
	Seperator     string      `json:"seperator"`
	MessageType   string      `json:"msgtype"`
	Platform_type string      `json:"platform_type"`
	UserKey       string      `json:"user_key"`
	McseID        string      `json:"mcse_id"`
	AuthKey       string      `json:"auth_key"`
	AuthToken     string      `json:"auth_token"`
	Package       interface{} `json:"package"`
}

type jsonOutputWebAPIAuthPackagePack struct {
	Version                     string `json:"version"`
	Method                      string `json:"method"`
	SessionType                 string `json:"sessiontype"`
	Seperator                   string `json:"seperator"`
	MessageType                 string `json:"msgtype"`
	Code                        string `json:"code"`
	Message                     string `json:"message"`
	AuthKey                     string `json:"auth_key"`
	Expiretime                  string `json:"expiretime"`
	Pkg_result_device_full_path string `json:"pkg_result_device_full_path"`
	Pkg_create_device_full_path string `json:"pkg_create_device_full_path"`
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

type jsonOutputWebAPIPerformanceMemoryRsp struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	InputValue  string `json:"input"`
	OutputValue string `json:"output"`
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

func InitLogger () {
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

	if CurrentMenu == "provisioning" {
		TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/auth_api/provisioning/v1.0/input_debugger\">Provisioning</a></li>")
		MainMenu.Provisioning = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/statistics/input_debugger/\">Statistics</a></li>")
		MainMenu.Statistics = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/package/v1.0/input_debugger/\">Package</a></li>")
		MainMenu.Package = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/association/v1.0/input_debugger/\">AuthAssociation</a></li>")
		MainMenu.AuthAssociation = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/association/v1.0/dashboard/\">AuthAssociationDashboard</a></li>")
		MainMenu.AuthAssociationDashboard = template.HTML(TempString)
	} else if CurrentMenu == "statistics" {
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/provisioning/v1.0/input_debugger\">Provisioning</a></li>")
		MainMenu.Provisioning = template.HTML(TempString)
		TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/auth_api/statistics/input_debugger/\">Statistics</a></li>")
		MainMenu.Statistics = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/package/v1.0/input_debugger/\">Package</a></li>")
		MainMenu.Package = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/association/v1.0/input_debugger/\">AuthAssociation</a></li>")
		MainMenu.AuthAssociation = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/association/v1.0/dashboard/\">AuthAssociationDashboard</a></li>")
		MainMenu.AuthAssociationDashboard = template.HTML(TempString)
	} else if CurrentMenu == "package" {
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/provisioning/v1.0/input_debugger\">Provisioning</a></li>")
		MainMenu.Provisioning = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/statistics/input_debugger/\">Statistics</a></li>")
		MainMenu.Statistics = template.HTML(TempString)
		TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/auth_api/package/v1.0/input_debugger/\">Package</a></li>")
		MainMenu.Package = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/association/v1.0/input_debugger/\">AuthAssociation</a></li>")
		MainMenu.AuthAssociation = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/association/v1.0/dashboard/\">AuthAssociationDashboard</a></li>")
		MainMenu.AuthAssociationDashboard = template.HTML(TempString)
	} else if CurrentMenu == "authassociation" {
		TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/auth_api/provisioning/v1.0/input_debugger\">Provisioning</a></li>")
		MainMenu.Provisioning = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/statistics/input_debugger/\">Statistics</a></li>")
		MainMenu.Statistics = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/package/v1.0/input_debugger/\">Package</a></li>")
		MainMenu.Package = template.HTML(TempString)
		TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/auth_api/association/v1.0/input_debugger/\">AuthAssociation</a></li>")
		MainMenu.AuthAssociation = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/association/v1.0/dashboard/\">AuthAssociationDashboard</a></li>")
		MainMenu.AuthAssociationDashboard = template.HTML(TempString)
	} else if CurrentMenu == "authassociationdashboard" {
		TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/auth_api/provisioning/v1.0/input_debugger\">Provisioning</a></li>")
		MainMenu.Provisioning = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/statistics/input_debugger/\">Statistics</a></li>")
		MainMenu.Statistics = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/package/v1.0/input_debugger/\">Package</a></li>")
		MainMenu.Package = template.HTML(TempString)
		TempString = fmt.Sprintf("<li><a href=\"/auth_api/association/v1.0/input_debugger/\">AuthAssociation</a></li>")
		MainMenu.AuthAssociation = template.HTML(TempString)
		TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/auth_api/association/v1.0/dashboard/\">AuthAssociationDashboard</a></li>")
		MainMenu.AuthAssociationDashboard = template.HTML(TempString)
	}

	return RET_INT_SUCC
}

func WebServer_Auth_API_Package_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlPackage CommonHTML
	var HtmlTemplate *template.Template
	var err error

	log.Println("WebServer_Auth_API_Package_Input", req.Method)

	/*---------------------------------------
		res := Cookie_Check(w, req)
		if res < 0 {
			WebServer_Redirect(w, req, "/login/")
			return
		}
		//SessionCookieUserData(&HtmlPackage.CookiesData, req)
		//WebServerOEMInformation(&HtmlPackage.OEMData)
	  ----------------------------------------*/
	WebServerMainMenu(&HtmlPackage.MainMenu, "package")

	HtmlTemplate, err = template.ParseFiles("./html/svc_gowas_auth_package_input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/svc_gowas_auth_package_input.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, HtmlPackage)
}

func ProvisioningUploadDBSetTransaction(Database *sql.DB, keyid int64, userid int64, deviceid int, InputData *jsonInputWebAPIAuthProvisioningPack, OutputData *jsonOutputWebAPIAuthProvisioningPack, proviReq *ProvisionProtocol) int {
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryString string
	var err error

	log.Println("init node information setting :", InputData.NodeID)

	tx, err = msdb_lib.DB_TX_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return 0
	}
	defer tx.Rollback()

	QueryString = "INSERT INTO MCSE_Info (device_id, user_id, key_id, password, status, max_connections, receive_buffer_size, send_buffer_size, " +
		"time_connect, time_client, time_server, " +
		"limit_size_log, max_size_log_file, log_file_path_dir, log_file_path_name, error_log_file_path_dir, error_log_file_path_name, " +
		"statistics_yn, statistics_cycle, statistics_ip, statistics_port, statistics_data_cycle, " +
		"bridge_yn, mcs_size, encrypt_mode, change_ip_mode, " +
		"kms_addr, kms_port, site_id) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?," +
		"?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, " +
		"?, ?, ?) "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	max_connections, _ := strconv.Atoi(proviReq.Body.Data.Maximum_ConnectionCount)
	receive_buffer_size, _ := strconv.Atoi(proviReq.Body.Data.Recv_Buf_Size)
	send_buffer_size, _ := strconv.Atoi(proviReq.Body.Data.Send_Buf_Size)

	time_connect, _ := strconv.Atoi(proviReq.Body.Data.Connection_Timeout)
	time_client, _ := strconv.Atoi(proviReq.Body.Data.Client_Reconnect_Timeout)
	time_server, _ := strconv.Atoi(proviReq.Body.Data.Server_Reconnect_Timeout)

	limit_size_log, _ := strconv.Atoi(proviReq.Body.Data.Limit_Size_Log_Storage)
	max_size_log_file, _ := strconv.Atoi(proviReq.Body.Data.Maxsize_Per_Logfile)

	statistics_cycle, _ := strconv.Atoi(proviReq.Body.Data.Statistic_Collection_Cycle)
	statistics_port, _ := strconv.Atoi(proviReq.Body.Data.Statistic_Server_Port)
	statistics_data_cycle, _ := strconv.Atoi(proviReq.Body.Data.Statistic_Send_Cycle)

	mcs_size, _ := strconv.Atoi(proviReq.Body.Data.Bridge_Buf_Size)
	encrypt := "001"
	if strings.ToLower(proviReq.Body.Data.Encrypt_Mode) == "aes_128" {
		encrypt = "002"
	} else if strings.ToLower(proviReq.Body.Data.Encrypt_Mode) == "aes_256" {
		encrypt = "003"
	} else if strings.ToLower(proviReq.Body.Data.Encrypt_Mode) == "rc4" {
		encrypt = "004"
	}

	kms_port, _ := strconv.Atoi(proviReq.Body.Data.KMS_Port)

	_, err = stmt.Exec(deviceid, userid, keyid, proviReq.Body.Data.Password, "000", max_connections, receive_buffer_size, send_buffer_size,
		time_connect, time_client, time_server,
		limit_size_log, max_size_log_file, proviReq.Body.Data.Logfile_Path, "app.log", proviReq.Body.Data.Err_Logfile_Path, "app_err.log",
		1, statistics_cycle, proviReq.Body.Data.Statistic_Server_Ip, statistics_port, statistics_data_cycle,
		0, mcs_size, encrypt, 0,
		proviReq.Body.Data.KMS_Address, kms_port, 1)

	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	for _, frontend := range proviReq.Body.Data.SiteList {

		QueryString = "INSERT INTO MCSE_Frontend (device_id, name, symbol, port, mode, site_id) " +
			"VALUES (?, ?, ?, ?, ?, ?) "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		if frontend.NodeMode == "1" {
			_, err = stmt.Exec(deviceid, "", frontend.Frontendsymbol, frontend.FrontendPort, "001", 1)
		} else if frontend.NodeMode == "2" {
			_, err = stmt.Exec(deviceid, "", frontend.Frontendsymbol, frontend.FrontendPort, "002", 1)
		} else {
			_, err = stmt.Exec(deviceid, "", frontend.Frontendsymbol, frontend.FrontendPort, "171", 1)
		}

		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()

		feid := 0
		QueryString = "SELECT @@IDENTITY "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return 0
		}

		err = stmt.QueryRow().Scan(&feid)
		if err != nil {
			stmt.Close()
			log.Println("QueryRow Fail!:", err, ", deviceid:", deviceid)
			return 0
		}

		stmt.Close()

		QueryString = "INSERT INTO MCSE_Backend (fe_id, name, site_id) " +
			"VALUES (?, ?, ?) "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		_, err = stmt.Exec(feid, frontend.Frontendsymbol, 1)
		if err != nil {
			log.Println("Exec Fail!:", err)
			stmt.Close()
			return 0
		}

		stmt.Close()

		beid := 0
		QueryString = "SELECT @@IDENTITY "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return 0
		}

		err = stmt.QueryRow().Scan(&beid)
		if err != nil {
			stmt.Close()
			log.Println("QueryRow Fail!:", err, ", deviceid:", deviceid)
			return 0
		}

		stmt.Close()

		for _, backend := range frontend.Backend {
			QueryString = "INSERT INTO MCSE_Backend_Addr (be_id, addr, port, nickname, site_id) " +
				"VALUES (?, ?, ?, ?, ?) "
			stmt, err = tx.Prepare(QueryString)
			if err != nil {
				log.Println("Prepare Fail!:", err)
				return 0
			}

			port, _ := strconv.Atoi(backend.BackendPort)

			_, err = stmt.Exec(beid, backend.BackendIP, port, backend.LAN_Interface, 1)
			if err != nil {
				log.Println("Exec Fail!:", err)
				stmt.Close()
				return 0
			}
			stmt.Close()
		}
	}

	QueryString = "INSERT INTO CWS_Sync_Seq (device_id, sync_seq_no, sync_seq_type) " +
		"VALUES (?, ?, ?) "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(deviceid, proviReq.Header.Seq, InputData.SessionType)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	QueryString = "UPDATE Node_ID " +
		"SET status = '001' " +
		"WHERE device_id = ? "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(deviceid)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	tx.Commit()
	return 1
}

func ProvisioningUploadDBUpdateTransaction(Database *sql.DB, deviceid int, InputData *jsonInputWebAPIAuthProvisioningPack, OutputData *jsonOutputWebAPIAuthProvisioningPack, proviReq *ProvisionProtocol) int {
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryString string
	var err error

	log.Println("update node information setting :", InputData.NodeID)

	tx, err = msdb_lib.DB_TX_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return 0
	}
	defer tx.Rollback()

	QueryString = "UPDATE Node_ID " +
		"SET  node_id = ?, status = '001' " +
		"WHERE device_id = ?"

	log.Println("Query:", QueryString)

	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(InputData.NodeID, deviceid)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	QueryString = "UPDATE MCSE_Info SET " +
		"password = ?, max_connections = ?, receive_buffer_size = ?, send_buffer_size = ?, " +
		"time_connect = ?, time_client = ?, time_server = ?, " +
		"limit_size_log = ?, max_size_log_file = ?, log_file_path_dir = ?, log_file_path_name = ?, error_log_file_path_dir = ?, error_log_file_path_name = ?, " +
		"statistics_yn = ?, statistics_cycle = ?, statistics_ip = ?, statistics_port = ?, statistics_data_cycle = ?, " +
		"bridge_yn = ?, mcs_size = ?, encrypt_mode = ?, change_ip_mode = ?, " +
		"kms_addr = ?, kms_port = ? " +
		"WHERE device_id = ? "
	log.Println("Query:", QueryString)

	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	max_connections, _ := strconv.Atoi(proviReq.Body.Data.Maximum_ConnectionCount)
	receive_buffer_size, _ := strconv.Atoi(proviReq.Body.Data.Recv_Buf_Size)
	send_buffer_size, _ := strconv.Atoi(proviReq.Body.Data.Send_Buf_Size)

	time_connect, _ := strconv.Atoi(proviReq.Body.Data.Connection_Timeout)
	time_client, _ := strconv.Atoi(proviReq.Body.Data.Client_Reconnect_Timeout)
	time_server, _ := strconv.Atoi(proviReq.Body.Data.Server_Reconnect_Timeout)

	limit_size_log, _ := strconv.Atoi(proviReq.Body.Data.Limit_Size_Log_Storage)
	max_size_log_file, _ := strconv.Atoi(proviReq.Body.Data.Maxsize_Per_Logfile)

	statistics_cycle, _ := strconv.Atoi(proviReq.Body.Data.Statistic_Collection_Cycle)
	statistics_port, _ := strconv.Atoi(proviReq.Body.Data.Statistic_Server_Port)
	statistics_data_cycle, _ := strconv.Atoi(proviReq.Body.Data.Statistic_Send_Cycle)

	mcs_size, _ := strconv.Atoi(proviReq.Body.Data.Bridge_Buf_Size)
	encrypt := "001"
	if strings.ToLower(proviReq.Body.Data.Encrypt_Mode) == "aes_128" {
		encrypt = "002"
	} else if strings.ToLower(proviReq.Body.Data.Encrypt_Mode) == "aes_256" {
		encrypt = "003"
	} else if strings.ToLower(proviReq.Body.Data.Encrypt_Mode) == "rc4" {
		encrypt = "004"
	}

	kms_port, _ := strconv.Atoi(proviReq.Body.Data.KMS_Port)

	_, err = stmt.Exec(proviReq.Body.Data.Password, max_connections, receive_buffer_size, send_buffer_size,
		time_connect, time_client, time_server,
		limit_size_log, max_size_log_file, proviReq.Body.Data.Logfile_Path, "app.log", proviReq.Body.Data.Err_Logfile_Path, "app_err.log",
		1, statistics_cycle, proviReq.Body.Data.Statistic_Server_Ip, statistics_port, statistics_data_cycle,
		0, mcs_size, encrypt, 0,
		proviReq.Body.Data.KMS_Address, kms_port,
		deviceid)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	QueryString = "DELETE FROM MCSE_Backend_Addr " +
		"FROM MCSE_Backend_Addr AS A " +
		"INNER JOIN MCSE_Backend AS B " +
		"ON A.be_id = B.be_id " +
		"INNER JOIN MCSE_Frontend AS C " +
		"ON C.fe_id = B.fe_id " +
		"WHERE C.device_id = ? "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(deviceid)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	QueryString = "DELETE FROM MCSE_Backend " +
		"FROM MCSE_Backend AS A " +
		"INNER JOIN MCSE_Frontend AS B " +
		"ON A.fe_id = B.fe_id " +
		"WHERE B.device_id = ? "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(deviceid)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	QueryString = "DELETE FROM MCSE_Frontend WHERE device_id = ? "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(deviceid)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	for _, frontend := range proviReq.Body.Data.SiteList {
		QueryString = "INSERT INTO MCSE_Frontend (device_id, name, symbol, port, mode, site_id) " +
			"VALUES (?, ?, ?, ?, ?, ?) "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		if frontend.NodeMode == "1" {
			_, err = stmt.Exec(deviceid, "", frontend.Frontendsymbol, frontend.FrontendPort, "001", 1)
		} else if frontend.NodeMode == "2" {
			_, err = stmt.Exec(deviceid, "", frontend.Frontendsymbol, frontend.FrontendPort, "002", 1)
		} else {
			_, err = stmt.Exec(deviceid, "", frontend.Frontendsymbol, frontend.FrontendPort, "171", 1)
		}

		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()

		feid := 0
		QueryString = "SELECT @@IDENTITY "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return 0
		}

		err = stmt.QueryRow().Scan(&feid)
		if err != nil {
			stmt.Close()
			log.Println("QueryRow Fail!:", err, ", deviceid:", deviceid)
			return 0
		}

		stmt.Close()

		QueryString = "INSERT INTO MCSE_Backend (fe_id, name, site_id) " +
			"VALUES (?, ?, ?) "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		_, err = stmt.Exec(feid, frontend.Frontendsymbol, 1)
		if err != nil {
			log.Println("Exec Fail!:", err)
			stmt.Close()
			return 0
		}

		stmt.Close()

		beid := 0
		QueryString = "SELECT @@IDENTITY "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return 0
		}

		err = stmt.QueryRow().Scan(&beid)
		if err != nil {
			stmt.Close()
			log.Println("QueryRow Fail!:", err, ", deviceid:", deviceid)
			return 0
		}

		stmt.Close()

		for _, backend := range frontend.Backend {
			QueryString = "INSERT INTO MCSE_Backend_Addr (be_id, addr, port, nickname, site_id) " +
				"VALUES (?, ?, ?, ?, ?) "
			stmt, err = tx.Prepare(QueryString)
			if err != nil {
				log.Println("Prepare Fail!:", err)
				return 0
			}

			port, _ := strconv.Atoi(backend.BackendPort)

			_, err = stmt.Exec(beid, backend.BackendIP, port, backend.LAN_Interface, 1)
			if err != nil {
				log.Println("Exec Fail!:", err)
				stmt.Close()
				return 0
			}
			stmt.Close()
		}
	}

	QueryString = "UPDATE CWS_Sync_Seq SET " +
		"sync_seq_no = ? " +
		"WHERE device_id = ?  AND sync_seq_type = ? "

	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(proviReq.Header.Seq, deviceid, InputData.SessionType)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	tx.Commit()
	return 1
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

func WebServer_Auth_API_Provisioning_Response(w http.ResponseWriter, Version string, Method string, SessionType string, MsgType string, Code string, Message string, AuthKey string, Expiretime string, UserKeyID string, DeviceID string, Data interface{}) {
	var OutputData jsonOutputWebAPIAuthProvisioningPack
	var OutputBody string

	OutputData.Version = Version         // (security enhancement: tracking prevention)
	OutputData.Method = Method           // (security enhancement: tracking prevention)
	OutputData.SessionType = SessionType // (security enhancement: tracking prevention)
	OutputData.MsgType = MsgType         // (security enhancement: tracking prevention)
	OutputData.Code = Code
	OutputData.Message = Message
	OutputData.AuthKey = AuthKey
	OutputData.ExpireTime = Expiretime
	OutputData.UserkeyID = AESEncryptEncodingValue(UserKeyID)
	OutputData.DeviceID = AESEncryptEncodingValue(DeviceID)
	OutputData.StatCycleTime = AESEncryptEncodingValue(strconv.Itoa(StatCycleTime))
	OutputData.Data = Data

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

func WebServer_Web_Auth_API_Provisioning_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var Database *sql.DB
	var ResultSetRows *sql.Rows
	var QueryString string
	var InputData jsonInputWebAPIAuthProvisioningPack
	var OutputData jsonOutputWebAPIAuthProvisioningPack
	var DecryptUserKey string
	var DecryptUserKeyID string
	var DecryptNodeID string
	var DecryptDeviceID string
	var EncryptUserKey string
	var EncryptUserKeyID string
	var EncryptNodeID string
	var EncryptDeviceID string
	var GenerateAuthKey string
	var DBAuthUserKeySeq int64
	var DBAuthUserKey string
	var DBAuthUserID int64
	var DBDeviceID int
	var DBNodeIDStatus string
	var OEMAuthExpiretimeInterval int
	var DBAuthKey string
	var DBAuthToken string
	var DBAuthExpireTime uint64
	var Response string
	var err error

	log.Println("WebServer_Web_Auth_API_Provisioning_Proc", req.Method, ", Client Address:", req.RemoteAddr)

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		log.Println("json parsing error:", err)
		WebServer_Auth_API_Provisioning_Response(w, "", "", "", "", "610", "json parameter parsing error (simplify Information)", "", "", "", "", "")
		return
	}
	// comments: checking valid http method
	if req.Method != "POST" {
		log.Println("json parsing error(Not POST):", err)
		WebServer_Auth_API_Provisioning_Response(w, "", "", "", "", "610", "json parameter parsing error (simplify Information for security enhancement)", "", "", "", "", "")
		return
	}

	//log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", nodeid encrypt:" + InputData.NodeID + ", mac total:" + InputData.MACTotal + ", authtoken:" + InputData.AuthToken + ", data:" + InputData.Data + "]")
	//log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", nodeid encrypt:" + InputData.NodeID + ", mac total:" + InputData.MACTotal + ", authtoken:" + InputData.AuthToken + ", data:" + InputData.Data + "]")
	log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", nodeid encrypt:" + InputData.NodeID + ", mac total:" + InputData.MACTotal + ", authtoken:" + InputData.AuthToken)

	// comments: checking madatory input value
	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.MessageType == "" || InputData.UserKey == "" || InputData.NodeID == "" || InputData.MACTotal == "" {
		log.Println("invalid parmeter value: null")
		WebServer_Auth_API_Provisioning_Response(w, "", "", "", "", "611", "json parameter is null (simplify Information for security enhancement)", "", "", "", "", "")
		return
	}

	// comments: checking valid input value
	if InputData.Version != "1.0" || InputData.Method != "Auth" || InputData.SessionType != "ConfigData" || InputData.MessageType != "request" {
		log.Println("invalid parmeter value: not supported value")
		WebServer_Auth_API_Provisioning_Response(w, "", "", "", "", "612", "json parameter is invalid (simplify Information for security enhancement)", "", "", "", "", "")
		return
	}

	if InputData.UserKey != "" {
		// comments: decrypt and base32 input userkey value
		EncryptUserKey = InputData.UserKey
		DecryptUserKey = AESDecryptDecodeValue(EncryptUserKey)
		if DecryptUserKey == "" {
			log.Println("invalid parmeter value: user key decrypt error")
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "620", "json parameter decript error", "", "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - UserKey Decrypt Value [%s] -> [%s]", InputData.UserKey, DecryptUserKey)
		InputData.UserKey = DecryptUserKey
	}

	// comments: decrypt and base32 input userkey value
	if InputData.UserKeyID != "" {
		EncryptUserKeyID = InputData.UserKeyID
		DecryptUserKeyID = AESDecryptDecodeValue(EncryptUserKeyID)
		if DecryptUserKey == "" {
			log.Println("invalid parmeter value: user keyid decrypt error")
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "620", "json parameter decript error", "", "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - UserKeyid Decrypt Value [%s] -> [%s]", InputData.UserKeyID, DecryptUserKeyID)
		InputData.UserKeyID = DecryptUserKeyID
	}

	if InputData.NodeID != "" {
		EncryptNodeID = InputData.NodeID
		DecryptNodeID = AESDecryptDecodeValue(EncryptNodeID)
		if DecryptNodeID == "" {
			log.Println("invalid parmeter value: node id decrypt error")
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "620", "json parameter decript error", "", "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - NodeID Decrypt Value [%s] -> [%s]", InputData.NodeID, DecryptNodeID)
		InputData.NodeID = DecryptNodeID
	}

	if InputData.DeviceID != "" {
		EncryptDeviceID = InputData.DeviceID
		DecryptDeviceID = AESDecryptDecodeValue(EncryptDeviceID)
		if DecryptNodeID == "" {
			log.Println("invalid parmeter value: deviceid decrypt error")
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "620", "json parameter decript error", "", "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - deviceid Decrypt Value [%s] -> [%s]", InputData.DeviceID, DecryptDeviceID)
		InputData.DeviceID = DecryptDeviceID
	}

	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)

	OEMAuthExpiretimeInterval = 10

	var nodeip string
	forwarded := req.Header.Get("X-FORWARDED-FOR")
	nodeips := strings.Split(forwarded, ",")
	if len(nodeips) != 0 {
		InputData.IP = nodeips[0]
		nodeip = nodeips[0]
	} else {
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			InputData.IP = ""
		} else {
			InputData.IP = ip
		}
	}

	if Database == nil {
		WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db connection error", "", "", "", "", "")
		return
	}

	if InputData.DeviceID == "0" {
		//--[Query: Checking UserKey]----------------------------------------------{
		QueryString = "SELECT A.key_id, A.user_key, A.user_id, B.device_id, B.status " +
			"FROM User_Key AS A " +
			"JOIN Node_ID AS B " +
			"ON  A.key_id = B.key_id " +
			"AND A.user_key = '%s' " +
			"AND B.node_id = '%s'"
		QueryString = fmt.Sprintf(QueryString, InputData.UserKey, InputData.NodeID)
	} else {
		//--[Query: Checking UserKey]----------------------------------------------{
		QueryString = "SELECT A.key_id, A.user_key, A.user_id, B.device_id, B.status " +
			"FROM User_Key AS A " +
			"JOIN Node_ID AS B " +
			"ON  A.key_id = B.key_id " +
			"AND A.user_key = '%s' " +
			"AND B.device_id = %s"
		QueryString = fmt.Sprintf(QueryString, InputData.UserKey, InputData.DeviceID)
	}

	log.Println("Auth UserKey Exist Query : ", QueryString)
	//-------------------------------------------------------------------------}

	ResultSetRows, _ = msdb_lib.Query_DB(Database, QueryString)
	if err != nil {
		WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
		return
	}

	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&DBAuthUserKeySeq, &DBAuthUserKey, &DBAuthUserID, &DBDeviceID, &DBNodeIDStatus)
		if err != nil {
			ResultSetRows.Close()
			log.Println("data Scan error:", err)
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
			return
		}
	}
	ResultSetRows.Close()

	log.Println("UserKeySeq:", DBAuthUserKeySeq, ", Userkey:", DBAuthUserKey, "Device_ID:", DBDeviceID, "Status:", DBNodeIDStatus)
	if DBAuthUserKeySeq == 0 {
		log.Println("not exists nodeid:", InputData.NodeID)
		err := InsertMcseLog(Database, 0, 0, InputData.NodeID, req.RemoteAddr, 1, 1001, 0)
		if err != nil {
			log.Println("InsertMcseLog error:", err)
		}
		WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "660", "Not exists nodeid", "", "", "", "", "")
		return
	}

	if InputData.AuthKey == "" && InputData.AuthToken == "" {
		AuthProvisioningSeqNo += 1
		if AuthProvisioningSeqNo >= 100000 {
			AuthProvisioningSeqNo = 1
		}

		GenerateAuthKey = WEBAuthGenerateAuthKey(strconv.Itoa(AuthProvisioningSeqNo))
		if GenerateAuthKey == "" {
			log.Println("failed to generate auth key")
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "643", "failed to generate auth key", "", "", "", "", "")
			return
		}

		Response = WebServer_Auth_API_Hashing_Provisioning(InputData.UserKeyID, InputData.DeviceID, InputData.Method, GenerateAuthKey)
		if Response != "" {

			//--[Query: Delete Existed AuthKey & AuthToken]-------------------------------------------{
			QueryString = "DELETE FROM CWS_Auth WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' and ip = '%s' and mac = '%s'"
			QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, DBDeviceID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal)
			log.Println("CWS_AuthTbl Delete Query : ", QueryString)
			//----------------------------------------------------------------------------------------}
			_, err = msdb_lib.Delete_Data(Database, QueryString)
			if err != nil {
				WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
				return
			}

			//--[Query: Insert Temp AuthKey & AuthToken]----------------------------------------------{
			QueryString = "INSERT INTO CWS_Auth (key_id, user_id, device_id, method, session_type, ip, mac, auth_key, auth_token, expiretime) " +
				"values (%d, %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', DATEADD(second, %d, GETDATE())) "
			QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, DBAuthUserID, DBDeviceID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal, GenerateAuthKey, Response, OEMAuthExpiretimeInterval)
			log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
			//----------------------------------------------------------------------------------------}
			_, err = msdb_lib.Insert_Data(Database, QueryString)
			if err != nil {
				log.Println("Insert error: ", err)
				WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
				return
			}

			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "200", "auth success", GenerateAuthKey, strconv.Itoa(OEMAuthExpiretimeInterval), "", "", "")
			return
		} else {
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "644", "failed to generate auth token", "", "", "", "", "")
			log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
			return
		}

	} else if InputData.AuthKey != "" && InputData.AuthToken != "" {
		//--[Query: Checking Auth Information]-------------------------------------{
		QueryString = "SELECT auth_key, auth_token, CASE WHEN expiretime < GETDATE() THEN 0 ELSE 1 END AS expire " +
			"FROM CWS_Auth " +
			"WHERE key_id = %d AND auth_key = '%s' AND auth_token = '%s' AND ip = '%s' AND mac = '%s' AND method = '%s' AND session_type = '%s'"
		QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.AuthKey, InputData.AuthToken, InputData.IP, InputData.MACTotal, InputData.Method, InputData.SessionType)
		//-------------------------------------------------------------------------}
		log.Println("Auth Information Checking Query : ", QueryString)

		ResultSetRows, _ = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
			return
		}

		for ResultSetRows.Next() {
			err = ResultSetRows.Scan(&DBAuthKey, &DBAuthToken, &DBAuthExpireTime)
			if err != nil {
				ResultSetRows.Close()
				log.Println("data Scan error:", err)
				WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
				return
			}
		}
		ResultSetRows.Close()

		//--[Query: Delete Existed AuthKey & AuthToken]-------------------------------------------{
		QueryString = "DELETE FROM CWS_Auth WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' and ip = '%s' and mac = '%s'"
		QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, DBDeviceID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal)
		log.Println("CWS_Auth Delete Query : ", QueryString)
		//----------------------------------------------------------------------------------------}
		_, err = msdb_lib.Delete_Data(Database, QueryString)
		if err != nil {
			log.Println("Delete error:", err)
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
			return
		}

		if DBAuthExpireTime == 0 {
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "643", "auth error", "", "", "", "", "")
			return
		}
		if InputData.DeviceID == "0" && DBNodeIDStatus == "001" {
			//Set(001) : 장비에 설정된 MCSE

			log.Println("Already in use nodeid:", InputData.NodeID)
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "661", "Already in use nodeid", "", "", "", "", "")
			return
		} else if DBNodeIDStatus == "002" {
			//New(002) : 새로 생성한 MCSE ID
		} else if DBNodeIDStatus == "003" {
			//Renew(003) : 사용되었다가 반납된 MCSE ID
		}
		//-------------------------------------------------------------------------------------------
		// Provisioning Process

		proviReq := ProvisionProtocol{}
		if err := mapstructure.Decode(InputData.Data, &proviReq); err != nil {
			log.Println("json parser error:", err)
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "610", "json parameter parsing error (simplify Information)", "", "", "", "", "")
			return
		}

		if EncryptUserKey != proviReq.Header.Userkey || EncryptNodeID != proviReq.Header.Nodeid {
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
			return
		}

		seqNo, err := SelectDBSyncSeqNo(Database, DBDeviceID)
		if err != nil {
			log.Println("err SelectDBSyncSeqNo()", err)
			// write to response error code
		}
		if proviReq.Header.Seperator == "up" {
			if InputData.DeviceID == "0" {
				pvSetupRet := ProvisioningUploadDBSetTransaction(Database, DBAuthUserKeySeq, DBAuthUserID, DBDeviceID, &InputData, &OutputData, &proviReq)
				if pvSetupRet == 0 {
					WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
					return
				}
			} else {
				if seqNo < proviReq.Header.Seq {
					qeury := "SELECT COUNT(device_id) " +
						"FROM MCSE_Info " +
						"WHERE device_id = ? "

					stmt, err := Database.Prepare(qeury)
					if err != nil {
						log.Println("parser error:", err)
						return
					}

					count := 0
					err = stmt.QueryRow(DBDeviceID).Scan(&count)
					if err != nil {
						stmt.Close()
						log.Println("QueryRow error:", err)
						return
					}
					stmt.Close()

					if count == 0 {
						log.Println("not exists device_id:", DBDeviceID, "node_id:", InputData.NodeID)
						err := InsertMcseLog(Database, DBAuthUserKeySeq, DBDeviceID, InputData.NodeID, req.RemoteAddr, 1, 1003, 0)
						if err != nil {
							log.Println("InsertMcseLog error:", err)
						}
						WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "631", "db processing error", "", "", "", "", "")
						return
					}

					pvSetupRet := ProvisioningUploadDBUpdateTransaction(Database, DBDeviceID, &InputData, &OutputData, &proviReq)
					if pvSetupRet == 0 {
						WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
						return
					}
				} else {
					WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "650", "force apply (is already update)", "", "", "", "", "")
					return
				}
			}
		} else if proviReq.Header.Seperator == "down" {
			/* */
			err = UpdateDBProvisioningTime(Database, DBDeviceID)
			if err != nil {
				log.Println("err UpdateDBProvisioningTime()", err)
				WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
				return
			}

			if nodeip == "" {
				log.Println("nodeips empty")
			} else {
				err = UpdateProvisioningNodeip(Database, DBDeviceID, nodeip)
				if err != nil {
					log.Println("err UpdateProvisioningNodeip()", err)
					WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
					return
				}
			}
			/*
				Provisioning Download Processing
			*/
			proviRes := ProvisionProtocol{}
			proviRes.Header.Version = ProvisionVersion
			proviRes.Header.Msgtype = "response"
			proviRes.Header.Method = proviReq.Header.Method
			proviRes.Header.Seperator = proviReq.Header.Seperator
			proviRes.Header.Userkey = proviReq.Header.Userkey
			proviRes.Header.Nodeid = proviReq.Header.Nodeid
			proviRes.Header.CurSeq = proviReq.Header.CurSeq
			proviRes.Header.Seq = seqNo

			if seqNo <= proviReq.Header.CurSeq {
				// No update
				proviRes.Body.Code = 200
				proviRes.Body.Message = "success"
				proviRes.Body.Data = nil

			} else {
				settingData, _, err := SelectDBConfigData(Database, DBDeviceID)
				if err != nil {
					log.Println("err SelectDBConfigData()", err)
					WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "", "", "")
					return
					// write to response error code
				}
				// already update
				proviRes.Body.Code = 650
				proviRes.Body.Message = "force_apply"
				proviRes.Body.Data = settingData
			}

			OutputData.Data = proviRes
		} else {
			//unknown seperator type
			WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "620", "json parameter decript error", "", "", "", "", "")
			return
		}

		WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "200", "auth success", "", strconv.Itoa(0), strconv.FormatInt(DBAuthUserKeySeq, 10), strconv.Itoa(DBDeviceID), OutputData.Data)
		log.Printf("web api response [userkey:%s] [code:%s, msg:%s, description:%s (expiretime sec:%d, authtoken:%s)]", InputData.UserKey, OutputData.Code, OutputData.Message, "expiretime update", OEMAuthExpiretimeInterval, InputData.AuthToken)
		return

	} else {
		WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "641", "auth error", "", "", "", "", "")
		log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
		return
	}
}

func WebServer_Auth_API_Package_Response(w http.ResponseWriter, Version string, Method string, SessionType string, Seperator string, MessageType string, Code string, Message string, AuthKey string, Expiretime string, Pkg_result_device_full_path string, Pkg_create_device_full_path string) {
	var OutputData jsonOutputWebAPIAuthPackagePack
	var OutputBody string

	OutputData.Version = Version
	OutputData.Method = Method
	OutputData.SessionType = SessionType
	OutputData.Seperator = Seperator
	OutputData.MessageType = MessageType
	OutputData.Code = Code
	OutputData.Message = Message
	OutputData.AuthKey = AuthKey
	OutputData.Expiretime = Expiretime
	OutputData.Pkg_result_device_full_path = Pkg_result_device_full_path
	OutputData.Pkg_create_device_full_path = Pkg_create_device_full_path

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

func WebServer_Auth_API_Package_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var Database *sql.DB
	var InputData jsonInputWebAPIAuthPackagePack
	var ResponseMessage string

	var EncryptUserKey string
	var DecryptUserKey string
	//var EncryptMcseID string
	//var DecryptMcseID string
	var HashingText string
	var HashingValue string
	var HA1 string
	var HA2 string
	var GenerateAuthKey string
	var GenerateAuthToken string

	//var PackageEndYear string
	//var PackageEndMonth string
	//var PackageEndDay string
	//var PackageHomePath string

	var AuthExpiretimeInterval int
	var DBUserKeySeq int
	var DBUserKey string
	var DBAuthKey string
	var DBAuthToken string
	var DBAuthExpireTime uint64
	var DBAuthNOWTime uint64

	var PackageEncryptKey string
	var PackageEncryptIV string
	var PackageLockTblReturn int
	var PackageLockTblLock *sync.Mutex

	var SVCgoWASHomePath string
	var PackageHomePath string
	var InputHydraFullPath string
	var InputGoWASFullPath string
	var OutputFilePath string
	var OutputFileName string
	var QueryString string
	var QueryTupleCount int
	var ResultSetRows *sql.Rows
	var Result bool
	var err error

	log.Println("WebServer_Auth_API_Package_Proc", req.Method, ", Client Address:", req.RemoteAddr)

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		log.Println("json parsing error:", err)
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error - (simplify Information for security enhancement)"
		WebServer_Auth_API_Package_Response(w, "", "", "", "", "", "610", ResponseMessage, "", "", "", "")
		return
	}

	// comments: checking valid http method
	if req.Method != "POST" {
		log.Println("not supported request method")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error (not support method) - (simplify Information for security enhancement)"
		WebServer_Auth_API_Package_Response(w, "", "", "", "", "", "610", ResponseMessage, "", "", "", "")
		return
	}

	log.Println(">>> Input Data - version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", seperator:" + InputData.Seperator + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", mcseid encrypt:" + InputData.McseID + ", authkey:" + InputData.AuthKey + ", authtoken:" + InputData.AuthToken)

	// comments: checking mandatory input value
	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.Seperator == "" || InputData.MessageType == "" || InputData.Platform_type == "" || InputData.UserKey == "" {
		log.Println("invalid parmeter value: mandatory param is empty")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is empty (simplify Information for security enhancement)"
		WebServer_Auth_API_Package_Response(w, "", "", "", "", "", "611", ResponseMessage, "", "", "", "")
		return
	}

	// comments: checking validation input value
	if InputData.Version != "1.0" || InputData.Method != "auth" || InputData.SessionType != "package" || (InputData.Seperator != "create" && InputData.Seperator != "get" && InputData.Seperator != "delete") || (InputData.Platform_type != "windows" && InputData.Platform_type != "linux") || InputData.MessageType != "request" {
		log.Println("invalid parmeter value: not supported value")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is invalid (simplify Information for security enhancement)"
		WebServer_Auth_API_Package_Response(w, "", "", "", "", "", "612", ResponseMessage, "", "", "", "")
		return
	}

	// comments: decrypt and base32 input userkey value
	if InputData.UserKey != "" {
		EncryptUserKey = InputData.UserKey
		DecryptUserKey = AESDecryptDecodeValue(EncryptUserKey)

		if DecryptUserKey == "" {
			log.Println("invalid parmeter value: user key decrypt error")
			ResponseMessage = "json parameter decript error"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "612", ResponseMessage, "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - UserKey Decrypt Value [%s] -> [%s]", InputData.UserKey, DecryptUserKey)
	}

	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)
	//msdb_lib.DB_AutoCommit_Enable(Database)

	if Database == nil {
		log.Println("db connection error")
		ResponseMessage = "db connection error"
		WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
		return
	}

	AuthExpiretimeInterval = 60

	//--[Query: Checking UserKey]--------------------{
	QueryString = "SELECT key_id, user_key FROM mcs.User_Key WHERE user_key = '%s' "
	QueryString = fmt.Sprintf(QueryString, DecryptUserKey)
	log.Println("Auth UserKey Exist Query : ", QueryString)
	//-----------------------------------------------}

	ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
	if err != nil {
		log.Println("db query error (not founded user_key column of User_Key)")
		ResponseMessage = "db query error(not founded user_key column of User_Key)"
		WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
		return
	}

	QueryTupleCount = 0
	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&DBUserKeySeq, &DBUserKey)
		if err != nil {
			ResultSetRows.Close()
			log.Println("data Scan error:", err)
			ResponseMessage = "db query error(not founded result set row that was key_id, user_key column of User_Key)"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
			return
		}
		QueryTupleCount++
	}
	ResultSetRows.Close()

	if QueryTupleCount == 0 {
		log.Println("db query error(key_id, user_key of User_Key not founded)")
		ResponseMessage = "db query error(key_id, user_key of User_Key not founded)"
		WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
		return
	} else if QueryTupleCount > 1 {
		log.Println("db query error(key_id, user_key of User_Key is multi-tuple)")
		ResponseMessage = "db query error(key_id, user_key of User_Key is multi-tuple)"
		WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
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
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "643", ResponseMessage, "", "", "", "")
			log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, "643", ResponseMessage)
			return
		}

		hashing_algorithm := md5.New()
		HashingText = DecryptUserKey + ":" // ( + DecryptMcseID)
		hashing_algorithm.Write([]byte(HashingText))
		HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

		hashing_algorithm = md5.New()
		HashingText = InputData.Method + ":" + "/auth_api/package/v1.0/"
		hashing_algorithm.Write([]byte(HashingText))
		HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue += "[" + HashingText + " >> HA2:" + HA2 + "]"

		hashing_algorithm = md5.New()
		HashingText = HA1 + ":" + GenerateAuthKey + ":" + HA2
		hashing_algorithm.Write([]byte(HashingText))
		GenerateAuthToken = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue += "[" + HashingText + " >> GenerateAuthToken:" + GenerateAuthToken + "]"

		log.Println("WEB API Auth Package Information -> ", HashingValue)

		if GenerateAuthToken != "" {

			//--[Query: Delete Existed AuthKey & AuthToken]--{
			QueryString = "DELETE FROM mcs.CWS_Auth WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' and seperator = '%s' "
			QueryString = fmt.Sprintf(QueryString, DBUserKeySeq, 0, InputData.Method, InputData.SessionType, InputData.Platform_type)
			log.Println("CWS_AuthTbl Delete Query : ", QueryString)
			//-----------------------------------------------}
			_, err = msdb_lib.Delete_Data(Database, QueryString)
			if err != nil {
				log.Println("db processing error (delete CWS_Auth by key_id)")
				ResponseMessage = "db processing error (delete CWS_Auth by key_id)"
				WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
				return
			}

			//--[Query: Insert Temp AuthKey & AuthToken]-----{
			QueryString = "INSERT INTO mcs.CWS_Auth (user_id, key_id, device_id, method, session_type, seperator, ip, mac, auth_key, auth_token, expiretime, reg_date) " +
				"VALUES (%d, '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', DATEADD(second, %d, GETDATE()), GETDATE()) "
			QueryString = fmt.Sprintf(QueryString, 0, DBUserKeySeq, 0, InputData.Method, InputData.SessionType, InputData.Platform_type, req.RemoteAddr, "00:00:00:00:00:00", GenerateAuthKey, GenerateAuthToken, AuthExpiretimeInterval)
			log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
			//-----------------------------------------------}
			_, err = msdb_lib.Insert_Data(Database, QueryString)
			if err != nil {
				log.Println("db processing error (insert CWS_Auth by key_id, auth_key, auth_token)")
				ResponseMessage = "db processing error (insert CWS_Auth by key_id, auth_key, auth_token)"
				WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
				return
			}

			ResponseMessage = "success generation auth key"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "200", ResponseMessage, GenerateAuthKey, strconv.Itoa(AuthExpiretimeInterval), "", "")
			log.Printf("web api response [userkey:%s] [code:%s, msg:%s, description:%s (expiretime sec:%d, authkey:%s, authtoken:%s)]", DecryptUserKey, "200", ResponseMessage, "create new authkey and authtoken", AuthExpiretimeInterval, GenerateAuthKey, GenerateAuthToken)
			return

		} else {
			log.Println("failed to create auth token:")
			ResponseMessage = "failed to generate auth token"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "644", ResponseMessage, "", "", "", "")
			return
		}
		//------------------------------------------------------------------------------//
		// Transaction - Request Msg (AuthToken + Package Information)
		//------------------------------------------------------------------------------//
	} else if InputData.AuthKey != "" && InputData.AuthToken != "" {

		//--[Query: Checking Auth Information]-----------{
		QueryString = "SELECT auth_key, auth_token, " +
			"auth_expiretime=((DATEPART(HOUR,expiretime)*3600)+(DATEPART(MINUTE,expiretime)*60)+(DATEPART(Second,expiretime))), " +
			"auth_now=((DATEPART(HOUR,GETDATE())*3600)+(DATEPART(MINUTE,GETDATE())*60)+(DATEPART(Second,GETDATE()))) " +
			"FROM mcs.CWS_Auth " +
			"WHERE key_id = %d and device_id = %d and auth_key = '%s' and auth_token = '%s' and method = '%s' and session_type = '%s' and seperator = '%s' "
		QueryString = fmt.Sprintf(QueryString, DBUserKeySeq, 0, InputData.AuthKey, InputData.AuthToken, InputData.Method, InputData.SessionType, InputData.Platform_type)
		log.Println("Auth Information Checking Query : ", QueryString)
		//-----------------------------------------------}

		ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			log.Println("db processing error (not founded tuple by key_id, auth_key, auth_token)")
			ResponseMessage = "db processing error (not founded tuple by key_id, auth_key, auth_token)"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
			return
		}

		QueryTupleCount = 0
		for ResultSetRows.Next() {
			err = ResultSetRows.Scan(&DBAuthKey, &DBAuthToken, &DBAuthExpireTime, &DBAuthNOWTime)
			if err != nil {
				ResultSetRows.Close()
				log.Println("data Scan error:", err)
				ResponseMessage = "db processing error (not founded resultset row of tuple(auth_key, auth_token, expiretime, now))"
				WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
				return
			}
			QueryTupleCount++
		}
		ResultSetRows.Close()

		if QueryTupleCount == 0 {
			log.Println("db query error(auth data of AuthTable not founded)")
			ResponseMessage = "db query error(auth data of AuthTable not founded)"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
			return
		} else if QueryTupleCount > 1 {
			log.Println("db query error(auth data of AuthTable is multi-tuple)")
			ResponseMessage = "db query error(auth data of AuthTable is multi-tuple)"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
			return
		}

		//--[Query: Delete Existed AuthKey & AuthToken]--}
		QueryString = "DELETE FROM mcs.CWS_Auth WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' and seperator = '%s' "
		QueryString = fmt.Sprintf(QueryString, DBUserKeySeq, 0, InputData.Method, InputData.SessionType, InputData.Platform_type)
		log.Println("CWS_AuthTbl Delete Query : ", QueryString)
		//-----------------------------------------------}
		_, err = msdb_lib.Delete_Data(Database, QueryString)
		if err != nil {
			log.Println("db processing error (delete CWS_Auth by key_id)")
			ResponseMessage = "db processing error (delete CWS_Auth by key_id)"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "630", ResponseMessage, "", "", "", "")
			return
		}

		if DBAuthExpireTime < DBAuthNOWTime {
			ResponseMessage = "auth_key has expired"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "643", ResponseMessage, "", "", "", "")
			log.Printf("web api response [userkey:%s] [code:%s, msg:%s] %d, %d", DecryptUserKey, "643", ResponseMessage, DBAuthExpireTime, DBAuthNOWTime)
			return
		}

		pkgData := PackageInformation{}
		err = mapstructure.Decode(InputData.Package, &pkgData)
		if err != nil {
			log.Println("json parameter parsing error - (package data)")
			ResponseMessage = "json parameter parsing error - (package data)"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "610", ResponseMessage, "", "", "", "")
			return
		}

		/*-------------------------------------------------------------------
				log.Println("user_id:" + pkgData.User_id)
				log.Println("user_key:" + pkgData.User_key)
				log.Println("package_key:" + pkgData.Platform_type)
				log.Println("mcse_max_count:" + pkgData.Mcse_max_count)
				log.Println("pkg_end_year:" + pkgData.Pkg_end_year)
				log.Println("pkg_end_monty:" + pkgData.Pkg_end_monty)
				log.Println("pkg_end_day:" + pkgData.Pkg_end_day)
				log.Println("pkg_home_path:" + pkgData.Pkg_home_path)
				log.Println("pkg_unique_sub_path:" + pkgData.Pkg_unique_sub_path)
				log.Println("pkg_filename:" + pkgData.Pkg_filename)
				log.Println("pkg_product_name:" + pkgData.Pkg_product_name)
		    --------------------------------------------------------------------*/

		if InputData.UserKey != pkgData.User_key {
			log.Println("mismatching input pkg_user_key and userkey")
			ResponseMessage = "mismatching input pkg_user_key and userkey"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "612", ResponseMessage, "", "", "", "")
			return
		}

		if strconv.Itoa(DBUserKeySeq) != pkgData.Pkg_unique_sub_path {
			log.Println("mismatching input pkg_unique_sub_path and db key_id")
			ResponseMessage = "mismatching input pkg_unique_sub_path and db key_id"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "612", ResponseMessage, "", "", "", "")
			return
		}

		if len(pkgData.User_id) == 0 || len(pkgData.User_key) == 0 || len(pkgData.Platform_type) == 0 || len(pkgData.Mcse_max_count) == 0 || len(pkgData.Pkg_home_path) == 0 || len(pkgData.Pkg_unique_sub_path) == 0 || len(pkgData.Pkg_filename) == 0 || len(pkgData.Pkg_product_name) == 0 {
			log.Println("mandatory data of package is empty")
			ResponseMessage = "mandatory data of package is empty"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "612", ResponseMessage, "", "", "", "")
			return
		}

		if pkgData.Platform_type != "windows" && pkgData.Platform_type != "linux" && pkgData.Platform_type != "all" {
			log.Println("not supported platform (windows or linux or all)")
			ResponseMessage = "not supported platform (windows or linux or al)"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "612", ResponseMessage, "", "", "", "")
			return
		}

		if pkgData.Platform_type == "all" && InputData.Seperator != "create" {
			log.Println("not supported platform & seperator (in the case of platform all, it must be seperator create)")
			ResponseMessage = "not supported platform & seperator (in the case of platform all, it must be seperator create)"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "612", ResponseMessage, "", "", "", "")
			return
		}

		SVCgoWASHomePath = GetPackageNFSHomePath()
		PackageHomePath = GetPackageHomePath()
		InputHydraFullPath = pkgData.Pkg_home_path + "\\" + pkgData.Pkg_unique_sub_path
		InputGoWASFullPath = SVCgoWASHomePath + "/" + pkgData.Pkg_unique_sub_path

		Result = disk.IsExistDirectoryPath(InputGoWASFullPath)
		if Result != true {
			Result = disk.CreateDirectoryPath(InputGoWASFullPath)
			if Result != true {
				log.Println("failed to create full path (SVC goWAS Full Directory Path:" + InputGoWASFullPath + ")")
				ResponseMessage = "failed to create full path (SVC goWAS Full Directory Path:" + InputGoWASFullPath + ")"
				WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
				return
			}
		}

		PackageEncryptKey = GetAES256EncryptKey()
		PackageEncryptIV = GetAES256EncryptIV()

		if pkgData.Platform_type == "all" {

			if InputData.Seperator == "create" {
				PackageLockTblReturn, PackageLockTblLock = PackagMapTableValueSet(DBUserKeySeq, "windows")
				if PackageLockTblReturn == 0 {
					log.Printf("PackagMapTableValueSet is fail (keyID:%d, platform:%s", DBUserKeySeq, "windows")

					log.Println("package creation lock table registration failed (key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:windows)")
					ResponseMessage = "package creation lock table registration failed (" + "key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:windows)"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "653", ResponseMessage, "", "", "", "")
					return
				} else {
					log.Printf("PackagMapTableValueSet is succ (keyID:%d, platform:%s, lock:%p)", DBUserKeySeq, "windows", PackageLockTblLock)
				}

				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Windows("Create", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, "windows")
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, "windows")
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, "windows")
					}

					log.Println("failed to package of windows/all (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of windows/all (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}

				PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, "windows")
				if PackageLockTblReturn == 0 {
					log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, "windows")
				} else {
					log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, "windows")
				}

				PackageLockTblReturn, PackageLockTblLock = PackagMapTableValueSet(DBUserKeySeq, "linux")
				if PackageLockTblReturn == 0 {
					log.Printf("PackagMapTableValueSet is fail (keyID:%d, platform:%s", DBUserKeySeq, "linux")

					log.Println("package creation lock table registration failed (key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:linux)")
					ResponseMessage = "package creation lock table registration failed (" + "key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:linux)"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "653", ResponseMessage, "", "", "", "")
					return
				} else {
					log.Printf("PackagMapTableValueSet is succ (keyID:%d, platform:%s, lock:%p)", DBUserKeySeq, "linux", PackageLockTblLock)
				}

				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Linux("Create", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, "linux")
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, "linux")
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, "linux")
					}

					log.Println("failed to package of linux/all (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of linux/all (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}

				PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, "linux")
				if PackageLockTblReturn == 0 {
					log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, "linux")
				} else {
					log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, "linux")
				}

			} else if InputData.Seperator == "delete" {

				PackageLockTblReturn, PackageLockTblLock = PackagMapTableValueSet(DBUserKeySeq, "windows")
				if PackageLockTblReturn == 0 {
					log.Printf("PackagMapTableValueSet is fail (keyID:%d, platform:%s", DBUserKeySeq, "windows")

					log.Println("package creation lock table registration failed (key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:windows)")
					ResponseMessage = "package creation lock table registration failed (" + "key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:windows)"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "653", ResponseMessage, "", "", "", "")
					return
				} else {
					log.Printf("PackagMapTableValueSet is succ (keyID:%d, platform:%s, lock:%p)", DBUserKeySeq, "windows", PackageLockTblLock)
				}

				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Windows("Delete", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, "windows")
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, "windows")
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, "windows")
					}

					log.Println("failed to package of windows (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of windows (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}

				PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, "windows")
				if PackageLockTblReturn == 0 {
					log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, "windows")
				} else {
					log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, "windows")
				}

				PackageLockTblReturn, PackageLockTblLock = PackagMapTableValueSet(DBUserKeySeq, "linux")
				if PackageLockTblReturn == 0 {
					log.Printf("PackagMapTableValueSet is fail (keyID:%d, platform:%s", DBUserKeySeq, "linux")

					log.Println("package creation lock table registration failed (key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:linux)")
					ResponseMessage = "package creation lock table registration failed (" + "key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:linux)"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "653", ResponseMessage, "", "", "", "")
					return
				} else {
					log.Printf("PackagMapTableValueSet is succ (keyID:%d, platform:%s, lock:%p)", DBUserKeySeq, "linux", PackageLockTblLock)
				}

				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Linux("Delete", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, "linux")
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, "linux")
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, "linux")
					}

					log.Println("failed to package of linux/all (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of linux/all (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}

				PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, "linux")
				if PackageLockTblReturn == 0 {
					log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, "linux")
				} else {
					log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, "linux")
				}

			} else {
				log.Println("not supported seperator")
				ResponseMessage = "not supported seperator"
				WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "612", ResponseMessage, "", "", "", "")
				return
			}

			log.Println("package of all platform create success")
			ResponseMessage = "package of all platform create success"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "200", ResponseMessage, "", "0", "", "")
			return

		} else if pkgData.Platform_type == "windows" {

			PackageLockTblReturn, PackageLockTblLock = PackagMapTableValueSet(DBUserKeySeq, pkgData.Platform_type)
			if PackageLockTblReturn == 0 {
				log.Printf("PackagMapTableValueSet is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)

				log.Println("package creation lock table registration failed (key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:" + pkgData.Platform_type + ")")
				ResponseMessage = "package creation lock table registration failed (" + "key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:" + pkgData.Platform_type + ")"
				WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "653", ResponseMessage, "", "", "", "")
				return
			} else {
				log.Printf("PackagMapTableValueSet is succ (keyID:%d, platform:%s, lock:%p)", DBUserKeySeq, pkgData.Platform_type, PackageLockTblLock)
			}

			if InputData.Seperator == "create" {
				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Windows("Create", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					}

					log.Println("failed to package of windows (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of windows (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}
			} else if InputData.Seperator == "get" {
				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Windows("Get", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					}

					log.Println("failed to package of windows (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of windows (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}
			} else if InputData.Seperator == "delete" {
				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Windows("Delete", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					}

					log.Println("failed to package of windows (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of windows (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}
			} else {
				PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
				if PackageLockTblReturn == 0 {
					log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
				} else {
					log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
				}

				log.Println("not supported seperator")
				ResponseMessage = "not supported seperator"
				WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "612", ResponseMessage, "", "", "", "")
				return
			}

			PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
			if PackageLockTblReturn == 0 {
				log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
			} else {
				log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
			}

			log.Println("Success Windows Package File Full Path : ", OutputFilePath, "(FileName : ", OutputFileName, ")")
			log.Println("package create success")
			ResponseMessage = "package create success"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "200", ResponseMessage, "", "0", (InputHydraFullPath + "\\" + OutputFileName), OutputFilePath)
			return

		} else if pkgData.Platform_type == "linux" {

			PackageLockTblReturn, PackageLockTblLock = PackagMapTableValueSet(DBUserKeySeq, pkgData.Platform_type)
			if PackageLockTblReturn == 0 {
				log.Printf("PackagMapTableValueSet is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)

				log.Println("package creation lock table registration failed (key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:" + pkgData.Platform_type + ")")
				ResponseMessage = "package creation lock table registration failed (" + "key_id:" + strconv.Itoa(DBUserKeySeq) + ", platform:" + pkgData.Platform_type + ")"
				WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "653", ResponseMessage, "", "", "", "")
				return
			} else {
				log.Printf("PackagMapTableValueSet is succ (keyID:%d, platform:%s, lock:%p)", DBUserKeySeq, pkgData.Platform_type, PackageLockTblLock)
			}

			if InputData.Seperator == "create" {
				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Linux("Create", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					}

					log.Println("failed to package of linux (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of linux (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}
			} else if InputData.Seperator == "get" {
				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Linux("Get", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					}

					log.Println("failed to package of linux (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of linux (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}
			} else if InputData.Seperator == "delete" {
				OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Linux("Delete", PackageLockTblLock,
					PackageEncryptKey, PackageEncryptIV,
					pkgData.User_id, DecryptUserKey,
					pkgData.Mcse_max_count, "0",
					pkgData.Pkg_end_year, pkgData.Pkg_end_monty, pkgData.Pkg_end_day,
					nil,
					//InputGoWASFullPath, SVCgoWASHomePath,
					InputGoWASFullPath, PackageHomePath,
					pkgData.Pkg_filename, pkgData.Pkg_product_name)

				if err != nil {
					PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
					if PackageLockTblReturn == 0 {
						log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					} else {
						log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
					}

					log.Println("failed to package of linux (" + InputData.Seperator + ")")
					ResponseMessage = "failed to package of linux (" + InputData.Seperator + ")"
					WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "650", ResponseMessage, "", "", "", "")
					return
				}
			} else {
				PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
				if PackageLockTblReturn == 0 {
					log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
				} else {
					log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
				}

				log.Println("not supported seperator")
				ResponseMessage = "not supported seperator"
				WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "612", ResponseMessage, "", "", "", "")
				return
			}

			PackageLockTblReturn = PackageMapTableValueDelete(DBUserKeySeq, pkgData.Platform_type)
			if PackageLockTblReturn == 0 {
				log.Printf("PackageMapTableValueDelete is fail (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
			} else {
				log.Printf("PackageMapTableValueDelete is succ (keyID:%d, platform:%s", DBUserKeySeq, pkgData.Platform_type)
			}

			log.Println("Success Linux Package File Full Path : ", OutputFilePath, "(FileName : ", OutputFileName, ")")
			log.Println("package create success")
			ResponseMessage = "package create success"
			WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "200", ResponseMessage, "", "0", (InputHydraFullPath + "\\" + OutputFileName), OutputFilePath)
			return
		}

		//------------------------------------------------------------------------------//
		// Transaction - Request Msg (Exception Case)
		//------------------------------------------------------------------------------//
	} else {
		log.Println("not supported auth information case")
		ResponseMessage = "not supported auth information case"
		WebServer_Auth_API_Package_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", "611", ResponseMessage, "", "", "", "")
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

func WebServer_Web_Auth_API_Provisioning_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlNodeKeyPackage NodeKeyPackage
	var HtmlTemplate *template.Template
	var err error

	log.Println("Web Server - WebServer_Web_Auth_API_Provisioning_Input", req.Method)

	res := Cookie_Check(w, req)
	if res < 0 {
		WebServer_Redirect(w, req, "/login/")
		return
	}

	SessionCookieUserData(&HtmlNodeKeyPackage.CookiesData, req)
	WebServerMainMenu(&HtmlNodeKeyPackage.MainMenu, "nodekey")
	//WebServerOEMInformation(&HtmlNodeKeyPackage.OEMData)

	HtmlTemplate, err = template.ParseFiles("./html/api_auth_provisioning_input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/api_auth_provisioning_input.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, HtmlNodeKeyPackage)
}

func WebServer_Monitoring_Node_AuthDisplay(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var Database *sql.DB
	var HtmlMonitoringNodeAuth MonitoringNodeAuth
	var AuthItem MonitoringNodeAuthItem
	var HtmlTemplate *template.Template
	var ResultSetRows *sql.Rows
	var QueryString string
	var RowSeqNum int
	var ResultSetRowCount int
	var URLGetParam string
	var PageNumString string
	var PageSortString string
	var MaxCountPage int = 10
	var MaxRowCountPerPage int = 40
	var err error

	log.Println("KMS Web Server - WebServer_Monitoring_Node_AuthDisplay", req.Method)

	res := Cookie_Check(w, req)
	if res < 0 {
		WebServer_Redirect(w, req, "/login/")
		return
	}

	SessionCookieUserData(&HtmlMonitoringNodeAuth.CookiesData, req)
	WebServerMainMenu(&HtmlMonitoringNodeAuth.MainMenu, "serverauth")
	//WebServerOEMInformation(&HtmlMonitoringNodeAuth.OEMData)

	Database = MariaDB_Open()
	defer MariaDB_Close(Database)

	ParamPageNum, ok := req.URL.Query()["page_num"]
	if !ok || len(ParamPageNum) < 1 {
		//--------------------------------------------------------------------------//
		//WebServer_Redirect(w, req, "/nodekey/management/?page_num=1&page_sort=0")
		//return
		//--------------------------------------------------------------------------//
		PageNumString = "1"
	} else {
		PageNumString = fmt.Sprintf("%s", ParamPageNum)
		PageNumString = strings.Replace(PageNumString, "[", "", -1)
		PageNumString = strings.Replace(PageNumString, "]", "", -1)
	}

	ParamPageSort, ok := req.URL.Query()["page_sort"]
	if !ok || len(ParamPageSort) < 1 {
		//--------------------------------------------------------------------------//
		//WebServer_Redirect(w, req, "/nodekey/management/?page_num=1&page_sort=0")
		//return
		//--------------------------------------------------------------------------//
		PageSortString = fmt.Sprintf("%s", "default")
	} else {
		PageSortString = fmt.Sprintf("%s", PageSortString)
		PageSortString = strings.Replace(PageSortString, "[", "", -1)
		PageSortString = strings.Replace(PageSortString, "]", "", -1)
	}

	if req.Method == "GET" {
		HtmlMonitoringNodeAuth.SearchType = HTTPReq_ReturnParamValue(req, "GET", "search_type")
	} else {
		HtmlMonitoringNodeAuth.SearchType = HTTPReq_ReturnParamValue(req, "POST", "search_type")
	}

	if HtmlMonitoringNodeAuth.SearchType != "nogroup" && HtmlMonitoringNodeAuth.SearchType != "group" {
		HtmlMonitoringNodeAuth.SearchType = "group"
	}

	if HtmlMonitoringNodeAuth.CookiesData.CookieUserProperty == "admin" {

	} else if HtmlMonitoringNodeAuth.CookiesData.CookieUserProperty == "normal" {

	} else {
		WebServer_Redirect(w, req, "/service_invalid_access/")
		return
	}

	if HtmlMonitoringNodeAuth.SearchType == "group" {
		QueryString = "SELECT COUNT(a.max_auth_date) " +
			"FROM (SELECT MAX(auth_date) AS max_auth_date " +
			"FROM auth_access_node_list " +
			"GROUP BY NODE_ID) as a "
		URLGetParam += fmt.Sprintf("&search_type=%s", HtmlMonitoringNodeAuth.SearchType)
	} else {
		QueryString = "SELECT count(node_id) FROM auth_access_node_list "
		URLGetParam += fmt.Sprintf("&search_type=%s", HtmlMonitoringNodeAuth.SearchType)
	}

	HtmlMonitoringNodeAuth.SQLQuery = fmt.Sprintf(QueryString)
	log.Println("Auth Access NodeID List Count Query : ", HtmlMonitoringNodeAuth.SQLQuery)

	ResultSetRows, _ = msdb_lib.Query_DB(Database, HtmlMonitoringNodeAuth.SQLQuery)
	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&ResultSetRowCount)
		if err != nil {
			ResultSetRows.Close()
			log.Println(" data Scan error:", err)
			WebServer_Redirect(w, req, "/service_stop/")
			return
		}
	}
	ResultSetRows.Close()

	HtmlDataPage(&(HtmlMonitoringNodeAuth.TempletePage), "AuthPageNum", PageNumString, "AuthNodeIDSort", PageSortString, 0, MaxCountPage, MaxRowCountPerPage, ResultSetRowCount, "/monitoring/node_auth/", URLGetParam, "/service_stop/", "[exception]", "redirect")

	RowSeqNum = HtmlMonitoringNodeAuth.TempletePage.RowOffset
	if HtmlMonitoringNodeAuth.SearchType == "group" {
		QueryString = "SELECT node_id, node_ip, DATE_FORMAT(auth_date, '%%Y-%%m-%%d %%H:%%i:%%S') as max_auth_date, auth_token, auth_expire_time " +
			"FROM auth_access_node_list " +
			"WHERE seq IN (SELECT MAX(seq) " +
			"              FROM auth_access_node_list " +
			"              GROUP BY node_id) " +
			"ORDER BY max_auth_date DESC " +
			"LIMIT %d OFFSET %d "
	} else {
		QueryString = "SELECT node_id, node_ip, DATE_FORMAT(auth_date, '%%Y-%%m-%%d %%H:%%i:%%S') as max_auth_date, auth_token, auth_expire_time " +
			"FROM auth_access_node_list " +
			"ORDER BY max_auth_date DESC " +
			"LIMIT %d OFFSET %d "
	}

	HtmlMonitoringNodeAuth.SQLQuery = fmt.Sprintf(QueryString, HtmlMonitoringNodeAuth.TempletePage.MaxRowCountPage, HtmlMonitoringNodeAuth.TempletePage.RowOffset)
	log.Println("Auth Access NodeID List Query : ", HtmlMonitoringNodeAuth.SQLQuery)

	ResultSetRows, _ = msdb_lib.Query_DB(Database, HtmlMonitoringNodeAuth.SQLQuery)
	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&AuthItem.NodeID,
			&AuthItem.NodeIP,
			&AuthItem.AuthenticationTime,
			&AuthItem.AuthToken,
			&AuthItem.AuthTokenExpiretime)
		if err != nil {
			ResultSetRows.Close()
			log.Println(" data Scan error:", err)
			WebServer_Redirect(w, req, "/service_stop/")
			return
		}

		RowSeqNum++
		AuthItem.Num = RowSeqNum
		HtmlMonitoringNodeAuth.MonitoringItem = append(HtmlMonitoringNodeAuth.MonitoringItem, AuthItem)
	}
	ResultSetRows.Close()

	HtmlTemplate, err = template.ParseFiles("./html/kms_monitoring_auth_dashboard.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/kms_monitoring_auth_dashboard.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, HtmlMonitoringNodeAuth)
}

func WebServer_Monitoring_Node_AuthDetailDisplay(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var Database *sql.DB
	var HtmlMonitoringNodeAuthDetail MonitoringNodeAuthDetail
	var AuthDetailItem MonitoringNodeAuthDetailItem
	var HtmlTemplate *template.Template
	var ResultSetRows *sql.Rows
	var QueryString string
	var RowSeqNum int
	var ResultSetRowCount int
	var URLGetParam string
	var PageNumString string
	var PageSortString string
	var MaxCountPage int = 10
	var MaxRowCountPerPage int = 40
	var err error

	log.Println("KMS Web Server - WebServer_Monitoring_Node_AuthDisplay", req.Method)

	res := Cookie_Check(w, req)
	if res < 0 {
		WebServer_Redirect(w, req, "/login/")
		return
	}

	SessionCookieUserData(&HtmlMonitoringNodeAuthDetail.CookiesData, req)
	WebServerMainMenu(&HtmlMonitoringNodeAuthDetail.MainMenu, "serverauth")
	//WebServerOEMInformation(&HtmlMonitoringNodeAuthDetail.OEMData)

	Database = MariaDB_Open()
	defer MariaDB_Close(Database)

	ParamPageNum, ok := req.URL.Query()["page_num"]
	if !ok || len(ParamPageNum) < 1 {
		//--------------------------------------------------------------------------//
		//WebServer_Redirect(w, req, "/nodekey/management/?page_num=1&page_sort=0")
		//return
		//--------------------------------------------------------------------------//
		PageNumString = "1"
	} else {
		PageNumString = fmt.Sprintf("%s", ParamPageNum)
		PageNumString = strings.Replace(PageNumString, "[", "", -1)
		PageNumString = strings.Replace(PageNumString, "]", "", -1)
	}

	ParamPageSort, ok := req.URL.Query()["page_sort"]
	if !ok || len(ParamPageSort) < 1 {
		//--------------------------------------------------------------------------//
		//WebServer_Redirect(w, req, "/nodekey/management/?page_num=1&page_sort=0")
		//return
		//--------------------------------------------------------------------------//
		PageSortString = fmt.Sprintf("%s", "default")
	} else {
		PageSortString = fmt.Sprintf("%s", PageSortString)
		PageSortString = strings.Replace(PageSortString, "[", "", -1)
		PageSortString = strings.Replace(PageSortString, "]", "", -1)
	}

	if req.Method == "GET" {
		HtmlMonitoringNodeAuthDetail.SearchNodeID = HTTPReq_ReturnParamValue(req, "GET", "node_id")
	} else if req.Method == "POST" {
		HtmlMonitoringNodeAuthDetail.SearchNodeID = HTTPReq_ReturnParamValue(req, "POST", "node_id")
	}

	if HtmlMonitoringNodeAuthDetail.SearchNodeID == "" {
		WebServer_Redirect(w, req, "/service_invalid_access/")
		return
	}

	if HtmlMonitoringNodeAuthDetail.CookiesData.CookieUserProperty == "admin" {

	} else if HtmlMonitoringNodeAuthDetail.CookiesData.CookieUserProperty == "normal" {

	} else {
		WebServer_Redirect(w, req, "/service_invalid_access/")
		return
	}

	QueryString = "SELECT count(node_id) FROM auth_access_node_list WHERE node_id = '%s' "
	URLGetParam += fmt.Sprintf("&node_id=%s", HtmlMonitoringNodeAuthDetail.SearchNodeID)

	HtmlMonitoringNodeAuthDetail.SQLQuery = fmt.Sprintf(QueryString, HtmlMonitoringNodeAuthDetail.SearchNodeID)
	log.Println("Auth Access Detail NodeID List Count Query : ", HtmlMonitoringNodeAuthDetail.SQLQuery)

	ResultSetRows, _ = msdb_lib.Query_DB(Database, HtmlMonitoringNodeAuthDetail.SQLQuery)
	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&ResultSetRowCount)
		if err != nil {
			ResultSetRows.Close()
			log.Println(" data Scan error:", err)
			WebServer_Redirect(w, req, "/service_stop/")
			return
		}
	}
	ResultSetRows.Close()

	HtmlDataPage(&(HtmlMonitoringNodeAuthDetail.TempletePage), "AuthPageNum", PageNumString, "AuthNodeIDSort", PageSortString, 0, MaxCountPage, MaxRowCountPerPage, ResultSetRowCount, "/monitoring/node_auth_detail/", URLGetParam, "/service_stop/", "[exception]", "redirect")

	RowSeqNum = HtmlMonitoringNodeAuthDetail.TempletePage.RowOffset

	QueryString = "SELECT node_id, node_ip, DATE_FORMAT(auth_date, '%%Y-%%m-%%d %%H:%%i:%%S'), auth_response_code, auth_response_message, auth_token, auth_expire_time " +
		"FROM auth_access_node_list " +
		"WHERE node_id = '%s' " +
		"ORDER BY auth_date DESC " +
		"LIMIT %d OFFSET %d "

	HtmlMonitoringNodeAuthDetail.SQLQuery = fmt.Sprintf(QueryString, HtmlMonitoringNodeAuthDetail.SearchNodeID, HtmlMonitoringNodeAuthDetail.TempletePage.MaxRowCountPage, HtmlMonitoringNodeAuthDetail.TempletePage.RowOffset)
	log.Println("Auth Access Detail NodeID List Query : ", HtmlMonitoringNodeAuthDetail.SQLQuery)

	ResultSetRows, _ = msdb_lib.Query_DB(Database, HtmlMonitoringNodeAuthDetail.SQLQuery)
	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&AuthDetailItem.NodeID,
			&AuthDetailItem.NodeIP,
			&AuthDetailItem.AuthenticationTime,
			&AuthDetailItem.AuthRspCode,
			&AuthDetailItem.AuthRspMessage,
			&AuthDetailItem.AuthToken,
			&AuthDetailItem.AuthTokenExpiretime)
		if err != nil {
			ResultSetRows.Close()
			log.Println(" data Scan error:", err)
			WebServer_Redirect(w, req, "/service_stop/")
			return
		}

		RowSeqNum++
		AuthDetailItem.Num = RowSeqNum
		HtmlMonitoringNodeAuthDetail.MonitoringItem = append(HtmlMonitoringNodeAuthDetail.MonitoringItem, AuthDetailItem)
	}
	ResultSetRows.Close()

	HtmlTemplate, err = template.ParseFiles("./html/kms_monitoring_auth_detail_dashboard.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/kms_monitoring_auth_detail_dashboard.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, HtmlMonitoringNodeAuthDetail)
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

func WebServer_Auth_API_Association_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlAssociation CommonHTML
	var HtmlTemplate *template.Template
	var err error

	log.Println("WebServer_Auth_API_Association_Input", req.Method)

	/*---------------------------------------
		res := Cookie_Check(w, req)
		if res < 0 {
			WebServer_Redirect(w, req, "/login/")
			return
		}
		//SessionCookieUserData(&HtmlAssociation.CookiesData, req)
		//WebServerOEMInformation(&HtmlAssociation.OEMData)
	  ----------------------------------------*/
	WebServerMainMenu(&HtmlAssociation.MainMenu, "authassociation")

	HtmlTemplate, err = template.ParseFiles("./html/svc_gowas_auth_association_input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/svc_gowas_auth_association_input.html")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, HtmlAssociation)
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

func WebServer_Auth_API_Encode_Value(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var InputData jsonInputWebAPIEncodeValue
	var OutputData jsonOutputWebAPIEncodeValue
	var OutputBody string
	var EncryptValue string
	var DecryptValue string
	var err error

	log.Println("WebServer_Auth_API_Encode_Value", req.Method)

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

func WebServer_Auth_API_Package_AuthToken_Value(w http.ResponseWriter, req *http.Request) {
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

	log.Println("WebServer_Auth_API_Package_AuthToken_Value", req.Method)

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

func WebServer_Auth_API_Association_AuthToken_Value(w http.ResponseWriter, req *http.Request) {
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
	log.Println("WebServer_Auth_API_Association_AuthToken_Value", req.Method)

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
	HashingText = InputData.UserKeyID + ":" + InputData.DeviceID
	hashing_algorithm.Write([]byte(HashingText))
	HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
	HashingValue = "HA1 : [" + HashingText + "] >> [" + HA1 + "], "

	hashing_algorithm = md5.New()
	HashingText = InputData.Method + ":" + "/auth_api/association/v1.0/"
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

func WebServer_Auth_API_Association_Response(w http.ResponseWriter, Version string, Method string, SessionType string, Seperator string, MessageType string, MessageSeq string, Code string, Message string, AuthKey string, Expiretime string, Event string) {
	var OutputData jsonOutputWebAPIAuthAssociation
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
	OutputData.Event = Event

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

func WebServer_Auth_API_Association_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var Database *sql.DB
	var InputData jsonInputWebAPIAuthAssociation
	var ResponseMessage string

	var EncryptUserKeyID string
	var DecryptUserKeyID string
	var EncryptUserKey string
	var DecryptUserKey string
	var EncryptDeviceID string
	var DecryptDeviceID string
	var EncryptNodeID string
	var DecryptNodeID string
	var EncryptViaDeviceID string
	var DecryptViaDeviceID string
	var EncryptViaNodeID string
	var DecryptViaNodeID string

	var UserKeyID int
	var DeviceID int
	var ViaDeviceID int

	var ViaAccessIP string
	var ViaAccessMAC string
	var ViaAccessAuthToken string
	var ViaAccessAuthExpireTimeBoolean uint32

	var AuthExpiretimeInterval int
	var AuthAccessIP string

	var DBUserKeyID int
	var DBUserKey string
	var DBDeviceID int
	var DBNodeID string
	var DBSVCStartDayBoolean uint32
	var DBSVCEndDayBoolean uint32
	var DBAuthKey string
	var DBAuthToken string
	var DBAuthExpireTimeBoolean uint32

	var HashingText string
	var HashingValue string
	var HA1 string
	var HA2 string
	var GenerateAuthKey string
	var GenerateAuthToken string

	var TrafficLimitInboundGiGaBytes uint64
	var TrafficLimitInboundBytes uint64
	var TrafficSumInboundBytes uint64

	var QueryString string
	var QueryTupleCount int
	var ResultSetRows *sql.Rows
	var ErrorFlag int
	var err error

	access_ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		AuthAccessIP = "0.0.0.0"
	} else {
		AuthAccessIP = access_ip
	}

	log.Println("Auth Access Address IP:", AuthAccessIP)
	log.Println("WebServer_Auth_API_Association_Proc", req.Method, ", Client Address:", req.RemoteAddr)

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		log.Println("json parsing error:", err)
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error - (simplify Information for security enhancement)"
		WebServer_Auth_API_Association_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "")
		return
	}

	// comments: checking valid http method
	if req.Method != "POST" {
		log.Println("not supported request method")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error - (simplify Information for security enhancement)"
		WebServer_Auth_API_Association_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "")
		return
	}

	log.Println("Input Data : [method:" + InputData.Method + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", nodeid encrypt:" + InputData.NodeID + ", authtoken:" + InputData.AuthToken + "]")

	// comments: checking mandatory input value
	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.Seperator == "" || InputData.MessageType == "" || InputData.MessageSeq == "" || InputData.UserKeyID == "" || InputData.UserKey == "" || InputData.DeviceID == "" || InputData.NodeID == "" {
		log.Println("invalid parmeter value: mandatory param is empty")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is empty (simplify Information for security enhancement)"
		WebServer_Auth_API_Association_Response(w, "", "", "", "", "", "", "611", ResponseMessage, "", "", "")
		return
	}

	// comments: checking validation input value
	if InputData.Version != "1.0" || InputData.Method != "auth" || InputData.SessionType != "register" || InputData.Seperator != "create" || InputData.MessageType != "request" {
		log.Println("invalid parmeter value: not supported value")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is invalid (simplify Information for security enhancement)"
		WebServer_Auth_API_Association_Response(w, "", "", "", "", "", "", "611", ResponseMessage, "", "", "")
		return
	}

	// comments: decrypt and base32 input userkeyid value
	EncryptUserKeyID = InputData.UserKeyID
	DecryptUserKeyID = AESDecryptDecodeValue(EncryptUserKeyID)
	if DecryptUserKeyID == "" {
		log.Println("invalid parmeter value: userkeyid decrypt error")
		ResponseMessage = "json parameter userkeyid decript error"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "")
		return
	}
	//log.Printf("WEB API Auth - UserKeyID Decrypt Value [%s] -> [%s]", InputData.UserKey, DecryptUserKey)

	UserKeyID, err = strconv.Atoi(DecryptUserKeyID)
	if err != nil {
		log.Println("failed to Atoi DecryptUserKeyID")
		ResponseMessage = "failed to Atoi DecryptUserKeyID"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "")
		return
	}

	// comments: decrypt and base32 input userkey value
	EncryptUserKey = InputData.UserKey
	DecryptUserKey = AESDecryptDecodeValue(EncryptUserKey)
	if DecryptUserKey == "" {
		log.Println("invalid parmeter value: userkey decrypt error")
		ResponseMessage = "json parameter userkey decript error"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "")
		return
	}
	//log.Printf("WEB API Auth - UserKey Decrypt Value [%s] -> [%s]", InputData.UserKey, DecryptUserKey)

	// comments: decrypt and base32 input deviceid value
	EncryptDeviceID = InputData.DeviceID
	DecryptDeviceID = AESDecryptDecodeValue(EncryptDeviceID)
	if DecryptDeviceID == "" {
		log.Println("invalid parmeter value: deviceid decrypt error")
		ResponseMessage = "json parameter deviceid decript error"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "")
		return
	}
	//log.Printf("WEB API Auth - NodeID Decrypt Value [%s] -> [%s]", InputData.NodeID, DecryptNodeID)

	DeviceID, err = strconv.Atoi(DecryptDeviceID)
	if err != nil {
		log.Println("failed to Atoi DecryptDeviceID")
		ResponseMessage = "failed to Atoi DecryptDeviceID"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "")
		return
	}

	// comments: decrypt and base32 input nodeid value
	EncryptNodeID = InputData.NodeID
	DecryptNodeID = AESDecryptDecodeValue(EncryptNodeID)
	if DecryptNodeID == "" {
		log.Println("invalid parmeter value: nodeid decrypt error")
		ResponseMessage = "json parameter nodeid decript error"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "")
		return
	}
	//log.Printf("WEB API Auth - NodeID Decrypt Value [%s] -> [%s]", InputData.NodeID, DecryptNodeID)

	if InputData.ViaDeviceID != "" && InputData.ViaNodeID != "" {
		// comments: decrypt and base32 input via_deviceid value
		EncryptViaDeviceID = InputData.ViaDeviceID
		DecryptViaDeviceID = AESDecryptDecodeValue(EncryptViaDeviceID)
		if DecryptViaDeviceID == "" {
			log.Println("invalid parmeter value: via_deviceid decrypt error")
			ResponseMessage = "json parameter via_deviceid decript error"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "")
			return
		}
		//log.Printf("WEB API Auth - NodeID Decrypt Value [%s] -> [%s]", InputData.NodeID, DecryptNodeID)

		ViaDeviceID, err = strconv.Atoi(DecryptViaDeviceID)
		if err != nil {
			log.Println("failed to Atoi DecryptViaDeviceID")
			ResponseMessage = "failed to Atoi DecryptViaDeviceID"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "")
			return
		}

		// comments: decrypt and base32 input via_nodeid value
		EncryptViaNodeID = InputData.ViaNodeID
		DecryptViaNodeID = AESDecryptDecodeValue(EncryptViaNodeID)
		if DecryptViaNodeID == "" {
			log.Println("invalid parmeter value: via_nodeid decrypt error")
			ResponseMessage = "json parameter via_nodeid decript error"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "620", ResponseMessage, "", "", "")
			return
		}
		//log.Printf("WEB API Auth - NodeID Decrypt Value [%s] -> [%s]", InputData.NodeID, DecryptNodeID)
	}

	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)
	//msdb_lib.DB_AutoCommit_Enable(Database)

	if Database == nil {
		log.Println("db connection error")
		ResponseMessage = "db connection error"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
		return
	}

	AuthExpiretimeInterval = 60

	DBUserKeyID = 0
	DBUserKey = ""
	DBDeviceID = 0
	DBNodeID = ""
	//-----------------------------------------------{
	QueryString = "SELECT userkey.key_id, userkey.user_key, nodeid.device_id, nodeid.node_id, " +
		"CASE WHEN userkey.start_date <= GETDATE() THEN 0 ELSE 1 END AS start_date_boolean, CASE WHEN userkey.end_date > GETDATE() THEN 0 ELSE 1 END AS end_date_boolean " +
		"FROM mcs.User_Key userkey, " +
		"mcs.Node_ID nodeid " +
		"WHERE userkey.key_id = %d and nodeid.device_id = %d "
	QueryString = fmt.Sprintf(QueryString, UserKeyID, DeviceID)
	log.Println("Auth UserKey and NodeID Exist Query : ", QueryString)
	//-----------------------------------------------}

	ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
	if err != nil {
		log.Println("db query error (not founded user_key, node_id column of User_Key join Node_ID) (errmsg:", err, ")")
		ResponseMessage = "db query error (not founded user_key, node_id column of User_Key join Node_ID)"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
		return
	}

	QueryTupleCount = 0
	for ResultSetRows.Next() {
		err := ResultSetRows.Scan(&DBUserKeyID, &DBUserKey, &DBDeviceID, &DBNodeID, &DBSVCStartDayBoolean, &DBSVCEndDayBoolean)
		if err != nil {
			ResultSetRows.Close()
			log.Println("db query error (not founded user_key, node_id column of User_Key join Node_ID) (errmsg:", err, ")")
			ResponseMessage = "db query error(not founded user_key, node_id column of User_Key join Node_ID)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		}
		QueryTupleCount++
	}
	ResultSetRows.Close()

	if QueryTupleCount == 0 {
		log.Println("db query error(user_key, node_id of User_Key join Node_ID not founded)")
		ResponseMessage = "db query error(user_key, node_id of User_Key join Node_ID not founded)"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
		return
	} else if QueryTupleCount > 1 {
		log.Println("db query error(user_key, node_id of User_Key join Node_ID is multi-tuple)")
		ResponseMessage = "db query error(user_key, node_id of User_Key join Node_ID is multi-tuple)"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
		return
	}

	if DBSVCStartDayBoolean == 1 {
		ResponseMessage = "service start waiting period"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "651", ResponseMessage, "", "", "")
		log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", UserKeyID, DeviceID, "651", ResponseMessage)
		return
	}

	if DBSVCEndDayBoolean == 1 {
		ResponseMessage = "end of service period"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "651", ResponseMessage, "", "", "")
		log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", UserKeyID, DeviceID, "652", ResponseMessage)
		return
	}

	if InputData.ViaDeviceID != "" && InputData.ViaNodeID != "" {
		//-----------------------------------------------{
		QueryString = "SELECT ip, mac, auth_token, CASE WHEN expiretime > GETDATE() THEN 0 ELSE 1 END AS via_expiretime_boolean " +
			"FROM mcs.CWS_Auth " +
			"WHERE device_id = %d and key_id = %d and method = '%s' and session_type = '%s' "
		QueryString = fmt.Sprintf(QueryString, ViaDeviceID, DBUserKeyID, InputData.Method, InputData.SessionType)
		log.Println("Auth ViaDeviceID Exist Query : ", QueryString)
		//-----------------------------------------------}

		ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			log.Println("db query error (not founded ip, mac, auth_token column of CWS_Auth by via_deviceid) (errmsg:", err, ")")
			ResponseMessage = "db query error (not founded ip, mac, auth_token column of CWS_Auth by via_deviceid)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		}

		QueryTupleCount = 0
		for ResultSetRows.Next() {
			err := ResultSetRows.Scan(&ViaAccessIP, &ViaAccessMAC, &ViaAccessAuthToken, &ViaAccessAuthExpireTimeBoolean)
			if err != nil {
				ResultSetRows.Close()
				log.Println("ip, mac, auth_token column of CWS_Auth by via_deviceid (errmsg:", err, ")")
				ResponseMessage = "db query error(not founded ip, mac, auth_token column of CWS_Auth by via_deviceid)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
				return
			}
			QueryTupleCount++
		}
		ResultSetRows.Close()

		if QueryTupleCount == 0 {
			//-----------------------------------------------{
			QueryString = "DELETE FROM mcs.CWS_Auth " +
				"WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' "
			QueryString = fmt.Sprintf(QueryString, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType)
			log.Println("WEB API Auth Expiretime Delete Query -> [", QueryString, "]")
			//-----------------------------------------------}
			_, err = msdb_lib.Delete_Data(Database, QueryString)
			if err != nil {
				log.Println("db query error (failed to expiretime delete tuple of mcs.CWS_Auth) (errmsg:", err, ")")
				ResponseMessage = "db query error (failed to expiretime delete tuple of mcs.CWS_Auth)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
				return
			}

			log.Println("db query error(ip, mac, auth_token column of CWS_Auth by via_deviceid not founded)")
			ResponseMessage = "db query error(ip, mac, auth_token column of CWS_Auth by via_deviceid not founded)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		} else if QueryTupleCount > 1 {
			log.Println("db query error(ip, mac, auth_token column of CWS_Auth by via_deviceid is multi-tuple)")
			ResponseMessage = "db query error(ip, mac, auth_token column of CWS_Auth by via_deviceid is multi-tuple)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		}

		if ViaAccessAuthExpireTimeBoolean == 1 {
			//-----------------------------------------------{
			QueryString = "DELETE FROM mcs.CWS_Auth " +
				"WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' "
			QueryString = fmt.Sprintf(QueryString, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType)
			log.Println("WEB API Auth Expiretime Delete Query -> [", QueryString, "]")
			//-----------------------------------------------}
			_, err = msdb_lib.Delete_Data(Database, QueryString)
			if err != nil {
				log.Println("db query error (failed to expiretime delete tuple of mcs.CWS_Auth) (errmsg:", err, ")")
				ResponseMessage = "db query error (failed to expiretime delete tuple of mcs.CWS_Auth)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
				return
			}

			ResponseMessage = "auth error (via authtoken has expired)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "")
			log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "643", ResponseMessage)
			return
		}
	}

	DBAuthKey = ""
	DBAuthToken = ""
	DBAuthExpireTimeBoolean = 0
	//-----------------------------------------------{
	QueryString = "SELECT auth_key, auth_token, CASE WHEN expiretime > GETDATE() THEN 0 ELSE 1 END AS expiretime_boolean " +
		"FROM mcs.CWS_Auth " +
		"WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' "
	QueryString = fmt.Sprintf(QueryString, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType)
	log.Println("WEB API Auth Query -> [", QueryString, "]")
	//-----------------------------------------------}

	ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
	if err != nil {
		log.Println("db query error (not founded auth_key, auth_token, expiretime_boolean, of mcs.CWS_Auth) (errmsg:", err, ")")
		ResponseMessage = "db query error (not founded auth_key, auth_token, expiretime_boolean, of mcs.CWS_Auth)"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
		return
	}

	QueryTupleCount = 0
	for ResultSetRows.Next() {
		err := ResultSetRows.Scan(&DBAuthKey, &DBAuthToken, &DBAuthExpireTimeBoolean)
		if err != nil {
			ResultSetRows.Close()
			log.Println("db query error (not founded auth_key, auth_token, expiretime_boolean, of mcs.CWS_Auth) (errmsg:", err, ")")
			ResponseMessage = "db query error (not founded auth_key, auth_token, expiretime_boolean, of mcs.CWS_Auth)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		}
		QueryTupleCount++
	}
	ResultSetRows.Close()

	if QueryTupleCount == 1 {
		if DBAuthExpireTimeBoolean == 1 {
			//-----------------------------------------------{
			QueryString = "DELETE FROM mcs.CWS_Auth " +
				"WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' "
			QueryString = fmt.Sprintf(QueryString, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType)
			log.Println("WEB API Auth Expiretime Delete Query -> [", QueryString, "]")
			//-----------------------------------------------}
			_, err = msdb_lib.Delete_Data(Database, QueryString)
			if err != nil {
				log.Println("db query error (failed to expiretime delete tuple of mcs.CWS_Auth) (errmsg:", err, ")")
				ResponseMessage = "db query error (failed to expiretime delete tuple of mcs.CWS_Auth)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
				return
			}

			DBAuthKey = ""
			DBAuthToken = ""
		}
	} else if QueryTupleCount > 1 {
		//-----------------------------------------------{
		QueryString = "DELETE FROM mcs.CWS_Auth " +
			"WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' "
		QueryString = fmt.Sprintf(QueryString, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType)
		log.Println("WEB API Auth Expiretime Delete Query -> [", QueryString, "]")
		//-----------------------------------------------}
		_, err = msdb_lib.Delete_Data(Database, QueryString)
		if err != nil {
			log.Println("db query error (failed to expiretime delete tuple of mcs.CWS_Auth) (errmsg:", err, ")")
			ResponseMessage = "db query error (failed to expiretime delete tuple of mcs.CWS_Auth)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		}

		DBAuthKey = ""
		DBAuthToken = ""
	}

	if InputData.AuthToken == "" {
		if DBAuthToken != "" {
			log.Println("auth error (authtoken value already exists)")
			ResponseMessage = "auth error (authtoken value already exists)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "640", ResponseMessage, "", "", "")
			log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "640", ResponseMessage)
			return
		}

		AuthAssocationSeqNo += 1
		if AuthAssocationSeqNo >= 100000 {
			AuthAssocationSeqNo = 1
		}

		GenerateAuthKey = WEBAuthGenerateAuthKey(strconv.Itoa(AuthAssocationSeqNo))
		if GenerateAuthKey == "" {
			log.Println("failed to generate auth key")
			ResponseMessage = "failed to generate auth key"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "")
			log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "643", ResponseMessage)
			return
		}

		hashing_algorithm := md5.New()
		HashingText = DecryptUserKeyID + ":" + DecryptDeviceID
		hashing_algorithm.Write([]byte(HashingText))
		HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

		hashing_algorithm = md5.New()
		HashingText = InputData.Method + ":" + "/auth_api/association/v1.0/"
		hashing_algorithm.Write([]byte(HashingText))
		HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue += "[" + HashingText + " >> HA2:" + HA2 + "]"

		hashing_algorithm = md5.New()
		HashingText = HA1 + ":" + GenerateAuthKey + ":" + HA2
		hashing_algorithm.Write([]byte(HA1 + ":" + GenerateAuthKey + ":" + HA2))
		GenerateAuthToken = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue += "[" + HashingText + " >> GenerateAuthToken:" + GenerateAuthToken + "]"

		log.Println("WEB API Auth Association Information -> ", HashingValue)

		if GenerateAuthToken != "" {
			//-----------------------------------------------{
			QueryString = "INSERT INTO mcs.CWS_Auth (user_id, key_id, device_id, method, session_type, seperator, ip, mac, auth_key, auth_token, expiretime, reg_date) " +
				"VALUES (%d, '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', DATEADD(second, %d, GETDATE()), GETDATE()) "
			if InputData.ViaDeviceID != "" && InputData.ViaNodeID != "" {
				QueryString = fmt.Sprintf(QueryString, 0, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType, "client", req.RemoteAddr, "00:00:00:00:00:00", GenerateAuthKey, GenerateAuthToken, AuthExpiretimeInterval)
			} else {
				QueryString = fmt.Sprintf(QueryString, 0, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType, "server", req.RemoteAddr, "00:00:00:00:00:00", GenerateAuthKey, GenerateAuthToken, AuthExpiretimeInterval)
			}
			log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
			//-----------------------------------------------}
			_, err = msdb_lib.Insert_Data(Database, QueryString)
			if err != nil {
				log.Println("db processing error (insert CWS_Auth by key_id, deviceid, auth_key, auth_token)")
				ResponseMessage = "db processing error (insert CWS_Auth by key_id, deviceid, auth_key, auth_token)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
				return
			}

			ResponseMessage = "auth success (create authkey and authtoken)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "200", ResponseMessage, GenerateAuthKey, strconv.Itoa(AuthExpiretimeInterval), "")

			log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s, (expiretime sec:%d, authkey:%s, authtoken:%s)]", DBUserKeyID, DBDeviceID, "200", ResponseMessage, AuthExpiretimeInterval, GenerateAuthKey, GenerateAuthToken)
			return
		} else {
			ResponseMessage = "failed to create authkey, authtoken"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "644", ResponseMessage, "", "", "")
			log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "644", ResponseMessage)
			return
		}

	} else {
		if DBAuthToken == "" {
			if DBAuthExpireTimeBoolean == 1 {
				ResponseMessage = "auth error (authtoken has expired)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "")
				log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "643", ResponseMessage)
				return

			} else {
				ResponseMessage = "auth error (not exist authtoken)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "641", ResponseMessage, "", "", "")
				log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "641", ResponseMessage)
				return
			}
		}

		if InputData.AuthToken != DBAuthToken {
			ResponseMessage = "auth error (mismatching input authtoken and storage authtoken)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "642", ResponseMessage, "", "", "")
			log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "642", ResponseMessage)
			return
		}

		// not exist case : used from a maintenance point of view //
		if DBAuthExpireTimeBoolean == 1 {
			//-----------------------------------------------{
			QueryString = "DELETE FROM mcs.CWS_Auth " +
				"WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' "
			QueryString = fmt.Sprintf(QueryString, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType)
			log.Println("WEB API Auth Expiretime Delete Query -> [", QueryString, "]")
			//-----------------------------------------------}
			_, err = msdb_lib.Delete_Data(Database, QueryString)
			if err != nil {
				log.Println("db query error (failed to expiretime delete tuple of mcs.CWS_Auth) (errmsg:", err, ")")
				ResponseMessage = "db query error (failed to expiretime delete tuple of mcs.CWS_Auth)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
				return
			}

			DBAuthKey = ""
			DBAuthToken = ""

			ResponseMessage = "auth error (authtoken has expired)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "")
			log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "643", ResponseMessage)
			return
		}

		CurrentYear, CurrnetMonth, _ := time.Now().Date()
		//-----------------------------------------------{
		QueryString = "SELECT limit_rate " +
			"FROM mcs.Traffic_Info " +
			"WHERE key_id = %d and datepart(year,end_date) = %d and datepart(month,end_date) = %d "
		QueryString = fmt.Sprintf(QueryString, DBUserKeyID, CurrentYear, CurrnetMonth)
		log.Println("Traffic Limit Query -> [", QueryString, "]")
		//-----------------------------------------------}
		ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			log.Println("db query error (not founded limit_rate of mcs.Traffic_Info) (errmsg:", err, ")")
			ResponseMessage = "db query error (not founded limit_rate of mcs.Traffic_Info)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		}

		QueryTupleCount = 0
		for ResultSetRows.Next() {
			err := ResultSetRows.Scan(&TrafficLimitInboundGiGaBytes)
			if err != nil {
				ResultSetRows.Close()
				log.Println("db query error (not founded limit_rate of mcs.Traffic_Info) (errmsg:", err, ")")
				ResponseMessage = "db query error (not founded limit_rate of mcs.Traffic_Info)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
				return
			}
			QueryTupleCount++
		}
		ResultSetRows.Close()

		if QueryTupleCount == 0 {
			log.Println("db query error (traffic limit_rate tuple is zero)")
			ResponseMessage = "db query error (traffic limit_rate tuple is zero)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		} else if QueryTupleCount > 1 {
			log.Println("db query error (traffic limit_rate tuple is multi-tuple)")
			ResponseMessage = "db query error (traffic limit_rate tuple is multi-tuple)"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		}

		// calculate giga byte (GB -> B) (1GB : 1073741824 Byte) //
		TrafficLimitInboundBytes = (TrafficLimitInboundGiGaBytes * 1073741824)

		ErrorFlag = 0
		//-----------------------------------------------{
		QueryString = "SELECT CASE WHEN count(tmp.inbound) > 0 THEN sum(tmp.inbound) ELSE 0 END AS sum_up_traffic_byte " +
			"FROM (SELECT inbound, outbound " +
			"FROM mcs.Server_Statistics_Info " +
			"WHERE key_id = %d " +
			"and datepart(year,reg_date) = %d " +
			"and datepart(month,reg_date) = %d) tmp "
		QueryString = fmt.Sprintf(QueryString, DBUserKeyID, CurrentYear, CurrnetMonth)
		log.Println("Traffic Limit Query -> [", QueryString, "]")
		//-----------------------------------------------}
		ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			log.Println("db query error (not founded sum (inbound) of mcs.Server_Statistics_Info) (errmsg:", err, ")")
			ResponseMessage = "db query error (not founded sum (inbound) of mcs.Server_Statistics_Info))"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		}

		QueryTupleCount = 0
		for ResultSetRows.Next() {
			err := ResultSetRows.Scan(&TrafficSumInboundBytes)
			if err != nil {
				ErrorFlag = 1
				ResultSetRows.Close()
				log.Println("db query error (not founded sum (inbound) of mcs.Server_Statistics_Info)) (errmsg:", err, ")")
				ResponseMessage = "db query error (not founded sum (inbound) of mcs.Server_Statistics_Info))"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
				return
			}
			QueryTupleCount++
			if ErrorFlag == 1 {
				QueryTupleCount = 0
			}

		}
		ResultSetRows.Close()

		if QueryTupleCount > 1 {
			log.Println("db query error (traffic sum (inbound) of mcs.Server_Statistics_Info tuple is multi_tuple)")
			ResponseMessage = "db query error (traffic sum (inbound) of mcs.Server_Statistics_Info tuple is mulit-tuple))"
			WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
			return
		} else if QueryTupleCount == 1 {

			if TrafficLimitInboundBytes < (TrafficSumInboundBytes) {
				//-- TMP Log for support ---------------//
				tempLog := "Temp Log ==>>>> Limit Byte : %d, upByteSum : %d"
				tempLog = fmt.Sprintf(tempLog, TrafficLimitInboundBytes, TrafficSumInboundBytes)
				log.Println(tempLog)
				//--------------------------------------//

				//-----------------------------------------------{
				QueryString = "DELETE FROM mcs.CWS_Auth " +
					"WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' "
				QueryString = fmt.Sprintf(QueryString, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType)
				log.Println("WEB API Auth Expiretime Delete Query -> [", QueryString, "]")
				//-----------------------------------------------}
				_, err = msdb_lib.Delete_Data(Database, QueryString)
				if err != nil {
					log.Println("db query error (failed to expiretime delete tuple of mcs.CWS_Auth) (errmsg:", err, ")")
					ResponseMessage = "db query error (failed to expiretime delete tuple of mcs.CWS_Auth)"
					WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "")
					return
				}

				ResponseMessage = "product service restrictions (measured rate system : GB)"
				WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "653", ResponseMessage, "", "", "")
				log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "653", ResponseMessage)
				return
			}
		}

		//-----------------------------------------------{
		QueryString = "UPDATE mcs.CWS_Auth " +
			"SET expiretime = DATEADD(second, %d, GETDATE()) " +
			"WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' "
		QueryString = fmt.Sprintf(QueryString, AuthExpiretimeInterval, DBUserKeyID, DBDeviceID, InputData.Method, InputData.SessionType)
		log.Println("AuthKey & AuthToken Expiretime Update Query -> ", QueryString)
		//-----------------------------------------------}
		msdb_lib.Update_Data(Database, QueryString)
		// TODO: DB Excxception (return cnt)

		ResponseMessage = "auth succ (expiretime update)"
		WebServer_Auth_API_Association_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "200", ResponseMessage, "", "", "")
		log.Printf("web api response [userkeyid:%d, deviceid:%d] [code:%s, msg:%s]", DBUserKeyID, DBDeviceID, "200", ResponseMessage)
		return
	}
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
		WebServer_Redirect(w, req, "/login/")
	})

	//----- [ PACKAGE Processing ] {--------------------//
	WebServerMux.HandleFunc("/auth_api/package/v1.0/input_debugger/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Package_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/package/v1.0/key_encoding/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Encode_Value(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/package/v1.0/key_derivation/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Package_AuthToken_Value(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/package/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Package_Proc(w, req)
	})
	//----- [ PACKAGE Processing ] }--------------------//

	//----- [ MCS CLIENT PROVISIONING ACCESS ] {--------//
	WebServerMux.HandleFunc("/auth_api/provisioning/v1.0/input_debugger", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Provisioning_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/provisioning/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Provisioning_Proc(w, req)
	})
	//----- [ MCS CLIENT PROVISIONING ACCESS ] }--------//

	//----- [ MCS SERVER AUTH ACCESS] {-----------------//
	WebServerMux.HandleFunc("/auth_api/association/v1.0/input_debugger/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Association_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/association/v1.0/encoding/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Encode_Value(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/association/v1.0/key_derivation/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Association_AuthToken_Value(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/association/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_Association_Proc(w, req)
	})
	//----- [ MCS SERVER AUTH ACCESS] }-----------------//

	//----- [ MCS SERVER AUTH ACCESS BOARD ] {----------//
	WebServerMux.HandleFunc("/auth_api/association/v1.0/dashboard/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Monitoring_Node_AuthDisplay(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/association/v1.0/dashboard_detail/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Monitoring_Node_AuthDetailDisplay(w, req)
	})
	//----- [ MCS SERVER AUTH ACCESS BOARD ] }----------//

	//----- [ MCS Statistics AUTH ACCESS ] {-----------------//
	WebServerMux.HandleFunc("/auth_api/statistics/input_debugger/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Statistics_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/statistics/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Statistics_Proc(w, req)
	})
	//----- [ MCS Statistics AUTH ACCESS ] }-----------------//

	//----- [ MCS PERFORMANCE TEST ACCESS ] {-----------------//
	WebServerMux.HandleFunc("/performance/v1.0/memory_rsp/nolog/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Performance_API_Memory_NoLog(w, req)
	})

	WebServerMux.HandleFunc("/performance/v1.0/memory_rsp/log/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Performance_API_Memory_Log(w, req)
	})

	WebServerMux.HandleFunc("/performance/v1.0/mvc_rsp/nolog/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Performance_API_MVC_NoLog(w, req)
	})

	WebServerMux.HandleFunc("/performance/v1.0/mvc_rsp/log/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Performance_API_MVC_Log(w, req)
	})

	//WebServerMux.HandleFunc("/performance/v1.0/sample_db/nolog/", func(w http.ResponseWriter, req *http.Request) {
		//WebServer_Performance_API_SimpleDB_NoLog(w, req)
	//})

	//WebServerMux.HandleFunc("/performance/v1.0/simple_db/log/", func(w http.ResponseWriter, req *http.Request) {
		//WebServer_Performance_API_SimpleDB(w, req)
	//})
	//----- [ MCS PERFORMANCE TEST ACCESS ] }-----------------//

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
	go func() {
		for {
			Database := MssqlDB_Open()
			err := UpdateDBNodeStatus(Database)
			if err != nil {
				log.Println("error UpdateDBNodeStatus():", err)
			}
			Database.Close()
			time.Sleep(time.Second * 3)
		}
	}()

	go HttpListen(0, ":"+ServicePort, "", "", WebServerMux)
}

// UpdateDBNodeStatus ...
func UpdateDBNodeStatus(db *sql.DB) error {
	query := "UPDATE MCSE_Info\n" +
		"SET status = '002'\n" +
		"WHERE DATEADD(ss,24,provisioning_time) < GETDATE()  AND  status != '000' ;"

	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec()
	if err != nil {
		return err
	}

	return nil
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

//----------------------------------------------------------
type jsonInputWebAPIAuthStatLocalPack struct {
	Version     string      `json:"version"`
	Method      string      `json:"method"`
	SessionType string      `json:"sessiontype"`
	MessageType string      `json:"msgtype"`
	UserKey     string      `json:"userkey"`
	UserKeyID   string      `json:"userkeyid"`
	NodeID      string      `json:"nodeid"`
	DeviceID    string      `json:"deviceid"`
	IP          string      `json:"ip"`
	MACTotal    string      `json:"mactotal"`
	AuthKey     string      `json:"authkey"`
	AuthToken   string      `json:"authtoken"`
	Data        interface{} `json:"data"`
}

type jsonOutputWebAPIAuthStatLocalPack struct {
	Version     string      `json:"version"`
	Method      string      `json:"method"`
	SessionType string      `json:"sessiontype"`
	MsgType     string      `json:"msgtype"`
	Code        string      `json:"code"`
	Message     string      `json:"msg"`
	AuthKey     string      `json:"authkey"`
	ExpireTime  string      `json:"expiretime"`
	Data        interface{} `json:"data"`
}

//----------------------------------------------------------
//-----------------------Statistics Auth------------------------------
type StatisticsHeader struct {
	Version   string `json:"version"`
	Method    string `json:"method"`
	Seperator string `json:"seperator"`
	Msgtype   string `json:"msgtype"`
	Userkey   string `json:"userkey"`
	Nodeid    string `json:"nodeid"`
}

type StatisticsBody struct {
	Code    int                    `json:"code,omitempty"`    // 0 is ignore
	Message string                 `json:"message,omitempty"` // emptry is ignore
	Data    []StatisticInformation `json:"data,omitempty"`
}
type StatisticsProtocol struct {
	Header StatisticsHeader `json:"header"`
	Body   StatisticsBody   `json:"body, omitempty"`
}

type StatisticInformation struct {
	ID                 string `mapstructure:"ID" json:"id"`
	Time               string `mapstructure:"Time" json:"time"`
	Bridge_ID_Text     string `mapstructure:"Bridge_ID_Text" json:"bridge_id_text"`
	Node_ID_Text       string `mapstructure:"Node_ID_Text" json:"node_id_text"`
	Proxy_IP_Int       string `mapstructure:"Proxy_IP_Int" json:"proxy_ip_int"`
	Proxy_IP_Text      string `mapstructure:"Proxy_IP_Text" json:"proxy_ip_text"`
	Proxy_Listen_Port  string `mapstructure:"Proxy_Listen_Port" json:"proxy_listen_port"`
	Node_IP_Int        string `mapstructure:"Node_IP_Int" json:"node_ip_int"`
	Node_IP_Text       string `mapstructure:"Node_IP_Text" json:"node_ip_text"`
	Node_Listen_Port   string `mapstructure:"Node_Listen_Port" json:"node_listen_port"`
	Server_IP_Int      string `mapstructure:"Server_IP_Int" json:"server_ip_int"`
	Server_IP_Text     string `mapstructure:"Server_IP_Text" json:"server_ip_text"`
	Server_Listen_Port string `mapstructure:"Server_Listen_Port" json:"server_listen_port"`
	OverlapID          string `mapstructure:"OverlapID" json:"overlapid"`
	Client_IP_Int      string `mapstructure:"Client_IP_Int" json:"client_ip_int"`
	Client_IP_Text     string `mapstructure:"Client_IP_Text" json:"client_ip_text"`
	Inbound            string `mapstructure:"Inbound" json:"inbound"`
	Outbound           string `mapstructure:"Outbound" json:"outbound"`
	Type               string `mapstructure:"Type" json:"type"`
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
func WebServer_Auth_API_Statistic_Response(w http.ResponseWriter, Version string, Method string, SessionType string, MsgType string, Code string, Message string, AuthKey string, Expiretime string, Data interface{}) {
	var OutputData jsonOutputWebAPIAuthProvisioningPack
	var OutputBody string

	OutputData.Version = Version         // (security enhancement: tracking prevention)
	OutputData.Method = Method           // (security enhancement: tracking prevention)
	OutputData.SessionType = SessionType // (security enhancement: tracking prevention)
	OutputData.MsgType = MsgType         // (security enhancement: tracking prevention)
	OutputData.Code = Code
	OutputData.Message = Message
	OutputData.AuthKey = AuthKey
	OutputData.ExpireTime = Expiretime
	OutputData.Data = Data

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

func WebServer_Web_Auth_API_Statistics_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var Database *sql.DB
	var ResultSetRows *sql.Rows
	var QueryString string
	var InputData jsonInputWebAPIAuthStatLocalPack
	var OutputData jsonOutputWebAPIAuthStatLocalPack
	var EncryptUserKey string
	var EncryptUserKeyID string
	var EncryptNodeID string
	var EncryptDeviceID string
	var DecryptUserKey string
	var DecryptUserKeyID string
	var DecryptNodeID string
	var DecryptDeviceID string
	var GenerateAuthKey string
	var DBAuthUserKey string
	var DBAuthUserKeySeq int64
	var DBDeviceID int
	var DBNodeIDStatus string
	var OEMAuthExpiretimeInterval int
	var DBAuthKey string
	var DBAuthToken string
	var DBAuthExpireTime uint64
	var Response string
	var err error

	log.Println("WebServer_Web_Auth_API_Statistics_Proc", req.Method)
	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		log.Println("err decode")
		WebServer_Auth_API_Statistic_Response(w, "", "", "", "", "610", "json parameter parsing error (simplify Information)", "", "", "")
		return
	}

	if req.Method != "POST" {
		log.Println("err POST")
		WebServer_Auth_API_Statistic_Response(w, "", "", "", "", "610", "json parameter parsing error (simplify Information for security enhancement)", "", "", "")
		return
	}

	//log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", authtoken:" + InputData.AuthToken + ", data:" + InputData.Data + "]")
	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.MessageType == "" || InputData.UserKey == "" || InputData.UserKeyID == "" || InputData.NodeID == "" || InputData.DeviceID == "" {
		log.Println("invalid parmeter value: null")
		WebServer_Auth_API_Statistic_Response(w, "", "", "", "", "611", "json parameter is null (simplify Information for security enhancement)", "", "", "")
		return
	}

	if InputData.Version != "1.0" || InputData.Method != "Auth" || InputData.SessionType != "Statistics" || InputData.MessageType != "request" {
		log.Println("invalid parmeter value: not supported value")
		WebServer_Auth_API_Statistic_Response(w, "", "", "", "", "612", "json parameter is invalid (simplify Information for security enhancement)", "", "", "")
		return
	}

	if InputData.UserKey != "" {
		EncryptUserKey = InputData.UserKey
		DecryptUserKey = AESDecryptDecodeValue(EncryptUserKey)
		if DecryptUserKey == "" {
			log.Println("invalid parmeter value: user key decrypt error")
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "620", "json parameter decript error", "", "", "")
			return
		}
		log.Printf("WEB API Auth - UserKey Decrypt Value [%s] -> [%s]", InputData.UserKey, DecryptUserKey)
		InputData.UserKey = DecryptUserKey
	}

	if InputData.UserKeyID != "" {
		EncryptUserKeyID = InputData.UserKeyID
		DecryptUserKeyID = AESDecryptDecodeValue(EncryptUserKeyID)
		if DecryptUserKeyID == "" {
			log.Println("invalid parmeter value: user key decrypt error")
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "620", "json parameter decript error", "", "", "")
			return
		}
		log.Printf("WEB API Auth - UserKeyID Decrypt Value [%s] -> [%s]", InputData.UserKeyID, DecryptUserKeyID)
		InputData.UserKeyID = DecryptUserKeyID
	}

	if InputData.NodeID != "" {
		EncryptNodeID = InputData.NodeID
		DecryptNodeID = AESDecryptDecodeValue(EncryptNodeID)
		if DecryptNodeID == "" {
			log.Println("invalid parmeter value: node id decrypt error")
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "620", "json parameter decript error", "", "", "")
			return
		}
		InputData.NodeID = DecryptNodeID
	}

	if InputData.DeviceID != "" {
		EncryptDeviceID = InputData.DeviceID
		DecryptDeviceID = AESDecryptDecodeValue(EncryptDeviceID)
		if DecryptDeviceID == "" {
			log.Println("invalid parmeter value: node id decrypt error")
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "620", "json parameter decript error", "", "", "")
			return
		}
		log.Printf("WEB API Auth - DeviceID Decrypt Value [%s] -> [%s]", InputData.DeviceID, DecryptDeviceID)
		InputData.DeviceID = DecryptDeviceID
	}
	//-----------------------------------------------------------
	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)

	Database.SetMaxIdleConns(1000)
	Database.SetMaxOpenConns(1000)

	OEMAuthExpiretimeInterval = 10

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

	if Database == nil {
		WebServer_Auth_API_Provisioning_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db connection error", "", "", "", "", "")
		return
	}

	log.Println("InputData.Deviceid", InputData.DeviceID)
	QueryString = "SELECT A.key_id, A.user_key, B.device_id, B.status " +
		"FROM User_Key AS A " +
		"JOIN Node_ID AS B " +
		"ON  A.key_id = B.key_id " +
		"AND A.user_key = '%s' " +
		"AND B.device_id = %s"

	QueryString = fmt.Sprintf(QueryString, InputData.UserKey, InputData.DeviceID)
	log.Println("Auth UserKey Exist Query : ", QueryString)

	ResultSetRows, _ = msdb_lib.Query_DB(Database, QueryString)
	if err != nil {
		WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "")
		return
	}

	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&DBAuthUserKeySeq, &DBAuthUserKey, &DBDeviceID, &DBNodeIDStatus)
		if err != nil {
			ResultSetRows.Close()
			log.Println("data Scan error:", err)
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "")
			return
		}
	}
	ResultSetRows.Close()

	log.Println("UserKeySeq:", DBAuthUserKeySeq, ", Userkey:", DBAuthUserKey, "Device_ID:", DBDeviceID, "Status:", DBNodeIDStatus)
	if DBAuthUserKeySeq == 0 {
		log.Println("not exists deviceid:", InputData.DeviceID)
		WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "660", "Not exists deviceid", "", "", "")
		return
	}
	//-----------------------------------------------------------

	if InputData.AuthKey == "" && InputData.AuthToken == "" {

		AuthStatisticsSeqNo += 1

		if AuthStatisticsSeqNo >= 100000 {
			AuthStatisticsSeqNo = 1
		}

		GenerateAuthKey = WEBAuthGenerateAuthKey(strconv.Itoa(AuthStatisticsSeqNo))
		log.Println("GenerateAuthKey:", GenerateAuthKey)

		if GenerateAuthKey == "" {
			log.Println("failed to generate auth key")
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "643", "failed to generate auth key", "", "", "")
			return
		}

		Response = WebServer_Auth_API_Hashing_Statistic(InputData.UserKeyID, InputData.DeviceID, InputData.Method, GenerateAuthKey)
		//log.Println("WEB API Auth Information -> ", EventValue)

		if Response != "" {

			//--[Query: Delete Existed AuthKey & AuthToken]-------------------------------------------{
			QueryString = "DELETE FROM CWS_Auth WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' and ip = '%s' and mac = '%s'"
			QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, DBDeviceID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal)
			log.Println("CWS_AuthTbl Delete Query : ", QueryString)
			//----------------------------------------------------------------------------------------}
			_, err = msdb_lib.Delete_Data(Database, QueryString)
			if err != nil {
				WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "")
				return
			}

			//--[Query: Insert Temp AuthKey & AuthToken]----------------------------------------------{
			QueryString = "INSERT INTO CWS_Auth (key_id, user_id, device_id, method, session_type, ip, mac, auth_key, auth_token, expiretime) " +
				"values (%d, %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', DATEADD(second, %d, GETDATE())) "
			QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, 0, DBDeviceID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal, GenerateAuthKey, Response, OEMAuthExpiretimeInterval)
			log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
			//----------------------------------------------------------------------------------------}
			_, err = msdb_lib.Insert_Data(Database, QueryString)
			if err != nil {
				log.Println("Insert error: ", err)
				WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "")
				return
			}

			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "200", "auth success", GenerateAuthKey, strconv.Itoa(OEMAuthExpiretimeInterval), "")
			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s, description:%s (expiretime sec:%d, authkey:%s, authtoken:%s)]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message, "create new authkey and authtoken", OEMAuthExpiretimeInterval, GenerateAuthKey, Response)
			return

		} else {
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "644", "failed to generate auth token", "", "", "")
			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message)
			return
		}

	} else if InputData.AuthKey != "" && InputData.AuthToken != "" {
		//--[Query: Checking Auth Information]-------------------------------------{
		QueryString = "SELECT auth_key, auth_token, CASE WHEN expiretime < GETDATE() THEN 0 ELSE 1 END AS expire " +
			"FROM CWS_Auth " +
			"WHERE key_id = %d AND auth_key = '%s' AND auth_token = '%s' AND ip = '%s' AND mac = '%s' AND method = '%s' AND session_type = '%s'"
		QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.AuthKey, InputData.AuthToken, InputData.IP, InputData.MACTotal, InputData.Method, InputData.SessionType)
		//-------------------------------------------------------------------------}
		log.Println("Auth Information Checking Query : ", QueryString)

		ResultSetRows, _ = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "")
			return
		}

		for ResultSetRows.Next() {
			err = ResultSetRows.Scan(&DBAuthKey, &DBAuthToken, &DBAuthExpireTime)
			if err != nil {
				ResultSetRows.Close()
				log.Println("data Scan error:", err)
				WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "")
				return
			}
		}
		ResultSetRows.Close()

		//--[Query: Delete Existed AuthKey & AuthToken]-------------------------------------------{
		QueryString = "DELETE FROM CWS_Auth WHERE key_id = %d and device_id = %d and method = '%s' and session_type = '%s' and ip = '%s' and mac = '%s'"
		QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, DBDeviceID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal)
		log.Println("CWS_Auth Delete Query : ", QueryString)
		//----------------------------------------------------------------------------------------}
		_, err = msdb_lib.Delete_Data(Database, QueryString)
		if err != nil {
			log.Println("Delete error:", err)
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "")
			return
		}

		if DBAuthExpireTime == 0 {
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "643", "auth error", "", "", "")
			return
		}

		if DBAuthKey == "" || DBAuthToken == "" {
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "641", "auth error", "", "", "")
			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message)
			return
		}

		if InputData.AuthKey != DBAuthKey || InputData.AuthToken != DBAuthToken {
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "642", "auth error", "", "", "")
			log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message)
			return
		}

		StatReq := StatisticsProtocol{}
		if err := mapstructure.Decode(InputData.Data, &StatReq); err != nil {
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "610", "json parameter parsing error (simplify Information for security enhancement)", "", "", "")
			return
		}

		//--------------------insert Statistics DB -------------------
		if err := InsertStatisticsDB(StatReq.Body.Data, DBDeviceID); err != nil {
			WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "630", "db processing error", "", "", "")
			return
		}
		//---------------------insert Statistics DB -------------------

		WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "200", "auth success", "", strconv.Itoa(0), "")
		return
	} else {

		WebServer_Auth_API_Statistic_Response(w, InputData.Version, InputData.Method, InputData.SessionType, "response", "641", "auth error", "", "", "")
		log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.UserKey, InputData.NodeID, OutputData.Code, OutputData.Message)
		return
	}
}

func InsertStatisticsDB(Statistics []StatisticInformation, DBDeviceID int) error {
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryString string
	var err error
	var Rows *sql.Rows
	var device_id_seq int
	var key_id_seq int
	var Database *sql.DB
	var Site_Type int

	Site_Type = 1

	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)

	tx, err = msdb_lib.DB_TX_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return err
	}

	defer msdb_lib.DB_TX_Rollback(tx)

	if Statistics[0].Type == "002" {
		QueryString = "SELECT device_id, key_id FROM mcs.MCSE_Info WHERE device_id = ?"
	} else if Statistics[0].Type == "001" {
		QueryString = "SELECT device_id, key_id FROM mcs.MCSE_Info WHERE device_id = ?"
	}

	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return err
	}

	Rows, err = stmt.Query(DBDeviceID)
	if err != nil {
		stmt.Close()
		log.Println("Query:", err)
		return err
	}

	for Rows.Next() {
		err := Rows.Scan(&device_id_seq, &key_id_seq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return err
		}
	}
	Rows.Close()

	valueStrings := make([]string, 0)
	valueArgs := []interface{}{}
	var Server_Listen_Port, Inbound, Outbound, Node_Listen_Port, Proxy_Listen_Port int

	for i := range Statistics {

		if Statistics[i].Type == "001" {
			Server_Listen_Port, _ = strconv.Atoi(Statistics[i].Server_Listen_Port)
			Node_Listen_Port, _ = strconv.Atoi(Statistics[i].Node_Listen_Port)
			Inbound, _ = strconv.Atoi(Statistics[i].Inbound)
			Outbound, _ = strconv.Atoi(Statistics[i].Outbound)

			placeHolders := "(?,?,?,?,?,?,?,?,?,?,?,?,?)"
			valueStrings = append(valueStrings, placeHolders)

			valueArgs = append(valueArgs, device_id_seq)
			valueArgs = append(valueArgs, key_id_seq)
			valueArgs = append(valueArgs, Statistics[i].Bridge_ID_Text)
			valueArgs = append(valueArgs, Statistics[i].Time)
			valueArgs = append(valueArgs, Statistics[i].Server_IP_Text)
			valueArgs = append(valueArgs, Server_Listen_Port)
			valueArgs = append(valueArgs, Statistics[i].Node_IP_Text)
			valueArgs = append(valueArgs, Node_Listen_Port)
			valueArgs = append(valueArgs, Statistics[i].Proxy_IP_Text)
			valueArgs = append(valueArgs, Statistics[i].Client_IP_Text)
			valueArgs = append(valueArgs, Inbound)
			valueArgs = append(valueArgs, Outbound)
			valueArgs = append(valueArgs, Site_Type)

		} else {
			Node_Listen_Port, _ = strconv.Atoi(Statistics[i].Node_Listen_Port)
			Proxy_Listen_Port, _ = strconv.Atoi(Statistics[i].Proxy_Listen_Port)
			Inbound, _ = strconv.Atoi(Statistics[i].Inbound)
			Outbound, _ = strconv.Atoi(Statistics[i].Outbound)

			placeHolders := "(?,?,?,?,?,?,?,?,?,?,?,?)"
			valueStrings = append(valueStrings, placeHolders)

			valueArgs = append(valueArgs, device_id_seq)
			valueArgs = append(valueArgs, key_id_seq)
			valueArgs = append(valueArgs, Statistics[i].Node_ID_Text)
			valueArgs = append(valueArgs, Statistics[i].Time)
			valueArgs = append(valueArgs, Statistics[i].Node_IP_Text)
			valueArgs = append(valueArgs, Node_Listen_Port)
			valueArgs = append(valueArgs, Statistics[i].Proxy_IP_Text)
			valueArgs = append(valueArgs, Proxy_Listen_Port)
			valueArgs = append(valueArgs, Statistics[i].Client_IP_Text)
			valueArgs = append(valueArgs, Inbound)
			valueArgs = append(valueArgs, Outbound)
			valueArgs = append(valueArgs, Site_Type)

		}
	}

	if Statistics[0].Type == "001" {
		QueryString = "INSERT INTO mcs.Server_Statistics_Info (device_id,key_id,node_id,reg_date,server_ip,server_port,mcse_ip,\n" +
			"mcse_port,proxy_ip,client_ip,inbound,outbound,site_id)\n" +
			"VALUES %s"
		QueryString = fmt.Sprintf(QueryString, strings.Join(valueStrings, ","))

		log.Println("QueryString", QueryString)

		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		_, err = stmt.Exec(valueArgs...)
		if err != nil {
			log.Println("exec Fail!:", err)
			return err
		}
	} else {

		QueryString = "INSERT INTO mcs.Client_Statistics_Info (device_id,key_id,node_id,reg_date,mcse_ip,mcse_port,proxy_ip,\n" +
			"proxy_port,client_ip,inbound,outbound,site_id)\n" +
			"VALUES %s"

		QueryString = fmt.Sprintf(QueryString, strings.Join(valueStrings, ","))

		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		_, err = stmt.Exec(valueArgs...)
		if err != nil {
			log.Println("exec Fail!:", err)
			return err
		}
	}
	stmt.Close()

	msdb_lib.DB_TX_Commit(tx)

	return nil
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

func WebServer_Performance_API_Memory_NoLog(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	//var InputData jsonInputWebAPIEncodeValue
	var OutputData jsonOutputWebAPIPerformanceMemoryRsp
	var OutputBody string

	//log.Println("WebServer_Performance_API_Memory_NoLog", req.Method)

  OutputData.Code = "200"
  OutputData.Message = "Performance Memory Response - NoLog"
  OutputData.InputValue = "null"
  OutputData.OutputValue = "null"

	//log.Println("Response Data - Code:", OutputData.Code, ", Message:", OutputData.Message, ", Input:", OutputData.InputValue, ", Output:", OutputData.OutputValue)

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json")
  w.Write([]byte(OutputBody))
  return
}

func WebServer_Performance_API_Memory_Log(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	//var InputData jsonInputWebAPIEncodeValue
	var OutputData jsonOutputWebAPIPerformanceMemoryRsp
	var OutputBody string

	log.Println("WebServer_Performance_API_Memory_Log", req.Method)

  OutputData.Code = "200"
  OutputData.Message = "Performance Memory Response - NoLog"
  OutputData.InputValue = "null"
  OutputData.OutputValue = "null"

	log.Println("Response Data - Code:", OutputData.Code, ", Message:", OutputData.Message, ", Input:", OutputData.InputValue, ", Output:", OutputData.OutputValue)

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json")
  w.Write([]byte(OutputBody))
  return
}

func WebServer_Performance_API_MVC_NoLog(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlPackage CommonHTML
	var HtmlTemplate *template.Template
	var err error

	//log.Println("WebServer_Performance_API_MVC_NoLog", req.Method)

	HtmlTemplate, err = template.ParseFiles("./html/svc_gowas_performance_mvc.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/svc_gowas_performance_mvc.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	//log.Println("Loading Html File - svc_gowas_performance_mvc.html")
	HtmlTemplate.Execute(w, HtmlPackage)
}

func WebServer_Performance_API_MVC_Log(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlPackage CommonHTML
	var HtmlTemplate *template.Template
	var err error

	log.Println("WebServer_Performance_API_MVC_Log", req.Method)

	HtmlTemplate, err = template.ParseFiles("./html/svc_gowas_performance_mvc.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./html/svc_gowas_performance_mvc.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	log.Println("Loading Html File - svc_gowas_performance_mvc.html")
	HtmlTemplate.Execute(w, HtmlPackage)
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
  InitLogger ()

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
			PidFileName: "innogs_gowas.pid",
			PidFilePerm: 0644,
			LogFileName: ProcessLogFileName,
			LogFilePerm: 0640,
			WorkDir:     "./",
			Umask:       027,
			Args:        []string{"./innogs_gowas", "-l", ListenerPort, "-p", ProcessType},
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
