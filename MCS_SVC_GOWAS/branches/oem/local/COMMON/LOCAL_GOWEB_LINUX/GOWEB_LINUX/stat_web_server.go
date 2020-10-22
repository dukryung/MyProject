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
	"errors"
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
	"runtime"
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
	"github.com/mitchellh/mapstructure"
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
var LocalWebServerDB = "./db/localwebserver.db"
var LicenseSqliteDB = "./db/license.db"
var DBPath, DBName string
var SettingUpdateLock = &sync.Mutex{}
var ProcessLogFileName = "stat_web_server.log"
var Login = "SELECT COUNT(*) FROM Users WHERE ID=? AND PASSWORD=?"

var Stat_Serv_Common_ID int64
var Stat_Serv_Data_ID int64
var Stat_Clint_Common_ID int64
var Stat_Clint_Data_ID int64
var UpdateLock = &sync.Mutex{}
var db_cfg_path = "./cfg/db.cfg"
var LicenseFileSN int

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

type Settingtoml struct {
	Global     global
	Logfile    logfile
	Statistics statistics
	Node       node
	KMS        kms
	Frontend   map[string]frontendSection
	Backend    map[string]backendSection
}

type global struct {
	Max_conn         string
	Recv_buffer_size string
	Send_buffer_size string
	Timeout_connect  string
	Timeout_client   string
	Timeout_server   string
}
type logfile struct {
	Disk_limit string
	Max_size   string
	Log        string
	Error      string
}

type statistics struct {
	Interval string
	Use      string
}
type node struct {
	Position       string
	Interval_retry string
	Buffer_size    string
	Encrypt        string
	Cp_tunneling   string
}
type kms struct {
	Url string
}

// FrontendSection ...
type frontendSection struct {
	Bind      string
	Node_Mode string
	Backend   string
}

// BackendSection ...
type backendSection struct {
	Server []string
}

type LicenseUploadData struct {
	Result      string
	Nodeid_list string
	EndDate     string
	FileName    string
}
type PopupPageInfo struct {
	Result      string
	FileName    string
	EndDate     string
	Nodeid_list []PopupNodeIDInfo
}
type PopupNodeIDInfo struct {
	Nodeid_list template.HTML
}
type LicenseFileName struct {
	FileName string
}
type IsInsertLic struct {
	Result string `json:"result"`
}

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
	EndDateMonth   string
	EndDateDay     string
}

type NodeID struct {
	NodeID []string
}
type NodeIDtoml struct {
	NodeID nodeidSection
}

type nodeidSection struct {
	NodeID string
}

type LicensepopuppageInfo struct {
	EndYear   int
	EndMonth  int
	EndDay    int
	NodeIDArr []LicensepopupNodeIDData
}
type LicensepopupNodeIDData struct {
	NodeID string
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

	EndDate string

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

	//--- Provioning -----------------{
	PV_Version              string
	PV_Method               string
	PV_SessionType          string
	PV_MessageType          string
	PV_ControlServerAddress string
	PV_UserKey              string
	PV_NodeID               string
	PV_MacTotalString       string
	PV_CurrentSeq           string
	PV_NextSeq              string
	//--- Provioning -----------------}

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

type UseBridgeHTML struct {
	UseBridge_HTML template.HTML
}
type ChangeClientIPHTML struct {
	ChangeClientIP_HTML template.HTML
}

type EnableSelectHTML struct {
	Value_HTML template.HTML
}

type HTMLType struct {
	Value_HTML template.HTML
}

type ServerStatisticPageInfo struct {
	NodeSettingsList   template.HTML
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
	NodeSettingsList   template.HTML

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
type TempletNameInformation struct {
	TempletName string `"json:"TempletName"`
}
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
type SaveParamsSettingsInformation struct {
	Params      SettingsInformation `"json:"params"`
	Pv_rsp_code string              `"json:"pv_rsp_code"`
	Pv_rsp_seq  string              `"json:"pv_rsp_seq"`
}

type CfglistSettingsInformation struct {
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

	Node_Status template.HTML
}

type CfgListPageInfo struct {
	NodeClientStatMenu   template.HTML
	NodeServerStatMenu   template.HTML
	NodeSettingsList     template.HTML
	SearchNodeIP         string
	SearchNodeID         string
	SearchUseBridge      string
	SearchClientChangeIP string

	SortNodeID                    template.HTML
	SortConnections               template.HTML
	SortReceiveBuffer             template.HTML
	SortSendBuffer                template.HTML
	SortConnect                   template.HTML
	SortClient                    template.HTML
	SortServer                    template.HTML
	SortLimitSize                 template.HTML
	SortMaxSize                   template.HTML
	SortPath                      template.HTML
	SortErrPath                   template.HTML
	SortStatisticsCollectionCycle template.HTML
	SortUseBridge                 template.HTML
	SortNodeBufferSize            template.HTML
	SortEncryptMode               template.HTML
	SortChangeIPMode              template.HTML

	UseBridgeHTML      template.HTML
	ChangeClientIPHTML template.HTML

	FirstPage template.HTML
	PrevPage  template.HTML
	NextPage  template.HTML
	LastPage  template.HTML

	Node_Status template.HTML

	Cfginfo     []CfglistSettingsInformation
	PageNumInfo []PageNumInfo
}

type CfgDetailPageInfo struct {
	NodeClientStatMenu template.HTML
	NodeServerStatMenu template.HTML
	NodeSettingsList   template.HTML

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

	ModeSelectHTMLList []HTMLType
	UseBridge          string
	Buffer_Size        int
	EncryptMode        string
	ChangeIpClientMode string

	EncModeSelectHTMLList  []HTMLType
	ChangeIPSelectHTMLList []HTMLType
	TempletSelectHTMLList  []HTMLType

	Node_ID string

	KMS_Address string
	KMS_Port    int

	DeviceID          uint64
	FrontBackHTMLList []HTMLType
	NICNAMEHTMLList   []HTMLType

	FrontendNodeMode template.HTML
}

type TempletPageInfo struct {
	NodeClientStatMenu template.HTML
	NodeServerStatMenu template.HTML
	NodeSettingsList   template.HTML

	TempletName       string
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

	ModeSelectHTMLList []HTMLType
	UseBridge          string
	Buffer_Size        int
	EncryptMode        string
	ChangeIpClientMode string

	EncModeSelectHTMLList  []HTMLType
	ChangeIPSelectHTMLList []HTMLType
	TempletSelectHTMLList  []HTMLType

	KMS_Address string
	KMS_Port    int

	FrontBackHTMLList []HTMLType
	NICNAMEHTMLList   []HTMLType

	FrontendNodeMode template.HTML
}

//-------------------Templetparamstruct-------------------

type TempletSettingsInformation struct {
	TempletName                   string
	DeviceID                      string
	NewTempletName                string
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
	SiteList                      []TempletFrontendInformation
}

type TempletFrontendInformation struct {
	Frontendsymbol string
	FrontendPort   string
	NodeMode       string
	Backend        []TempletBackendInformationList
}

type TempletBackendInformationList struct {
	LAN_Interface string
	BackendIP     string
	BackendPort   string
}

type jsonTempletResult struct {
	Result string `mapstructure:"Result" json:"Result"`
}

//-------------------Templetparamstruct-------------------

type DetailSettingsInformation struct {
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

func WebServer_Login(w http.ResponseWriter, req *http.Request, database *sql.DB) {
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

func UpdateConfigFiles(Database *sql.DB, Settings SettingsInformation, SeqNo int64) (int32, error) {
	var ConfGlobal, ConfLogFile, ConfStatistics, ConfNode, ConfNodeID, ConfKMS, ConfFrontend, ConfBackend string
	var tx *sql.Tx
	var stmt *sql.Stmt
	var err error
	var UpdateDataStr string
	var CRLF string
	var Whole_Config_File string
	var Node_Mode_Str string
	var BackendList string
	var Frontend_Config string
	var Backend_Config string
	var fd *os.File
	var EncText string
	var TempConfFrontend string
	var TempConfBackend string
	var StatSendFlag int

	SettingUpdateLock.Lock()
	defer SettingUpdateLock.Unlock()

	err = os.MkdirAll("./cfg", 0644)
	if err != nil {
		return DB_RET_FAIL, err
	}

	fd, err = os.Create("./cfg/app.cfg")
	if err != nil {
		return DB_RET_FAIL, err
	}
	defer fd.Close()
	tx, err = Database.Begin()
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return DB_RET_FAIL, err
	}

	defer sqlitedb_lib.DB_Rollback(tx)

	//Josk: Add Code for SyncSeqNo========================================{
	if SeqNo > 0 {
		query := "UPDATE SyncSeqNoTbl\n" +
			"SET SeqNo = ?\n" +
			"WHERE SeqNoName = 'ConfigData';"

		stmt, err = tx.Prepare(query)
		if err != nil {
			return DB_RET_FAIL, err
		}

		_, err = stmt.Exec(SeqNo)
		if err != nil {
			stmt.Close()
			return DB_RET_FAIL, err
		}

		stmt.Close()
	}
	//==================================================================}

	if Settings.Password == "" {
		log.Println("Password didn't update")
	} else {
		UpdateDataStr = "UPDATE Users SET Password=?"
		stmt, err = tx.Prepare(UpdateDataStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return DB_RET_FAIL, err
		}

		_, err = stmt.Exec(GetCipherText(Settings.Password))
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return DB_RET_FAIL, err
		}

		stmt.Close()
	}

	UpdateDataStr = "UPDATE Users SET Stat_StatServerIP=?, Stat_StatServerPort=?, Stat_StatDataSendCycle=?, Stat_Send_Flag=? WHERE Seq=1"
	if Settings.Statistic_Send_Control_Server == "Enable" {
		StatSendFlag = ENABLE
	} else {
		StatSendFlag = DISABLE
		/*
			Settings.Statistic_Server_Ip = ""
			Settings.Statistic_Server_Port = ""
			Settings.Statistic_Send_Cycle = "10"
		*/
	}

	stmt, err = tx.Prepare(UpdateDataStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return DB_RET_FAIL, err
	}
	defer stmt.Close()

	_, err = stmt.Exec(Settings.Statistic_Server_Ip, Settings.Statistic_Server_Port, Settings.Statistic_Send_Cycle, StatSendFlag)
	if err != nil {
		log.Println("Exec Fail!:", err)
		return DB_RET_FAIL, err
	}

	if runtime.GOOS == "linux" {
		CRLF = "\n"
	} else if runtime.GOOS == "windows" {
		CRLF = "\n"
		//CRLF = "\r\n"
	}

	ConfGlobal = "[global]" + CRLF
	ConfGlobal += "max_conn = \"<MAX_CONN>\"" + CRLF
	ConfGlobal += "recv_buffer_size = \"<DEFAULT_RECV_BUFF_SIZE>\"" + CRLF
	ConfGlobal += "send_buffer_size = \"<DEFAULT_SEND_BUFF_SIZE>\"" + CRLF
	ConfGlobal += "timeout_connect = \"<TIMEOUT_CONNECT>\"" + CRLF
	ConfGlobal += "timeout_client = \"<TIMEOUT_CLIENT>\"" + CRLF
	ConfGlobal += "timeout_server = \"<TIMEOUT_SERVER>\"" + CRLF
	ConfGlobal += CRLF

	ConfLogFile = "[logfile]" + CRLF
	ConfLogFile += "disk_limit = \"<DISK_LIMIT>\"" + CRLF
	ConfLogFile += "max_size = \"<LOGFILE_MAX_SIZE>\"" + CRLF
	ConfLogFile += "log = \"<LOGFILE_LOCATION>\"" + CRLF
	ConfLogFile += "error = \"<ERRORLOGFILE_LOCATION>\"" + CRLF
	ConfLogFile += CRLF

	ConfStatistics = "[statistics]" + CRLF
	ConfStatistics += "use = \"enable\"" + CRLF
	ConfStatistics += "interval = \"<STATISTICS_INTERVAL>\"" + CRLF
	ConfStatistics += CRLF

	ConfNode = "[node]" + CRLF
	ConfNode += "position = \"wan\"" + CRLF
	ConfNode += "interval_retry = \"5\"" + CRLF
	ConfNode += "buffer_size = \"<Node_BUFF_SIZE>\"" + CRLF
	ConfNode += "encrypt = \"<Node_ENCRYPT>\"" + CRLF
	ConfNode += "cp_tunneling = \"<CHANGE_IP_FUNC>\"" + CRLF
	ConfNode += CRLF

	ConfNodeID += "[NodeID]" + CRLF
	ConfNodeID += "NodeID = \"<NODE_ID>\"" + CRLF
	ConfNodeID += CRLF

	ConfKMS += "[kms]" + CRLF
	ConfKMS += "url = \"<KMS_ADDR_PORT>\"" + CRLF
	ConfKMS += CRLF

	ConfFrontend += "[frontend.<SYMBOL_NAME>]" + CRLF
	ConfFrontend += "bind = \"<FRONTEND_BIND>\"" + CRLF
	ConfFrontend += "backend = \"<SYMBOL_NAME>\"" + CRLF
	ConfFrontend += "node_mode = \"<Node_MODE>\"" + CRLF
	ConfFrontend += CRLF

	ConfBackend += "[backend.<SYMBOL_NAME>]" + CRLF
	ConfBackend += "server = [<LANID_SERVER_IP_PORT>]" + CRLF
	ConfBackend += CRLF

	ConfGlobal = strings.Replace(ConfGlobal, "<MAX_CONN>", Settings.Maximum_ConnectionCount, -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<DEFAULT_RECV_BUFF_SIZE>", Settings.Recv_Buf_Size, -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<DEFAULT_SEND_BUFF_SIZE>", Settings.Send_Buf_Size, -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<TIMEOUT_CONNECT>", Settings.Connection_Timeout, -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<TIMEOUT_CLIENT>", Settings.Client_Reconnect_Timeout, -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<TIMEOUT_SERVER>", Settings.Server_Reconnect_Timeout, -1)

	Whole_Config_File += ConfGlobal

	ConfLogFile = strings.Replace(ConfLogFile, "<DISK_LIMIT>", Settings.Limit_Size_Log_Storage, -1)
	ConfLogFile = strings.Replace(ConfLogFile, "<LOGFILE_MAX_SIZE>", Settings.Maxsize_Per_Logfile, -1)
	ConfLogFile = strings.Replace(ConfLogFile, "<LOGFILE_LOCATION>", Settings.Logfile_Path+"/app.log", -1)
	ConfLogFile = strings.Replace(ConfLogFile, "<ERRORLOGFILE_LOCATION>", Settings.Err_Logfile_Path+"/app_err.log", -1)

	Whole_Config_File += ConfLogFile

	ConfStatistics = strings.Replace(ConfStatistics, "<STATISTICS_INTERVAL>", Settings.Statistic_Collection_Cycle, -1)

	Whole_Config_File += ConfStatistics

	ConfNode = strings.Replace(ConfNode, "<Node_BUFF_SIZE>", Settings.Bridge_Buf_Size, -1)

	encrypt := "none"
	if Settings.Encrypt_Mode == "None" {
		encrypt = "none"
	} else if Settings.Encrypt_Mode == "AES_128" {
		encrypt = "aes128"
	} else if Settings.Encrypt_Mode == "AES_256" {
		encrypt = "aes256"
	} else if Settings.Encrypt_Mode == "RC4" {
		encrypt = "rc4"
	} else {
	}

	ConfNode = strings.Replace(ConfNode, "<Node_ENCRYPT>", encrypt, -1)

	if Settings.Change_Client_IP == "Disable" {
		Settings.Change_Client_IP = "disable"
	} else {
		Settings.Change_Client_IP = "enable"
	}
	ConfNode = strings.Replace(ConfNode, "<CHANGE_IP_FUNC>", Settings.Change_Client_IP, -1)

	Whole_Config_File += ConfNode

	if Settings.KMS_Address != "" && Settings.KMS_Port != "" {
		strings.TrimLeft(Settings.KMS_Port, "0")
		ConfKMS = strings.Replace(ConfKMS, "<KMS_ADDR_PORT>", "http://"+Settings.KMS_Address+":"+Settings.KMS_Port, -1)
	} else {
		ConfKMS = strings.Replace(ConfKMS, "<KMS_ADDR_PORT>", "", -1)
	}

	Whole_Config_File += ConfKMS

	for i := range Settings.SiteList {
		TempConfFrontend = strings.Replace(ConfFrontend, "<SYMBOL_NAME>", Settings.SiteList[i].Frontendsymbol, -1)
		TempConfFrontend = strings.Replace(TempConfFrontend, "<FRONTEND_BIND>", Settings.SiteList[i].FrontendPort, -1)

		Node_Mode, _ := strconv.Atoi(Settings.SiteList[i].NodeMode)
		if Node_Mode == Node_MODE_CLIENT {
			Node_Mode_Str = "client"
		} else if Node_Mode == Node_MODE_SERVER {
			Node_Mode_Str = "server"
		} else {
			Node_Mode_Str = Settings.SiteList[i].NodeMode
		}

		TempConfFrontend = strings.Replace(TempConfFrontend, "<Node_MODE>", Node_Mode_Str, -1)

		BackendList = ""
		for j := range Settings.SiteList[i].Backend {

			if len(BackendList) > 0 {
				BackendList += ", "
			}
			if Settings.SiteList[i].Backend[j].LAN_Interface == "OS_Default" {
				Settings.SiteList[i].Backend[j].LAN_Interface = ""
			}
			BackendList += "\"" + Settings.SiteList[i].Backend[j].LAN_Interface + "/" + Settings.SiteList[i].Backend[j].BackendIP + ":" + Settings.SiteList[i].Backend[j].BackendPort + "\""
		}
		TempConfBackend = strings.Replace(ConfBackend, "<SYMBOL_NAME>", Settings.SiteList[i].Frontendsymbol, -1)
		TempConfBackend = strings.Replace(TempConfBackend, "<LANID_SERVER_IP_PORT>", BackendList, -1)
		Frontend_Config += TempConfFrontend
		Backend_Config += TempConfBackend
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

	err = sqlitedb_lib.DB_Commit(tx)
	if err != nil {
		log.Println("Commit Fail!:", err)
		return DB_RET_FAIL, err
	}

	return DB_RET_SUCC, nil
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

func UpdateNodeFiles(Settings SettingsInformation) (int32, error) {
	var fd *os.File
	var EncText string
	var err error
	var CRLF string
	var ConfNodeID string

	err = os.MkdirAll("./cfg", 0644)
	if err != nil {
		return DB_RET_FAIL, err
	}

	fd, err = os.Create("./cfg/nodeid.key")
	if err != nil {
		return DB_RET_FAIL, err
	}
	defer fd.Close()

	if runtime.GOOS == "linux" {
		CRLF = "\n"
	} else if runtime.GOOS == "windows" {
		CRLF = "\r\n"
	}

	ConfNodeID += "[NodeID]" + CRLF
	ConfNodeID += "NodeID = \"<NODE_ID>\"" + CRLF
	ConfNodeID += CRLF

	ConfNodeID = strings.Replace(ConfNodeID, "<NODE_ID>", Settings.Node_ID, -1)

	EncryptEncodingStr(ConfNodeID, &EncText)

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
func WebServer_Update_Settings(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()

	var Settings SaveParamsSettingsInformation
	var ctrlSeqNo, localSeqNo, seqNo int64
	var err error

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	bodyData, _ := ioutil.ReadAll(req.Body)
	log.Println("update_setting: json=", string(bodyData))
	err = json.Unmarshal(bodyData, &Settings)
	if err != nil {
		log.Println("error Settings json parser:", Settings)
		goto err_res
	}

	if Settings.Pv_rsp_code != "" {
		if Settings.Pv_rsp_code != "200" {
			log.Println("error Pv_rsp_code Settings:", err)
			goto err_res
		}

		ctrlSeqNo, err = strconv.ParseInt(Settings.Pv_rsp_seq, 10, 64)
		if err != nil {
			log.Println("error parser pv_rsp_seq Settings:", err)
			goto err_res
		}

		localSeqNo, err = GetLocalSyncSeqNo(Database, "ConfigData")
		if err != nil {
			log.Println("error GetLocalSyncSeqNo():", err)
			goto err_res
		}

		if localSeqNo < ctrlSeqNo {
			log.Println("Need to update configdata")
			seqNo = ctrlSeqNo
		} else {
			log.Println("Not need to update configdata")
			goto err_res
		}
	}

	_, err = UpdateConfigFiles(Database, Settings.Params, seqNo)
	if err != nil {
		log.Println("UpdateConfigFile err:", err)
		goto err_res
	}

	_, err = UpdateNodeFiles(Settings.Params)
	if err != nil {
		log.Println("UpdateNodeFile err:", err)
		goto err_res
	}

	_, err = GetProxyInfos()
	if err != nil {
		log.Println("GetProxyInfo err:", err)
		goto err_res
	}

	_, err = GetNodeModes()
	if err != nil {
		log.Println("GetNodeMode err:", err)
		goto err_res
	}

	{
		w.Header().Set("Content-Type", "application/json")
		result := "{\"code\":\"200\", \"message\": \"success\"}"
		w.Write([]byte(result))
	}
	return

err_res:
	{
		w.Header().Set("Content-Type", "application/json")
		result := "{\"code\":\"652\", \"message\": \"failed to save\"}"
		w.Write([]byte(result))
	}
	return
}

func WebServer_Settings(w http.ResponseWriter, req *http.Request, db *sql.DB) {
	var tmpl *template.Template
	var SetPageInfo SettingPageInfo
	var TempStr string
	var cfginfo Settingtoml
	var cfgdataStr string
	var TempHTML HTMLType
	var UseEnc, UseChangeIP int
	var nodeidinfo NodeIDtoml
	var nodeiddataStr string
	var Symbol_Name /*, Server*/ string
	var Bind, Node_Mode int
	var kmsserveraddr []string
	var NICName, ProxyIP, ProxyPort string
	var NIC_Name_Len, ProxyIP_Len int
	var Frontendname, Backendname string
	var Frontendelm frontendSection
	var Backendelm backendSection
	var OptionStr string
	var BackendList, IDTagStart, IDTagEnd, HRTag, Button string
	var count int
	var FrontBack_Data_Count int
	var StatSendFlag int
	var MacArrary []string
	var MacTotalString string

	log.Println("Setting", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

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
		QueryStr := fmt.Sprintf("SELECT Stat_StatServerIP,Stat_StatServerPort,Stat_StatDataSendCycle,Stat_Send_Flag FROM Users;")
		Rows, _ := sqlitedb_lib.Query_DB(db, QueryStr)
		defer func() {
			if Rows != nil {
				Rows.Close()
			}
		}()
		if Rows == nil {
			return
		}
		var Control_Server_Port string
		var Control_Server_Send_Interval string
		for Rows.Next() {
			err := Rows.Scan(&SetPageInfo.Control_Server_IP, &Control_Server_Port, &Control_Server_Send_Interval, &StatSendFlag)
			if err != nil {
				log.Println(" data Scan error:", err)
				return
			}
		}

		SetPageInfo.Control_Server_Port, _ = strconv.Atoi(Control_Server_Port)
		SetPageInfo.Control_Server_Send_Interval, _ = strconv.Atoi(Control_Server_Send_Interval)
		Rows.Close()

		cfgdata, err := ioutil.ReadFile("./cfg/app.cfg")
		if err != nil {
			log.Println(err)
		}

		cfgdataStr = AESDecryptDecodeValuePrefix(string(cfgdata))

		if _, err = toml.Decode(cfgdataStr, &cfginfo); err != nil {
			log.Println(err)
		}

		logPath := strings.Replace(cfginfo.Logfile.Log, "/app.log", "", -1)
		logFileName := "app.log"
		logErrPath := strings.Replace(cfginfo.Logfile.Error, "/app_err.log", "", -1)
		logErrFileName := "app_err.log"

		SetPageInfo.Max_Conn, _ = strconv.Atoi(cfginfo.Global.Max_conn)
		SetPageInfo.Recv_Buffer_Size, _ = strconv.Atoi(cfginfo.Global.Recv_buffer_size)
		SetPageInfo.Send_Buffer_Size, _ = strconv.Atoi(cfginfo.Global.Send_buffer_size)
		SetPageInfo.Timeout_Connect, _ = strconv.Atoi(cfginfo.Global.Timeout_connect)
		SetPageInfo.Timeout_Client, _ = strconv.Atoi(cfginfo.Global.Timeout_client)
		SetPageInfo.Timeout_Server, _ = strconv.Atoi(cfginfo.Global.Timeout_server)

		SetPageInfo.Disk_Limit, _ = strconv.Atoi(cfginfo.Logfile.Disk_limit)
		cfginfo.Logfile.Max_size = strings.TrimRight(cfginfo.Logfile.Max_size, "MB")
		SetPageInfo.Max_Size, _ = strconv.Atoi(cfginfo.Logfile.Max_size)
		SetPageInfo.Log = logPath
		SetPageInfo.LogFileName = logFileName
		SetPageInfo.Error = logErrPath
		SetPageInfo.ErrorFileName = logErrFileName

		SetPageInfo.Interval, _ = strconv.Atoi(cfginfo.Statistics.Interval)

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

		SetPageInfo.Buffer_Size, _ = strconv.Atoi(cfginfo.Node.Buffer_size)

		if cfginfo.Node.Encrypt == "none" {
			UseEnc = 0
		} else if cfginfo.Node.Encrypt == "aes128" {
			UseEnc = 1
		} else if cfginfo.Node.Encrypt == "aes256" {
			UseEnc = 2
		} else if cfginfo.Node.Encrypt == "rc4" {
			UseEnc = 3
		}

		if cfginfo.Node.Cp_tunneling == "disable" {
			UseChangeIP = DISABLE
		} else {
			UseChangeIP = ENABLE
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

		nodeiddata, err := ioutil.ReadFile("./cfg/nodeid.key")
		if err != nil {
			log.Println(err)
		}

		if _, err := os.Stat("./cfg/nodeid.key"); os.IsNotExist(err) {
			log.Println("not exist nodeidinfo")
		} else {
			nodeiddataStr = string(nodeiddata)
			nodeiddataStr = AESDecryptDecodeValuePrefix(nodeiddataStr)
			if _, err = toml.Decode(nodeiddataStr, &nodeidinfo); err != nil {
				log.Println(err)
			}
			SetPageInfo.Node_ID = nodeidinfo.NodeID.NodeID
		}

		if cfginfo.KMS.Url != "" {
			cfginfo.KMS.Url = strings.TrimLeft(cfginfo.KMS.Url, "http://")
			kmsserveraddr = strings.Split(cfginfo.KMS.Url, ":")
			SetPageInfo.KMS_Address = kmsserveraddr[0]
			SetPageInfo.KMS_Port, _ = strconv.Atoi(kmsserveraddr[1])
		}

		for _, _ = range cfginfo.Frontend {
			FrontBack_Data_Count++
		}

		for Frontendname, Frontendelm = range cfginfo.Frontend {
			count++
			Symbol_Name = Frontendname

			arrbind := strings.Split(Frontendelm.Bind, ":")
			if len(arrbind) > 1 {
				Bind, _ = strconv.Atoi(arrbind[1])
			} else {
				Bind, _ = strconv.Atoi(arrbind[0])
			}

			//Server = Frontendelm.Backend
			//log.Println("Server:", Server)
			if Frontendelm.Node_Mode == "client" {
				Node_Mode = 1
			} else if Frontendelm.Node_Mode == "server" {
				Node_Mode = 2
			} else {
				Node_Mode = 0
			}

			BackendList = ""
			for Backendname, Backendelm = range cfginfo.Backend {
				if Backendname == Frontendname {
					for _, Serveraddr := range Backendelm.Server {
						NIC_Name_Len = strings.Index(Serveraddr, "/")
						NICName = Serveraddr[0:NIC_Name_Len]
						Serveraddr = Serveraddr[NIC_Name_Len+1:]

						ProxyIP_Len = strings.Index(Serveraddr, ":")
						ProxyIP = Serveraddr[0:ProxyIP_Len]
						Serveraddr = Serveraddr[ProxyIP_Len+1:]

						ProxyPort = Serveraddr
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
				}
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

		//---[ Provisioning Protocol Must Value ]----------------------------------------------------{
		authData, err := GetAuthData()
		if err != nil {
			log.Println(err)
			return
		}

		MacArrary, _ = GetNICMAC()
		if MacArrary != nil {
			MacTotalString = strings.Join(MacArrary, "-")
			log.Println("Mac:", MacTotalString)
		}

		SetPageInfo.PV_Version = "1.0"
		SetPageInfo.PV_Method = "Auth"
		SetPageInfo.PV_SessionType = "ConfigData"
		SetPageInfo.PV_MessageType = "request"
		SetPageInfo.PV_UserKey = authData.UserKey
		SetPageInfo.PV_NodeID = authData.NodeID
		SetPageInfo.PV_MacTotalString = MacTotalString
		if len(SetPageInfo.Control_Server_IP) > 0 && SetPageInfo.Control_Server_Port != 0 {
			SetPageInfo.PV_ControlServerAddress = fmt.Sprintf("http://%s:%d", SetPageInfo.Control_Server_IP, SetPageInfo.Control_Server_Port)
		} else {
			SetPageInfo.PV_ControlServerAddress = ""
		}

		syncSeqNo, err := GetLocalSyncSeqNo(db, "ConfigData")
		SetPageInfo.PV_CurrentSeq = strconv.FormatInt(syncSeqNo, 10)
		SetPageInfo.PV_NextSeq = strconv.FormatInt(syncSeqNo+1, 10)
		//-------------------------------------------------------------------------------------------}

		tmpl, err = template.ParseFiles("./pages/Node_Setting.html")
		if err != nil {
			log.Println("failed to template.ParseFiles")
			log.Println("1124/Release Lock")
			return
		}
		tmpl.Execute(w, SetPageInfo)
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
		TempStr = fmt.Sprintf("<li><a href=\"/node_cfg_list/\">Node Setting List</a></li>")
		StatPageInfo.NodeSettingsList = template.HTML(TempStr)
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
func Insert_License(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	var licenseinfo tomlinfo
	var licdataStr string
	var licfilename LicenseFileName
	var isinsertlic IsInsertLic
	Decoder := json.NewDecoder(req.Body)
	err := Decoder.Decode(&licfilename)
	if err != io.EOF {
		if err != nil {
			log.Println("error:", err)
		}
	}
	log.Println("licfilename value:", licfilename.FileName)

	licensedata, err := ioutil.ReadFile("./" + licfilename.FileName)
	if err != nil {
		log.Println("error:", err)
		isinsertlic.Result = "Fail"
		jstrbyte, _ := json.Marshal(isinsertlic)
		OutputBody := string(jstrbyte)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

	} else {

		licdataStr = AESDecryptDecodeValuePrefix(string(licensedata))

		if _, err := toml.Decode(licdataStr, &licenseinfo); err != nil {
			log.Fatal(err)
		}

		DB_Flag, _ := mariadb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS Node_ID_List (Node_ID Text)")
		if DB_RET_FAIL == DB_Flag {
			log.Println("Create Table Fail!")
		}
		log.Println("DB_Flag:", DB_Flag)

		DelDataStr := fmt.Sprint("DELETE FROM Node_ID_List")

		DB_Flag_2, _ := sqlitedb_lib.Delete_Data(Database, DelDataStr)
		if DB_RET_FAIL == DB_Flag {
			log.Println("sqlitedb Delete error!")
		}
		log.Println("DB_Flag:", DB_Flag_2)

		for i := range licenseinfo.NodeID.NodeID {
			InsertDataStr := fmt.Sprintf("INSERT INTO Node_ID_List (Node_ID) VALUES('%s')", licenseinfo.NodeID.NodeID[i])

			DB_Flag, _ := sqlitedb_lib.Insert_Data(Database, InsertDataStr)
			if DB_RET_FAIL == DB_Flag {
				log.Println("sqlitedb Insert Fail!")
			}
		}
		isinsertlic.Result = "Succ"
		jstrbyte, _ := json.Marshal(isinsertlic)
		OutputBody := string(jstrbyte)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

		err = os.Remove("./" + licfilename.FileName)
		if err != nil {
			log.Println("remove  error:", err)
		}

	}

}

func WebServer_Web_Popup_Parent_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlTemplate *template.Template
	var err error

	log.Println("Web Server - WebServer_Web_Upload_File_Input", req.Method)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	HtmlTemplate, err = template.ParseFiles("./pages/popup_parent_input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./pages/popup_parent_input.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, "")
}

func WebServer_Web_Popup_Child_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var poppageinfo PopupPageInfo
	var popnodeidlist PopupNodeIDInfo
	var HtmlTemplate *template.Template
	var report_result string
	var report_nodeid_list string
	var report_enddate string
	var report_filename string
	var err error
	var NodeID []string
	log.Println("Web Server - WebServer_Web_Upload_File_Input", req.Method)

	if req.Method == "POST" {
		req.ParseForm()

		report_result = fmt.Sprintf("%s", req.Form["report_result"])
		report_result = strings.Replace(report_result, "[", "", -1)
		report_result = strings.Replace(report_result, "]", "", -1)
		report_result = strings.TrimSpace(report_result)

		report_nodeid_list = fmt.Sprintf("%s", req.Form["report_nodeid_list"])
		report_nodeid_list = strings.Replace(report_nodeid_list, "[", "", -1)
		report_nodeid_list = strings.Replace(report_nodeid_list, "]", "", -1)
		report_nodeid_list = strings.TrimSpace(report_nodeid_list)

		report_enddate = fmt.Sprintf("%s", req.Form["report_enddate"])
		report_enddate = strings.Replace(report_enddate, "[", "", -1)
		report_enddate = strings.Replace(report_enddate, "]", "", -1)
		report_enddate = strings.TrimSpace(report_enddate)

		report_filename = fmt.Sprintf("%s", req.Form["report_filename"])
		report_filename = strings.Replace(report_filename, "[", "", -1)
		report_filename = strings.Replace(report_filename, "]", "", -1)
		report_filename = strings.TrimSpace(report_filename)
		log.Println(">>> Web Server - Input POST Value - report_result:", report_result, ", report_nodeid_list:", report_nodeid_list, ", report_enddate:", report_enddate, ", report_filename:", report_filename)
	}

	if report_nodeid_list != "" {
		NodeID = strings.Split(report_nodeid_list, ",")

		for i := range NodeID {
			NodeID[i] = strings.Replace(NodeID[i], "\"", "", -1)
			popnodeidlist.Nodeid_list = template.HTML("<li> " + strconv.Itoa(i+1) + ". " + NodeID[i] + "</li>")
			poppageinfo.Nodeid_list = append(poppageinfo.Nodeid_list, popnodeidlist)

		}
	}
	poppageinfo.EndDate = report_enddate
	poppageinfo.FileName = report_filename
	poppageinfo.Result = report_result

	HtmlTemplate, err = template.ParseFiles("./pages/popup_child_input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./pages/popup_child_input.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, poppageinfo)
}

func WebServer_Web_Auth_API_Config_Upload_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlTemplate *template.Template
	var err error

	log.Println("Web Server - WebServer_Web_Auth_API_Test_Input", req.Method)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	HtmlTemplate, err = template.ParseFiles("./pages/WEB_API_Auth_Config_Upload_Input.html")
	if err != nil {
		log.Println("failed to template.ParseFiles (./pages/WEB_API_Auth_Config_Upload_Input.html)")
		WebServer_Redirect(w, req, "/service_stop/")
		return
	}

	HtmlTemplate.Execute(w, "")
}
func WebServer_Web_Upload_File_Proc(w http.ResponseWriter, req *http.Request) {
	fmt.Println("File Upload Endpoint Hit")
	var licinfo tomlinfo
	var licensedataup LicenseUploadData
	var nodeliststr string
	var Newlicfilename string
	req.ParseMultipartForm(10 << 20)
	if LicenseFileSN == 10000 {
		LicenseFileSN = 1
	}
	file, handler, err := req.FormFile("myFile")
	if err != nil {
		fmt.Println("Error Retrieving the File")
		fmt.Println(err)
		WebServer_Redirect(w, req, "/license/?page_num=1&sort=0")
		return
	}
	defer file.Close()

	if handler.Filename != "license_linux.lic" && handler.Filename != "license_windows.lic" {

		HtmlTemplate, err := template.ParseFiles("./pages/popup_parent_proc.html")
		if err != nil {
			log.Println("failed to template.ParseFiles (./pages/popup_parent_proc.html)")
			WebServer_Redirect(w, req, "/service_stop/")
			return
		}
		licensedataup.Result = "Invalid File"
		licensedataup.Nodeid_list = ""
		licensedataup.EndDate = ""
		licensedataup.FileName = ""
		HtmlTemplate.Execute(w, licensedataup)
	} else {
		Newlicfilename = "license_linux_" + strconv.Itoa(LicenseFileSN) + ".lic"
		tempFile, err := os.Create("./" + Newlicfilename)
		if err != nil {
			log.Println("Create file err:", err)
		}
		defer tempFile.Close()
		LicenseFileSN++

		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println(err)
		}

		if strings.HasPrefix(string(fileBytes), "COD$_") == false {
			log.Println("COD$_ is not here")
			licensedataup.Result = "Fail"
			licensedataup.Nodeid_list = ""
			licensedataup.EndDate = ""
			licensedataup.FileName = ""
		} else {

			PlainText := AESDecryptDecodeValuePrefix(string(fileBytes))

			if _, err := toml.Decode(PlainText, &licinfo); err != nil {
				log.Println("Decode Error:", err)
			}

			for i := range licinfo.NodeID.NodeID {
				nodeliststr += "\"" + licinfo.NodeID.NodeID[i] + "\","
			}
			nodeliststr = strings.TrimRight(nodeliststr, ",")
			licensedataup.Nodeid_list = nodeliststr
			licensedataup.Result = "Succ"
			licensedataup.EndDate = licinfo.UserKey.EndDateYear + "." + licinfo.UserKey.EndDateMonth + "." + licinfo.UserKey.EndDateDay
			licensedataup.FileName = Newlicfilename
			tempFile.Write(fileBytes)
		}

		if err != nil {
			log.Println("failed to template.ParseFiles (./pages/upload_file_result.html)")
			WebServer_Redirect(w, req, "/service_stop/")
			return
		}

		HtmlTemplate, err := template.ParseFiles("./pages/popup_parent_proc.html")
		if err != nil {
			log.Println("failed to template.ParseFiles (./pages/popup_parent_proc.html)")
			WebServer_Redirect(w, req, "/service_stop/")
			return
		}

		HtmlTemplate.Execute(w, licensedataup)
	}
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

func AESDecryptDecodeValuePrefix(InputText string) string {
	if strings.HasPrefix(InputText, "COD$_") == true {
		InputText = strings.TrimLeft(InputText, "COD$_")
		return AESDecryptDecodeValue(InputText)
	}

	return InputText
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

func WebServer_Web_Auth_API_Session_Encode_Value(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var InputData jsonInputWebAPIEncodeValue
	var OutputData jsonOutputWebAPIEncodeValue
	var OutputBody string
	var EncryptValue string
	var DecryptValue string
	var err error

	log.Println("WebServer_Web_Auth_API_Session_Encode_Value", req.Method)

	res := Cookie_Check(w, req)
	if res < 0 {
		OutputData.Code = "600"
		OutputData.Message = "no existed cookie"
		OutputData.InputValue = ""
		OutputData.OutputValue = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")

		w.Write([]byte(OutputBody))
		return
	}

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

type jsonInputWebAPIAuthTokenPack struct {
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	UserKey     string `json:"userkey"`
	AuthKey     string `json:"authkey"`
}

type jsonOutputWebAPIAuthTokenPack struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	InputValue  string `json:"input"`
	OutputValue string `json:"output"`
}

func WebServer_Web_Auth_API_Session_AuthToken(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var InputData jsonInputWebAPIAuthTokenPack
	var OutputData jsonOutputWebAPIAuthTokenPack
	var OutputBody string
	var HashingText string
	var HA1 string
	var HA2 string
	var Response string
	var err error

	log.Println("WebServer_Web_Auth_API_Session_AuthToken", req.Method)

	res := Cookie_Check(w, req)
	if res < 0 {
		OutputData.Code = "600"
		OutputData.Message = "no existed cookie"
		OutputData.InputValue = ""
		OutputData.OutputValue = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")

		w.Write([]byte(OutputBody))
		return
	}

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

	if req.Method != "POST" {
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

	log.Println(">>> Input Data : [method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", userkey:" + InputData.UserKey + ", authkey:" + InputData.AuthKey + "]")

	if InputData.Method == "" || InputData.SessionType == "" || InputData.UserKey == "" || InputData.AuthKey == "" {
		log.Println("invalid parmeter value: null")
		OutputData.Code = "600"
		OutputData.Message = "parmeter value is null"
		OutputData.InputValue = ""
		OutputData.OutputValue = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")

		w.Write([]byte(OutputBody))
		return
	}

	if InputData.Method != "Auth" || InputData.SessionType != "ConfigData" {
		log.Println("invalid parmeter value: not supported value")

		OutputData.Code = "600"
		OutputData.Message = "not supported parmeter value"
		OutputData.InputValue = ""
		OutputData.OutputValue = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")

		w.Write([]byte(OutputBody))
		return
	}

	hashing_algorithm := md5.New()
	HashingText = InputData.UserKey + ":" + InputData.SessionType
	hashing_algorithm.Write([]byte(HashingText))
	HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))

	hashing_algorithm = md5.New()
	HashingText = InputData.Method + ":" + "/auth_api/provisioning/v1.0/"
	hashing_algorithm.Write([]byte(HashingText))
	HA2 = hex.EncodeToString(hashing_algorithm.Sum(nil))

	hashing_algorithm = md5.New()
	HashingText = HA1 + ":" + InputData.AuthKey + ":" + HA2
	hashing_algorithm.Write([]byte(HashingText))
	Response = hex.EncodeToString(hashing_algorithm.Sum(nil))

	if Response != "" {

		OutputData.Code = "200"
		OutputData.Message = "authtoken"
		OutputData.InputValue = ""
		OutputData.OutputValue = Response

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")

		w.Write([]byte(OutputBody))

		log.Printf("web api response [userkey:%s] [code:%s, msg:%s, description:%s (authkey:%s, authtoken:%s)]", InputData.UserKey, OutputData.Code, OutputData.Message, "authtoken", InputData.AuthKey, Response)

		return

	} else {

		OutputData.Code = "600"
		OutputData.Message = "failed to generate auth token"
		OutputData.InputValue = ""
		OutputData.OutputValue = ""

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Content-Type", "application/json")

		w.Write([]byte(OutputBody))
		return
	}
}

func GetNICMAC() ([]string, error) {
	var as []string

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Print(err)
		return nil, err
	}

	for _, i := range ifaces {

		addr := i.HardwareAddr.String()
		if addr != "" {
			as = append(as, addr)
		}
	}

	return as, nil
}

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
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
	Version     string      `json:"version"`
	Method      string      `json:"method"`
	SessionType string      `json:"sessiontype"`
	MessageType string      `json:"msgtype"`
	UserKey     string      `json:"userkey"`
	NodeID      string      `json:"nodeid"`
	IP          string      `json:"ip"`
	MACTotal    string      `json:"mactotal"`
	AuthKey     string      `json:"authkey"`
	AuthToken   string      `json:"authtoken"`
	Data        interface{} `json:"data"`
}

type jsonOutputWebAPIAuthProvisioningPack struct {
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

var AuthProvisioningSeqNo = 1
var AuthStatisticsSeqNo = 1

func ProvisioningUploadDBSetTransaction(Database *sql.DB, InputData *jsonInputWebAPIAuthProvisioningPack, OutputData *jsonOutputWebAPIAuthProvisioningPack, proviReq *ProvisionProtocol, userKeySeq int64) int {
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryString string
	var NewNodeIDSeq int64
	var NewBackendSeq int64
	var err error

	log.Println("init node information setting :", InputData.NodeID)

	tx, err = mariadb_lib.DB_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return 0
	}
	defer mariadb_lib.DB_Rollback(tx)

	QueryString = "INSERT INTO NodeIDTbl (SeqUserKey, Password, VerifyingPassword, Global_MaxConn, Global_RecvBufferSize, Global_SendBufferSize, " +
		"Global_TimeoutConnect, Global_TimeoutClient, Global_TimeoutServer, " +
		"Log_DiskLimit, Log_MaxSize, Log_LogDir, Log_LogName, Log_ErrDir, Log_ErrName, " +
		"Stat_SendControlServerFlag, Stat_StatCollectionCycle, Stat_StatSendControlServer, Stat_StatServerIP, Stat_StatServerPort, Stat_StatDataSendCycle, " +
		"Node_UseBridgeRouter, Node_NodeBufferSize, Node_EncryptMode, Node_ChangeIPClientMode, Node_NodeID, " +
		"KMS_IP, KMS_Port) " +
		"VALUES (?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, " +
		"?, ?) "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(userKeySeq, proviReq.Body.Data.Password, proviReq.Body.Data.VerifyingPassword, proviReq.Body.Data.Maximum_ConnectionCount, proviReq.Body.Data.Recv_Buf_Size, proviReq.Body.Data.Send_Buf_Size,
		proviReq.Body.Data.Connection_Timeout, proviReq.Body.Data.Client_Reconnect_Timeout, proviReq.Body.Data.Server_Reconnect_Timeout,
		proviReq.Body.Data.Limit_Size_Log_Storage, proviReq.Body.Data.Maxsize_Per_Logfile, proviReq.Body.Data.Logfile_Path, "app.log", proviReq.Body.Data.Err_Logfile_Path, "app_err.log",
		proviReq.Body.Data.Statistic_Send_Control_Server, proviReq.Body.Data.Statistic_Collection_Cycle, proviReq.Body.Data.Statistic_Server_Ip, proviReq.Body.Data.Statistic_Server_Ip, proviReq.Body.Data.Statistic_Server_Port, proviReq.Body.Data.Statistic_Send_Cycle,
		proviReq.Body.Data.Bridge_Used, proviReq.Body.Data.Bridge_Buf_Size, proviReq.Body.Data.Encrypt_Mode, proviReq.Body.Data.Change_Client_IP, proviReq.Body.Data.Node_ID,
		proviReq.Body.Data.KMS_Address, proviReq.Body.Data.KMS_Port)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	QueryString = "SELECT Seq FROM NodeIDTbl WHERE Node_NodeID = ? "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Exec Fail!:", err)
		return 0
	}

	err = stmt.QueryRow(InputData.NodeID).Scan(&NewNodeIDSeq)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err, ", nodeid:", InputData.NodeID)
		return 0
	}
	//ResultSetRows.Close()
	stmt.Close()

	for _, frontend := range proviReq.Body.Data.SiteList {

		QueryString = "INSERT INTO NodeIDFrontendTbl (SeqNodeID, Name, NicName, Bind, Backend, NodeMode) " +
			"VALUES (?, ?, ?, ?, ?, ?) "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		if frontend.NodeMode == "1" {
			_, err = stmt.Exec(NewNodeIDSeq, frontend.Frontendsymbol, "", frontend.FrontendPort, frontend.Frontendsymbol, "client")
		} else if frontend.NodeMode == "2" {
			_, err = stmt.Exec(NewNodeIDSeq, frontend.Frontendsymbol, "", frontend.FrontendPort, frontend.Frontendsymbol, "server")
		} else {
			_, err = stmt.Exec(NewNodeIDSeq, frontend.Frontendsymbol, "", frontend.FrontendPort, frontend.Frontendsymbol, "client")
		}

		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()

		QueryString = "INSERT INTO NodeIDBackendTbl (SeqNodeID, Name) " +
			"VALUES (?, ?) "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		_, err = stmt.Exec(NewNodeIDSeq, frontend.Frontendsymbol)
		if err != nil {
			stmt.Close()
			return 0
		}
		stmt.Close()

		QueryString = "SELECT Seq FROM NodeIDBackendTbl WHERE SeqNodeID = ? AND Name = ? "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return 0
		}

		err = stmt.QueryRow(NewNodeIDSeq, frontend.Frontendsymbol).Scan(&NewBackendSeq)
		if err != nil {
			stmt.Close()
			return 0
		}
		//ResultSetRows.Close()
		stmt.Close()

		for _, backend := range frontend.Backend {
			QueryString = "INSERT INTO NodeIDBackendAddressTbl (SeqNodeID, SeqBackend, NicName, IP, Port) " +
				"VALUES (?, ?, ?, ?, ?) "
			stmt, err = tx.Prepare(QueryString)
			if err != nil {
				log.Println("Prepare Fail!:", err)
				return 0
			}

			_, err = stmt.Exec(NewNodeIDSeq, NewBackendSeq, backend.LAN_Interface, backend.BackendIP, backend.BackendPort)
			if err != nil {
				stmt.Close()
				return 0
			}
			stmt.Close()
		}
	}

	QueryString = "INSERT INTO CWS_SyncSeqNoTbl (SeqNodeID, SeqNoName, SeqNo) " +
		"VALUES (?, ?, ?) "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(NewNodeIDSeq, InputData.SessionType, proviReq.Header.Seq)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	mariadb_lib.DB_Commit(tx)
	return 1
}

func ProvisioningUploadDBUpdateTransaction(Database *sql.DB, InputData *jsonInputWebAPIAuthProvisioningPack, OutputData *jsonOutputWebAPIAuthProvisioningPack, proviReq *ProvisionProtocol, nodeIDSeq int64) int {
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryString string
	var NewBackendSeq int64
	var err error

	log.Println("update node information setting :", InputData.NodeID)

	tx, err = mariadb_lib.DB_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return 0
	}
	defer mariadb_lib.DB_Rollback(tx)

	QueryString = "UPDATE NodeIDTbl SET " +
		"Password = ?, VerifyingPassword = ?, Global_MaxConn = ?, Global_RecvBufferSize = ?, Global_SendBufferSize = ?, " +
		"Global_TimeoutConnect = ?, Global_TimeoutClient = ?, Global_TimeoutServer = ?, " +
		"Log_DiskLimit = ?, Log_MaxSize = ?, Log_LogDir = ?, Log_LogName = ?, Log_ErrDir = ?, Log_ErrName = ?, " +
		"Stat_SendControlServerFlag = ?, Stat_StatCollectionCycle = ?, Stat_StatSendControlServer = ?, Stat_StatServerIP = ?, Stat_StatServerPort = ?, Stat_StatDataSendCycle = ?, " +
		"Node_UseBridgeRouter = ?, Node_NodeBufferSize = ?, Node_EncryptMode = ?, Node_ChangeIPClientMode = ?, Node_NodeID = ?, " +
		"KMS_IP = ?, KMS_Port = ? " +
		"WHERE Seq = ? "
	log.Println("Query:", QueryString)

	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(proviReq.Body.Data.Password, proviReq.Body.Data.VerifyingPassword, proviReq.Body.Data.Maximum_ConnectionCount, proviReq.Body.Data.Recv_Buf_Size, proviReq.Body.Data.Send_Buf_Size,
		proviReq.Body.Data.Connection_Timeout, proviReq.Body.Data.Client_Reconnect_Timeout, proviReq.Body.Data.Server_Reconnect_Timeout,
		proviReq.Body.Data.Limit_Size_Log_Storage, proviReq.Body.Data.Maxsize_Per_Logfile, proviReq.Body.Data.Logfile_Path, "app.log", proviReq.Body.Data.Err_Logfile_Path, "app_err.log",
		proviReq.Body.Data.Statistic_Send_Control_Server, proviReq.Body.Data.Statistic_Collection_Cycle, proviReq.Body.Data.Statistic_Server_Ip, proviReq.Body.Data.Statistic_Server_Ip, proviReq.Body.Data.Statistic_Server_Port, proviReq.Body.Data.Statistic_Send_Cycle,
		"N", proviReq.Body.Data.Bridge_Buf_Size, proviReq.Body.Data.Encrypt_Mode, proviReq.Body.Data.Change_Client_IP, proviReq.Body.Data.Node_ID,
		proviReq.Body.Data.KMS_Address, proviReq.Body.Data.KMS_Port,
		nodeIDSeq)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	QueryString = "DELETE FROM NodeIDFrontendTbl WHERE SeqNodeID = ? "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(nodeIDSeq)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	QueryString = "DELETE FROM NodeIDBackendTbl WHERE SeqNodeID = ? "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(nodeIDSeq)
	if err != nil {
		stmt.Close()
		return 0
	}
	stmt.Close()

	QueryString = "DELETE FROM NodeIDBackendAddressTbl WHERE SeqNodeID = ? "
	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(nodeIDSeq)
	if err != nil {
		stmt.Close()
		return 0
	}
	stmt.Close()

	for _, frontend := range proviReq.Body.Data.SiteList {

		QueryString = "INSERT INTO NodeIDFrontendTbl (SeqNodeID, Name, NicName, Bind, Backend, NodeMode) " +
			"VALUES (?, ?, ?, ?, ?, ?) "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		if frontend.NodeMode == "1" {
			_, err = stmt.Exec(nodeIDSeq, frontend.Frontendsymbol, "", frontend.FrontendPort, frontend.Frontendsymbol, "client")
		} else if frontend.NodeMode == "2" {
			_, err = stmt.Exec(nodeIDSeq, frontend.Frontendsymbol, "", frontend.FrontendPort, frontend.Frontendsymbol, "server")
		} else {
			_, err = stmt.Exec(nodeIDSeq, frontend.Frontendsymbol, "", frontend.FrontendPort, frontend.Frontendsymbol, "client")
		}

		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()

		QueryString = "INSERT INTO NodeIDBackendTbl (SeqNodeID, Name) " +
			"VALUES (?, ?) "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		_, err = stmt.Exec(nodeIDSeq, frontend.Frontendsymbol)
		if err != nil {
			stmt.Close()
			return 0
		}
		stmt.Close()

		QueryString = "SELECT Seq FROM NodeIDBackendTbl WHERE SeqNodeID = ? AND Name = ? "
		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Exec Fail!:", err)
			return 0
		}

		err = stmt.QueryRow(nodeIDSeq, frontend.Frontendsymbol).Scan(&NewBackendSeq)
		if err != nil {
			stmt.Close()
			return 0
		}
		//ResultSetRows.Close()
		stmt.Close()

		for _, backend := range frontend.Backend {
			QueryString = "INSERT INTO NodeIDBackendAddressTbl (SeqNodeID, SeqBackend, NicName, IP, Port) " +
				"VALUES (?, ?, ?, ?, ?) "
			stmt, err = tx.Prepare(QueryString)
			if err != nil {
				log.Println("Prepare Fail!:", err)
				return 0
			}

			_, err = stmt.Exec(nodeIDSeq, NewBackendSeq, backend.LAN_Interface, backend.BackendIP, backend.BackendPort)
			if err != nil {
				stmt.Close()
				return 0
			}
			stmt.Close()
		}
	}

	QueryString = "UPDATE CWS_SyncSeqNoTbl SET " +
		"SeqNo = ? " +
		"WHERE SeqNodeID = ?  AND SeqNoName = ? "

	stmt, err = tx.Prepare(QueryString)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(proviReq.Header.Seq, nodeIDSeq, InputData.SessionType)
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	mariadb_lib.DB_Commit(tx)
	return 1
}

func WebServer_Web_Auth_API_Provisioning_Proc(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()
	var ResultSetRows *sql.Rows
	var QueryString string
	var InputData jsonInputWebAPIAuthProvisioningPack
	var OutputData jsonOutputWebAPIAuthProvisioningPack
	var OutputBody string
	var DecryptUserKey string
	var DecryptNodeID string
	var EncryptUserKey string
	var EncryptNodeID string
	var GenerateAuthKey string
	var DBAuthUserKeySeq int64
	var DBAuthUserKey string
	var DBAuthNodeIDSeq int64
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

	log.Println("WebServer_Web_Auth_API_Provisioning_Proc", req.Method, ", Client Address:", req.RemoteAddr)
	// comments: input json parsing
	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		log.Println("json parsing error:", err)
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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "10")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	//log.Println("settingData : ", InputData.Body.Data)

	// comments: checking valid http method
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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "10")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	//log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", nodeid encrypt:" + InputData.NodeID + ", mac total:" + InputData.MACTotal + ", authtoken:" + InputData.AuthToken + ", data:" + InputData.Data + "]")
	//log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", nodeid encrypt:" + InputData.NodeID + ", mac total:" + InputData.MACTotal + ", authtoken:" + InputData.AuthToken + ", data:" + InputData.Data + "]")
	log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", nodeid encrypt:" + InputData.NodeID + ", mac total:" + InputData.MACTotal + ", authtoken:" + InputData.AuthToken)

	// comments: checking madatory input value
	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.MessageType == "" || InputData.UserKey == "" || InputData.NodeID == "" || InputData.MACTotal == "" {
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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "10")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	// comments: checking valid input value
	if InputData.Version != "1.0" || InputData.Method != "Auth" || InputData.SessionType != "ConfigData" || InputData.MessageType != "request" {
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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "10")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))
		return
	}

	// comments: decrypt and base32 input userkey value
	if InputData.UserKey != "" {
		EncryptUserKey = InputData.UserKey
		DecryptUserKey = AESDecryptDecodeValue(EncryptUserKey)
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

			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "10")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))
			return
		}
		log.Printf("WEB API Auth - UserKey Decrypt Value [%s] -> [%s]", InputData.UserKey, DecryptUserKey)
		InputData.UserKey = DecryptUserKey
	}

	if InputData.NodeID != "" {
		EncryptNodeID = InputData.NodeID
		DecryptNodeID = AESDecryptDecodeValue(EncryptNodeID)
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

			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "10")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))
			return
		}
		log.Printf("WEB API Auth - NodeID Decrypt Value [%s] -> [%s]", InputData.NodeID, DecryptNodeID)
		InputData.NodeID = DecryptNodeID
	}

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
		OutputData.Version = InputData.Version
		OutputData.Method = InputData.Method
		OutputData.SessionType = InputData.SessionType
		OutputData.MsgType = "response"
		OutputData.Code = "630"
		OutputData.Message = "db connection error"
		OutputData.AuthKey = ""
		OutputData.ExpireTime = ""
		OutputData.Data = ""

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

	//--[Query: Checking UserKey]----------------------------------------------{
	QueryString = "SELECT Seq, UserKey FROM UserKeyTbl WHERE UserKey = '%s' "
	QueryString = fmt.Sprintf(QueryString, InputData.UserKey)
	log.Println("Auth UserKey Exist Query : ", QueryString)
	//-------------------------------------------------------------------------}

	ResultSetRows, err = mariadb_lib.Query_DB(Database, QueryString)
	if err != nil {
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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "10")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

		return
	}

	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&DBAuthUserKeySeq, &DBAuthUserKey)
		if err != nil {
			ResultSetRows.Close()
			log.Println("data Scan error:", err)

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

			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "10")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			return
		}
	}
	ResultSetRows.Close()

	log.Println("UserKeySeq:", DBAuthUserKeySeq, ", Userkey:", DBAuthUserKey)

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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "10")
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

			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "10")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
			return
		}

		hashing_algorithm := md5.New()
		HashingText = InputData.UserKey + ":" + InputData.SessionType
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
		hashing_algorithm.Write([]byte(HashingText))
		Response = hex.EncodeToString(hashing_algorithm.Sum(nil))
		EventValue += "[" + HashingText + " >> Response:" + Response + "]"

		//log.Println("WEB API Auth Information -> ", EventValue)

		if Response != "" {

			//--[Query: Delete Existed AuthKey & AuthToken]-------------------------------------------{
			QueryString = "DELETE FROM CWS_AuthTbl WHERE SeqUserKey = %d and NodeID = '%s' and Method = '%s' and SessionType = '%s' and IP = '%s' and MAC = '%s'"
			QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.NodeID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal)
			log.Println("CWS_AuthTbl Delete Query : ", QueryString)
			//----------------------------------------------------------------------------------------}
			_, err = mariadb_lib.Delete_Data(Database, QueryString)
			if err != nil {
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

				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
				w.Header().Set("Access-Control-Max-Age", "10")
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(OutputBody))

				return
			}

			//--[Query: Insert Temp AuthKey & AuthToken]----------------------------------------------{
			QueryString = "Insert into CWS_AuthTbl (SeqUserKey, NodeID, Method, SessionType, IP, MAC, AuthKey, AuthToken, Expiretime) " +
				"values (%d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', DATE_ADD(NOW(), INTERVAL %d SECOND)) "
			QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.NodeID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal, GenerateAuthKey, Response, OEMAuthExpiretimeInterval)
			log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
			//----------------------------------------------------------------------------------------}
			_, err = mariadb_lib.Insert_Data(Database, QueryString)
			if err != nil {
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

				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
				w.Header().Set("Access-Control-Max-Age", "10")
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(OutputBody))

				return
			}

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

			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "10")
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

			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "10")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
			return
		}

	} else if InputData.AuthKey != "" && InputData.AuthToken != "" {
		//--[Query: Checking Auth Information]-------------------------------------{
		QueryString = "SELECT AuthKey, AuthToken, TIME_TO_SEC(Expiretime), TIME_TO_SEC(NOW()) " +
			"FROM CWS_AuthTbl " +
			"WHERE SeqUserKey = %d and AuthKey = '%s' and AuthToken = '%s' and IP = '%s' and MAC = '%s' and Method = '%s' and SessionType = '%s'"
		QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.AuthKey, InputData.AuthToken, InputData.IP, InputData.MACTotal, InputData.Method, InputData.SessionType)
		//-------------------------------------------------------------------------}
		log.Println("Auth Information Checking Query : ", QueryString)

		ResultSetRows, err = mariadb_lib.Query_DB(Database, QueryString)
		if err != nil {
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

			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "10")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))
			return
		}

		for ResultSetRows.Next() {
			err = ResultSetRows.Scan(&DBAuthKey, &DBAuthToken, &DBAuthExpireTime, &DBAuthNOWTime)
			if err != nil {
				ResultSetRows.Close()
				log.Println("data Scan error:", err)

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

				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
				w.Header().Set("Access-Control-Max-Age", "10")
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(OutputBody))
				return
			}
		}
		ResultSetRows.Close()

		if DBAuthExpireTime < DBAuthNOWTime {
			//--[Query: Delete Existed AuthKey & AuthToken]-------------------------------------------{
			QueryString = "DELETE FROM CWS_AuthTbl WHERE SeqUserKey = %d and NodeID = '%s' and Method = '%s' and SessionType = '%s' and IP = '%s' and MAC = '%s'"
			QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.NodeID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal)
			log.Println("CWS_AuthTbl Delete Query : ", QueryString)
			//----------------------------------------------------------------------------------------}
			_, err = mariadb_lib.Delete_Data(Database, QueryString)
			if err != nil {
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

				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
				w.Header().Set("Access-Control-Max-Age", "10")
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(OutputBody))

				return
			}

			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "643"
			OutputData.Message = "auth error"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

			jstrbyte, _ := json.Marshal(OutputData)
			OutputBody = string(jstrbyte)

			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "10")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			log.Printf("web api response [userkey:%s] [code:%s, msg:%s] %d, %d", InputData.UserKey, OutputData.Code, OutputData.Message, DBAuthExpireTime, DBAuthNOWTime)
			return
		}

		//--[Query: Delete Existed AuthKey & AuthToken]-------------------------------------------{
		QueryString = "DELETE FROM CWS_AuthTbl WHERE SeqUserKey = %d and NodeID = '%s' and Method = '%s' and SessionType = '%s' and IP = '%s' and MAC = '%s'"
		QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.NodeID, InputData.Method, InputData.SessionType, InputData.IP, InputData.MACTotal)
		log.Println("CWS_AuthTbl Delete Query : ", QueryString)
		//----------------------------------------------------------------------------------------}
		_, err = mariadb_lib.Delete_Data(Database, QueryString)
		if err != nil {
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

			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "10")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(OutputBody))

			return
		}

		//-------------------------------------------------------------------------------------------
		// Provisioning Process
		proviReq := ProvisionProtocol{}
		if err := mapstructure.Decode(InputData.Data, &proviReq); err != nil {
			log.Println("json parser error:", err)
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "610"
			OutputData.Message = "json parameter parsing error (simplify Information)"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

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

		if EncryptUserKey != proviReq.Header.Userkey || EncryptNodeID != proviReq.Header.Nodeid {
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "630"                    //
			OutputData.Message = "db processing error" //
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""
			OutputData.Data = ""

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

		seqNo, nodeIDSeqNo, err := SelectDBSyncSeqNo(Database, InputData.NodeID)
		DBAuthNodeIDSeq = nodeIDSeqNo
		if err != nil {
			log.Println("err SelectDBSyncSeqNo()", err)
			DBAuthNodeIDSeq = 0
			// write to response error code
		}

		if proviReq.Header.Seperator == "up" {
			if DBAuthNodeIDSeq == 0 {
				pvSetupRet := ProvisioningUploadDBSetTransaction(Database, &InputData, &OutputData, &proviReq, DBAuthUserKeySeq)
				if pvSetupRet == 0 {
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

					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
					w.Header().Set("Access-Control-Max-Age", "10")
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(OutputBody))
					return
				}
			} else {
				if seqNo < proviReq.Header.Seq {
					pvSetupRet := ProvisioningUploadDBUpdateTransaction(Database, &InputData, &OutputData, &proviReq, DBAuthNodeIDSeq)
					if pvSetupRet == 0 {
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

						w.Header().Set("Access-Control-Allow-Origin", "*")
						w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
						w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
						w.Header().Set("Access-Control-Max-Age", "10")
						w.Header().Set("Content-Type", "application/json")
						w.Write([]byte(OutputBody))
						return
					}
				} else {
					OutputData.Version = InputData.Version
					OutputData.Method = InputData.Method
					OutputData.SessionType = InputData.SessionType
					OutputData.MsgType = "response"
					OutputData.Code = "650"
					OutputData.Message = "force apply (is already update)"
					OutputData.AuthKey = ""
					OutputData.ExpireTime = ""
					OutputData.Data = ""

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
			}
		} else if proviReq.Header.Seperator == "down" {
			/* */
			UpdateDBProvisioningTime(Database, InputData.NodeID)

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
				settingData, _, err := SelectDBConfigData(Database, InputData.NodeID)
				if err != nil {
					log.Println("err SelectDBConfigData()", err)
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
			OutputData.Version = InputData.Version
			OutputData.Method = InputData.Method
			OutputData.SessionType = InputData.SessionType
			OutputData.MsgType = "response"
			OutputData.Code = "620"
			OutputData.Message = "json parameter decript error"
			OutputData.AuthKey = ""
			OutputData.ExpireTime = ""

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

		//-------------------------------------------------------------------------------------------
		/*
				//--[Query: Exist NodeID Select ]---------------------------------------------------------{
				QueryString = "SELECT Seq FROM NodeIDTbl WHERE Node_NodeID = '%s' "
				QueryString = fmt.Sprintf(QueryString, InputData.NodeID)
				log.Println("Checking Exist NodeID of CWS_SyncSeqNoTbl Query : ", QueryString)
				//----------------------------------------------------------------------------------------}

				ResultSetRows, err = mariadb_lib.Query_DB(Database, QueryString)
				if err != nil {
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

					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
					w.Header().Set("Access-Control-Max-Age", "10")
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(OutputBody))

					return
				}

				for ResultSetRows.Next() {
					err = ResultSetRows.Scan(&DBAuthNodeIDSeq)
					if err != nil {
						ResultSetRows.Close()
						log.Println("data Scan error:", err)

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

						w.Header().Set("Access-Control-Allow-Origin", "*")
						w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
						w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
						w.Header().Set("Access-Control-Max-Age", "10")
						w.Header().Set("Content-Type", "application/json")
						w.Write([]byte(OutputBody))

						return
					}
				}
				ResultSetRows.Close()

			if DBAuthNodeIDSeq == 0 {
				//--[Query: Init CWS_SyncSeqNoTbl Insert ]------------------------------------------------{
				QueryString = "Insert into CWS_SyncSeqNoTbl (SeqNodeID, SeqNoName, SeqNo) " +
					"values (%d, '%s', %d) "
				QueryString = fmt.Sprintf(QueryString, 1, InputData.SessionType, 1)
				log.Println("Init CWS_SyncSeqNoTbl Insert Query : ", QueryString)
				//----------------------------------------------------------------------------------------}
				_, err = mariadb_lib.Insert_Data(Database, QueryString)
				if err != nil {
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

					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
					w.Header().Set("Access-Control-Max-Age", "10")
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(OutputBody))

					return
				}
			}
		*/
		//############################################################################//
		// 1. Not Exist Node-ID
		// (1) Insert Into CWS_SyncSeqNoTbl
		// (2-1) Insert into Table NodeIDTbl
		// (2-2) Insert into Table NodeIDFrontendTbl
		// (2-3) Insert into Table NodeIDBackendTbl

		// 2. Exist Node-ID
		// (1) Select Table CWS_SyncSeqNoTbl & Update Table CWS_SyncSeqNoTbl
		// (2-1) Insert into Table NodeIDTbl
		// (2-2) Insert into Table NodeIDFrontendTbl
		// (2-3) Insert into Table NodeIDBackendTbl

		//QueryString = ""
		// DB Query Processing
		//############################################################################//

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
		//OutputData.Data = "Response-" + InputData.Data
		//-----------------------------------------------------------}

		jstrbyte, _ := json.Marshal(OutputData)
		OutputBody = string(jstrbyte)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "10")
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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "10")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(OutputBody))

		log.Printf("web api response [userkey:%s] [code:%s, msg:%s]", InputData.UserKey, OutputData.Code, OutputData.Message)
		return
	}
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

//-----------------------Statistics Auth------------------------------

func WebServer_Web_Auth_API_Statistics_Proc(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()
	//var Database *sql.DB
	//var ResultSetRows *sql.Rows
	//var QueryString string
	var InputData jsonInputWebAPIAuthStatLocalPack
	var OutputData jsonOutputWebAPIAuthStatLocalPack
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
	//log.Println(">>> Input Data : [version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.UserKey + ", authtoken:" + InputData.AuthToken + ", data:" + InputData.Data + "]")
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
	//DBAuthToken = "69c35a7c2dfa4edf8b3b29e12a681a0f"
	DBAuthToken = "bc412e2f86d7e36cc5bef024d7c3f3d1"
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
	log.Println("InputData.AuthKey:", InputData.AuthKey)
	log.Println("InputData.AuthToken:", InputData.AuthToken)

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
		HashingText = InputData.Method + ":" + InputData.SessionType + ":" + "/auth_api/statistics/v1.0/"
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
		  ----------------------------------------------------z---------*/

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

		StatReq := StatisticsProtocol{}
		if err := mapstructure.Decode(InputData.Data, &StatReq); err != nil {
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

		//--------------------insert Statistics DB -------------------
		if err := InsertStatisticsDB(StatReq.Body.Data, Database); err != nil {
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

		//---------------------insert Statistics DB -------------------
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
		//OutputData.Data = "Response-" + InputData.Data
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

func InsertStatisticsDB(Statistics StatisticInformation, Database *sql.DB) error {
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryString string
	var err error

	tx, err = mariadb_lib.DB_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return err
	}

	defer mariadb_lib.DB_Rollback(tx)

	var ID, Client_IP_Int, Node_IP_Int, Server_Listen_Port, Proxy_Listen_Port int
	var Proxy_IP_Int, Server_IP_Int, Inbound, Outbound, Node_Listen_Port int
	if Statistics.Type == "002" {

		ID, _ = strconv.Atoi(Statistics.ID)
		Client_IP_Int, _ = strconv.Atoi(Statistics.Client_IP_Int)
		Node_IP_Int, _ = strconv.Atoi(Statistics.Node_IP_Int)
		Node_Listen_Port, _ = strconv.Atoi(Statistics.Node_Listen_Port)
		Proxy_IP_Int, _ = strconv.Atoi(Statistics.Proxy_IP_Int)
		Proxy_Listen_Port, _ = strconv.Atoi(Statistics.Proxy_Listen_Port)
		Inbound, _ = strconv.Atoi(Statistics.Inbound)
		Outbound, _ = strconv.Atoi(Statistics.Outbound)

		QueryString = "INSERT INTO `CLIENT_STATISTICS_COMMON` (ID,Time, Node_ID_TEXT, Client_IP_INT,\n" + "Client_IP_TEXT, Node_IP_INT, Node_IP_TEXT, Node_Listen_Port)\n" +
			"SELECT ?,?,?,?,?,?,?,? FROM dual\n" +
			"WHERE NOT EXISTS ( SELECT *  FROM `CLIENT_STATISTICS_COMMON`\n" +
			"WHERE  ID = ? AND  Time = ? AND Node_ID_TEXT= ? AND Client_IP_INT= ? AND Client_IP_TEXT= ? AND Node_IP_INT= ? AND Node_IP_TEXT= ? AND Node_Listen_Port= ?)"

		log.Println("QueryString", QueryString)

		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		_, err = stmt.Exec(ID, Statistics.Time, Statistics.Node_ID_Text, Client_IP_Int, Statistics.Client_IP_Text, Node_IP_Int, Statistics.Node_IP_Text, Node_Listen_Port,
			ID, Statistics.Time, Statistics.Node_ID_Text, Client_IP_Int, Statistics.Client_IP_Text, Node_IP_Int, Statistics.Node_IP_Text, Node_Listen_Port)
		if err != nil {
			log.Println("stmt exec err", err)
			stmt.Close()
			return err
		}
		stmt.Close()

		QueryString = "INSERT INTO `CLIENT_STATISTICS_DATA` ( ID, Proxy_IP_INT, Proxy_IP_TEXT, Proxy_Listen_Port,Inbound,Outbound )\n" +
			"SELECT ?,?,?,?,?,? FROM dual\n" +
			"WHERE NOT EXISTS ( SELECT *  FROM `CLIENT_STATISTICS_DATA`\n" +
			"WHERE  ID = ? AND  Proxy_IP_INT = ? AND Proxy_IP_TEXT= ? AND Proxy_Listen_Port= ? AND Inbound= ? AND Outbound= ?)"

		log.Println("QueryString", QueryString)

		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		_, err = stmt.Exec(ID, Proxy_IP_Int, Statistics.Proxy_IP_Text, Proxy_Listen_Port, Inbound, Outbound,
			ID, Proxy_IP_Int, Statistics.Proxy_IP_Text, Proxy_Listen_Port, Inbound, Outbound)
		if err != nil {
			stmt.Close()
			log.Println("stmt exec err", err)
			return err
		}
		stmt.Close()

	} else if Statistics.Type == "001" {

		ID, _ = strconv.Atoi(Statistics.ID)
		Proxy_IP_Int, _ = strconv.Atoi(Statistics.Proxy_IP_Int)
		Node_IP_Int, _ = strconv.Atoi(Statistics.Node_IP_Int)
		Node_Listen_Port, _ = strconv.Atoi(Statistics.Node_Listen_Port)
		Server_IP_Int, _ = strconv.Atoi(Statistics.Server_IP_Int)
		Server_Listen_Port, _ = strconv.Atoi(Statistics.Server_Listen_Port)
		Client_IP_Int, _ = strconv.Atoi(Statistics.Client_IP_Int)
		Inbound, _ = strconv.Atoi(Statistics.Inbound)
		Outbound, _ = strconv.Atoi(Statistics.Outbound)

		QueryString = "INSERT INTO `SERVER_STATISTICS_COMMON` (ID, Time, Bridge_ID_TEXT , Proxy_IP_INT, Proxy_IP_TEXT, Node_IP_INT, Node_IP_TEXT,\n" +
			"Node_Listen_Port, Server_IP_INT, Server_IP_TEXT, Server_Listen_Port)\n" +
			"SELECT ?,?,?,?,?,?,?,?,?,?,? FROM dual\n" +
			"WHERE NOT EXISTS ( SELECT *  FROM `SERVER_STATISTICS_COMMON`\n" +
			"WHERE  ID = ? AND  Time = ? AND Bridge_ID_TEXT= ? AND Proxy_IP_INT= ? AND Proxy_IP_TEXT= ? AND Node_IP_INT= ? \n" +
			"AND Node_IP_TEXT= ? AND Node_Listen_Port= ? AND Server_IP_INT= ? AND Server_IP_TEXT= ? AND Server_Listen_Port= ?)"

		log.Println("QueryString", QueryString)

		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		_, err = stmt.Exec(ID, Statistics.Time, Statistics.Bridge_ID_Text, Proxy_IP_Int, Statistics.Proxy_IP_Text, Node_IP_Int, Statistics.Node_IP_Text, Node_Listen_Port, Server_IP_Int, Statistics.Server_IP_Text, Server_Listen_Port,
			ID, Statistics.Time, Statistics.Bridge_ID_Text, Proxy_IP_Int, Statistics.Proxy_IP_Text, Node_IP_Int, Statistics.Node_IP_Text, Node_Listen_Port, Server_IP_Int, Statistics.Server_IP_Text, Server_Listen_Port)
		if err != nil {
			stmt.Close()
			log.Println("stmt exec err", err)
			return err
		}
		stmt.Close()

		QueryString = "INSERT INTO `SERVER_STATISTICS_DATA` (ID, Client_IP_INT, Client_IP_TEXT, Inbound, Outbound)\n" +
			"SELECT ?,?,?,?,? FROM dual\n" +
			"WHERE NOT EXISTS ( SELECT *  FROM `SERVER_STATISTICS_DATA`\n" +
			"WHERE  ID = ? AND  Client_IP_INT = ? AND Client_IP_TEXT= ? AND Inbound= ? AND Outbound= ?)"

		log.Println("QueryString", QueryString)

		stmt, err = tx.Prepare(QueryString)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return err
		}

		_, err = stmt.Exec(ID, Client_IP_Int, Statistics.Client_IP_Text, Inbound, Outbound,
			ID, Client_IP_Int, Statistics.Client_IP_Text, Inbound, Outbound)
		if err != nil {
			stmt.Close()
			log.Println("stmt exec err", err)
			return err
		}
		stmt.Close()

	}

	mariadb_lib.DB_Commit(tx)

	return nil
}

//-----------------------Statistics Auth------------------------------

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
		TempStr = fmt.Sprintf("<li><a href=\"/node_cfg_list/\">Node Setting List</a></li>")
		StatPageInfo.NodeSettingsList = template.HTML(TempStr)

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

func MariaDBInsertUsers(Database *sql.DB, ID string, Password string) {
	var DB_Flag int64

	InsertDataStr := fmt.Sprintf("INSERT INTO Users (ID, Password) VALUES ('%s','%s')", ID, GetCipherText(Password))

	log.Println("Insert Configure", InsertDataStr)

	DB_Flag, _ = mariadb_lib.Insert_Data(Database, InsertDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("mariadb Insert Fail!")
	}
}
func MariaDBInsertDefaultNewTemplet(Database *sql.DB) {
	var tx *sql.Tx
	var stmt *sql.Stmt
	var err error
	var QueryStr string

	tx, err = mariadb_lib.DB_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)

		return
	}
	defer mariadb_lib.DB_Rollback(tx)

	QueryStr = "INSERT IGNORE INTO TempletNodeIDTbl (Seq,TempletName, Global_MaxConn, Global_RecvBufferSize, Global_SendBufferSize," +
		"Global_TimeoutConnect, Global_TimeoutClient, Global_TimeoutServer," +
		"Log_DiskLimit, Log_MaxSize, Log_LogDir, Log_LogName, Log_ErrDir, Log_ErrName," +
		"Stat_SendControlServerFlag, Stat_StatCollectionCycle," +
		"Node_UseBridgeRouter, Node_NodeBufferSize, Node_EncryptMode, Node_ChangeIPClientMode" +
		")" +
		"VALUES (?,?, ?, ?, ?," +
		"?, ?, ?," +
		"?, ?, ?, ?, ?, ?," +
		"?, ?," +
		"?, ?, ?, ?" +
		")"

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return
	}
	_, err = stmt.Exec(1, "New", "1024", "16384", "16384",
		"5", "30", "30",
		"95", "150", "./logs/", "app.log", "./logs/", "app_err.log",
		"Enable", "1",
		"N", "524288", "AES_256", "Disable",
	)
	if err != nil {
		stmt.Close()

		return
	}
	stmt.Close()

	QueryStr = "INSERT IGNORE INTO TempletNodeIDFrontendTbl (Seq,SeqNodeID,Name,Bind,Backend , NodeMode)" +
		"VALUES(?,?,?,?,?,?)"

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return
	}

	_, err = stmt.Exec(1, "1", "node1", "9090", "node1", "client")
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return
	}
	stmt.Close()

	QueryStr = "INSERT IGNORE INTO TempletNodeIDBackendTbl (Seq,SeqNodeID,Name)" +
		"VALUES(?,?,?)"

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return
	}
	_, err = stmt.Exec(1, "1", "node1")
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return
	}
	stmt.Close()

	QueryStr = "INSERT IGNORE INTO TempletNodeIDBackendAddressTbl (Seq, SeqNodeID, SeqBackend, NicName)" +
		"VALUES (?,?, ?, ?) "
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)

		return
	}

	_, err = stmt.Exec(1, "1", "1", "OS_Default")
	if err != nil {
		stmt.Close()

		return
	}
	stmt.Close()
	mariadb_lib.DB_Commit(tx)
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
	var sql string
	var DB_Flag int32
	var RowCount int32

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
	sql = "CREATE TABLE IF NOT EXISTS `TempletNodeIDTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`TempletName` varchar(256) NOT NULL, " +
		"`Password` varchar(256) NOT NULL, " +
		"`Global_MaxConn` varchar(256) NOT NULL, " +
		"`Global_RecvBufferSize` varchar(256) NOT NULL, " +
		"`Global_SendBufferSize` varchar(256) NOT NULL, " +
		"`Global_TimeoutConnect` varchar(256) NOT NULL, " +
		"`Global_TimeoutClient` varchar(256) NOT NULL, " +
		"`Global_TimeoutServer` varchar(256) NOT NULL, " +
		"`Log_DiskLimit` varchar(256) NOT NULL, " +
		"`Log_MaxSize` varchar(256) NOT NULL, " +
		"`Log_LogDir` varchar(256) NOT NULL, " +
		"`Log_LogName` varchar(256) NOT NULL, " +
		"`Log_ErrDir` varchar(256) NOT NULL, " +
		"`Log_ErrName` varchar(256) NOT NULL, " +
		"`Stat_SendControlServerFlag` varchar(256) NOT NULL, " +
		"`Stat_StatCollectionCycle` varchar(256) NOT NULL, " +
		"`Stat_StatSendControlServer` varchar(256) NOT NULL, " +
		"`Stat_StatServerIP` varchar(256) NOT NULL, " +
		"`Stat_StatServerPort` varchar(256) NOT NULL, " +
		"`Stat_StatDataSendCycle` varchar(256) NOT NULL, " +
		"`Node_UseBridgeRouter` varchar(256) NOT NULL, " +
		"`Node_NodeBufferSize` varchar(256) NOT NULL, " +
		"`Node_EncryptMode` varchar(256) NOT NULL, " +
		"`Node_ChangeIPClientMode` varchar(256) NOT NULL, " +
		"`KMS_IP` varchar(256) NOT NULL, " +
		"`KMS_Port` varchar(256) NOT NULL, " +
		"unique index idx__templetnodeidtbl__seq (Seq) " +
		") "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	sql = "CREATE TABLE IF NOT EXISTS `TempletNodeIDFrontendTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`SeqNodeID` int NOT NULL, " +
		"`Name` varchar(256) NOT NULL, " +
		"`NicName` varchar(256) NOT NULL, " +
		"`Bind` int NOT NULL, " +
		"`Backend` varchar(256) NOT NULL, " +
		"`NodeMode` varchar(256) NOT NULL, " +
		"unique index idx__nodeidfrontendtbl__seq (Seq), " +
		"index idx__nodeidfrontendtbl__seqnodeid (SeqNodeID) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	sql = "CREATE TABLE IF NOT EXISTS `TempletNodeIDBackendTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`SeqNodeID` int NOT NULL, " +
		"`Name` varchar(256) NOT NULL, " +
		"unique index idx__nodeidbackendtbl__seq (Seq), " +
		"index idx__nodeidbackendtbl__seqnodeid (SeqNodeID) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	sql = "CREATE TABLE IF NOT EXISTS `TempletNodeIDBackendAddressTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`SeqNodeID` int NOT NULL, " +
		"`SeqBackend` int NOT NULL, " +
		"`NicName` varchar(256) NOT NULL, " +
		"`IP` varchar(256) NOT NULL, " +
		"`Port` int NOT NULL, " +
		"unique index idx__nodeidbackendtbl__seq (Seq), " +
		"index idx__nodeidbackendtbl__seqbackend (SeqBackend), " +
		"index idx__nodeidbackendtbl__idx01 (NicName, IP, Port), " +
		"index idx__nodeidbackendtbl__idx02 (IP, Port) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	MariaDBInsertDefaultNewTemplet(Database)
	RowCount, _ = mariadb_lib.RowCount(Database, "Users")
	if RowCount == 0 {
		MariaDBInsertUsers(Database, "admin", "admin123")
	}
	sql = "CREATE TABLE IF NOT EXISTS `UserKeyTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`UserKey` varchar(256) NOT NULL, " +
		"unique index idx__userkeytbl__seq (Seq) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	sql = "CREATE TABLE IF NOT EXISTS `NodeIDTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`SeqUserKey` int NOT NULL, " +
		"`Password` varchar(256) NOT NULL, " +
		"`VerifyingPassword` varchar(256) NOT NULL, " +
		"`Global_MaxConn` varchar(256) NOT NULL, " +
		"`Global_RecvBufferSize` varchar(256) NOT NULL, " +
		"`Global_SendBufferSize` varchar(256) NOT NULL, " +
		"`Global_TimeoutConnect` varchar(256) NOT NULL, " +
		"`Global_TimeoutClient` varchar(256) NOT NULL, " +
		"`Global_TimeoutServer` varchar(256) NOT NULL, " +
		"`Log_DiskLimit` varchar(256) NOT NULL, " +
		"`Log_MaxSize` varchar(256) NOT NULL, " +
		"`Log_LogDir` varchar(256) NOT NULL, " +
		"`Log_LogName` varchar(256) NOT NULL, " +
		"`Log_ErrDir` varchar(256) NOT NULL, " +
		"`Log_ErrName` varchar(256) NOT NULL, " +
		"`Stat_SendControlServerFlag` varchar(16) NOT NULL, " +
		"`Stat_StatCollectionCycle` varchar(256) NOT NULL, " +
		"`Stat_StatSendControlServer` varchar(256) NOT NULL, " +
		"`Stat_StatServerIP` varchar(256) NOT NULL, " +
		"`Stat_StatServerPort` varchar(256) NOT NULL, " +
		"`Stat_StatDataSendCycle` varchar(256) NOT NULL, " +
		"`Node_UseBridgeRouter` varchar(256) NOT NULL, " +
		"`Node_NodeBufferSize` varchar(256) NOT NULL, " +
		"`Node_EncryptMode` varchar(256) NOT NULL, " +
		"`Node_ChangeIPClientMode` varchar(256) NOT NULL, " +
		"`Node_NodeID` varchar(256) NOT NULL, " +
		"`KMS_IP` varchar(256) NOT NULL, " +
		"`KMS_Port` varchar(256) NOT NULL, " +
		"`Provisioning_Time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
		"`Node_Status` TINYINT NOT NULL DEFAULT 1, " +
		"unique index idx__nodeidtbl__seq (Seq), " +
		"unique index idx__nodeidtbl__nodeid (Node_NodeID), " +
		"index idx__nodeidtbl__sequserkey (SeqUserKey) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	sql = "CREATE TABLE IF NOT EXISTS `NodeIDFrontendTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`SeqNodeID` int NOT NULL, " +
		"`Name` varchar(256) NOT NULL, " +
		"`NicName` varchar(256) NOT NULL, " +
		"`Bind` int NOT NULL, " +
		"`Backend` varchar(256) NOT NULL, " +
		"`NodeMode` varchar(256) NOT NULL, " +
		"unique index idx__nodeidfrontendtbl__seq (Seq), " +
		"index idx__nodeidfrontendtbl__seqnodeid (SeqNodeID) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	sql = "CREATE TABLE IF NOT EXISTS `NodeIDBackendTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`SeqNodeID` int NOT NULL, " +
		"`Name` varchar(256) NOT NULL, " +
		"unique index idx__nodeidbackendtbl__seq (Seq), " +
		"index idx__nodeidbackendtbl__seqnodeid (SeqNodeID), " +
		"index idx__nodeidbackendtbl__idx01 (SeqNodeID, Name) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	sql = "CREATE TABLE IF NOT EXISTS `NodeIDBackendAddressTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`SeqNodeID` int NOT NULL, " +
		"`SeqBackend` int NOT NULL, " +
		"`NicName` varchar(256) NOT NULL, " +
		"`IP` varchar(256) NOT NULL, " +
		"`Port` int NOT NULL, " +
		"unique index idx__nodeidbackendtbl__seq (Seq), " +
		"index idx__nodeidbackendaddresstbl__seqnodeid (SeqNodeID), " +
		"index idx__nodeidbackendaddresstbl__seqbackend (SeqBackend), " +
		"index idx__nodeidbackendaddresstbl__idx01 (NicName, IP, Port), " +
		"index idx__nodeidbackendaddresstbl__idx02 (IP, Port) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	sql = "CREATE TABLE IF NOT EXISTS `CWS_AuthTbl` ( " +
		"`Seq` int NOT NULL AUTO_INCREMENT, " +
		"`SeqUserKey` int NOT NULL, " +
		"`NodeID` varchar(256) NOT NULL, " +
		"`Method` varchar(256) NOT NULL, " +
		"`SessionType` varchar(256) NOT NULL, " +
		"`IP` varchar(256) NOT NULL, " +
		"`MAC` varchar(256) NOT NULL, " +
		"`AuthKey` varchar(256) NOT NULL, " +
		"`AuthToken` varchar(256) NOT NULL, " +
		"`Expiretime` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
		"unique index idx__cws_authtbl__seq (Seq), " +
		"unique index idx__cws_authtbl__pkkey01 (SeqUserKey, NodeID, Method, SessionType, IP, MAC), " +
		"index idx__cws_authtbl__idxkey01 (NodeID, Method, SessionType, IP, MAC), " +
		"index idx__cws_authtbl__idxkey02 (Method, SessionType, IP, MAC), " +
		"index idx__cws_authtbl__idxkey03 (SeqUserKey, IP, MAC), " +
		"index idx__cws_authtbl__sequserkey (SeqUserKey) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}

	sql = "CREATE TABLE IF NOT EXISTS `CWS_SyncSeqNoTbl` ( " +
		"`SeqNodeID` int NOT NULL, " +
		"`SeqNoName` varchar(256) NOT NULL, " +
		"`SeqNo` int NOT NULL, " +
		"unique index idx__cwssyncseqnotbl__pkkey (SeqNodeID, SeqNoName), " +
		"index idx__cwssyncseqnotbl__seqnodeid (SeqNodeID) " +
		") " +
		"DEFAULT CHARACTER SET euckr COLLATE 'euckr_korean_ci' ENGINE=InnoDB "
	DB_Flag, _ = mariadb_lib.Create_Table(Database, sql)
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

func RunControlWebServer(bindPort string) {
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
	//---------------node cfg detail------------------
	WebServerMux.HandleFunc("/node_cfg_list/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		Node_Info_List_Dashboard(w, req, Database)
		Database.Close()
	})

	WebServerMux.HandleFunc("/node_cfg_detail/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		Node_Cfg_Detail(w, req, Database)
		Database.Close()
	})
	WebServerMux.HandleFunc("/apply_templet_to_cfg_detail/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		Apply_Templet_to_Cfg(w, req, Database)
		Database.Close()
	})
	WebServerMux.HandleFunc("/modified_cfg_detail/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		Modified_Cfg_Detail(w, req, Database)
		Database.Close()
	})
	//------------------node cfg detail---------------
	//------------------node templet---------------
	WebServerMux.HandleFunc("/add_cfg_templet/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		Add_Templet(w, req, Database)
		Database.Close()
	})
	WebServerMux.HandleFunc("/load_cfg_templet/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		Load_Templet(w, req, Database)
		Database.Close()
	})
	WebServerMux.HandleFunc("/save_cfg_newtemplet/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		Save_NewTemplet(w, req, Database)
		Database.Close()
	})
	WebServerMux.HandleFunc("/delete_cfg_templet/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		Delete_Templet(w, req, Database)
		Database.Close()
	})
	WebServerMux.HandleFunc("/modified_cfg_templet/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		Save_Modified_TempletInfo(w, req, Database)
		Database.Close()
	})
	//------------------node templet---------------
	//---------------------------------

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
	WebServerMux.HandleFunc("/auth_api_input/provisioning/transaction/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Provisioning_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_input/statistics/transaction/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Statistics_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_encode_value/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Encode_Value(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/provisioning/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		WebServer_Web_Auth_API_Provisioning_Proc(w, req, Database)
		Database.Close()
	})

	WebServerMux.HandleFunc("/auth_api/statistics/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
		WebServer_Web_Auth_API_Statistics_Proc(w, req, Database)
		Database.Close()
	})
	//------------------------------------------------------------------------- [ WEB API ] }--------//

	go HttpListen(1, ":443", "server.crt", "server.key", StatServerMux)

	bind := fmt.Sprintf(":%s", bindPort)
	go HttpListen(0, bind, "", "", WebServerMux)

	// Node Status check
	go func() {
		for {
			Database, _ := MariaDBOpen(db_cfg_info.DB.ID, db_cfg_info.DB.PASSWORD, db_cfg_info.DB.IP, db_cfg_info.DB.PORT, db_cfg_info.DB.DBNAME)
			err := UpdateDBNodeStatus(Database)
			if err != nil {
				log.Println("error UpdateDBNodeStatus():", err)
			}
			Database.Close()
			time.Sleep(time.Second * 3)
		}
	}()

	//go Delete_Client_Statistics(Database)
	//go Delete_Server_Statistics(Database)

}

func SendStat(lwsDatabase *sql.DB, trafficDatabase *sql.DB) {
	var SendIntervalTime time.Duration
	var SendInterval int
	var StatSendFlag int
	var CtrlServIP, CtrlServPort, CtrlServInfo string
	var SendIntervalTimeStr string
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
		if SendIntervalTime <= 0 {
			SendIntervalTime = 3
		}

		timer := time.NewTimer(time.Second * time.Duration(SendIntervalTime))
		<-timer.C

		QueryStr = "SELECT Stat_Send_Flag, Stat_StatServerIP, Stat_StatServerPort, Stat_StatDataSendCycle FROM Users;"
		StatCfgRows, err = sqlitedb_lib.Query_DB(lwsDatabase, QueryStr)
		if StatCfgRows == nil {
			log.Println("StatCfgRows Error:", err)
		} else {
			for StatCfgRows.Next() {
				err := StatCfgRows.Scan(&StatSendFlag, &CtrlServIP, &CtrlServPort, &SendIntervalTimeStr)
				if err != nil {
					log.Println("StatCfgRows Scan Error:", err)
				}
			}
			CtrlServInfo = CtrlServIP + ":" + CtrlServPort
			SendInterval, _ = strconv.Atoi(SendIntervalTimeStr)
			SendIntervalTime = time.Duration(SendInterval)
			StatCfgRows.Close()
		}

		if StatSendFlag == ENABLE {
			Server_SendStat(trafficDatabase, CtrlServInfo, CtrlServIP, CtrlServPort, &Serv_StartID, &Serv_FinishID, &Serv_first_send)
			Client_SendStat(trafficDatabase, CtrlServInfo, CtrlServIP, CtrlServPort, &Clint_StartID, &Clint_FinishID, &Clint_first_send)
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
func SqliteDBInsertUserIDPwd(Database *sql.DB, ID string, Password string) {
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

func SqliteDBInsertSyncSeqNo(Database *sql.DB, seqNoName string, seqNo int) {
	var DB_Flag int64
	InsertDataStr := fmt.Sprintf("INSERT INTO SyncSeqNoTbl (SeqNoName, SeqNo) VALUES ('%s', %d)", seqNoName, seqNo)

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
func LicenseSqliteDBInit(DbName string) *sql.DB {
	var Database *sql.DB
	Database, _ = sqlitedb_lib.Create_DB(DbName)
	return Database
}
func TrafficSqliteDBInit(DbName string) *sql.DB {
	var Database *sql.DB
	var DB_Flag int64
	Database, _ = sqlitedb_lib.Create_DB(DbName)

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

	return Database
}

func LocalWebServerSqliteDBInit(DbName string) *sql.DB {
	db, err := sqlitedb_lib.Create_DB(DbName)
	if err != nil {
		return nil
	}

	query := "CREATE TABLE IF NOT EXISTS SyncSeqNoTbl (" +
		"Seq       INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," +
		"SeqNoName TEXT," +
		"SeqNo     INTEGER" +
		");"

	var result int64
	result, _ = sqlitedb_lib.Create_Table(db, query)
	if result != DB_RET_SUCC {
		log.Println("Create Table Fail!")
	}

	var RowCount int32
	RowCount, _ = sqlitedb_lib.RowCount(db, "SyncSeqNoTbl")
	if RowCount == 0 {
		SqliteDBInsertSyncSeqNo(db, "ConfigData", 1)
	}

	query = "CREATE TABLE IF NOT EXISTS AuthInfoTbl (" +
		"Seq         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," +
		"Method      TEXT," +
		"SessionType TEXT," +
		"Authkey     TEXT," +
		"AuthToken   TEXT," +
		"ExpireTime  TEXT" +
		");"

	result, _ = sqlitedb_lib.Create_Table(db, query)
	if result != DB_RET_SUCC {
		log.Println("Create Table Fail!")
	}

	query = "CREATE TABLE IF NOT EXISTS Users  (" +
		"Seq                    INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," +
		"ID                     TEXT NOT NULL," +
		"Password               TEXT NOT NULL," +
		"Stat_StatServerIP      TEXT NOT NULL DEFAULT '0.0.0.0'," +
		"Stat_StatServerPort    TEXT NOT NULL DEFAULT '8080'," +
		"Stat_StatDataSendCycle TEXT NOT NULL DEFAULT '10'," +
		"Stat_Send_Flag         INTEGER NOT NULL DEFAULT 2," +
		"Del_Time               TEXT NOT NULL DEFAULT '3'," +
		"Cyc_Time               TEXT NOT NULL DEFAULT '30'" +
		");"
	result, _ = sqlitedb_lib.Create_Table(db, query)
	if result != DB_RET_SUCC {
		log.Println("Create Table Fail!")
	}

	RowCount, _ = sqlitedb_lib.RowCount(db, "Users")
	if RowCount == 0 {
		SqliteDBInsertUserIDPwd(db, "admin", "admin123")
	}

	return db
}

func RunLocalWebServer(bindPort string) {
	log.Print("Run Local Web Server..\n")

	PrepareSqliteDB()

	lwsDatabase := LocalWebServerSqliteDBInit(LocalWebServerDB)
	trafficDatabase := TrafficSqliteDBInit(SqliteDB)
	licenseDatabase := LicenseSqliteDBInit(LicenseSqliteDB)

	if _, err := os.Stat("./cfg/app.cfg"); os.IsNotExist(err) {
		Make_cfg_File()
	}

	GetProxyInfos()
	GetNodeModes()
	Node_Change_Client_IP_Mode, _ = GetChangeClientIPModes()

	WebServerMux := http.NewServeMux()

	WebServerMux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Redirect(w, req, "/login/")
	})

	WebServerMux.HandleFunc("/login/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Login(w, req, lwsDatabase)
	})

	WebServerMux.HandleFunc("/logging/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Login_Check(w, req, lwsDatabase)
	})

	WebServerMux.HandleFunc("/setting/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Settings(w, req, lwsDatabase)
	})

	WebServerMux.HandleFunc("/update_setting/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Update_Settings(w, req, lwsDatabase)
	})

	WebServerMux.HandleFunc("/statistics/client/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Client_Statistics(w, req, trafficDatabase)
	})

	WebServerMux.HandleFunc("/statistics/server/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Server_Statistics(w, req, trafficDatabase)
	})

	WebServerMux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Forbidden(w, req, lwsDatabase)
	})

	//------------------------------------------------------------------------- [ WEB API:gkwon ] {--------//
	WebServerMux.HandleFunc("/auth_api_input/provisioning/transaction/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Provisioning_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_input/statistics/transaction", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Statistics_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_input/config_upload_test/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Config_Upload_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_encode_value/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Session_Encode_Value(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_encode_authtoken/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Auth_API_Session_AuthToken(w, req)
	})
	//------------------------------------------------------------------------- [ WEB API ] }--------//

	WebServerMux.HandleFunc("/upload_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Upload_File_Proc(w, req)
	})

	WebServerMux.HandleFunc("/popup_window_parent_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Popup_Parent_Input(w, req)
	})

	WebServerMux.HandleFunc("/popup_window_child_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Web_Popup_Child_Input(w, req)
	})
	WebServerMux.HandleFunc("/insert_license/", func(w http.ResponseWriter, req *http.Request) {
		Insert_License(w, req, licenseDatabase)
	})

	WebServerMux.HandleFunc("/license/", func(w http.ResponseWriter, req *http.Request) {
		Read_License(w, req, licenseDatabase)
	})

	WebServerMux.Handle("/pages/", http.StripPrefix("/pages/", http.FileServer(http.Dir("pages"))))

	bind := fmt.Sprintf(":%s", bindPort)
	go HttpListen(0, bind, "", "", WebServerMux)

	//go SendStat(lwsDatabase, trafficDatabase)
	go Delete_Client_Statistics(lwsDatabase, trafficDatabase)
	go Delete_Server_Statistics(lwsDatabase, trafficDatabase)

	go ProvisioningDownloadLocalPorcess(lwsDatabase)

	go StatisticsUploadLocalProcess(lwsDatabase, trafficDatabase)

}

func Make_cfg_File() {
	var CRLF string
	var ConfGlobal, ConfLogFile, ConfStatistics, ConfNode, ConfNodeID, ConfKMS, ConfFrontend, ConfBackend string
	var fd *os.File
	var err error
	var Whole_Config_File string
	var EncText string

	err = os.MkdirAll("./cfg", 0644)
	if err != nil {
		log.Println("MkdirAll err:", err)

	}

	fd, err = os.Create("./cfg/app.cfg")
	if err != nil {
		log.Println("create file err:", err)
	}
	defer fd.Close()

	if runtime.GOOS == "linux" {
		CRLF = "\n"
	} else if runtime.GOOS == "windows" {
		//CRLF = "\r\n"
		CRLF = "\n"
	}

	ConfGlobal = "[global]" + CRLF
	ConfGlobal += "max_conn = \"<MAX_CONN>\"" + CRLF
	ConfGlobal += "recv_buffer_size = \"<DEFAULT_RECV_BUFF_SIZE>\"" + CRLF
	ConfGlobal += "send_buffer_size = \"<DEFAULT_SEND_BUFF_SIZE>\"" + CRLF
	ConfGlobal += "timeout_connect = \"<TIMEOUT_CONNECT>\"" + CRLF
	ConfGlobal += "timeout_client = \"<TIMEOUT_CLIENT>\"" + CRLF
	ConfGlobal += "timeout_server = \"<TIMEOUT_SERVER>\"" + CRLF
	ConfGlobal += CRLF

	ConfLogFile = "[logfile]" + CRLF
	ConfLogFile += "disk_limit = \"<DISK_LIMIT>\"" + CRLF
	ConfLogFile += "max_size = \"<LOGFILE_MAX_SIZE>\"" + CRLF
	ConfLogFile += "log = \"<LOGFILE_LOCATION>\"" + CRLF
	ConfLogFile += "error = \"<ERRORLOGFILE_LOCATION>\"" + CRLF
	ConfLogFile += CRLF

	ConfStatistics = "[statistics]" + CRLF
	ConfStatistics += "use = \"disable\"" + CRLF
	ConfStatistics += "interval = \"<STATISTICS_INTERVAL>\"" + CRLF
	ConfStatistics += CRLF

	ConfNode = "[node]" + CRLF
	ConfNode += "position = \"wan\"" + CRLF
	ConfNode += "interval_retry = \"5\"" + CRLF
	ConfNode += "buffer_size = \"<Node_BUFF_SIZE>\"" + CRLF
	ConfNode += "encrypt = \"<Node_ENCRYPT>\"" + CRLF
	ConfNode += "cp_tunneling = \"<CHANGE_IP_FUNC>\"" + CRLF
	ConfNode += CRLF

	ConfNodeID += "[NodeID]" + CRLF
	ConfNodeID += "NodeID = \"<NODE_ID>\"" + CRLF
	ConfNodeID += CRLF

	ConfKMS += "[kms]" + CRLF
	ConfKMS += "url = \"<KMS_ADDR_PORT>\"" + CRLF
	ConfKMS += CRLF

	ConfFrontend = "[frontend]" + CRLF
	/*
		ConfFrontend += "[frontend.<SYMBOL_NAME>]" + CRLF
		ConfFrontend += "symbol = \"<SYMBOL_NAME>\"" + CRLF
		ConfFrontend += "bind = \"<FRONTEND_BIND>\"" + CRLF
		ConfFrontend += "node_mode = \"<Node_MODE>\"" + CRLF
		ConfFrontend += "backend = \"<SYMBOL_NAME>\"" + CRLF
		ConfFrontend += CRLF
	*/

	ConfBackend = "[backend]" + CRLF
	/*
		ConfBackend += "[backend.<SYMBOL_NAME>]" + CRLF
		ConfBackend += "symbol = \"<SYMBOL_NAME>\"" + CRLF
		ConfBackend += "server = [<LANID_SERVER_IP_PORT>]" + CRLF
		ConfBackend += CRLF
	*/

	ConfGlobal = strings.Replace(ConfGlobal, "<MAX_CONN>", strconv.Itoa(1024), -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<DEFAULT_RECV_BUFF_SIZE>", strconv.Itoa(16384), -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<DEFAULT_SEND_BUFF_SIZE>", strconv.Itoa(16384), -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<TIMEOUT_CONNECT>", strconv.Itoa(5), -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<TIMEOUT_CLIENT>", strconv.Itoa(30), -1)
	ConfGlobal = strings.Replace(ConfGlobal, "<TIMEOUT_SERVER>", strconv.Itoa(30), -1)

	Whole_Config_File += ConfGlobal

	ConfLogFile = strings.Replace(ConfLogFile, "<DISK_LIMIT>", strconv.Itoa(95), -1)
	ConfLogFile = strings.Replace(ConfLogFile, "<LOGFILE_MAX_SIZE>", strconv.Itoa(150), -1)
	ConfLogFile = strings.Replace(ConfLogFile, "<LOGFILE_LOCATION>", "./logs/app.log", -1)
	ConfLogFile = strings.Replace(ConfLogFile, "<ERRORLOGFILE_LOCATION>", "./logs/app_err.log", -1)

	Whole_Config_File += ConfLogFile

	ConfStatistics = strings.Replace(ConfStatistics, "<STATISTICS_INTERVAL>", strconv.Itoa(1), -1)

	Whole_Config_File += ConfStatistics

	ConfNode = strings.Replace(ConfNode, "<Bridge_MODE>", strconv.Itoa(2), -1)
	ConfNode = strings.Replace(ConfNode, "<Node_BUFF_SIZE>", strconv.Itoa(524288), -1)
	ConfNode = strings.Replace(ConfNode, "<Node_ENCRYPT>", "none", -1)
	ConfNode = strings.Replace(ConfNode, "<CHANGE_IP_FUNC>", "disable", -1)

	Whole_Config_File += ConfNode

	ConfKMS = strings.Replace(ConfKMS, "<KMS_ADDR_PORT>", "", -1)

	Whole_Config_File += ConfKMS
	Whole_Config_File += ConfFrontend
	Whole_Config_File += ConfBackend

	EncryptEncodingStr(Whole_Config_File, &EncText)
	_, err = fd.Write([]byte("COD$_"))
	if err != nil {
		log.Println(" Write err:", err)
	}

	_, err = fd.Write([]byte(EncText))
	if err != nil {
		log.Println(" Write err:", err)
	}
}

func Read_License(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()
	var tmpl *template.Template
	var TempStr string

	var LicensePageInfo LicenseMagementPageInfo
	var LicInfo LicenseData
	var PageNumInfo PageNumInfo
	var err error
	var PageIndexStart, PageNumber, PageCount, NextPageNumber, PrevPageNumber, SortNumber, LastPageNumber int
	var QueryStr string
	var ConditionArray []interface{}
	var CommonRows *sql.Rows
	var CommonRowsCount int
	var ConditionCount int
	var NextRowOffset int
	var perpagerowscount int

	log.Println("Server Statistics", req.URL)
	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	if Node_Flag == Node_FLAG_SERVER {
		TempStr = fmt.Sprintf("<li><a href=\"/statistics/server/\">Server Statistics</a></li>")
		LicensePageInfo.NodeServerStatMenu = template.HTML(TempStr)
		LicensePageInfo.NodeClientStatMenu = ""
		TempStr = fmt.Sprintf("<li class=\"current\"><a href=\"/license/\">License Management</a></li>")
		LicensePageInfo.LicenseManagement = template.HTML(TempStr)
	}

	Param_PageNumber, ok := req.URL.Query()["page_num"]
	if !ok || len(Param_PageNumber) < 1 {
		log.Println("hello world ")
		WebServer_Redirect(w, req, "/license/?page_num=1&sort=0")
		return
	}
	log.Println("param_PageNumber:", Param_PageNumber)

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

	PageNumberStr := fmt.Sprintf("%s", Param_PageNumber)
	PageNumberStr = strings.Replace(PageNumberStr, "[", "", -1)
	PageNumberStr = strings.Replace(PageNumberStr, "]", "", -1)
	PageNumber, err = strconv.Atoi(PageNumberStr)
	if err != nil {
		log.Println("failed to strconv.Atoi PageNamber")
		return
	}

	QueryStr = fmt.Sprintf("SELECT EndDate FROM LicenseUserKey LIMIT 1")
	if len(ConditionArray) == 0 {
		CommonRows = ConditionQuery_DB(Database, QueryStr)
	} else {
		stmt, _ := Database.Prepare(QueryStr)
		CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
		stmt.Close()
	}
	for CommonRows.Next() {
		err := CommonRows.Scan(&LicensePageInfo.EndDate)
		if err != nil {
			log.Println(" data Scan error:", err)
			return
		}
	}
	CommonRows.Close()

	//license select rowscount
	QueryStr = fmt.Sprintf("SELECT COUNT(*) FROM AccessLog")
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

	//license select data
	NextRowOffset = (PageNumber - 1) * RowCountPerPage
	QueryStr = fmt.Sprintf("SELECT  NodeID, LastConnectionTime FROM AccessLog  LIMIT %d OFFSET %d", RowCountPerPage, NextRowOffset)
	if len(ConditionArray) == 0 {
		CommonRows = ConditionQuery_DB(Database, QueryStr)
	} else {
		stmt, _ := Database.Prepare(QueryStr)
		CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
		stmt.Close()
	}
	perpagerowscount = 1
	for CommonRows.Next() {

		err := CommonRows.Scan(&LicInfo.NodeID, &LicInfo.LastConnTime)
		if err != nil {
			log.Println(" data Scan error:", err)
			return
		}
		LicInfo.No = perpagerowscount
		log.Println(fmt.Sprintf("No : % d , NodeID : %s, LastConnTime : %s", LicInfo.No, LicInfo.NodeID, LicInfo.LastConnTime))
		LicensePageInfo.LicInfo = append(LicensePageInfo.LicInfo, LicInfo)
		perpagerowscount++
	}
	CommonRows.Close()

	//page number setting
	if PageNumber > 1 {
		PrevPageNumber = PageNumber - 1
	} else {
		PrevPageNumber = 1
	}

	PageCount = int(math.Ceil(float64(CommonRowsCount) / float64(RowCountPerPage)))
	log.Println("PageCount:", PageCount)
	if PageNumber < PageCount {
		NextPageNumber = PageNumber + 1
	} else {
		NextPageNumber = PageCount
		log.Println("NexPageNumber:", NextPageNumber)
	}

	log.Println("MaxPageCountInPage:", MaxPageCountInPage)
	PageIndexStart = (((PageNumber - 1) / MaxPageCountInPage) * MaxPageCountInPage) + 1

	TempStr = fmt.Sprintf("/license/?page_num=%d", 1)
	LicensePageInfo.FirstPage = template.HTML(TempStr)

	TempStr = fmt.Sprintf("/license/?page_num=%d", PrevPageNumber)
	LicensePageInfo.PrevPage = template.HTML(TempStr)

	TempStr = fmt.Sprintf("/license/?page_num=%d", NextPageNumber)
	LicensePageInfo.NextPage = template.HTML(TempStr)

	TempStr = fmt.Sprintf("/license/?page_num=%d", PageCount)
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

func Delete_Client_Statistics(lwsDatabase *sql.DB, trafficDatabase *sql.DB) {
	var Select_Standard_ID_SQL string
	var Select_Del_And_Cyc_Time_SQL string
	var timer *time.Timer
	var Del_Time, Cyc_Time int
	var Del_Time_Str string
	var Rows *sql.Rows
	var err error

	log.Println("here is in Delete_Client_Statistics")

	Select_Del_And_Cyc_Time_SQL = "Select Del_Time, Cyc_Time from Users"
	Rows, _ = sqlitedb_lib.Query_DB(lwsDatabase, Select_Del_And_Cyc_Time_SQL)
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

		err = DB_Clnt_Delete_Transaction(trafficDatabase, Select_Standard_ID_SQL)
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

func Delete_Server_Statistics(lwsDatabase *sql.DB, trafficDatabase *sql.DB) {
	var Select_Standard_ID_SQL string
	var Select_Del_And_Cyc_Time_SQL string
	var timer *time.Timer
	var Del_Time, Cyc_Time int
	var Del_Time_Str string
	var Rows *sql.Rows
	var err error

	log.Println("here is in Delete_Client_Statistics")

	Select_Del_And_Cyc_Time_SQL = "Select Del_Time, Cyc_Time from Users"
	Rows, _ = sqlitedb_lib.Query_DB(lwsDatabase, Select_Del_And_Cyc_Time_SQL)
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

		err = DB_Serv_Delete_Transaction(trafficDatabase, Select_Standard_ID_SQL)
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

func GetProxyInfos() (int32, error) {
	var cfgdataStr string
	var cfginfo Settingtoml
	var Frontendname, Backendname string
	var Frontendelm frontendSection
	var Backendelm backendSection
	var NIC_Name_Len, ProxyIP_Len int
	var ProxyIP string
	cfgdata, err := ioutil.ReadFile("./cfg/app.cfg")
	if err != nil {
		log.Println(err)
	}

	cfgdataStr = AESDecryptDecodeValuePrefix(string(cfgdata))
	if _, err = toml.Decode(cfgdataStr, &cfginfo); err != nil {
		log.Println(err)
	}

	for Frontendname, Frontendelm = range cfginfo.Frontend {

		ProxyIPStrArray = nil

		if Frontendelm.Node_Mode == "server" {
			continue
		}

		for Backendname, Backendelm = range cfginfo.Backend {
			if Backendname == Frontendname {
				for _, Serveraddr := range Backendelm.Server {

					NIC_Name_Len = strings.Index(Serveraddr, "/")
					Serveraddr = Serveraddr[NIC_Name_Len+1:]
					ProxyIP_Len = strings.Index(Serveraddr, ":")
					ProxyIP = Serveraddr[0:ProxyIP_Len]
					Serveraddr = Serveraddr[ProxyIP_Len+1:]
					ProxyIPStrArray = append(ProxyIPStrArray, ProxyIP)
				}
			}
		}
	}
	return DB_RET_SUCC, nil
}

func GetNodeModes() (int32, error) {
	var err error
	var Node_Mode, TempNodeMode int
	var Frontendelm frontendSection
	var cfginfo Settingtoml
	var cfgdataStr string

	TempNodeMode = Node_FLAG_NONE

	cfgdata, err := ioutil.ReadFile("./cfg/app.cfg")
	if err != nil {
		log.Println(err)
	}

	cfgdataStr = AESDecryptDecodeValuePrefix(string(cfgdata))
	if _, err = toml.Decode(cfgdataStr, &cfginfo); err != nil {
		log.Println(err)
	}

	for _, Frontendelm = range cfginfo.Frontend {

		if Frontendelm.Node_Mode == "client" {
			Node_Mode = 1
		} else if Frontendelm.Node_Mode == "server" {
			Node_Mode = 2
		} else {
			Node_Mode = 0
		}
		TempNodeMode |= Node_Mode

	}
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

func GetChangeClientIPModes() (int, error) {
	var Change_IP_Func int
	var err error
	var cfginfo Settingtoml
	var cfgdataStr string
	cfgdata, err := ioutil.ReadFile("./cfg/app.cfg")
	if err != nil {
		log.Println(err)
	}

	cfgdataStr = AESDecryptDecodeValuePrefix(string(cfgdata))
	if _, err = toml.Decode(cfgdataStr, &cfginfo); err != nil {
		log.Println(err)
	}

	Change_IP_Func, _ = strconv.Atoi(cfginfo.Node.Cp_tunneling)

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

func Node_Info_List_Dashboard(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	var CfgListPageInfo CfgListPageInfo
	var Params string
	var NodeID, UseBridge, ChangeClientIP string
	var ConditionCount int
	var PageNumInfo PageNumInfo
	var CfgSettingInfo CfglistSettingsInformation

	log.Println("Node_Info_List_Dashboard", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}
	TempStr := fmt.Sprintf("<li class=\"current\"><a href=\"/node_cfg_list/\">Node Setting List</a></li>")
	CfgListPageInfo.NodeSettingsList = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li><a href=\"/statistics/client/\">Client Statistics</a></li>")
	CfgListPageInfo.NodeClientStatMenu = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li><a href=\"/statistics/server/\">Server Statistics</a></li>")
	CfgListPageInfo.NodeServerStatMenu = template.HTML(TempStr)

	Param_PageNumber, ok := req.URL.Query()["page_num"]
	if !ok || len(Param_PageNumber) < 1 {
		log.Println("Parma_PageNumber:", Param_PageNumber)
		WebServer_Redirect(w, req, "/node_cfg_list/?page_num=1")
		return
	}

	if req.Method == "GET" {
		Param_NodeID, ok := req.URL.Query()["nodeid"]
		if ok {
			NodeID = fmt.Sprintf("%s", Param_NodeID)
			NodeID = strings.Replace(NodeID, "[", "", -1)
			NodeID = strings.Replace(NodeID, "]", "", -1)
			NodeID = strings.TrimSpace(NodeID)

			CfgListPageInfo.SearchNodeID = NodeID
		}
		Param_Use_Bridge, ok := req.URL.Query()["usebridge"]
		if ok {
			UseBridge = fmt.Sprintf("%s", Param_Use_Bridge)
			UseBridge = strings.Replace(UseBridge, "[", "", -1)
			UseBridge = strings.Replace(UseBridge, "]", "", -1)
			UseBridge = strings.TrimSpace(UseBridge)

			CfgListPageInfo.SearchUseBridge = UseBridge
		}

		if len(UseBridge) > 0 {
			var UseBridgeHTML UseBridgeHTML

			if UseBridge == "Enable" {
				TempStr = fmt.Sprintf("<option selected=\"selected\">%s</option>", "Enable")
				TempStr += fmt.Sprintf("<option>%s</option>", "Disable")

			} else if UseBridge == "Disable" {
				TempStr = fmt.Sprintf("<option selected=\"selected\">%s</option>", "Disable")
				TempStr += fmt.Sprintf("<option>%s</option>", "Enable")
			} else {
				TempStr = fmt.Sprintf("<option>%s</option>", "Enable")
				TempStr += fmt.Sprintf("<option>%s</option>", "Disable")
			}
			UseBridgeHTML.UseBridge_HTML = template.HTML(TempStr)
			CfgListPageInfo.UseBridgeHTML = UseBridgeHTML.UseBridge_HTML

		} else {
			var UseBridgeHTML UseBridgeHTML

			TempStr = fmt.Sprintf("<option>%s</option>", "Disable")
			TempStr += fmt.Sprintf("<option>%s</option>", "Enable")
			UseBridgeHTML.UseBridge_HTML = template.HTML(TempStr)
			CfgListPageInfo.UseBridgeHTML = UseBridgeHTML.UseBridge_HTML
		}

		Param_Change_Client_IP, ok := req.URL.Query()["changeclientip"]
		if ok {
			ChangeClientIP = fmt.Sprintf("%s", Param_Change_Client_IP)
			ChangeClientIP = strings.Replace(ChangeClientIP, "[", "", -1)
			ChangeClientIP = strings.Replace(ChangeClientIP, "]", "", -1)
			ChangeClientIP = strings.TrimSpace(ChangeClientIP)

			CfgListPageInfo.SearchClientChangeIP = ChangeClientIP
		}

		if len(ChangeClientIP) > 0 {
			var ChangeClientIPHTML ChangeClientIPHTML

			if ChangeClientIP == "Enable" {
				TempStr = fmt.Sprintf("<option selected=\"selected\">%s</option>", "Enable")
				TempStr += fmt.Sprintf("<option>%s</option>", "Disable")

			} else if ChangeClientIP == "Disable" {
				TempStr = fmt.Sprintf("<option selected=\"selected\">%s</option>", "Disable")
				TempStr += fmt.Sprintf("<option>%s</option>", "Enable")
			} else {
				TempStr = fmt.Sprintf("<option>%s</option>", "Enable")
				TempStr += fmt.Sprintf("<option>%s</option>", "Disable")
			}
			ChangeClientIPHTML.ChangeClientIP_HTML = template.HTML(TempStr)
			CfgListPageInfo.ChangeClientIPHTML = ChangeClientIPHTML.ChangeClientIP_HTML

		} else {
			var ChangeClientIPHTML ChangeClientIPHTML

			TempStr = fmt.Sprintf("<option>%s</option>", "Disable")
			TempStr += fmt.Sprintf("<option>%s</option>", "Enable")
			ChangeClientIPHTML.ChangeClientIP_HTML = template.HTML(TempStr)
			CfgListPageInfo.ChangeClientIPHTML = ChangeClientIPHTML.ChangeClientIP_HTML
		}

	} else {
		req.ParseForm()

		NodeID = fmt.Sprintf("%s", req.Form["node_id"])
		NodeID = strings.Replace(NodeID, "[", "", -1)
		NodeID = strings.Replace(NodeID, "]", "", -1)
		NodeID = strings.TrimSpace(NodeID)

		UseBridge = fmt.Sprintf("%s", req.Form["use_bridge"])
		UseBridge = strings.Replace(UseBridge, "[", "", -1)
		UseBridge = strings.Replace(UseBridge, "]", "", -1)
		UseBridge = strings.TrimSpace(UseBridge)

		ChangeClientIP = fmt.Sprintf("%s", req.Form["change_client_ip"])
		ChangeClientIP = strings.Replace(ChangeClientIP, "[", "", -1)
		ChangeClientIP = strings.Replace(ChangeClientIP, "]", "", -1)
		ChangeClientIP = strings.TrimSpace(ChangeClientIP)

	}

	var QueryCommonCondition string
	var ConditionArray []interface{}
	if len(NodeID) > 0 {
		Params += fmt.Sprintf("&nodeid=%s", NodeID)
		if StrtoUUID(NodeID) != 0 {
			QueryCommonCondition += fmt.Sprintf("AND (Node_NodeID=?)")
			ConditionArray = append(ConditionArray, NodeID)
			ConditionCount++

		} else {
			QueryCommonCondition += fmt.Sprintf("AND (Node_NodeID LIKE ?)")
			ConditionArray = append(ConditionArray, NodeID+"%")
			ConditionCount++
		}
	}

	if len(UseBridge) > 0 && UseBridge != "All" {
		Params += fmt.Sprintf("&usebridge=%s", UseBridge)
		if UseBridge == "Enable" {
			QueryCommonCondition += fmt.Sprintf("AND (Node_UseBridgeRouter=?)")
			ConditionArray = append(ConditionArray, UseBridge)
			ConditionCount++
		} else {
			QueryCommonCondition += fmt.Sprintf("AND (Node_UseBridgeRouter LIKE ?)")
			ConditionArray = append(ConditionArray, UseBridge)
			ConditionCount++
		}
	}

	if len(ChangeClientIP) > 0 && ChangeClientIP != "All" {
		Params += fmt.Sprintf("&changeclientip=%s", ChangeClientIP)
		if ChangeClientIP == "Enable" {
			QueryCommonCondition += fmt.Sprintf("AND (Node_ChangeIPClientMode=?)")
			ConditionArray = append(ConditionArray, ChangeClientIP)
			ConditionCount++
		} else {
			QueryCommonCondition += fmt.Sprintf("AND (Node_ChangeIPClientMode LIKE ?)")
			ConditionArray = append(ConditionArray, ChangeClientIP)
			ConditionCount++
		}
	}
	if req.Method == "POST" {
		StatURL := "/node_cfg_list/?page_num=1"
		if len(Params) > 0 {
			StatURL += Params
		}
		WebServer_Redirect(w, req, StatURL)
		return
	}
	PageNumberStr := fmt.Sprintf("%s", Param_PageNumber)
	PageNumberStr = strings.Replace(PageNumberStr, "[", "", -1)
	PageNumberStr = strings.Replace(PageNumberStr, "]", "", -1)
	log.Println("PageNumberStr------------------------------------------:", PageNumberStr)
	PageNumber, err := strconv.Atoi(PageNumberStr)
	if err != nil {
		log.Println("failed to strconv.Atoi")
		StatURL := "/node_cfg_list/?page_num=1"
		WebServer_Redirect(w, req, StatURL)
		return
	}
	log.Println("PageNumber:", PageNumber)

	TempStr = fmt.Sprintf("<th rowspan=\"2\" colspan=\"3\"><a href=\"/node_cfg_list/?page_num=1%s\">Node ID</a></th>", Params)
	CfgListPageInfo.SortNodeID = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th rowspan=\"2\"><a href=\"/node_cfg_list/?page_num=1%s\">Connections</a></th>", Params)
	CfgListPageInfo.SortConnections = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th rowspan=\"2\"><a href=\"/node_cfg_list/?page_num=1%s\">Receive Buffer</a></th>", Params)
	CfgListPageInfo.SortReceiveBuffer = template.HTML(TempStr)

	TempStr = fmt.Sprintf("<th title=\"Connections\"><a href=\"/node_cfg_list/?page_num=1%s\">Send buffer</a></</th>", Params)
	CfgListPageInfo.SortSendBuffer = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th title=\"Receive Buffer\"><a href=\"/node_cfg_list/?page_num=1%s\">Connect</a></</th>", Params)
	CfgListPageInfo.SortConnect = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th title=\"Send Buffer\"><a href=\"/node_cfg_list/?page_num=1%s\">Client</a></</th>", Params)
	CfgListPageInfo.SortClient = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th title=\"Connect\"><a href=\"/node_cfg_list/?page_num=1%s\">Server</a></</th>", Params)
	CfgListPageInfo.SortServer = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th title=\"Client\"><a href=\"/node_cfg_list/?page_num=1%s\">Limit Size</a></</th>", Params)
	CfgListPageInfo.SortLimitSize = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th title=\"Server\"><a href=\"/node_cfg_list/?page_num=1%s\">Max Size</a></</th>", Params)
	CfgListPageInfo.SortMaxSize = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th title=\"Limit Size\"><a href=\"/node_cfg_list/?page_num=1%s\">Path</a></</th>", Params)
	CfgListPageInfo.SortPath = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th title=\"Max Size\"><a href=\"/node_cfg_list/?page_num=1%s\">Error Path</a></</th>", Params)
	CfgListPageInfo.SortErrPath = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th rowspan=\"2\" rowspantitle=\"Path\"><a href=\"/node_cfg_list/?page_num=1%s\">Statistics Collection Cycle</a></</th>", Params)
	CfgListPageInfo.SortStatisticsCollectionCycle = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th rowspan=\"2\" title=\"Error Path\"><a href=\"/node_cfg_list/?page_num=1%s\">Use of Bridge</a></</th>", Params)
	CfgListPageInfo.SortUseBridge = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th rowspan=\"2\" title=\"Error Path\"><a href=\"/node_cfg_list/?page_num=1%s\">Node Buffer Size</a></</th>", Params)
	CfgListPageInfo.SortNodeBufferSize = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th rowspan=\"2\" title=\"Error Path\"><a href=\"/node_cfg_list/?page_num=1%s\">Encriypt Mode</a></</th>", Params)
	CfgListPageInfo.SortEncryptMode = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<th rowspan=\"2\" title=\"Error Path\"><a href=\"/node_cfg_list/?page_num=1%s\">Change IP for Client Mode</a></</th>", Params)
	CfgListPageInfo.SortChangeIPMode = template.HTML(TempStr)

	tmpl, err := template.ParseFiles("./pages/Control_Node_Setting.html")
	if err != nil {
		log.Println("failed to template.ParseFiles")
		return
	}

	NextRowOffset := (PageNumber - 1) * RowCountPerPage
	log.Println("NextRowOffset:", NextRowOffset)
	QueryStr := fmt.Sprintf("Select Count(*) From NodeIDTbl b Where 1=1 %s", QueryCommonCondition)
	log.Println("QueryStr:", QueryStr)
	var CommonRows *sql.Rows
	var CommonRowsCount int
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
	//----------page number setting -------------------

	var PageCount int
	var NextPageNumber int
	var PrevPageNumber int
	var LastPageNumber int
	var PageIndexStart int

	PageCount = int(math.Ceil(float64(CommonRowsCount) / float64(RowCountPerPage)))
	if PageNumber < PageCount {
		NextPageNumber = PageNumber + 1
	} else {
		NextPageNumber = PageCount
	}

	if PageNumber > 1 {
		PrevPageNumber = PageNumber - 1
	} else {
		PrevPageNumber = 1
	}

	TempStr = fmt.Sprintf("/node_cfg_list/?page_num=%d%s", 1, Params)
	CfgListPageInfo.FirstPage = template.HTML(TempStr)

	CfgListPageInfo.PrevPage = template.HTML(TempStr)
	TempStr = fmt.Sprintf("/node_cfg_list/?page_num=%d%s", PrevPageNumber, Params)

	CfgListPageInfo.NextPage = template.HTML(TempStr)
	TempStr = fmt.Sprintf("/node_cfg_list/?page_num=%d%s", NextPageNumber, Params)

	CfgListPageInfo.LastPage = template.HTML(TempStr)
	TempStr = fmt.Sprintf("/node_cfg_list/?page_num=%d%s", PageCount, Params)

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
			TempTag := fmt.Sprintf("<a href=\"/node_cfg_list/?page_num=%d%s\">", PageNumInfo.PageNum, Params)
			PageNumInfo.TagStart = template.HTML(TempTag)
			PageNumInfo.TagEnd = "</a>"
		}

		CfgListPageInfo.PageNumInfo = append(CfgListPageInfo.PageNumInfo, PageNumInfo)
	}
	//----------page number setting -------------------

	//----------setting data query---------------------
	var LogPath string
	var ErrLogpath string
	var LogName string
	var ErrLogName string
	var Node_Status int
	var Node_StatusStr string
	QueryStr = fmt.Sprintf("Select b.Global_MaxConn, b.Global_RecvBufferSize, b.Global_SendBufferSize,b.Global_TimeoutConnect, b.Global_TimeoutClient, b.Global_TimeoutServer,b.Log_DiskLimit, b.Log_MaxSize, b.Log_LogDir, b.Log_LogName, b.Log_ErrDir,b.Log_ErrName, b.Stat_StatCollectionCycle, b.Node_UseBridgeRouter, b.Node_NodeBufferSize,b.Node_EncryptMode, b.Node_ChangeIPClientMode, b.Node_NodeID, b.Node_Status From NodeIDTbl b Where 1=1 %s LIMIT %d OFFSET %d", QueryCommonCondition, RowCountPerPage, NextRowOffset)

	if len(ConditionArray) == 0 {
		CommonRows = ConditionQuery_DB(Database, QueryStr)
	} else {
		stmt, _ := Database.Prepare(QueryStr)
		CommonRows = ConditionQuery_Stmt(stmt, ConditionCount, ConditionArray)
		stmt.Close()
	}
	for CommonRows.Next() {
		err := CommonRows.Scan(&CfgSettingInfo.Maximum_ConnectionCount, &CfgSettingInfo.Recv_Buf_Size, &CfgSettingInfo.Send_Buf_Size, &CfgSettingInfo.Connection_Timeout,
			&CfgSettingInfo.Client_Reconnect_Timeout, &CfgSettingInfo.Server_Reconnect_Timeout, &CfgSettingInfo.Limit_Size_Log_Storage, &CfgSettingInfo.Maxsize_Per_Logfile,
			&LogPath, &LogName, &ErrLogpath, &ErrLogName, &CfgSettingInfo.Statistic_Collection_Cycle, &CfgSettingInfo.Bridge_Used, &CfgSettingInfo.Bridge_Buf_Size,
			&CfgSettingInfo.Encrypt_Mode, &CfgSettingInfo.Change_Client_IP, &CfgSettingInfo.Node_ID, &Node_Status)
		if err != nil {
			log.Println(" data Scan error:", err)
			return
		}

		CfgSettingInfo.Logfile_Path = LogPath + LogName
		CfgSettingInfo.Err_Logfile_Path = ErrLogpath + ErrLogName
		if Node_Status == 0 {
			Node_StatusStr = "<span class=\"status n\"></span>"
		} else {
			Node_StatusStr = "<span class=\"status y\"></span>"
		}
		CfgSettingInfo.Node_Status = template.HTML(Node_StatusStr)

		CfgListPageInfo.Cfginfo = append(CfgListPageInfo.Cfginfo, CfgSettingInfo)
	}

	CommonRows.Close()
	//----------setting data query---------------------

	tmpl.Execute(w, CfgListPageInfo)

}

func Node_Cfg_Detail(w http.ResponseWriter, req *http.Request, Database *sql.DB) {
	defer req.Body.Close()
	var QueryStr string
	var tmpl *template.Template
	var CfgDetailPageInfo CfgDetailPageInfo
	var DeviceID uint64
	var TempStr string
	var Rows *sql.Rows
	var err error
	var TempletName string
	var TempHTML HTMLType

	log.Println("Setting", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	NodeID, ok := req.URL.Query()["node_id"]
	if !ok || len(NodeID) < 1 {
		WebServer_Redirect(w, req, "/node_cfg_list/?page_num=1")
		return
	}
	Node_ID := fmt.Sprintf("%s", NodeID)
	Node_ID = strings.Replace(Node_ID, "[", "", -1)
	Node_ID = strings.Replace(Node_ID, "]", "", -1)
	Node_ID = strings.TrimSpace(Node_ID)
	log.Println("Node_ID:", Node_ID)

	TempStr = fmt.Sprintf("<li><a href=\"/node_cfg_list/\">Node Setting List</a></li>")
	CfgDetailPageInfo.NodeSettingsList = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li><a href=\"/statistics/client/\">Client Statistics</a></li>")
	CfgDetailPageInfo.NodeClientStatMenu = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li ><a href=\"/statistics/server/\">Server Statistics</a></li>")
	CfgDetailPageInfo.NodeServerStatMenu = template.HTML(TempStr)

	//------------------------select TempletName--------------------------------

	QueryStr = "SELECT TempletName from TempletNodeIDTbl;"
	Rows, err = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return
	}
	for Rows.Next() {
		err = Rows.Scan(&TempletName)
		if err != nil {
			log.Println(" data Scan error:", err)
			return
		}
		log.Println("TempletName:", TempletName)

		TempStr = fmt.Sprintf("<option>%s</option>", TempletName)
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.TempletSelectHTMLList = append(CfgDetailPageInfo.TempletSelectHTMLList, TempHTML)

	}
	//------------------------select TempletName--------------------------------
	//------------------------select cfg info--------------------------------
	QueryStr = "SELECT  A.Seq, A.Password, A.VerifyingPassword\n" +
		", A.Global_MaxConn, A.Global_RecvBufferSize, A.Global_SendBufferSize, A.Global_TimeoutConnect, A.Global_TimeoutClient, A.Global_TimeoutServer\n" +
		", A.Log_DiskLimit, A.Log_MaxSize, A.Log_LogDir, A.Log_LogName, A.Log_ErrDir, A.Log_ErrName, A.Stat_SendControlServerFlag\n" +
		", A.Stat_StatCollectionCycle, A.Stat_StatSendControlServer, A.Stat_StatServerIP, A.Stat_StatServerPort, A.Stat_StatDataSendCycle\n" +
		", A.Node_NodeBufferSize, A.Node_EncryptMode, A.Node_ChangeIPClientMode, A.Node_NodeID\n" +
		", A.KMS_IP, A.KMS_Port\n" +
		", B.Name, B.NicName, B.Bind, B.NodeMode /* Frontend */\n" +
		", C.Name, D.NicName, D.IP, D.Port /* Backend */\n" +

		"from NodeIDTbl as A\n" +
		"join NodeIDFrontendTbl as B\n" +
		"on A.Seq = B.SeqNodeID\n" +
		"AND A.Node_NodeID = '" + Node_ID + "'\n" +
		"join NodeIDBackendTbl as C\n" +
		"on A.Seq = C.SeqNodeID\n" +
		"join NodeIDBackendAddressTbl as D\n" +
		"on C.Seq = D.SeqBackend\n" +
		"and B.Name = C.Name;"

	Rows, err = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		log.Println("Rows nil")
		return
	}
	var StatSendFlag int
	var UseEnc, UseChangeIP int
	var idx int
	var frontendName, frontendPort, frontendNIC, frontendNodeMode, backendName, backendNIC, backendIP, backendPort, frontendName1 string
	var StatSendFlagStr string
	settingData := new(DetailSettingsInformation)
	idx = -1
	for Rows.Next() {
		err = Rows.Scan(&DeviceID, &settingData.Password, &settingData.VerifyingPassword,
			&settingData.Maximum_ConnectionCount, &settingData.Recv_Buf_Size, &settingData.Send_Buf_Size, &settingData.Connection_Timeout, &settingData.Client_Reconnect_Timeout, &settingData.Server_Reconnect_Timeout,
			&settingData.Limit_Size_Log_Storage, &settingData.Maxsize_Per_Logfile, &CfgDetailPageInfo.Log, &CfgDetailPageInfo.LogFileName, &CfgDetailPageInfo.Error, &CfgDetailPageInfo.ErrorFileName, &StatSendFlagStr,
			&settingData.Statistic_Collection_Cycle, &settingData.Statistic_Send_Control_Server, &CfgDetailPageInfo.Control_Server_IP, &settingData.Statistic_Server_Port, &settingData.Statistic_Send_Cycle,
			&settingData.Bridge_Buf_Size, &settingData.Encrypt_Mode, &settingData.Change_Client_IP, &settingData.Node_ID,
			&settingData.KMS_Address, &settingData.KMS_Port, &frontendName, &frontendNIC, &frontendPort, &frontendNodeMode, &backendName, &backendNIC, &backendIP, &backendPort)
		if err != nil {
			log.Println(" data Scan error:", err)
			return
		}

		if StatSendFlagStr == "Enable" {
			StatSendFlag = ENABLE
		} else {
			StatSendFlag = DISABLE
		}

		if frontendName != frontendName1 {
			frontend := FrontendInformation{}
			settingData.SiteList = append(settingData.SiteList, frontend)
			idx++

			settingData.SiteList[idx].Frontendsymbol = frontendName
			//settingData.SiteList[idx].FrontendPort = frontendNIC + ":" + frontendPort
			settingData.SiteList[idx].FrontendPort = frontendPort
			settingData.SiteList[idx].NodeMode = frontendNodeMode
			frontendName1 = frontendName
		}

		backend := BackendInformationList{}
		backend.LAN_Interface = backendNIC
		backend.BackendIP = backendIP
		backend.BackendPort = backendPort
		settingData.SiteList[idx].Backend = append(settingData.SiteList[idx].Backend, backend)

		CfgDetailPageInfo.DeviceID = DeviceID
		CfgDetailPageInfo.Max_Conn, _ = strconv.Atoi(settingData.Maximum_ConnectionCount)
		CfgDetailPageInfo.Recv_Buffer_Size, _ = strconv.Atoi(settingData.Recv_Buf_Size)
		CfgDetailPageInfo.Send_Buffer_Size, _ = strconv.Atoi(settingData.Send_Buf_Size)
		CfgDetailPageInfo.Timeout_Connect, _ = strconv.Atoi(settingData.Connection_Timeout)
		CfgDetailPageInfo.Timeout_Client, _ = strconv.Atoi(settingData.Client_Reconnect_Timeout)
		CfgDetailPageInfo.Timeout_Server, _ = strconv.Atoi(settingData.Server_Reconnect_Timeout)
		CfgDetailPageInfo.Disk_Limit, _ = strconv.Atoi(settingData.Limit_Size_Log_Storage)
		Maxsize_Per_Logfile := strings.TrimRight(settingData.Maxsize_Per_Logfile, "MB")
		CfgDetailPageInfo.Max_Size, _ = strconv.Atoi(Maxsize_Per_Logfile)
		CfgDetailPageInfo.Interval, _ = strconv.Atoi(settingData.Statistic_Collection_Cycle)
		CfgDetailPageInfo.Control_Server_IP = settingData.Statistic_Server_Ip
		CfgDetailPageInfo.Control_Server_Port, _ = strconv.Atoi(settingData.Statistic_Server_Port)
		CfgDetailPageInfo.Control_Server_Send_Interval, _ = strconv.Atoi(settingData.Statistic_Send_Cycle)
		CfgDetailPageInfo.Buffer_Size, _ = strconv.Atoi(settingData.Bridge_Buf_Size)
		CfgDetailPageInfo.EncryptMode = settingData.Encrypt_Mode
		CfgDetailPageInfo.ChangeIpClientMode = settingData.Change_Client_IP
		CfgDetailPageInfo.Node_ID = settingData.Node_ID
		CfgDetailPageInfo.KMS_Address = settingData.KMS_Address
		CfgDetailPageInfo.KMS_Port, _ = strconv.Atoi(settingData.KMS_Port)

		if CfgDetailPageInfo.EncryptMode == "None" {
			UseEnc = ENC_NONE
		} else if CfgDetailPageInfo.EncryptMode == "AES_128" {
			UseEnc = ENC_AES128
		} else if CfgDetailPageInfo.EncryptMode == "AES_256" {
			UseEnc = ENC_AES256
		} else {
			UseEnc = ENC_RC4
		}
		//------------------test UpseChangeIP value ---------------------
		CfgDetailPageInfo.ChangeIpClientMode = "Disable"
		if CfgDetailPageInfo.ChangeIpClientMode == "Enable" {
			UseChangeIP = ENABLE
		} else {
			UseChangeIP = DISABLE
		}
		//------------------test UpseChangeIP value ---------------------
		if CfgDetailPageInfo.ChangeIpClientMode == "Enable" {
			UseChangeIP = ENABLE
		} else {
			UseChangeIP = DISABLE
		}
	}

	log.Println("settingData:", settingData)
	Rows.Close()

	if StatSendFlag == ENABLE {
		TempStr = "<option selected=\"selected\">Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.StatSelectHTMLList = append(CfgDetailPageInfo.StatSelectHTMLList, TempHTML)
		TempStr = "<option>Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.StatSelectHTMLList = append(CfgDetailPageInfo.StatSelectHTMLList, TempHTML)
	} else {
		TempStr = "<option selected=\"selected\">Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.StatSelectHTMLList = append(CfgDetailPageInfo.StatSelectHTMLList, TempHTML)
		TempStr = "<option>Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.StatSelectHTMLList = append(CfgDetailPageInfo.StatSelectHTMLList, TempHTML)
	}

	if UseEnc == ENC_NONE {
		TempStr = "<option selected=\"selected\">None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
	} else if UseEnc == ENC_AES128 {
		TempStr = "<option selected=\"selected\">AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
	} else if UseEnc == ENC_AES256 {
		TempStr = "<option selected=\"selected\">AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
	} else if UseEnc == ENC_RC4 {
		TempStr = "<option selected=\"selected\">RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.EncModeSelectHTMLList = append(CfgDetailPageInfo.EncModeSelectHTMLList, TempHTML)
	}

	if UseChangeIP == ENABLE {
		TempStr = "<option selected=\"selected\">Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.ChangeIPSelectHTMLList = append(CfgDetailPageInfo.ChangeIPSelectHTMLList, TempHTML)
		TempStr = "<option>Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.ChangeIPSelectHTMLList = append(CfgDetailPageInfo.ChangeIPSelectHTMLList, TempHTML)
	} else {
		TempStr = "<option selected=\"selected\">Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.ChangeIPSelectHTMLList = append(CfgDetailPageInfo.ChangeIPSelectHTMLList, TempHTML)
		TempStr = "<option>Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.ChangeIPSelectHTMLList = append(CfgDetailPageInfo.ChangeIPSelectHTMLList, TempHTML)
	}

	var FrontBack_Data_Count int
	QueryStr = fmt.Sprintf("SELECT  Count(*) FROM NodeIDTbl b, NodeIDFrontendTbl c WHERE b.Node_NodeID = '" + Node_ID + "'and b.Seq = c.SeqNodeID;")
	Rows, _ = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return
	}

	for Rows.Next() {
		err = Rows.Scan(&FrontBack_Data_Count)
		if err != nil {
			log.Println(" data Scan error:", err)
			return
		}
	}

	var Symbol_Name string
	var Bind, Node_Mode int
	var OptionStr string
	var count int
	var BackendList, IDTagStart, IDTagEnd, HRTag, Button string
	var NICName, ProxyIP, ProxyPort string

	for i := range settingData.SiteList {
		count++

		Symbol_Name = settingData.SiteList[i].Frontendsymbol
		Bind, _ = strconv.Atoi(settingData.SiteList[i].FrontendPort)
		Node_Mode, _ = strconv.Atoi(settingData.SiteList[i].NodeMode)
		if settingData.SiteList[i].NodeMode == "client" {
			Node_Mode = Node_MODE_CLIENT
		} else if settingData.SiteList[i].NodeMode == "server" {
			Node_Mode = Node_MODE_SERVER
		} else {
			Node_Mode = Node_MODE_NONE
		}

		BackendList = ""
		for j := range settingData.SiteList[i].Backend {

			NICName = settingData.SiteList[i].Backend[j].LAN_Interface
			ProxyIP = settingData.SiteList[i].Backend[j].BackendIP
			ProxyPort = settingData.SiteList[i].Backend[j].BackendPort
			// for j := range NICInfoArray {
			// 	if NICInfoArray[j].Name == NICName {
			// 		OptionStr += fmt.Sprintf("<option selected=\"selected\" value=\"%s\">%s</option>", NICInfoArray[j].Name, NICInfoArray[j].Name)
			// 	} else {
			// 		OptionStr += fmt.Sprintf("<option value=\"%s\">%s</option>", NICInfoArray[j].Name, NICInfoArray[j].Name)
			// 	}
			// }
			OptionStr = ""
			if NICName != "OS_Default" {
				OptionStr = fmt.Sprintf("<option selected=\"selected\" value=\"%s\">%s</option>", NICName, NICName)
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
		CfgDetailPageInfo.FrontBackHTMLList = append(CfgDetailPageInfo.FrontBackHTMLList, TempHTML)
	}
	Rows.Close()

	NodeModeStr := fmt.Sprintf("<option selected=\"selected\" value=\"%d\">선택해주세요</option>", Node_MODE_NONE)
	NodeModeStr += fmt.Sprintf("<option value=\"%d\">Node Client</option>", Node_MODE_CLIENT)
	if DeviceOSFlag == GENERAL_OS {
		NodeModeStr += fmt.Sprintf("<option value=\"%d\">Node Server</option>", Node_MODE_SERVER)
	}
	CfgDetailPageInfo.FrontendNodeMode = template.HTML(NodeModeStr)

	if count == 0 {
		TempStr = fmt.Sprintf("<div id=\"Frontend\"><div data-SiteType=\"1\"><h2>Frontend<div><button type=\"button\" class=\"green\" act=\"btnFrontendAdd\">Add</button></div></h2><table class=\"input\"><colgroup><col width=\"250\"><col></colgroup><tbody><tr><th>Symbol</th><td><input type=\"text\" class=\"s100\" Frontendsymbol reserve=\"ko en number space length\" min=\"2\" max=\"32\" msg=\"글자 2 - 32 까지만 입력이 가능 합니다.\" group=\"all\" value=\"\"></td></tr><tr><th>Bind Port</th><td><input type=\"text\" class=\"s100\" FrontendPort reserve=\"between\" min=\"1\" max=\"65535\" msg=\"숫자 1 - 65535 까지만 입력이 가능 합니다.\" group=\"all\" value=\"\"/></td></tr><tr><th>Node Mode</th><td><select Node_Mode>%s</select><button type=\"button\" act=\"btnFrontendConfirm\" >Confirm</button></td></tr></tbody></table></div></div>", NodeModeStr)
		TempHTML.Value_HTML = template.HTML(TempStr)
		CfgDetailPageInfo.FrontBackHTMLList = append(CfgDetailPageInfo.FrontBackHTMLList, TempHTML)
	}

	var NICNAMEHTML HTMLType

	LAN_Interface_Templet := fmt.Sprintf("<option>%s</option>", "OS_Default")
	NICNAMEHTML.Value_HTML = template.HTML(LAN_Interface_Templet)
	CfgDetailPageInfo.NICNAMEHTMLList = append(CfgDetailPageInfo.NICNAMEHTMLList, NICNAMEHTML)

	tmpl, err = template.ParseFiles("./pages/Control_Node_Setting_Detail.html")
	if err != nil {
		log.Println("failed to template.ParseFiles")
		return
	}

	tmpl.Execute(w, CfgDetailPageInfo)

}
func Modified_Cfg_Detail(w http.ResponseWriter, req *http.Request, Database *sql.DB) int {
	defer req.Body.Close()
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryStr string
	var Settings TempletSettingsInformation
	var Rows *sql.Rows
	var NodeIDSeq int
	var err error
	var UserkeySeq int
	log.Println("Save_NewTemplet", req.URL)

	r := json.NewDecoder(req.Body)
	err = r.Decode(&Settings)
	if err != io.EOF {
		if err != nil {
			log.Println(err)
			return 0
		}
	}

	log.Println("Settings value:", Settings)
	tx, err = mariadb_lib.DB_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return 0
	}
	defer mariadb_lib.DB_Rollback(tx)
	//----------------------------Select NodeIDSeq --------------------------
	QueryStr = "SELECT Seq , SeqUserKey from NodeIDTbl WHERE Node_NodeID = ?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(Settings.Node_ID)
	if err != nil {
		stmt.Close()
		log.Println("Query:", err)
		return 0
	}
	for Rows.Next() {
		err := Rows.Scan(&NodeIDSeq, &UserkeySeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}
	}
	stmt.Close()

	log.Println("select from NodeIDSeq :", NodeIDSeq)

	//----------------------------Select NodeIDSeq --------------------------
	//----------------------------Delete NodeIDFrontendTbl --------------------------

	QueryStr = "DELETE FROM NodeIDFrontendTbl WHERE  SeqNodeID =?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(NodeIDSeq)
	if err != nil {
		stmt.Close()
		log.Println("Query:", err)
		return 0
	}
	stmt.Close()
	//----------------------------Delete NodeIDFrontendTbl --------------------------
	//----------------------------Delete NodeIDBackendTbl --------------------------

	QueryStr = "DELETE FROM NodeIDBackendTbl WHERE  SeqNodeID =?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(NodeIDSeq)
	if err != nil {
		stmt.Close()
		log.Println("Query:", err)
		return 0
	}
	stmt.Close()
	//----------------------------Delete NodeIDBackendTbl --------------------------
	//----------------------------Delete NodeIDBackendAddressTbl --------------------------
	QueryStr = "DELETE FROM NodeIDBackendAddressTbl WHERE  SeqNodeID =?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(NodeIDSeq)
	if err != nil {
		stmt.Close()
		log.Println("Query:", err)
		return 0
	}
	stmt.Close()
	//----------------------------Delete NodeIDBackendAddressTbl --------------------------

	//----------------------------Update into NodeIDTbl --------------------------
	QueryStr = "UPDATE NodeIDTbl SET " +
		"Password = ?, VerifyingPassword = ?, Global_MaxConn = ?, Global_RecvBufferSize = ?, Global_SendBufferSize = ?, " +
		"Global_TimeoutConnect = ?, Global_TimeoutClient = ?, Global_TimeoutServer = ?, " +
		"Log_DiskLimit = ?, Log_MaxSize = ?, Log_LogDir = ?, Log_LogName = ?, Log_ErrDir = ?, Log_ErrName = ?, " +
		"Stat_SendControlServerFlag = ?, Stat_StatCollectionCycle = ?, Stat_StatSendControlServer = ?, Stat_StatServerIP = ?, Stat_StatServerPort = ?, Stat_StatDataSendCycle = ?, " +
		"Node_UseBridgeRouter = ?, Node_NodeBufferSize = ?, Node_EncryptMode = ?, Node_ChangeIPClientMode = ?, Node_NodeID = ?, " +
		"KMS_IP = ?, KMS_Port = ? " +
		"WHERE Seq = ? "
	log.Println("Query:", QueryStr)

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(Settings.Password, Settings.VerifyingPassword, Settings.Maximum_ConnectionCount, Settings.Recv_Buf_Size, Settings.Send_Buf_Size,
		Settings.Connection_Timeout, Settings.Client_Reconnect_Timeout, Settings.Server_Reconnect_Timeout,
		Settings.Limit_Size_Log_Storage, Settings.Maxsize_Per_Logfile, Settings.Logfile_Path, "app.log", Settings.Err_Logfile_Path, "app_err.log",
		Settings.Statistic_Send_Control_Server, Settings.Statistic_Collection_Cycle, Settings.Statistic_Server_Ip, Settings.Statistic_Server_Ip, Settings.Statistic_Server_Port, Settings.Statistic_Send_Cycle,
		Settings.Bridge_Used, Settings.Bridge_Buf_Size, Settings.Encrypt_Mode, Settings.Change_Client_IP, Settings.Node_ID,
		Settings.KMS_Address, Settings.KMS_Port,
		NodeIDSeq)
	if err != nil {
		stmt.Close()
		log.Println("Query:", err)
		return 0
	}
	stmt.Close()

	//----------------------------Update into NodeIDTbl --------------------------
	//----------------------------Select NodeIDSeq --------------------------
	QueryStr = "SELECT Seq from NodeIDTbl WHERE Node_NodeID = ?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(Settings.Node_ID)
	if err != nil {
		stmt.Close()
		log.Println("Query:", err)
		return 0
	}
	for Rows.Next() {
		err := Rows.Scan(&NodeIDSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}
	}
	stmt.Close()

	log.Println("select from NodeIDSeq :", NodeIDSeq)

	//----------------------------Select NodeIDSeq --------------------------
	//----------------------------Insert Into NodeIDFrontendTbl --------------------------

	for i := range Settings.SiteList {

		QueryStr = "INSERT INTO NodeIDFrontendTbl (SeqNodeID,Name, NicName,Bind,Backend , NodeMode)\n" +
			"VALUES(?,?,?,?,?,?)"

		stmt, err = tx.Prepare(QueryStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		if Settings.SiteList[i].NodeMode == "1" {
			Settings.SiteList[i].NodeMode = "client"
		} else if Settings.SiteList[i].NodeMode == "2" {
			Settings.SiteList[i].NodeMode = "server"
		} else {
			Settings.SiteList[i].NodeMode = "client"
		}
		_, err = stmt.Exec(NodeIDSeq, Settings.SiteList[i].Frontendsymbol, "", Settings.SiteList[i].FrontendPort, Settings.SiteList[i].Frontendsymbol, Settings.SiteList[i].NodeMode)
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()
	}
	//----------------------------Insert Into NodeIDFrontendTbl --------------------------
	//----------------------------Insert Into NodeIDBackendTbl --------------------------
	for i := range Settings.SiteList {

		QueryStr = "INSERT INTO NodeIDBackendTbl (SeqNodeID,Name)\n" +
			"VALUES(?,?)"

		stmt, err = tx.Prepare(QueryStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}
		_, err = stmt.Exec(NodeIDSeq, Settings.SiteList[i].Frontendsymbol)
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()
	}

	//----------------------------Insert Into NodeIDBackendTbl ------------------------------------------------------------
	//----------------------------Select NodeIDBackendTbl and insert into NodeIDBackendAddressTbl-------------------------
	var NewBackendSeq int
	var NewBackendSeqArr []int

	QueryStr = "SELECT Seq FROM NodeIDBackendTbl WHERE SeqNodeID = ?"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(NodeIDSeq)
	if err != nil {
		stmt.Close()
		log.Println("Query:", err)
		return 0
	}

	for Rows.Next() {
		err := Rows.Scan(&NewBackendSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}

		NewBackendSeqArr = append(NewBackendSeqArr, NewBackendSeq)

	}
	stmt.Close()
	for i := range Settings.SiteList {
		for j := range Settings.SiteList[i].Backend {
			QueryStr = "INSERT INTO NodeIDBackendAddressTbl (SeqNodeID, SeqBackend, NicName, IP, Port) " +
				"VALUES (?, ?, ?, ?, ?) "
			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("Prepare Fail!:", err)

				return 0
			}

			_, err = stmt.Exec(NodeIDSeq, NewBackendSeqArr[i], Settings.SiteList[i].Backend[j].LAN_Interface, Settings.SiteList[i].Backend[j].BackendIP, Settings.SiteList[i].Backend[j].BackendPort)
			if err != nil {
				stmt.Close()
				log.Println("Query:", err)
				return 0
			}
			stmt.Close()
		}
	}

	QueryStr = "UPDATE CWS_SyncSeqNoTbl SET \n" +
		"SeqNo = SeqNo + 1, SeqNodeID = ? \n" +
		"WHERE SeqNodeID = ?  AND SeqNoName = ? "

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	DeviceID, _ := strconv.Atoi(Settings.DeviceID)
	_, err = stmt.Exec(NodeIDSeq, DeviceID, "ConfigData")
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	mariadb_lib.DB_Commit(tx)
	return 0
}

func Apply_Templet_to_Cfg(w http.ResponseWriter, req *http.Request, Database *sql.DB) int {
	defer req.Body.Close()
	var QueryStr string
	var TempletPageInfo TempletPageInfo
	var TempStr string
	var Rows *sql.Rows
	var err error
	var TempletName string
	var stmt *sql.Stmt
	var tx *sql.Tx
	var NodeIDSeq int
	log.Println("Load_Templet", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return 0
	}
	Param_TempletName, ok := req.URL.Query()["TempletName"]
	if !ok || len(Param_TempletName) < 1 {
		WebServer_Redirect(w, req, "/node_cfg_list/?page_num=1")
		return 0
	}
	TempletNameStr := fmt.Sprintf("%s", Param_TempletName)
	TempletNameStr = strings.Replace(TempletNameStr, "[", "", -1)
	TempletNameStr = strings.Replace(TempletNameStr, "]", "", -1)

	Param_NodeID, ok := req.URL.Query()["NodeID"]
	if !ok || len(Param_NodeID) < 1 {
		WebServer_Redirect(w, req, "/node_cfg_list/?page_num=1")
		return 0
	}
	NodeIDStr := fmt.Sprintf("%s", Param_NodeID)
	NodeIDStr = strings.Replace(NodeIDStr, "[", "", -1)
	NodeIDStr = strings.Replace(NodeIDStr, "]", "", -1)

	Param_DeviceID, ok := req.URL.Query()["DeviceID"]
	if !ok || len(Param_NodeID) < 1 {
		WebServer_Redirect(w, req, "/node_cfg_list/?page_num=1")
		return 0
	}
	DeviceIDStr := fmt.Sprintf("%s", Param_DeviceID)
	DeviceIDStr = strings.Replace(DeviceIDStr, "[", "", -1)
	DeviceIDStr = strings.Replace(DeviceIDStr, "]", "", -1)

	TempStr = fmt.Sprintf("<li><a href=\"/node_cfg_list/\">Node Setting List</a></li>")
	TempletPageInfo.NodeSettingsList = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li><a href=\"/statistics/client/\">Client Statistics</a></li>")
	TempletPageInfo.NodeClientStatMenu = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li ><a href=\"/statistics/server/\">Server Statistics</a></li>")
	TempletPageInfo.NodeServerStatMenu = template.HTML(TempStr)
	//------------------------------select templet info-------------------------------
	QueryStr = "SELECT A.TempletName, A.Password\n" +
		", A.Global_MaxConn, A.Global_RecvBufferSize, A.Global_SendBufferSize, A.Global_TimeoutConnect, A.Global_TimeoutClient, A.Global_TimeoutServer\n" +
		", A.Log_DiskLimit, A.Log_MaxSize, A.Log_LogDir, A.Log_LogName, A.Log_ErrDir, A.Log_ErrName, A.Stat_SendControlServerFlag\n" +
		", A.Stat_StatCollectionCycle, A.Stat_StatSendControlServer, A.Stat_StatServerIP, A.Stat_StatServerPort, A.Stat_StatDataSendCycle\n" +
		", A.Node_NodeBufferSize, A.Node_EncryptMode, A.Node_ChangeIPClientMode\n" +
		", A.KMS_IP, A.KMS_Port\n" +
		", B.Name, B.NicName, B.Bind, B.NodeMode /* Frontend */\n" +
		", C.Name, D.NicName, D.IP, D.Port /* Backend */\n" +

		"from TempletNodeIDTbl as A\n" +
		"join TempletNodeIDFrontendTbl as B\n" +
		"on A.Seq = B.SeqNodeID\n" +
		"AND A.TempletName = '" + TempletNameStr + "'\n" +
		"join TempletNodeIDBackendTbl as C\n" +
		"on A.Seq = C.SeqNodeID\n" +
		"join TempletNodeIDBackendAddressTbl as D\n" +
		"on C.Seq = D.SeqBackend\n" +
		"and B.Name = C.Name;"

	Rows, err = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return 0
	}

	var idx int
	var frontendName, frontendPort, frontendNIC, frontendNodeMode, backendName, backendNIC, backendIP, backendPort, frontendName1 string
	var StatSendFlagStr string
	var LogFilePath, LogName, ErrLogFilePath, ErrLogName string
	Settings := new(SettingsInformation)
	idx = -1
	for Rows.Next() {
		err = Rows.Scan(&TempletName, &Settings.Password,
			&Settings.Maximum_ConnectionCount, &Settings.Recv_Buf_Size, &Settings.Send_Buf_Size, &Settings.Connection_Timeout, &Settings.Client_Reconnect_Timeout, &Settings.Server_Reconnect_Timeout,
			&Settings.Limit_Size_Log_Storage, &Settings.Maxsize_Per_Logfile, &LogFilePath, &LogName, &ErrLogFilePath, &ErrLogName, &StatSendFlagStr,
			&Settings.Statistic_Collection_Cycle, &Settings.Statistic_Send_Control_Server, &Settings.Statistic_Server_Ip, &Settings.Statistic_Server_Port, &Settings.Statistic_Send_Cycle,
			&Settings.Bridge_Buf_Size, &Settings.Encrypt_Mode, &Settings.Change_Client_IP,
			&Settings.KMS_Address, &Settings.KMS_Port, &frontendName, &frontendNIC, &frontendPort, &frontendNodeMode, &backendName, &backendNIC, &backendIP, &backendPort)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}
		if frontendName != frontendName1 {
			frontend := FrontendInformation{}
			Settings.SiteList = append(Settings.SiteList, frontend)
			idx++

			Settings.SiteList[idx].Frontendsymbol = frontendName
			//Settings.SiteList[idx].FrontendPort = frontendNIC + ":" + frontendPort
			Settings.SiteList[idx].FrontendPort = frontendPort
			Settings.SiteList[idx].NodeMode = frontendNodeMode
			frontendName1 = frontendName
		}

		backend := BackendInformationList{}
		backend.LAN_Interface = backendNIC
		backend.BackendIP = backendIP
		backend.BackendPort = backendPort
		Settings.SiteList[idx].Backend = append(Settings.SiteList[idx].Backend, backend)
	}
	log.Println("Settings:", Settings)
	Rows.Close()
	//------------------------------select templet info-------------------------------

	tx, err = mariadb_lib.DB_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return 0
	}
	defer mariadb_lib.DB_Rollback(tx)

	//----------------------------Select NodeIDSeq --------------------------
	QueryStr = "SELECT Seq  from NodeIDTbl WHERE Node_NodeID = ?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)
		return 0
	}
	Rows, err = stmt.Query(NodeIDStr)
	if err != nil {
		stmt.Close()
		return 0
	}
	for Rows.Next() {
		err := Rows.Scan(&NodeIDSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}
	}
	stmt.Close()

	log.Println("select from NodeIDSeq :", NodeIDSeq)

	//----------------------------Select NodeIDSeq --------------------------
	//----------------------------Update NodeIDTbl --------------------------
	QueryStr = "UPDATE NodeIDTbl SET " +
		"Password = ?, VerifyingPassword = ?, Global_MaxConn = ?, Global_RecvBufferSize = ?, Global_SendBufferSize = ?, " +
		"Global_TimeoutConnect = ?, Global_TimeoutClient = ?, Global_TimeoutServer = ?, " +
		"Log_DiskLimit = ?, Log_MaxSize = ?, Log_LogDir = ?, Log_LogName = ?, Log_ErrDir = ?, Log_ErrName = ?, " +
		"Stat_SendControlServerFlag = ?, Stat_StatCollectionCycle = ?, Stat_StatSendControlServer = ?, Stat_StatServerIP = ?, Stat_StatServerPort = ?, Stat_StatDataSendCycle = ?, " +
		"Node_UseBridgeRouter = ?, Node_NodeBufferSize = ?, Node_EncryptMode = ?, Node_ChangeIPClientMode = ?, Node_NodeID = ?, " +
		"KMS_IP = ?, KMS_Port = ? " +
		"WHERE Seq = ? "
	log.Println("Query:", QueryStr)
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(Settings.Password, Settings.Password, Settings.Maximum_ConnectionCount, Settings.Recv_Buf_Size, Settings.Send_Buf_Size,
		Settings.Connection_Timeout, Settings.Client_Reconnect_Timeout, Settings.Server_Reconnect_Timeout,
		Settings.Limit_Size_Log_Storage, Settings.Maxsize_Per_Logfile, LogFilePath, LogName, ErrLogFilePath, ErrLogName,
		Settings.Statistic_Send_Control_Server, Settings.Statistic_Collection_Cycle, StatSendFlagStr, Settings.Statistic_Server_Ip, Settings.Statistic_Server_Port, Settings.Statistic_Send_Cycle,
		Settings.Bridge_Used, Settings.Bridge_Buf_Size, Settings.Encrypt_Mode, Settings.Change_Client_IP, NodeIDStr,
		Settings.KMS_Address, Settings.KMS_Port,
		NodeIDSeq)
	if err != nil {
		log.Println("Exec err:", err)
		stmt.Close()

		return 0
	}
	stmt.Close()
	//----------------------------Update into NodeIDTbl --------------------------
	QueryStr = "DELETE FROM NodeIDFrontendTbl WHERE SeqNodeID = ? "
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(NodeIDSeq)

	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	QueryStr = "DELETE FROM NodeIDBackendTbl WHERE SeqNodeID = ? "
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(NodeIDSeq)
	if err != nil {
		stmt.Close()
		return 0
	}
	stmt.Close()

	QueryStr = "DELETE FROM NodeIDBackendAddressTbl WHERE SeqNodeID = ? "
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}

	_, err = stmt.Exec(NodeIDSeq)
	if err != nil {
		stmt.Close()
		return 0
	}
	stmt.Close()
	//----------------------------Insert Into NodeIDFrontendTbl --------------------------

	for i := range Settings.SiteList {

		QueryStr = "INSERT  INTO NodeIDFrontendTbl (SeqNodeID,Name, NicName,Bind,Backend , NodeMode)\n" +
			"VALUES(?,?,?,?,?,?)"

		stmt, err = tx.Prepare(QueryStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}
		_, err = stmt.Exec(NodeIDSeq, Settings.SiteList[i].Frontendsymbol, "", Settings.SiteList[i].FrontendPort, Settings.SiteList[i].Frontendsymbol, Settings.SiteList[i].NodeMode)
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()
	}

	//----------------------------Insert Into NodeIDFrontendTbl --------------------------
	//----------------------------Insert Into NodeIDBackendTbl --------------------------
	for i := range Settings.SiteList {

		QueryStr = "INSERT INTO NodeIDBackendTbl (SeqNodeID,Name)\n" +
			"VALUES(?,?)"

		stmt, err = tx.Prepare(QueryStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}
		_, err = stmt.Exec(NodeIDSeq, Settings.SiteList[i].Frontendsymbol)
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()
	}

	//----------------------------Insert Into NodeIDBackendTbl ------------------------------------------------------------
	//----------------------------Select NodeIDBackendTbl and  insert into NodeIDBackendAddressTbl-------------------------
	var NewBackendSeq int
	var NewBackendSeqArr []int

	QueryStr = "SELECT Seq FROM NodeIDBackendTbl WHERE SeqNodeID = ?"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(NodeIDSeq)
	if err != nil {
		stmt.Close()
		log.Println("Query err:", err)
		return 0
	}

	for Rows.Next() {
		err := Rows.Scan(&NewBackendSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}

		NewBackendSeqArr = append(NewBackendSeqArr, NewBackendSeq)

	}
	stmt.Close()
	for i := range Settings.SiteList {
		for j := range Settings.SiteList[i].Backend {
			QueryStr = "INSERT INTO NodeIDBackendAddressTbl (SeqNodeID, SeqBackend, NicName, IP, Port) " +
				"VALUES (?, ?, ?, ?, ?) "
			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("Prepare Fail!:", err)

				return 0
			}

			_, err = stmt.Exec(NodeIDSeq, NewBackendSeqArr[i], Settings.SiteList[i].Backend[j].LAN_Interface, Settings.SiteList[i].Backend[j].BackendIP, Settings.SiteList[i].Backend[j].BackendPort)
			if err != nil {
				stmt.Close()

				return 0
			}
			stmt.Close()
		}
	}
	QueryStr = "UPDATE CWS_SyncSeqNoTbl SET \n" +
		"SeqNo = SeqNo + 1, SeqNodeID = ? \n" +
		"WHERE SeqNodeID = ?  AND SeqNoName = ?"

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	DeviceID, _ := strconv.Atoi(DeviceIDStr)
	_, err = stmt.Exec(NodeIDSeq, DeviceID, "ConfigData")
	if err != nil {
		stmt.Close()
		log.Println("Exec Fail!:", err)
		return 0
	}
	stmt.Close()

	mariadb_lib.DB_Commit(tx)
	WebServer_Redirect(w, req, "/node_cfg_list/?page_num=1/")

	return 0
}

func Add_Templet(w http.ResponseWriter, req *http.Request, Database *sql.DB) {

	defer req.Body.Close()

	var QueryStr string
	var tmpl *template.Template
	var TempletPageInfo TempletPageInfo
	var TempStr string
	var Rows *sql.Rows
	var err error
	var TempletName string
	var TempHTML HTMLType
	log.Println("Setting", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}
	TempStr = fmt.Sprintf("<li><a href=\"/node_cfg_list/\">Node Setting List</a></li>")
	TempletPageInfo.NodeSettingsList = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li><a href=\"/statistics/client/\">Client Statistics</a></li>")
	TempletPageInfo.NodeClientStatMenu = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li ><a href=\"/statistics/server/\">Server Statistics</a></li>")
	TempletPageInfo.NodeServerStatMenu = template.HTML(TempStr)

	//-----------------------templet name list-----------------------------------
	QueryStr = "SELECT A.TempletName from TempletNodeIDTbl as A;"
	Rows, err = mariadb_lib.Query_DB(Database, QueryStr)
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
		err = Rows.Scan(&TempletName)
		if err != nil {
			log.Println(" data Scan error:", err)
			UpdateLock.Unlock()
			log.Println("1018/Release Lock")
			return
		}
		if TempletName == "New" {
			TempStr = fmt.Sprintf("<option  selected=\"selected\" value=\"%s\">%s</option>", TempletName, TempletName)
			TempHTML.Value_HTML = template.HTML(TempStr)
			TempletPageInfo.TempletSelectHTMLList = append(TempletPageInfo.TempletSelectHTMLList, TempHTML)
		} else {
			TempStr = fmt.Sprintf("<option>%s</option>", TempletName)
			TempHTML.Value_HTML = template.HTML(TempStr)
			TempletPageInfo.TempletSelectHTMLList = append(TempletPageInfo.TempletSelectHTMLList, TempHTML)
		}
	}
	//------------------templet name list -------------------------------------------

	QueryStr = "SELECT A.TempletName, A.Password\n" +
		", A.Global_MaxConn, A.Global_RecvBufferSize, A.Global_SendBufferSize, A.Global_TimeoutConnect, A.Global_TimeoutClient, A.Global_TimeoutServer\n" +
		", A.Log_DiskLimit, A.Log_MaxSize, A.Log_LogDir, A.Log_LogName, A.Log_ErrDir, A.Log_ErrName, A.Stat_SendControlServerFlag\n" +
		", A.Stat_StatCollectionCycle, A.Stat_StatSendControlServer, A.Stat_StatServerIP, A.Stat_StatServerPort, A.Stat_StatDataSendCycle\n" +
		", A.Node_NodeBufferSize, A.Node_EncryptMode, A.Node_ChangeIPClientMode\n" +
		", A.KMS_IP, A.KMS_Port\n" +
		", B.Name, B.NicName, B.Bind, B.NodeMode /* Frontend */\n" +
		", C.Name, D.NicName, D.IP, D.Port /* Backend */\n" +

		"from TempletNodeIDTbl as A\n" +
		"join TempletNodeIDFrontendTbl as B\n" +
		"on A.Seq = B.SeqNodeID\n" +
		//"AND A.Node_NodeID = 'aa01cr8v-00000002-aeLlO-CzqAk-N3WJmTTRV0zz'\n" +
		"AND A.TempletName = 'New'\n" +
		"join TempletNodeIDBackendTbl as C\n" +
		"on A.Seq = C.SeqNodeID\n" +
		"join TempletNodeIDBackendAddressTbl as D\n" +
		"on C.Seq = D.SeqBackend\n" +
		"and B.Name = C.Name;"

	Rows, err = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return
	}

	var StatSendFlag int
	var UseEnc, UseChangeIP int
	var idx int
	var frontendName, frontendPort, frontendNIC, frontendNodeMode, backendName, backendNIC, backendIP, backendPort, frontendName1 string
	var StatSendFlagStr string
	settingData := new(SettingsInformation)
	idx = -1
	for Rows.Next() {
		err = Rows.Scan(&TempletName, &settingData.Password,
			&settingData.Maximum_ConnectionCount, &settingData.Recv_Buf_Size, &settingData.Send_Buf_Size, &settingData.Connection_Timeout, &settingData.Client_Reconnect_Timeout, &settingData.Server_Reconnect_Timeout,
			&settingData.Limit_Size_Log_Storage, &settingData.Maxsize_Per_Logfile, &TempletPageInfo.Log, &TempletPageInfo.LogFileName, &TempletPageInfo.Error, &StatSendFlagStr, &TempletPageInfo.ErrorFileName,
			&settingData.Statistic_Collection_Cycle, &settingData.Statistic_Send_Control_Server, &TempletPageInfo.Control_Server_IP, &settingData.Statistic_Server_Port, &settingData.Statistic_Send_Cycle,
			&settingData.Bridge_Buf_Size, &settingData.Encrypt_Mode, &settingData.Change_Client_IP,
			&settingData.KMS_Address, &settingData.KMS_Port, &frontendName, &frontendNIC, &frontendPort, &frontendNodeMode, &backendName, &backendNIC, &backendIP, &backendPort)
		if err != nil {
			log.Println(" data Scan error:", err)
			UpdateLock.Unlock()
			log.Println("866/Release Lock")
			return
		}

		if StatSendFlagStr == "Enable" {
			StatSendFlag = ENABLE
		} else {
			StatSendFlag = DISABLE
		}

		if frontendName != frontendName1 {
			frontend := FrontendInformation{}
			settingData.SiteList = append(settingData.SiteList, frontend)
			idx++

			settingData.SiteList[idx].Frontendsymbol = frontendName
			//settingData.SiteList[idx].FrontendPort = frontendNIC + ":" + frontendPort
			settingData.SiteList[idx].FrontendPort = frontendPort
			settingData.SiteList[idx].NodeMode = frontendNodeMode
			frontendName1 = frontendName
		}

		backend := BackendInformationList{}
		backend.LAN_Interface = backendNIC
		backend.BackendIP = backendIP
		backend.BackendPort = backendPort
		settingData.SiteList[idx].Backend = append(settingData.SiteList[idx].Backend, backend)

		TempletPageInfo.Max_Conn, _ = strconv.Atoi(settingData.Maximum_ConnectionCount)
		TempletPageInfo.Recv_Buffer_Size, _ = strconv.Atoi(settingData.Recv_Buf_Size)
		TempletPageInfo.Send_Buffer_Size, _ = strconv.Atoi(settingData.Send_Buf_Size)
		TempletPageInfo.Timeout_Connect, _ = strconv.Atoi(settingData.Connection_Timeout)
		TempletPageInfo.Timeout_Client, _ = strconv.Atoi(settingData.Client_Reconnect_Timeout)
		TempletPageInfo.Timeout_Server, _ = strconv.Atoi(settingData.Server_Reconnect_Timeout)
		TempletPageInfo.Disk_Limit, _ = strconv.Atoi(settingData.Limit_Size_Log_Storage)
		Maxsize_Per_Logfile := strings.TrimRight(settingData.Maxsize_Per_Logfile, "MB")
		TempletPageInfo.Max_Size, _ = strconv.Atoi(Maxsize_Per_Logfile)
		TempletPageInfo.Interval, _ = strconv.Atoi(settingData.Statistic_Collection_Cycle)
		TempletPageInfo.Control_Server_IP = settingData.Statistic_Server_Ip
		TempletPageInfo.Control_Server_Port, _ = strconv.Atoi(settingData.Statistic_Server_Port)
		TempletPageInfo.Control_Server_Send_Interval, _ = strconv.Atoi(settingData.Statistic_Send_Cycle)
		TempletPageInfo.Buffer_Size, _ = strconv.Atoi(settingData.Bridge_Buf_Size)
		TempletPageInfo.EncryptMode = settingData.Encrypt_Mode
		TempletPageInfo.ChangeIpClientMode = settingData.Change_Client_IP
		TempletPageInfo.KMS_Address = settingData.KMS_Address
		TempletPageInfo.KMS_Port, _ = strconv.Atoi(settingData.KMS_Port)

		if TempletPageInfo.EncryptMode == "None" {
			UseEnc = ENC_NONE
		} else if TempletPageInfo.EncryptMode == "AES_128" {
			UseEnc = ENC_AES128
		} else if TempletPageInfo.EncryptMode == "AES_256" {
			UseEnc = ENC_AES256
		} else {
			UseEnc = ENC_RC4
		}
		//------------------test UpseChangeIP value ---------------------
		TempletPageInfo.ChangeIpClientMode = "Disable"
		if TempletPageInfo.ChangeIpClientMode == "Enable" {
			UseChangeIP = ENABLE
		} else {
			UseChangeIP = DISABLE
		}
		//------------------test UpseChangeIP value ---------------------
		if TempletPageInfo.ChangeIpClientMode == "Enable" {
			UseChangeIP = ENABLE
		} else {
			UseChangeIP = DISABLE
		}
	}
	Rows.Close()

	log.Println("Settingsdata:", settingData)
	if StatSendFlag == ENABLE {
		TempStr = "<option selected=\"selected\">Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.StatSelectHTMLList = append(TempletPageInfo.StatSelectHTMLList, TempHTML)
		TempStr = "<option>Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.StatSelectHTMLList = append(TempletPageInfo.StatSelectHTMLList, TempHTML)
	} else {
		TempStr = "<option selected=\"selected\">Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.StatSelectHTMLList = append(TempletPageInfo.StatSelectHTMLList, TempHTML)
		TempStr = "<option>Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.StatSelectHTMLList = append(TempletPageInfo.StatSelectHTMLList, TempHTML)
	}

	if UseEnc == ENC_NONE {
		TempStr = "<option selected=\"selected\">None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
	} else if UseEnc == ENC_AES128 {
		TempStr = "<option selected=\"selected\">AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
	} else if UseEnc == ENC_AES256 {
		TempStr = "<option selected=\"selected\">AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
	} else if UseEnc == ENC_RC4 {
		TempStr = "<option selected=\"selected\">RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
	}

	if UseChangeIP == ENABLE {
		TempStr = "<option selected=\"selected\">Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.ChangeIPSelectHTMLList = append(TempletPageInfo.ChangeIPSelectHTMLList, TempHTML)
		TempStr = "<option>Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.ChangeIPSelectHTMLList = append(TempletPageInfo.ChangeIPSelectHTMLList, TempHTML)
	} else {
		TempStr = "<option selected=\"selected\">Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.ChangeIPSelectHTMLList = append(TempletPageInfo.ChangeIPSelectHTMLList, TempHTML)
		TempStr = "<option>Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.ChangeIPSelectHTMLList = append(TempletPageInfo.ChangeIPSelectHTMLList, TempHTML)
	}

	var FrontBack_Data_Count int
	QueryStr = "SELECT  Count(*)\n" +
		"FROM TempletNodeIDTbl as B, TempletNodeIDFrontendTbl as C\n" +
		"WHERE   B.TempletName = 'New'\n" +
		"and B.Seq = C.SeqNodeID;"
	Rows, _ = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return
	}

	for Rows.Next() {
		err = Rows.Scan(&FrontBack_Data_Count)
		if err != nil {
			log.Println(" data Scan error:", err)
			return
		}
	}
	var Symbol_Name string
	var Bind, Node_Mode int
	var OptionStr string
	var count int
	var BackendList, IDTagStart, IDTagEnd, HRTag, Button string
	var NICName, ProxyIP, ProxyPort string

	for i := range settingData.SiteList {
		count++

		Symbol_Name = settingData.SiteList[i].Frontendsymbol
		Bind, _ = strconv.Atoi(settingData.SiteList[i].FrontendPort)
		Node_Mode, _ = strconv.Atoi(settingData.SiteList[i].NodeMode)
		if settingData.SiteList[i].NodeMode == "" {
			Node_Mode = Node_MODE_NONE
		} else if settingData.SiteList[i].NodeMode == "client" {
			Node_Mode = Node_MODE_CLIENT
		} else {
			Node_Mode = Node_MODE_SERVER
		}

		BackendList = ""
		for j := range settingData.SiteList[i].Backend {

			NICName = settingData.SiteList[i].Backend[j].LAN_Interface
			ProxyIP = settingData.SiteList[i].Backend[j].BackendIP
			ProxyPort = settingData.SiteList[i].Backend[j].BackendPort
			// for j := range NICInfoArray {
			// 	if NICInfoArray[j].Name == NICName {
			// 		OptionStr += fmt.Sprintf("<option selected=\"selected\" value=\"%s\">%s</option>", NICInfoArray[j].Name, NICInfoArray[j].Name)
			// 	} else {
			// 		OptionStr += fmt.Sprintf("<option value=\"%s\">%s</option>", NICInfoArray[j].Name, NICInfoArray[j].Name)
			// 	}
			// }
			if NICName != "OS_Default" {
				OptionStr = fmt.Sprintf("<option selected=\"selected\" value=\"%s\">%s</option>", NICName, NICName)
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
		TempletPageInfo.FrontBackHTMLList = append(TempletPageInfo.FrontBackHTMLList, TempHTML)
	}
	Rows.Close()

	NodeModeStr := fmt.Sprintf("<option selected=\"selected\" value=\"%d\">선택해주세요</option>", Node_MODE_NONE)
	NodeModeStr += fmt.Sprintf("<option value=\"%d\">Node Client</option>", Node_MODE_CLIENT)
	if DeviceOSFlag == GENERAL_OS {
		NodeModeStr += fmt.Sprintf("<option value=\"%d\">Node Server</option>", Node_MODE_SERVER)
	}
	TempletPageInfo.FrontendNodeMode = template.HTML(NodeModeStr)

	if count == 0 {
		TempStr = fmt.Sprintf("<div id=\"Frontend\"><div data-SiteType=\"1\"><h2>Frontend<div><button type=\"button\" class=\"green\" act=\"btnFrontendAdd\">Add</button></div></h2><table class=\"input\"><colgroup><col width=\"250\"><col></colgroup><tbody><tr><th>Symbol</th><td><input type=\"text\" class=\"s100\" Frontendsymbol reserve=\"ko en number space length\" min=\"2\" max=\"32\" msg=\"글자 2 - 32 까지만 입력이 가능 합니다.\" group=\"all\" value=\"\"></td></tr><tr><th>Bind Port</th><td><input type=\"text\" class=\"s100\" FrontendPort reserve=\"between\" min=\"1\" max=\"65535\" msg=\"숫자 1 - 65535 까지만 입력이 가능 합니다.\" group=\"all\" value=\"\"/></td></tr><tr><th>Node Mode</th><td><select Node_Mode>%s</select><button type=\"button\" act=\"btnFrontendConfirm\" >Confirm</button></td></tr></tbody></table></div></div>", NodeModeStr)
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.FrontBackHTMLList = append(TempletPageInfo.FrontBackHTMLList, TempHTML)
	}
	var NICNAMEHTML HTMLType

	TempStr = fmt.Sprintf("<option>%s</option>", "OS_Default")
	NICNAMEHTML.Value_HTML = template.HTML(TempStr)
	TempletPageInfo.NICNAMEHTMLList = append(TempletPageInfo.NICNAMEHTMLList, NICNAMEHTML)

	tmpl, err = template.ParseFiles("./pages/Control_Node_Setting_Templet_Edit.html")
	if err != nil {
		log.Println("failed to template.ParseFiles")
		UpdateLock.Unlock()
		log.Println("1124/Release Lock")
		return
	}
	tmpl.Execute(w, TempletPageInfo)
}

func Load_Templet(w http.ResponseWriter, req *http.Request, Database *sql.DB) {

	defer req.Body.Close()
	var QueryStr string
	var tmpl *template.Template
	var TempletPageInfo TempletPageInfo
	var TempStr string
	var Rows *sql.Rows
	var err error
	var TempletName string
	var TempHTML HTMLType
	log.Println("Load_Templet", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}
	Param_TempletName, ok := req.URL.Query()["TempletName"]
	if !ok || len(Param_TempletName) < 1 {
		WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
		return
	}
	TempletNameStr := fmt.Sprintf("%s", Param_TempletName)
	TempletNameStr = strings.Replace(TempletNameStr, "[", "", -1)
	TempletNameStr = strings.Replace(TempletNameStr, "]", "", -1)
	TempStr = fmt.Sprintf("<li><a href=\"/node_cfg_list/\">Node Setting List</a></li>")
	TempletPageInfo.NodeSettingsList = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li><a href=\"/statistics/client/\">Client Statistics</a></li>")
	TempletPageInfo.NodeClientStatMenu = template.HTML(TempStr)
	TempStr = fmt.Sprintf("<li ><a href=\"/statistics/server/\">Server Statistics</a></li>")
	TempletPageInfo.NodeServerStatMenu = template.HTML(TempStr)

	//-----------------------templet name list-----------------------------------
	QueryStr = "SELECT A.TempletName from TempletNodeIDTbl as A;"
	Rows, err = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return
	}
	for Rows.Next() {
		err = Rows.Scan(&TempletName)
		if err != nil {
			log.Println(" data Scan error:", err)
			log.Println("1018/Release Lock")
			return
		}
		if TempletNameStr == TempletName {
			TempStr = fmt.Sprintf("<option  selected=\"selected\" value=\"%s\">%s</option>", TempletName, TempletName)
			TempHTML.Value_HTML = template.HTML(TempStr)
			TempletPageInfo.TempletSelectHTMLList = append(TempletPageInfo.TempletSelectHTMLList, TempHTML)
		} else {
			TempStr = fmt.Sprintf("<option>%s</option>", TempletName)
			TempHTML.Value_HTML = template.HTML(TempStr)
			TempletPageInfo.TempletSelectHTMLList = append(TempletPageInfo.TempletSelectHTMLList, TempHTML)
		}
	}
	//------------------templet name list -------------------------------------------

	QueryStr = "SELECT A.TempletName, A.Password\n" +
		", A.Global_MaxConn, A.Global_RecvBufferSize, A.Global_SendBufferSize, A.Global_TimeoutConnect, A.Global_TimeoutClient, A.Global_TimeoutServer\n" +
		", A.Log_DiskLimit, A.Log_MaxSize, A.Log_LogDir, A.Log_LogName, A.Log_ErrDir, A.Log_ErrName, A.Stat_SendControlServerFlag\n" +
		", A.Stat_StatCollectionCycle, A.Stat_StatSendControlServer, A.Stat_StatServerIP, A.Stat_StatServerPort, A.Stat_StatDataSendCycle\n" +
		", A.Node_NodeBufferSize, A.Node_EncryptMode, A.Node_ChangeIPClientMode\n" +
		", A.KMS_IP, A.KMS_Port\n" +
		", B.Name, B.NicName, B.Bind, B.NodeMode /* Frontend */\n" +
		", C.Name, D.NicName, D.IP, D.Port /* Backend */\n" +

		"from TempletNodeIDTbl as A\n" +
		"join TempletNodeIDFrontendTbl as B\n" +
		"on A.Seq = B.SeqNodeID\n" +
		"AND A.TempletName = '" + TempletNameStr + "'\n" +
		"join TempletNodeIDBackendTbl as C\n" +
		"on A.Seq = C.SeqNodeID\n" +
		"join TempletNodeIDBackendAddressTbl as D\n" +
		"on C.Seq = D.SeqBackend\n" +
		"and B.Name = C.Name;"

	Rows, err = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return
	}

	var StatSendFlag int
	var UseEnc, UseChangeIP int
	var idx int
	var frontendName, frontendPort, frontendNIC, frontendNodeMode, backendName, backendNIC, backendIP, backendPort, frontendName1 string
	var StatSendFlagStr string
	settingData := new(SettingsInformation)
	idx = -1
	for Rows.Next() {
		err = Rows.Scan(&TempletName, &settingData.Password,
			&settingData.Maximum_ConnectionCount, &settingData.Recv_Buf_Size, &settingData.Send_Buf_Size, &settingData.Connection_Timeout, &settingData.Client_Reconnect_Timeout, &settingData.Server_Reconnect_Timeout,
			&settingData.Limit_Size_Log_Storage, &settingData.Maxsize_Per_Logfile, &TempletPageInfo.Log, &TempletPageInfo.LogFileName, &TempletPageInfo.Error, &StatSendFlagStr, &TempletPageInfo.ErrorFileName,
			&settingData.Statistic_Collection_Cycle, &settingData.Statistic_Send_Control_Server, &TempletPageInfo.Control_Server_IP, &settingData.Statistic_Server_Port, &settingData.Statistic_Send_Cycle,
			&settingData.Bridge_Buf_Size, &settingData.Encrypt_Mode, &settingData.Change_Client_IP,
			&settingData.KMS_Address, &settingData.KMS_Port, &frontendName, &frontendNIC, &frontendPort, &frontendNodeMode, &backendName, &backendNIC, &backendIP, &backendPort)
		if err != nil {
			log.Println(" data Scan error:", err)
			return
		}

		if StatSendFlagStr == "Enable" {
			StatSendFlag = ENABLE
		} else {
			StatSendFlag = DISABLE
		}

		if frontendName != frontendName1 {
			frontend := FrontendInformation{}
			settingData.SiteList = append(settingData.SiteList, frontend)
			idx++

			settingData.SiteList[idx].Frontendsymbol = frontendName
			//settingData.SiteList[idx].FrontendPort = frontendNIC + ":" + frontendPort
			settingData.SiteList[idx].FrontendPort = frontendPort
			settingData.SiteList[idx].NodeMode = frontendNodeMode
			frontendName1 = frontendName
		}

		backend := BackendInformationList{}
		backend.LAN_Interface = backendNIC
		backend.BackendIP = backendIP
		backend.BackendPort = backendPort
		settingData.SiteList[idx].Backend = append(settingData.SiteList[idx].Backend, backend)

		TempletPageInfo.Password = settingData.Password
		TempletPageInfo.Max_Conn, _ = strconv.Atoi(settingData.Maximum_ConnectionCount)
		TempletPageInfo.Recv_Buffer_Size, _ = strconv.Atoi(settingData.Recv_Buf_Size)
		TempletPageInfo.Send_Buffer_Size, _ = strconv.Atoi(settingData.Send_Buf_Size)
		TempletPageInfo.Timeout_Connect, _ = strconv.Atoi(settingData.Connection_Timeout)
		TempletPageInfo.Timeout_Client, _ = strconv.Atoi(settingData.Client_Reconnect_Timeout)
		TempletPageInfo.Timeout_Server, _ = strconv.Atoi(settingData.Server_Reconnect_Timeout)
		TempletPageInfo.Disk_Limit, _ = strconv.Atoi(settingData.Limit_Size_Log_Storage)
		Maxsize_Per_Logfile := strings.TrimRight(settingData.Maxsize_Per_Logfile, "MB")
		TempletPageInfo.Max_Size, _ = strconv.Atoi(Maxsize_Per_Logfile)
		TempletPageInfo.Interval, _ = strconv.Atoi(settingData.Statistic_Collection_Cycle)
		TempletPageInfo.Control_Server_Port, _ = strconv.Atoi(settingData.Statistic_Server_Port)
		TempletPageInfo.Control_Server_Send_Interval, _ = strconv.Atoi(settingData.Statistic_Send_Cycle)
		TempletPageInfo.Buffer_Size, _ = strconv.Atoi(settingData.Bridge_Buf_Size)
		TempletPageInfo.EncryptMode = settingData.Encrypt_Mode
		TempletPageInfo.ChangeIpClientMode = settingData.Change_Client_IP
		TempletPageInfo.KMS_Address = settingData.KMS_Address
		TempletPageInfo.KMS_Port, _ = strconv.Atoi(settingData.KMS_Port)

		if TempletPageInfo.EncryptMode == "None" {
			UseEnc = ENC_NONE
		} else if TempletPageInfo.EncryptMode == "AES_128" {
			UseEnc = ENC_AES128
		} else if TempletPageInfo.EncryptMode == "AES_256" {
			UseEnc = ENC_AES256
		} else {
			UseEnc = ENC_RC4
		}

		//------------------test UpseChangeIP value ---------------------
		TempletPageInfo.ChangeIpClientMode = "Disable"
		if TempletPageInfo.ChangeIpClientMode == "Enable" {
			UseChangeIP = ENABLE
		} else {
			UseChangeIP = DISABLE
		}
		//------------------test UpseChangeIP value ---------------------
		if TempletPageInfo.ChangeIpClientMode == "Enable" {
			UseChangeIP = ENABLE
		} else {
			UseChangeIP = DISABLE
		}
	}
	log.Println("settingData:", settingData)
	Rows.Close()

	if StatSendFlag == ENABLE {
		TempStr = "<option selected=\"selected\">Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.StatSelectHTMLList = append(TempletPageInfo.StatSelectHTMLList, TempHTML)
		TempStr = "<option>Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.StatSelectHTMLList = append(TempletPageInfo.StatSelectHTMLList, TempHTML)
	} else {
		TempStr = "<option selected=\"selected\">Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.StatSelectHTMLList = append(TempletPageInfo.StatSelectHTMLList, TempHTML)
		TempStr = "<option>Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.StatSelectHTMLList = append(TempletPageInfo.StatSelectHTMLList, TempHTML)
	}

	if UseEnc == ENC_NONE {
		TempStr = "<option selected=\"selected\">None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
	} else if UseEnc == ENC_AES128 {
		TempStr = "<option selected=\"selected\">AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
	} else if UseEnc == ENC_AES256 {
		TempStr = "<option selected=\"selected\">AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
	} else if UseEnc == ENC_RC4 {
		TempStr = "<option selected=\"selected\">RC4</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>None</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_128</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
		TempStr = "<option>AES_256</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.EncModeSelectHTMLList = append(TempletPageInfo.EncModeSelectHTMLList, TempHTML)
	}

	if UseChangeIP == ENABLE {
		TempStr = "<option selected=\"selected\">Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.ChangeIPSelectHTMLList = append(TempletPageInfo.ChangeIPSelectHTMLList, TempHTML)
		TempStr = "<option>Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.ChangeIPSelectHTMLList = append(TempletPageInfo.ChangeIPSelectHTMLList, TempHTML)
	} else {
		TempStr = "<option selected=\"selected\">Disable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.ChangeIPSelectHTMLList = append(TempletPageInfo.ChangeIPSelectHTMLList, TempHTML)
		TempStr = "<option>Enable</option>"
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.ChangeIPSelectHTMLList = append(TempletPageInfo.ChangeIPSelectHTMLList, TempHTML)
	}

	var FrontBack_Data_Count int
	QueryStr = "SELECT  Count(*)\n" +
		"FROM TempletNodeIDTbl as B, TempletNodeIDFrontendTbl as C\n" +
		"WHERE   B.TempletName = '" + TempletNameStr + "'\n" +
		"and B.Seq = C.SeqNodeID;"
	Rows, _ = mariadb_lib.Query_DB(Database, QueryStr)
	defer func() {
		if Rows != nil {
			Rows.Close()
		}
	}()
	if Rows == nil {
		return
	}

	for Rows.Next() {
		err = Rows.Scan(&FrontBack_Data_Count)
		if err != nil {
			log.Println(" data Scan error:", err)
			return
		}
	}

	var Symbol_Name string
	var Bind, Node_Mode int
	var OptionStr string
	var count int
	var BackendList, IDTagStart, IDTagEnd, HRTag, Button string
	var NICName, ProxyIP, ProxyPort string

	for i := range settingData.SiteList {
		count++

		Symbol_Name = settingData.SiteList[i].Frontendsymbol
		Bind, _ = strconv.Atoi(settingData.SiteList[i].FrontendPort)
		Node_Mode, _ = strconv.Atoi(settingData.SiteList[i].NodeMode)

		if settingData.SiteList[i].NodeMode == "" {
			Node_Mode = Node_MODE_NONE
		} else if settingData.SiteList[i].NodeMode == "client" {
			Node_Mode = Node_MODE_CLIENT
		} else {
			Node_Mode = Node_MODE_SERVER
		}

		BackendList = ""
		for j := range settingData.SiteList[i].Backend {

			NICName = settingData.SiteList[i].Backend[j].LAN_Interface
			ProxyIP = settingData.SiteList[i].Backend[j].BackendIP
			ProxyPort = settingData.SiteList[i].Backend[j].BackendPort

			// for j := range NICInfoArray {
			// 	if NICInfoArray[j].Name == NICName {
			// 		OptionStr += fmt.Sprintf("<option selected=\"selected\" value=\"%s\">%s</option>", NICInfoArray[j].Name, NICInfoArray[j].Name)
			// 	} else {
			// 		OptionStr += fmt.Sprintf("<option value=\"%s\">%s</option>", NICInfoArray[j].Name, NICInfoArray[j].Name)
			// 	}
			// }

			OptionStr = fmt.Sprintf("<option selected=\"selected\" value=\"%s\">%s</option>", NICName, NICName)
			if NICName == "OS_Default" {
				BackendList += fmt.Sprintf("<tr><th>Server</th><td><select class=\"s100\" LAN_interface><option value=\"OS_Default\">OS Default</option></select></td><td><input type=\"text\" class=\"s100\" placeholder=\"IP Address\" BackendIP reserve=\"ipv4\" min=\"7\" max=\"15\" msg=\"IP만 입력이 가능 합니다.\" group=\"all\" value=\"%s\"/></td><td><input type=\"text\" class=\"s100\" placeholder=\"Bind Port\"  BackendPort reserve=\"between\" min=\"1\" max=\"65535\" msg=\"PORT만 입력이 가능 합니다.\" group=\"all\" value=\"%s\"/></td></tr>", ProxyIP, ProxyPort)
			} else {
				BackendList += fmt.Sprintf("<tr><th>Server</th><td><select class=\"s100\" LAN_interface><option value=\"OS_Default\">OS Default</option>%s</select></td><td><input type=\"text\" class=\"s100\" placeholder=\"IP Address\" BackendIP reserve=\"ipv4\" min=\"7\" max=\"15\" msg=\"IP만 입력이 가능 합니다.\" group=\"all\" value=\"%s\"/></td><td><input type=\"text\" class=\"s100\" placeholder=\"Bind Port\"  BackendPort reserve=\"between\" min=\"1\" max=\"65535\" msg=\"PORT만 입력이 가능 합니다.\" group=\"all\" value=\"%s\"/></td></tr>", OptionStr, ProxyIP, ProxyPort)
			}
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
		TempletPageInfo.FrontBackHTMLList = append(TempletPageInfo.FrontBackHTMLList, TempHTML)
	}
	Rows.Close()

	NodeModeStr := fmt.Sprintf("<option selected=\"selected\" value=\"%d\">선택해주세요</option>", Node_MODE_NONE)
	NodeModeStr += fmt.Sprintf("<option value=\"%d\">Node Client</option>", Node_MODE_CLIENT)
	if DeviceOSFlag == GENERAL_OS {
		NodeModeStr += fmt.Sprintf("<option value=\"%d\">Node Server</option>", Node_MODE_SERVER)
	}
	TempletPageInfo.FrontendNodeMode = template.HTML(NodeModeStr)

	if count == 0 {
		TempStr = fmt.Sprintf("<div id=\"Frontend\"><div data-SiteType=\"1\"><h2>Frontend<div><button type=\"button\" class=\"green\" act=\"btnFrontendAdd\">Add</button></div></h2><table class=\"input\"><colgroup><col width=\"250\"><col></colgroup><tbody><tr><th>Symbol</th><td><input type=\"text\" class=\"s100\" Frontendsymbol reserve=\"ko en number space length\" min=\"2\" max=\"32\" msg=\"글자 2 - 32 까지만 입력이 가능 합니다.\" group=\"all\" value=\"\"></td></tr><tr><th>Bind Port</th><td><input type=\"text\" class=\"s100\" FrontendPort reserve=\"between\" min=\"1\" max=\"65535\" msg=\"숫자 1 - 65535 까지만 입력이 가능 합니다.\" group=\"all\" value=\"\"/></td></tr><tr><th>Node Mode</th><td><select Node_Mode>%s</select><button type=\"button\" act=\"btnFrontendConfirm\" >Confirm</button></td></tr></tbody></table></div></div>", NodeModeStr)
		TempHTML.Value_HTML = template.HTML(TempStr)
		TempletPageInfo.FrontBackHTMLList = append(TempletPageInfo.FrontBackHTMLList, TempHTML)
	}

	var NICNAMEHTML HTMLType

	TempStr = fmt.Sprintf("<option>%s</option>", "OS_Default")
	NICNAMEHTML.Value_HTML = template.HTML(TempStr)
	TempletPageInfo.NICNAMEHTMLList = append(TempletPageInfo.NICNAMEHTMLList, NICNAMEHTML)

	tmpl, err = template.ParseFiles("./pages/Control_Node_Setting_Templet_Edit.html")
	if err != nil {
		log.Println("failed to template.ParseFiles")
		UpdateLock.Unlock()
		log.Println("1124/Release Lock")
		return
	}
	tmpl.Execute(w, TempletPageInfo)
}
func Save_NewTemplet(w http.ResponseWriter, req *http.Request, Database *sql.DB) int {
	defer req.Body.Close()
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryStr string

	var Rows *sql.Rows
	var Settings TempletSettingsInformation
	var TempletNameSeq int
	var err error
	log.Println("Save_NewTemplet", req.URL)

	r := json.NewDecoder(req.Body)
	err = r.Decode(&Settings)
	if err != io.EOF {
		if err != nil {
			log.Println(err)
			return 0
		}
	}

	log.Println("Settings value:", Settings)
	if Settings.NewTempletName == "" || Settings.Password == "" || Settings.Maximum_ConnectionCount == "" || Settings.Recv_Buf_Size == "" || Settings.Send_Buf_Size == "" || Settings.Connection_Timeout == "" || Settings.Client_Reconnect_Timeout == "" || Settings.Server_Reconnect_Timeout == "" || Settings.Limit_Size_Log_Storage == "" || Settings.Maxsize_Per_Logfile == "" || Settings.Logfile_Path == "" || Settings.Err_Logfile_Path == "" || Settings.Statistic_Send_Control_Server == "" || Settings.Statistic_Collection_Cycle == "" || Settings.Statistic_Server_Ip == "" || Settings.Statistic_Server_Port == "" || Settings.Statistic_Send_Cycle == "" || Settings.Bridge_Buf_Size == "" || Settings.Encrypt_Mode == "" || Settings.Change_Client_IP == "" || Settings.KMS_Address == "" || Settings.KMS_Port == "" {
		log.Println("Settings Datas Empty Value!!")
		log.Println("Settings.TempletName :", Settings.NewTempletName)
		log.Println("Settings.Password :", Settings.Password)
		log.Println("Settings.Maximum_ConnectionCount :", Settings.Maximum_ConnectionCount)
		log.Println("Settings.Recv_Buf_Size :", Settings.Recv_Buf_Size)
		log.Println("Settings.Send_Buf_Size :", Settings.Send_Buf_Size)
		log.Println(" Settings.Connection_Timeout  :", Settings.Connection_Timeout)
		log.Println("Settings.Client_Reconnect_Timeout :", Settings.Client_Reconnect_Timeout)
		log.Println("Settings.Server_Reconnect_Timeout :", Settings.Server_Reconnect_Timeout)
		log.Println("Settings.Limit_Size_Log_Storage", Settings.Limit_Size_Log_Storage)
		log.Println("Settings.Maxsize_Per_Logfile:", Settings.Maxsize_Per_Logfile)
		log.Println("Settings.Logfile_Path:", Settings.Logfile_Path)
		log.Println("Settings.Err_Logfile_Path:", Settings.Err_Logfile_Path)
		log.Println("Settings.Statistic_Send_Control_Server", Settings.Statistic_Send_Control_Server)
		log.Println("Settings.Statistic_Collection_Cycle", Settings.Statistic_Collection_Cycle)
		log.Println("Settings.Statistic_Server_Ip", Settings.Statistic_Server_Ip)
		log.Println("Settings.Statistic_Server_Port", Settings.Statistic_Server_Port)
		log.Println("Settings.Statistic_Send_Cycle", Settings.Statistic_Send_Cycle)
		log.Println("Settings.Bridge_Buf_Size", Settings.Bridge_Buf_Size)
		log.Println("Settings.Change_Client_IP", Settings.Change_Client_IP)
		log.Println("Settings.KMS_Address", Settings.KMS_Address)
		log.Println("Settings.KMS_Port", Settings.KMS_Port)

		WebServer_Redirect(w, req, "/add_cfg_templet/")
		return 0
	}

	for i := range Settings.SiteList {
		if Settings.SiteList[i].Frontendsymbol == "" || Settings.SiteList[i].FrontendPort == "" || Settings.SiteList[i].Frontendsymbol == "" || Settings.SiteList[i].NodeMode == "" {
			log.Println("Settings Frontend  Datas Empty Value!!")
			WebServer_Redirect(w, req, "/add_cfg_templet/")
			return 0
		}
		for j := range Settings.SiteList[i].Backend {
			if Settings.SiteList[i].Backend[j].LAN_Interface == "" || Settings.SiteList[i].Backend[j].BackendIP == "" || Settings.SiteList[i].Backend[j].BackendPort == "" {
				log.Println("Settings Backend Datas Empty Value!!")
				WebServer_Redirect(w, req, "/add_cfg_templet/")
				return 0
			}
		}
	}

	tx, err = mariadb_lib.DB_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)

		return 0
	}
	defer mariadb_lib.DB_Rollback(tx)

	//----------------------------insert into TempletNodeIDTbl --------------------------
	QueryStr = "INSERT IGNORE INTO TempletNodeIDTbl (TempletName, Password, Global_MaxConn, Global_RecvBufferSize, Global_SendBufferSize, " +
		"Global_TimeoutConnect, Global_TimeoutClient, Global_TimeoutServer, " +
		"Log_DiskLimit, Log_MaxSize, Log_LogDir, Log_LogName, Log_ErrDir, Log_ErrName, " +
		"Stat_SendControlServerFlag, Stat_StatCollectionCycle, Stat_StatServerIP, Stat_StatServerPort, Stat_StatDataSendCycle, " +
		"Node_UseBridgeRouter, Node_NodeBufferSize, Node_EncryptMode, Node_ChangeIPClientMode," +
		"KMS_IP, KMS_Port) " +
		"VALUES (?,?, ?, ?, ?," +
		"?, ?, ?, " +
		"?, ?, ?, ?, ?, ?," +
		"?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, " +
		"?, ?) "

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(Settings.NewTempletName, Settings.Password, Settings.Maximum_ConnectionCount, Settings.Recv_Buf_Size, Settings.Send_Buf_Size,
		Settings.Connection_Timeout, Settings.Client_Reconnect_Timeout, Settings.Server_Reconnect_Timeout,
		Settings.Limit_Size_Log_Storage, Settings.Maxsize_Per_Logfile, Settings.Logfile_Path, "app.log", Settings.Err_Logfile_Path, "app_err.log",
		Settings.Statistic_Send_Control_Server, Settings.Statistic_Collection_Cycle, Settings.Statistic_Server_Ip, Settings.Statistic_Server_Port, Settings.Statistic_Send_Cycle,
		"N", Settings.Bridge_Buf_Size, Settings.Encrypt_Mode, Settings.Change_Client_IP,
		Settings.KMS_Address, Settings.KMS_Port)
	if err != nil {
		stmt.Close()
		log.Println("Query err!:", err)
		return 0
	}
	stmt.Close()

	//----------------------------insert into TempletNodeIDTbl --------------------------
	//----------------------------Select TempletNameSeq --------------------------
	QueryStr = "SELECT Seq from TempletNodeIDTbl WHERE TempletName = ?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(Settings.NewTempletName)
	if err != nil {
		stmt.Close()
		log.Println("Query err!:", err)
		return 0
	}
	for Rows.Next() {
		err := Rows.Scan(&TempletNameSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}
	}
	stmt.Close()

	log.Println("select from TempletNameSeq :", TempletNameSeq)

	//----------------------------Select TempletNameSeq --------------------------
	//----------------------------Insert Into TempletNodeIDFrontendTbl --------------------------

	for i := range Settings.SiteList {

		QueryStr = "INSERT IGNORE INTO TempletNodeIDFrontendTbl (SeqNodeID,Name,Bind,Backend , NodeMode)\n" +
			"VALUES(?,?,?,?,?)"

		stmt, err = tx.Prepare(QueryStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}
		if Settings.SiteList[i].NodeMode == "1" {
			Settings.SiteList[i].NodeMode = "client"
		} else if Settings.SiteList[i].NodeMode == "2" {
			Settings.SiteList[i].NodeMode = "server"
		} else {
			Settings.SiteList[i].NodeMode = ""
		}

		_, err = stmt.Exec(TempletNameSeq, Settings.SiteList[i].Frontendsymbol, Settings.SiteList[i].FrontendPort, Settings.SiteList[i].Frontendsymbol, Settings.SiteList[i].NodeMode)
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()
	}

	//----------------------------Insert Into TempletNodeIDFrontendTbl --------------------------
	//----------------------------Insert Into TempletNodeIDBackendTbl --------------------------
	for i := range Settings.SiteList {

		QueryStr = "INSERT IGNORE INTO TempletNodeIDBackendTbl (SeqNodeID,Name)\n" +
			"VALUES(?,?)"

		stmt, err = tx.Prepare(QueryStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}
		_, err = stmt.Exec(TempletNameSeq, Settings.SiteList[i].Frontendsymbol)
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()
	}

	//----------------------------Insert Into TempletNodeIDBackendTbl ------------------------------------------------------------
	//----------------------------Select TempletNodeIDBackendTbl and  insert into NodeIDBackendAddressTbl-------------------------
	var NewBackendSeq int
	var NewBackendSeqArr []int

	QueryStr = "SELECT Seq FROM TempletNodeIDBackendTbl WHERE SeqNodeID = ?"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(TempletNameSeq)
	if err != nil {
		stmt.Close()
		log.Println("Query err!:", err)
		return 0
	}

	for Rows.Next() {
		err := Rows.Scan(&NewBackendSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}

		NewBackendSeqArr = append(NewBackendSeqArr, NewBackendSeq)

	}
	stmt.Close()
	for i := range Settings.SiteList {
		for j := range Settings.SiteList[i].Backend {
			QueryStr = "INSERT IGNORE INTO TempletNodeIDBackendAddressTbl (SeqNodeID, SeqBackend, NicName, IP, Port)\n" +
				"VALUES (?, ?, ?, ?, ?) "
			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("Prepare Fail!:", err)
				return 0
			}

			_, err = stmt.Exec(TempletNameSeq, NewBackendSeqArr[i], Settings.SiteList[i].Backend[j].LAN_Interface, Settings.SiteList[i].Backend[j].BackendIP, Settings.SiteList[i].Backend[j].BackendPort)
			if err != nil {
				stmt.Close()

				return 0
			}
			stmt.Close()
		}
	}
	mariadb_lib.DB_Commit(tx)
	WebServer_Redirect(w, req, "/add_cfg_templet/")
	return 0

}

func Delete_Templet(w http.ResponseWriter, req *http.Request, Database *sql.DB) int {
	defer req.Body.Close()
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryStr string

	var Rows *sql.Rows
	var TempletNameSeq int
	var err error
	log.Println("Save_NewTemplet", req.URL)

	Param_TempletName, ok := req.URL.Query()["TempletName"]
	if !ok || len(Param_TempletName) < 1 {
		WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
		return 0
	}
	TempletNameStr := fmt.Sprintf("%s", Param_TempletName)
	TempletNameStr = strings.Replace(TempletNameStr, "[", "", -1)
	TempletNameStr = strings.Replace(TempletNameStr, "]", "", -1)

	tx, err = mariadb_lib.DB_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)

		return 0
	}

	defer mariadb_lib.DB_Rollback(tx)
	//----------------------------Select TempletNameSeq --------------------------
	QueryStr = "SELECT Seq from TempletNodeIDTbl WHERE TempletName = ?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(TempletNameStr)
	if err != nil {
		stmt.Close()
		return 0
	}
	for Rows.Next() {
		err := Rows.Scan(&TempletNameSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}
	}
	stmt.Close()

	log.Println("select from TempletNameSeq :", TempletNameSeq)

	//----------------------------Select TempletNameSeq --------------------------

	//----------------------------Delete TempletNodeIDTbl --------------------------
	QueryStr = "DELETE FROM TempletNodeIDTbl WHERE TempletName= ? AND Seq =? ;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(TempletNameStr, TempletNameSeq)
	if err != nil {
		stmt.Close()

		return 0
	}
	stmt.Close()
	//----------------------------Delete TempletNodeIDTbl ----------------------------
	//----------------------------Delete TempletNodeIDFrontendTbl --------------------------

	QueryStr = "DELETE FROM TempletNodeIDFrontendTbl WHERE  SeqNodeID =?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(TempletNameSeq)
	if err != nil {
		stmt.Close()

		return 0
	}
	stmt.Close()
	//----------------------------Delete TempletNodeIDFrontendTbl --------------------------
	//----------------------------Delete TempletNodeIDBackendTbl --------------------------

	QueryStr = "DELETE FROM TempletNodeIDBackendTbl WHERE  SeqNodeID =?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(TempletNameSeq)
	if err != nil {
		stmt.Close()

		return 0
	}
	stmt.Close()
	//----------------------------Delete TempletNodeIDBackendTbl --------------------------
	//----------------------------Delete TempletNodeIDBackendAddressTbl --------------------------
	QueryStr = "DELETE FROM TempletNodeIDBackendAddressTbl WHERE  SeqNodeID =?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(TempletNameSeq)
	if err != nil {
		stmt.Close()

		return 0
	}
	stmt.Close()
	//----------------------------Delete TempletNodeIDBackendAddressTbl --------------------------
	mariadb_lib.DB_Commit(tx)

	WebServer_Redirect(w, req, "/add_cfg_templet/")
	return 0
}

func Save_Modified_TempletInfo(w http.ResponseWriter, req *http.Request, Database *sql.DB) int {
	defer req.Body.Close()
	var stmt *sql.Stmt
	var tx *sql.Tx
	var QueryStr string
	var Settings TempletSettingsInformation
	var Rows *sql.Rows
	var TempletNameSeq int
	var err error
	log.Println("Save_NewTemplet", req.URL)

	r := json.NewDecoder(req.Body)
	err = r.Decode(&Settings)
	if err != io.EOF {
		if err != nil {
			log.Println(err)
			return 0
		}
	}

	log.Println("Settings value:", Settings)
	tx, err = mariadb_lib.DB_Begin(Database)
	if err != nil {
		log.Println("Transaction Begin err:", err)

		return 0
	}

	defer mariadb_lib.DB_Rollback(tx)
	//----------------------------Select TempletNameSeq --------------------------
	QueryStr = "SELECT Seq from TempletNodeIDTbl WHERE TempletName = ?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(Settings.TempletName)
	if err != nil {
		stmt.Close()
		return 0
	}
	for Rows.Next() {
		err := Rows.Scan(&TempletNameSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}
	}
	stmt.Close()

	log.Println("select from TempletNameSeq :", TempletNameSeq)

	//----------------------------Select TempletNameSeq --------------------------

	//----------------------------Delete TempletNodeIDTbl --------------------------
	QueryStr = "DELETE FROM TempletNodeIDTbl WHERE TempletName= ? AND Seq =? ;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(Settings.TempletName, TempletNameSeq)
	if err != nil {
		stmt.Close()

		return 0
	}
	stmt.Close()
	//----------------------------Delete TempletNodeIDTbl ----------------------------
	//----------------------------Delete TempletNodeIDFrontendTbl --------------------------

	QueryStr = "DELETE FROM TempletNodeIDFrontendTbl WHERE  SeqNodeID =?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(TempletNameSeq)
	if err != nil {
		stmt.Close()

		return 0
	}
	stmt.Close()
	//----------------------------Delete TempletNodeIDFrontendTbl --------------------------
	//----------------------------Delete TempletNodeIDBackendTbl --------------------------

	QueryStr = "DELETE FROM TempletNodeIDBackendTbl WHERE  SeqNodeID =?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(TempletNameSeq)
	if err != nil {
		stmt.Close()

		return 0
	}
	stmt.Close()
	//----------------------------Delete TempletNodeIDBackendTbl --------------------------
	//----------------------------Delete TempletNodeIDBackendAddressTbl --------------------------
	QueryStr = "DELETE FROM TempletNodeIDBackendAddressTbl WHERE  SeqNodeID =?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(TempletNameSeq)
	if err != nil {
		stmt.Close()

		return 0
	}
	stmt.Close()
	//----------------------------Delete TempletNodeIDBackendAddressTbl --------------------------

	//----------------------------insert into TempletNodeIDTbl --------------------------
	QueryStr = "INSERT IGNORE INTO TempletNodeIDTbl (TempletName, Password, Global_MaxConn, Global_RecvBufferSize, Global_SendBufferSize, " +
		"Global_TimeoutConnect, Global_TimeoutClient, Global_TimeoutServer, " +
		"Log_DiskLimit, Log_MaxSize, Log_LogDir, Log_LogName, Log_ErrDir, Log_ErrName, " +
		"Stat_SendControlServerFlag, Stat_StatCollectionCycle, Stat_StatServerIP, Stat_StatServerPort, Stat_StatDataSendCycle, " +
		"Node_UseBridgeRouter, Node_NodeBufferSize, Node_EncryptMode, Node_ChangeIPClientMode, " +
		"KMS_IP, KMS_Port) " +
		"VALUES (?, ?, ?, ?, ?, " +
		"?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, " +
		"?, ?) "

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Prepare Fail!:", err)
		return 0
	}
	_, err = stmt.Exec(Settings.TempletName, Settings.Password, Settings.Maximum_ConnectionCount, Settings.Recv_Buf_Size, Settings.Send_Buf_Size,
		Settings.Connection_Timeout, Settings.Client_Reconnect_Timeout, Settings.Server_Reconnect_Timeout,
		Settings.Limit_Size_Log_Storage, Settings.Maxsize_Per_Logfile, Settings.Logfile_Path, "app.log", Settings.Err_Logfile_Path, "app_err.log",
		Settings.Statistic_Send_Control_Server, Settings.Statistic_Collection_Cycle, Settings.Statistic_Server_Ip, Settings.Statistic_Server_Port, Settings.Statistic_Send_Cycle,
		Settings.Bridge_Used, Settings.Bridge_Buf_Size, Settings.Encrypt_Mode, Settings.Change_Client_IP,
		Settings.KMS_Address, Settings.KMS_Port)
	if err != nil {
		stmt.Close()

		return 0
	}
	stmt.Close()

	//----------------------------insert into TempletNodeIDTbl --------------------------
	//----------------------------Select TempletNameSeq --------------------------
	QueryStr = "SELECT Seq from TempletNodeIDTbl WHERE TempletName = ?;"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(Settings.TempletName)
	if err != nil {
		stmt.Close()
		return 0
	}
	for Rows.Next() {
		err := Rows.Scan(&TempletNameSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}
	}
	stmt.Close()

	log.Println("select from TempletNameSeq :", TempletNameSeq)

	//----------------------------Select TempletNameSeq --------------------------
	//----------------------------Insert Into TempletNodeIDFrontendTbl --------------------------

	for i := range Settings.SiteList {

		QueryStr = "INSERT IGNORE INTO TempletNodeIDFrontendTbl (SeqNodeID,Name,Bind,Backend , NodeMode)\n" +
			"VALUES(?,?,?,?,?)"

		stmt, err = tx.Prepare(QueryStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}

		if Settings.SiteList[i].NodeMode == "1" {
			Settings.SiteList[i].NodeMode = "client"
		} else if Settings.SiteList[i].NodeMode == "2" {
			Settings.SiteList[i].NodeMode = "server"
		} else {
			Settings.SiteList[i].NodeMode = ""
		}

		_, err = stmt.Exec(TempletNameSeq, Settings.SiteList[i].Frontendsymbol, Settings.SiteList[i].FrontendPort, Settings.SiteList[i].Frontendsymbol, Settings.SiteList[i].NodeMode)
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()
	}

	//----------------------------Insert Into TempletNodeIDFrontendTbl --------------------------
	//----------------------------Insert Into TempletNodeIDBackendTbl --------------------------
	for i := range Settings.SiteList {

		QueryStr = "INSERT IGNORE INTO TempletNodeIDBackendTbl (SeqNodeID,Name)\n" +
			"VALUES(?,?)"

		stmt, err = tx.Prepare(QueryStr)
		if err != nil {
			log.Println("Prepare Fail!:", err)
			return 0
		}
		_, err = stmt.Exec(TempletNameSeq, Settings.SiteList[i].Frontendsymbol)
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return 0
		}
		stmt.Close()
	}

	//----------------------------Insert Into TempletNodeIDBackendTbl ------------------------------------------------------------
	//----------------------------Select TempletNodeIDBackendTbl and  insert into NodeIDBackendAddressTbl-------------------------
	var NewBackendSeq int
	var NewBackendSeqArr []int

	QueryStr = "SELECT  Seq FROM TempletNodeIDBackendTbl WHERE SeqNodeID = ?"
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("Exec Fail!:", err)

		return 0
	}
	Rows, err = stmt.Query(TempletNameSeq)
	if err != nil {
		stmt.Close()
		return 0
	}

	for Rows.Next() {
		err := Rows.Scan(&NewBackendSeq)
		if err != nil {
			log.Println(" data Scan error:", err)
			return 0
		}

		NewBackendSeqArr = append(NewBackendSeqArr, NewBackendSeq)

	}
	stmt.Close()
	for i := range Settings.SiteList {
		for j := range Settings.SiteList[i].Backend {
			QueryStr = "INSERT IGNORE INTO TempletNodeIDBackendAddressTbl (SeqNodeID, SeqBackend, NicName, IP, Port) " +
				"VALUES (?, ?, ?, ?, ?) "
			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("Prepare Fail!:", err)

				return 0
			}

			_, err = stmt.Exec(TempletNameSeq, NewBackendSeqArr[i], Settings.SiteList[i].Backend[j].LAN_Interface, Settings.SiteList[i].Backend[j].BackendIP, Settings.SiteList[i].Backend[j].BackendPort)
			if err != nil {
				stmt.Close()

				return 0
			}
			stmt.Close()
		}
	}
	mariadb_lib.DB_Commit(tx)
	/*
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Println(err)
			return 0
		}
		defer resp.Body.Close()

		fmt.Println("response Status:", resp.Status)
		fmt.Println("response Headers:", resp.Header)
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println("response Body:", string(body))
	*/
	WebServer_Redirect(w, req, "/add_cfg_templet/")
	return 1

}

//========================================================================================================{
// Provisioning Functions

const (
	ProvisionVersion = "1.0"
	ProvisionMethod  = "CFGSET"
)
const (
	StatisticsVersion = "1.0"
	StatisticsMethod  = "CFGSET"
)

type ProvisionHeader struct {
	Version   string `json:"version"`
	Method    string `json:"method"`
	Seperator string `json:"seperator"`
	Msgtype   string `json:"msgtype"`
	Userkey   string `json:"userkey"`
	Nodeid    string `json:"nodeid"`
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

//--------------------------------------------------
type StatisticsHeader struct {
	Version   string `json:"version"`
	Method    string `json:"method"`
	Seperator string `json:"seperator"`
	Msgtype   string `json:"msgtype"`
	Userkey   string `json:"userkey"`
	Nodeid    string `json:"nodeid"`
}

type StatisticsBody struct {
	Code    int                  `json:"code,omitempty"`    // 0 is ignore
	Message string               `json:"message,omitempty"` // emptry is ignore
	Data    StatisticInformation `json:"data,omitempty"`
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

//--------------------------------------------------

type UsersTlbData struct {
	Seq                    int64
	ID                     string
	Password               string
	Stat_StatServerIP      string
	Stat_StatServerPort    string
	Stat_StatDataSendCycle string
	Stat_Send_Flag         int
}

func GetCfgFileData() (*Settingtoml, error) {
	filepath := "./cfg/app.cfg"
	cfgdata, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	decryption := AESDecryptDecodeValuePrefix(string(cfgdata))

	var cfginfo Settingtoml
	if _, err = toml.Decode(decryption, &cfginfo); err != nil {
		return nil, err
	}

	return &cfginfo, nil
}

func GetUsersTlbData(db *sql.DB) (data *UsersTlbData, err error) {
	query := "SELECT Seq, ID, Password, Stat_StatServerIP, Stat_StatServerPort, Stat_StatDataSendCycle, Stat_Send_Flag FROM Users LIMIT 1;"
	rows, err := sqlitedb_lib.Query_DB(db, query)
	if err != nil {
		log.Println(err)
	}
	defer rows.Close()

	data = new(UsersTlbData)
	for rows.Next() {
		err = rows.Scan(&data.Seq, &data.ID, &data.Password, &data.Stat_StatServerIP, &data.Stat_StatServerPort, &data.Stat_StatDataSendCycle, &data.Stat_Send_Flag)
		if err != nil {
			log.Println(err)
			return
		}
	}
	return
}

type UserKeyFile struct {
	UserKey string
}

type NodeIDFile struct {
	NodeID string
}

type AuthTokenFile struct {
	AuthToken string
}

type UserKeyFileData struct {
	UserKey UserKeyFile
}

type NodeIDFileData struct {
	NodeID NodeIDFile
}

type AuthTokenFileData struct {
	AuthToken AuthTokenFile
}

type AuthData struct {
	UserKey   string
	NodeID    string
	AuthToken string
}

func GetAuthData() (data *AuthData, err error) {
	var userkey, nodeid, authtoken []byte
	var userkeyfiledata UserKeyFileData
	var nodeidfiledata NodeIDFileData
	var authtokenfiledata AuthTokenFileData

	userkey, err = ioutil.ReadFile("./cfg/userkey.key")
	if err != nil {
		return
	}

	data = new(AuthData)
	data.UserKey = AESDecryptDecodeValuePrefix(string(userkey))
	if _, err := toml.Decode(data.UserKey, &userkeyfiledata); err != nil {
		return nil, err
	}

	nodeid, err = ioutil.ReadFile("./cfg/nodeid.key")
	if err != nil {
		nodeidfiledata.NodeID.NodeID = ""
	} else {
		data.NodeID = AESDecryptDecodeValuePrefix(string(nodeid))
		if _, err := toml.Decode(data.NodeID, &nodeidfiledata); err != nil {
			return nil, err
		}
	}

	authtoken, err = ioutil.ReadFile("./cfg/authtoken.key")
	if err != nil {
		authtokenfiledata.AuthToken.AuthToken = ""
	} else {
		data.AuthToken = AESDecryptDecodeValuePrefix(string(authtoken))
		if _, err := toml.Decode(data.AuthToken, &authtokenfiledata); err != nil {
			return nil, err
		}
	}

	data.UserKey = userkeyfiledata.UserKey.UserKey
	data.NodeID = nodeidfiledata.NodeID.NodeID
	data.AuthToken = authtokenfiledata.AuthToken.AuthToken
	err = nil
	return
}

/*
 *	Provisioning Local DOWNLOAD -----------------------------------------------------------------
 */

func ProvisioningDownloadLocalPorcess(db *sql.DB) {
	for {
		select {
		case <-time.After(time.Second * 8):
		}

		userstlbData, err := GetUsersTlbData(db)
		if err != nil {
			log.Println(err)
			continue
		}

		if userstlbData.Stat_Send_Flag != ENABLE {
			continue
		}

		authData, err := GetAuthData()
		if err != nil {
			log.Println(err)
			continue
		}
		if authData.NodeID == "" {
			continue
		}

		syncSeqNo, err := GetLocalSyncSeqNo(db, "ConfigData")
		if err != nil {
			log.Println(err)
			continue
		}

		controlServerAddr := userstlbData.Stat_StatServerIP + ":" + userstlbData.Stat_StatServerPort
		url := fmt.Sprintf("http://%s/auth_api/provisioning/v1.0/", controlServerAddr)

		authkey, authtoken, err := ProvisioningAuthRequest(db, url, authData)
		if err != nil {
			log.Println(err)
			continue
		}

		if err := ProvisioningDownloadRequest(db, url, userstlbData, authData, authkey, authtoken, syncSeqNo); err != nil {
			log.Println(err)
		}
	}
}

func ProvisioningAuthRequest(db *sql.DB, url string, authData *AuthData) (string, string, error) {
	authReqProto := jsonInputWebAPIAuthProvisioningPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "ConfigData"
	authReqProto.MessageType = "request"
	authReqProto.UserKey = AESEncryptEncodingValue(authData.UserKey)
	authReqProto.NodeID = AESEncryptEncodingValue(authData.NodeID)
	authReqProto.IP = GetOutboundIP().To4().String()

	macs, _ := GetNICMAC()
	if macs != nil {
		authReqProto.MACTotal = strings.Join(macs, "-")
	}

	authReqProto.AuthKey = ""
	authReqProto.AuthToken = ""

	jsonBytes, err := json.Marshal(authReqProto)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", errors.New(fmt.Sprint("Response Auth Provisioning Http error: %d", resp.Status))
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	authResProto := jsonOutputWebAPIAuthProvisioningPack{}
	if err := json.Unmarshal(bodyBytes, &authResProto); err != nil {
		return "", "", errors.New(err.Error() + "\nurl: " + url)
	}

	if authResProto.Version != "1.0" {
		return "", "", errors.New("invailed auth protocol Version")
	}
	if authResProto.Method != authReqProto.Method {
		return "", "", errors.New("invailed auth protocol Method")
	}
	if authResProto.MsgType != "response" {
		return "", "", errors.New("invailed auth protocol MsgType")
	}
	if authResProto.SessionType != authReqProto.SessionType {
		return "", "", errors.New("invailed auth protocol SessionType")
	}

	if authResProto.AuthKey == "" {
		return "", "", errors.New("invailed auth protocol AuthKey")
	}

	hashing_algorithm := md5.New()
	HashingText := authData.UserKey + ":" + authResProto.SessionType
	hashing_algorithm.Write([]byte(HashingText))
	HA1 := hex.EncodeToString(hashing_algorithm.Sum(nil))

	hashing_algorithm = md5.New()
	HashingText = authResProto.Method + ":" + "/auth_api/provisioning/v1.0/"
	hashing_algorithm.Write([]byte(HashingText))
	HA2 := hex.EncodeToString(hashing_algorithm.Sum(nil))

	hashing_algorithm = md5.New()
	HashingText = HA1 + ":" + authResProto.AuthKey + ":" + HA2
	hashing_algorithm.Write([]byte(HashingText))
	authtoken := hex.EncodeToString(hashing_algorithm.Sum(nil))

	return authResProto.AuthKey, authtoken, nil
}

func ProvisioningDownloadRequest(db *sql.DB, url string, userstlbData *UsersTlbData, authData *AuthData, authkey string, authtoken string, syncSeqNo int64) error {
	proviReq := ProvisionProtocol{}
	proviReq.Header.Version = ProvisionVersion
	proviReq.Header.Msgtype = "request"
	proviReq.Header.Method = ProvisionMethod
	proviReq.Header.Seperator = "down"
	proviReq.Header.Userkey = AESEncryptEncodingValue(authData.UserKey)
	proviReq.Header.Nodeid = AESEncryptEncodingValue(authData.NodeID)
	proviReq.Header.CurSeq = syncSeqNo

	/*
		//Test--------------------{
		configData, err := GetProvisioningConfigData(db)
		if err != nil {
			return err
		}
		proviReq.Body.Data = configData
		//Test---------------------}
	*/

	authReqProto := jsonInputWebAPIAuthProvisioningPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "ConfigData"
	authReqProto.MessageType = "request"
	authReqProto.UserKey = proviReq.Header.Userkey
	authReqProto.NodeID = proviReq.Header.Nodeid
	authReqProto.IP = GetOutboundIP().To4().String()

	macs, _ := GetNICMAC()
	if macs != nil {
		authReqProto.MACTotal = strings.Join(macs, "-")
	}

	authReqProto.AuthKey = authkey
	authReqProto.AuthToken = authtoken
	authReqProto.Data = proviReq

	jsonBytes, err := json.Marshal(authReqProto)
	if err != nil {
		return err
	}

	//fmt.Printf(">>>ProvisioningDownloadRequest(): Request json=%s\n", string(jsonBytes))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprint("Response Provisioning Http error: %d", resp.Status))
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf(">>>ProvisioningDownloadRequest(): Response json=%s\n", string(bodyBytes))

	authResProto := jsonOutputWebAPIAuthStatisticsPack{}
	if err := json.Unmarshal(bodyBytes, &authResProto); err != nil {
		return err
	}

	if authResProto.Version != "1.0" {
		return errors.New("invailed auth protocol Version")
	}
	if authResProto.Method != authReqProto.Method {
		return errors.New("invailed auth protocol Method")
	}
	if authResProto.MsgType != "response" {
		return errors.New("invailed auth protocol MsgType")
	}
	if authResProto.SessionType != authReqProto.SessionType {
		return errors.New("invailed auth protocol SessionType")
	}

	proviRes := ProvisionProtocol{}

	if err := mapstructure.Decode(authResProto.Data, &proviRes); err != nil {
		return err
	}

	if err := CheckProvisionHeader(&proviRes.Header); err != nil {
		return err
	}

	if proviRes.Body.Code == 200 {
	} else if proviRes.Body.Code == 650 {
		if proviRes.Header.Seq <= proviRes.Header.CurSeq {
			log.Printf("Provisioning Download Respose Error: Invailed Seq=%d, CurSeq=%d\n", proviRes.Header.Seq, proviRes.Header.CurSeq)
		} else {
			log.Printf("Provisioning Download: Update New ConfigData CurSeq %d -> NewSeqNo %d\n", proviRes.Header.CurSeq, proviRes.Header.Seq)
			// Update CfgData
			UpdateConfigFiles(db, *proviRes.Body.Data, proviRes.Header.Seq)
		}
	} else {
		log.Printf("Provisioning Download Respose Error: Code=%d, Message=%s\n", proviRes.Body.Code, proviRes.Body.Message)
	}

	return nil
}

func GetLocalSyncSeqNo(db *sql.DB, seqNoName string) (int64, error) {
	query := "SELECT SeqNo\n" +
		"FROM SyncSeqNoTbl\n" +
		"WHERE SeqNoName = ?;"

	stmt, err := db.Prepare(query)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var seqNo int64
	err = stmt.QueryRow(seqNoName).Scan(&seqNo)
	if err != nil {
		return 0, err
	}

	return seqNo, nil
}

func CheckProvisionHeader(header *ProvisionHeader) error {
	if header.Version != ProvisionVersion {
		return errors.New("invalied header version in provisioning")
	}
	if header.Method != ProvisionMethod {
		return errors.New("invalied header method in provisioning")
	}

	return nil
}

// SelectDBSyncSeqNo for ControlServer
func SelectDBSyncSeqNo(db *sql.DB, nodeid string) (int64, int64, error) {
	query := "SELECT B.SeqNo, A.Seq " +
		"FROM NodeIDTbl AS A " +
		"JOIN CWS_SyncSeqNoTbl AS B " +
		"ON A.Seq = B.SeqNodeID " +
		"AND A.Node_NodeID = ? " +
		"AND B.SeqNoName = 'ConfigData';"

	stmt, err := db.Prepare(query)
	if err != nil {
		return 0, 0, err
	}

	defer stmt.Close()

	var seqNo int64
	var nodeSeqNo int64
	err = stmt.QueryRow(nodeid).Scan(&seqNo, &nodeSeqNo)
	if err != nil {
		return 0, 0, err
	}

	return seqNo, nodeSeqNo, nil
}

// SelectDBConfigData for ControlServer
func SelectDBConfigData(db *sql.DB, nodeid string) (*SettingsInformation, string, error) {
	query := "SELECT A.UserKey, B.Password, B.VerifyingPassword\n" +
		", B.Global_MaxConn, B.Global_RecvBufferSize, B.Global_SendBufferSize, B.Global_TimeoutConnect, B.Global_TimeoutClient, B.Global_TimeoutServer\n" +
		", B.Log_DiskLimit, B.Log_MaxSize, B.Log_LogDir, B.Log_LogName, B.Log_ErrDir, B.Log_ErrName\n" +
		", B.Stat_SendControlServerFlag, B.Stat_StatCollectionCycle, B.Stat_StatServerIP, B.Stat_StatServerPort, B.Stat_StatDataSendCycle\n" +
		", B.Node_NodeBufferSize, B.Node_EncryptMode, B.Node_ChangeIPClientMode, B.Node_NodeID\n" +
		", B.KMS_IP, B.KMS_Port\n" +
		", C.Name, C.NicName, C.Bind, C.NodeMode /* Frontend */\n" +
		", D.Name, E.NicName, E.IP, E.Port /* Backend */\n" +

		"FROM UserKeyTbl AS A\n" +
		"INNER JOIN NodeIDTbl AS B\n" +
		"ON A.Seq = B.SeqUserKey\n" +
		"AND B.Node_NodeID = ?\n" +
		"INNER JOIN NodeIDFrontendTbl AS C\n" +
		"ON B.Seq = C.SeqNodeID\n" +
		"INNER JOIN NodeIDBackendTbl AS D\n" +
		"ON C.SeqNodeID = D.SeqNodeID\n" +
		"AND C.Backend = D.Name\n" +
		"INNER JOIN NodeIDBackendAddressTbl AS E\n" +
		"ON D.Seq = E.SeqBackend\n" +
		"ORDER BY C.Name;"

	stmt, err := db.Prepare(query)
	if err != nil {
		return nil, "", err
	}
	defer stmt.Close()

	rows, err := stmt.Query(nodeid)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	settingData := new(SettingsInformation)

	var userkey, logDir, logFileName, errDir, errFileName, frontendName, frontendNIC, frontendPort, frontendNodeMode, backendName, backendNIC, backendIP, backendPort string
	frontendName1 := ""

	idx := -1
	for rows.Next() {
		err := rows.Scan(&userkey, &settingData.Password, &settingData.VerifyingPassword,
			&settingData.Maximum_ConnectionCount, &settingData.Recv_Buf_Size, &settingData.Send_Buf_Size, &settingData.Connection_Timeout, &settingData.Client_Reconnect_Timeout, &settingData.Server_Reconnect_Timeout,
			&settingData.Limit_Size_Log_Storage, &settingData.Maxsize_Per_Logfile, &logDir, &logFileName, &errDir, &errFileName,
			&settingData.Statistic_Send_Control_Server, &settingData.Statistic_Collection_Cycle, &settingData.Statistic_Server_Ip, &settingData.Statistic_Server_Port, &settingData.Statistic_Send_Cycle,
			&settingData.Bridge_Buf_Size, &settingData.Encrypt_Mode, &settingData.Change_Client_IP, &settingData.Node_ID,
			&settingData.KMS_Address, &settingData.KMS_Port, &frontendName, &frontendNIC, &frontendPort, &frontendNodeMode, &backendName, &backendNIC, &backendIP, &backendPort)
		if err != nil {
			return nil, "", err
		}

		if frontendName != frontendName1 {
			frontend := FrontendInformation{}
			settingData.SiteList = append(settingData.SiteList, frontend)
			idx++

			settingData.SiteList[idx].Frontendsymbol = frontendName
			settingData.SiteList[idx].FrontendPort = frontendNIC + ":" + frontendPort
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

// UpdateDBNodeStatus ...
func UpdateDBNodeStatus(db *sql.DB) error {
	query := "UPDATE NodeIDTbl " +
		"SET Node_Status = 0 " +
		"WHERE Seq IN ( " +
		"		SELECT Seq " +
		"		FROM ( " +
		"		   SELECT Seq " +
		"			FROM NodeIDTbl " +
		"			WHERE (TIME_TO_SEC(NOW()) - TIME_TO_SEC(Provisioning_Time)) > (8 * 3) " +
		"		) AS TMP " +
		") " +
		"AND Node_Status = 1"

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

// UpdateDBProvisioningTime ...
func UpdateDBProvisioningTime(db *sql.DB, nodeid string) error {
	query := "UPDATE NodeIDTbl " +
		"SET Provisioning_Time = NOW(), Node_Status = 1 " +
		"WHERE Node_NodeID = ?"

	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(nodeid)
	if err != nil {
		return err
	}

	return nil
}

func GetProvisioningConfigData(db *sql.DB) (*SettingsInformation, error) {
	data := SettingsInformation{}

	userstlbData, err := GetUsersTlbData(db)
	if err != nil {
		log.Println(err)
		return &data, err
	}

	settingData, err := GetCfgFileData()
	if err != nil {
		log.Println(err)
		return &data, err
	}

	authData, err := GetAuthData()
	if err != nil {
		log.Println(err)
		return &data, err
	}

	data.Password = userstlbData.Password
	data.VerifyingPassword = userstlbData.Password
	data.Maximum_ConnectionCount = settingData.Global.Max_conn
	data.Recv_Buf_Size = settingData.Global.Recv_buffer_size
	data.Send_Buf_Size = settingData.Global.Send_buffer_size
	data.Connection_Timeout = settingData.Global.Timeout_connect
	data.Server_Reconnect_Timeout = settingData.Global.Timeout_server
	data.Client_Reconnect_Timeout = settingData.Global.Timeout_client

	data.Limit_Size_Log_Storage = settingData.Logfile.Disk_limit
	data.Maxsize_Per_Logfile = settingData.Logfile.Max_size
	data.Logfile_Path = settingData.Logfile.Log
	data.Err_Logfile_Path = settingData.Logfile.Error

	data.Statistic_Collection_Cycle = settingData.Statistics.Interval
	if userstlbData.Stat_Send_Flag == ENABLE {
		data.Statistic_Send_Control_Server = "Enable"
	} else {
		data.Statistic_Send_Control_Server = "Disable"
	}
	data.Statistic_Server_Ip = userstlbData.Stat_StatServerIP
	data.Statistic_Server_Port = userstlbData.Stat_StatServerPort
	data.Statistic_Send_Cycle = userstlbData.Stat_StatDataSendCycle

	data.Bridge_Buf_Size = settingData.Node.Buffer_size
	data.Encrypt_Mode = settingData.Node.Encrypt
	data.Change_Client_IP = settingData.Node.Cp_tunneling
	data.Node_ID = authData.NodeID

	kmsAddr := strings.TrimLeft(settingData.KMS.Url, "http://")
	kmsSplit := strings.Split(kmsAddr, ":")
	data.KMS_Address = kmsSplit[0]
	if len(kmsSplit) == 2 {
		data.KMS_Port = kmsSplit[1]
	}
	data.SiteList = make([]FrontendInformation, len(settingData.Frontend))

	i := 0
	for k, v := range settingData.Frontend {
		data.SiteList[i].Frontendsymbol = k
		data.SiteList[i].FrontendPort = v.Bind
		data.SiteList[i].NodeMode = v.Node_Mode

		for k1, v1 := range settingData.Backend {
			if v.Backend == k1 {
				data.SiteList[i].Backend = make([]BackendInformationList, len(v1.Server))

				for j, srv := range v1.Server {
					arr := strings.Split(srv, "/")
					if len(arr) == 1 {
						data.SiteList[i].Backend[j].LAN_Interface = arr[0]
						addr := strings.Split(arr[0], ":")
						if len(addr) == 2 {
							data.SiteList[i].Backend[j].BackendIP = addr[0]
							data.SiteList[i].Backend[j].BackendPort = addr[1]
						}

					} else {
						data.SiteList[i].Backend[j].LAN_Interface = arr[0]
						addr := strings.Split(arr[1], ":")
						if len(addr) == 2 {
							data.SiteList[i].Backend[j].BackendIP = addr[0]
							data.SiteList[i].Backend[j].BackendPort = addr[1]
						}
					}
				}
				break
			}
		}

		i++
	}

	return &data, nil
}

//========================================================================================================}
//----------------------------------------------------------
type jsonInputWebAPIAuthStatLocalPack struct {
	Version     string      `json:"version"`
	Method      string      `json:"method"`
	SessionType string      `json:"sessiontype"`
	MessageType string      `json:"msgtype"`
	UserKey     string      `json:"userkey"`
	NodeID      string      `json:"nodeid"`
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
func StatisticsUploadLocalProcess(lwsDatabase *sql.DB, trafficDatabase *sql.DB) {
	var QueryStr string
	var StatRows *sql.Rows
	var ServerStatistic StatisticInformation
	var StatSendInterval_int int
	var StatSendInterval_time time.Duration

	for {
		if StatSendInterval_time <= 0 {
			StatSendInterval_time = 3
		}
		select {
		case <-time.After(time.Second * StatSendInterval_time):
		}

		userstlbData, err := GetUsersTlbData(lwsDatabase)
		if err != nil {
			log.Println(err)
			continue
		}

		//---for testg----------
		userstlbData.Stat_Send_Flag = ENABLE
		userstlbData.Stat_StatServerIP = "127.0.0.1"
		userstlbData.Stat_StatServerPort = "8888"
		userstlbData.Stat_StatDataSendCycle = "30"
		//---for testg----------

		StatSendInterval_int, _ = strconv.Atoi(userstlbData.Stat_StatDataSendCycle)
		StatSendInterval_time = time.Duration(StatSendInterval_int)

		if userstlbData.Stat_Send_Flag != ENABLE {
			log.Println("StatSendFlag is DISABLE")
			continue
		}

		authData, err := GetAuthData()
		if err != nil {
			log.Println(err)
			continue
		}
		if authData.NodeID == "" {
			continue
		}
		//------------for testing [hard cording]--------------
		authData.UserKey = "TC7rcr8v-00000002-aeLlO-CzqAk-N3WJmTTRV0Bu"
		authData.NodeID = "N7y8VbI8-00000001-hWJeh-AUCXS-mA0IhNYm2B4M"
		//------------for testing [hard cording]--------------

		QueryStr = "select A.ID, A.Time, A.Bridge_ID_TEXT , A.Proxy_IP_INT, A.Proxy_IP_TEXT, A.Node_IP_INT,\n" +
			"A.Node_IP_TEXT, A.Node_Listen_Port, A.Server_IP_INT, A.Server_IP_TEXT, A.Server_Listen_Port,\n" +
			"B.Client_IP_INT, B.Client_IP_TEXT, B.Inbound, B.Outbound\n" +
			"from SERVER_STATISTICS_COMMON A, SERVER_STATISTICS_DATA B where A.ID = B.ID"

		StatRows, err = sqlitedb_lib.Query_DB(trafficDatabase, QueryStr)
		if err != nil {
			log.Println("Query err", err)
			continue
		}
		defer StatRows.Close()
		for StatRows.Next() {
			err = StatRows.Scan(&ServerStatistic.ID, &ServerStatistic.Time, &ServerStatistic.Bridge_ID_Text, &ServerStatistic.Proxy_IP_Int, &ServerStatistic.Proxy_IP_Text, &ServerStatistic.Node_IP_Int,
				&ServerStatistic.Node_IP_Text, &ServerStatistic.Node_Listen_Port, &ServerStatistic.Server_IP_Int, &ServerStatistic.Server_IP_Text, &ServerStatistic.Server_Listen_Port,
				&ServerStatistic.Client_IP_Int, &ServerStatistic.Client_IP_Text, &ServerStatistic.Inbound, &ServerStatistic.Outbound)
			if err != nil {
				log.Println("Scan error", err)
				StatRows.Close()
				return
			}

			log.Println("ServerStatistic:", ServerStatistic)
			ServerStatistic.Type = "001"
			controlServerAddr := userstlbData.Stat_StatServerIP + ":" + userstlbData.Stat_StatServerPort
			url := fmt.Sprintf("http://%s/auth_api/statistics/v1.0/", controlServerAddr)

			authkey, authtoken, err := StatisticsAuthRequest(lwsDatabase, url, authData)
			if err != nil {
				log.Println(err)
				continue
			}
			log.Println("authkey:", authkey)
			log.Println("authtoken:", authtoken)

			if err := StatisticsUploadRequest(lwsDatabase, url, userstlbData, authData, authkey, authtoken, ServerStatistic); err != nil {
				log.Println(err)
			}
		}

		QueryStr = "select A.ID, A.Time, A.Node_ID_TEXT , A.Client_IP_INT, A.Client_IP_TEXT, A.Node_IP_INT,\n" +
			"A.Node_IP_TEXT, A.Node_Listen_Port, B.Proxy_IP_INT, B.Proxy_IP_TEXT, B.Proxy_Listen_Port,\n" +
			"B.Inbound, B.Outbound\n" +
			"from Client_Statistics_Common A, Client_Statistics_Data B where A.ID = B.ID"

		StatRows, err = sqlitedb_lib.Query_DB(trafficDatabase, QueryStr)
		if err != nil {
			log.Println("Query err", err)
			continue
		}
		defer StatRows.Close()
		for StatRows.Next() {
			err = StatRows.Scan(&ServerStatistic.ID, &ServerStatistic.Time, &ServerStatistic.Node_ID_Text, &ServerStatistic.Client_IP_Int, &ServerStatistic.Client_IP_Text, &ServerStatistic.Node_IP_Int,
				&ServerStatistic.Node_IP_Text, &ServerStatistic.Node_Listen_Port, &ServerStatistic.Proxy_IP_Int, &ServerStatistic.Proxy_IP_Text, &ServerStatistic.Proxy_Listen_Port,
				&ServerStatistic.Inbound, &ServerStatistic.Outbound)
			if err != nil {
				log.Println("Scan error", err)
				StatRows.Close()
				return
			}

			log.Println("ClientStatistic:", ServerStatistic)
			ServerStatistic.Type = "002"

			controlServerAddr := userstlbData.Stat_StatServerIP + ":" + userstlbData.Stat_StatServerPort
			url := fmt.Sprintf("http://%s/auth_api/statistics/v1.0/", controlServerAddr)

			authkey, authtoken, err := StatisticsAuthRequest(lwsDatabase, url, authData)
			if err != nil {
				log.Println(err)
				continue
			}
			log.Println("authkey:", authkey)
			log.Println("authtoken:", authtoken)

			if err := StatisticsUploadRequest(lwsDatabase, url, userstlbData, authData, authkey, authtoken, ServerStatistic); err != nil {
				log.Println(err)
			}
		}
	}
}

func StatisticsAuthRequest(db *sql.DB, url string, authData *AuthData) (string, string, error) {
	authReqProto := jsonInputWebAPIAuthStatLocalPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "Statistics"
	authReqProto.MessageType = "request"
	authReqProto.UserKey = AESEncryptEncodingValue(authData.UserKey)
	authReqProto.NodeID = AESEncryptEncodingValue(authData.NodeID)
	authReqProto.IP = GetOutboundIP().To4().String()

	macs, _ := GetNICMAC()
	if macs != nil {
		authReqProto.MACTotal = strings.Join(macs, "-")
	}

	authReqProto.AuthKey = ""
	authReqProto.AuthToken = ""

	jsonBytes, err := json.Marshal(authReqProto)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", errors.New(fmt.Sprint("Response Auth Provisioning Http error: %d", resp.Status))
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	authResProto := jsonOutputWebAPIAuthStatLocalPack{}
	if err := json.Unmarshal(bodyBytes, &authResProto); err != nil {
		return "", "", errors.New(err.Error() + "\nurl: " + url)
	}

	if authResProto.Version != "1.0" {
		return "", "", errors.New("invailed auth protocol Version")
	}
	if authResProto.Method != authReqProto.Method {
		return "", "", errors.New("invailed auth protocol Method")
	}
	if authResProto.MsgType != "response" {
		return "", "", errors.New("invailed auth protocol MsgType")
	}
	if authResProto.SessionType != authReqProto.SessionType {
		return "", "", errors.New("invailed auth protocol SessionType")
	}

	if authResProto.AuthKey == "" {
		return "", "", errors.New("invailed auth protocol AuthKey")
	}

	hashing_algorithm := md5.New()
	HashingText := authData.UserKey + ":" + authResProto.SessionType
	hashing_algorithm.Write([]byte(HashingText))
	HA1 := hex.EncodeToString(hashing_algorithm.Sum(nil))

	hashing_algorithm = md5.New()
	HashingText = authResProto.Method + ":" + "/auth_api/statistics/v1.0/"
	hashing_algorithm.Write([]byte(HashingText))
	HA2 := hex.EncodeToString(hashing_algorithm.Sum(nil))

	hashing_algorithm = md5.New()
	HashingText = HA1 + ":" + authResProto.AuthKey + ":" + HA2
	hashing_algorithm.Write([]byte(HashingText))
	authtoken := hex.EncodeToString(hashing_algorithm.Sum(nil))

	return authResProto.AuthKey, authtoken, nil
}

func StatisticsUploadRequest(db *sql.DB, url string, userstlbData *UsersTlbData, authData *AuthData, authkey string, authtoken string, ServerStatistic StatisticInformation) error {
	StatReq := StatisticsProtocol{}
	StatReq.Header.Version = StatisticsVersion
	StatReq.Header.Msgtype = "request"
	StatReq.Header.Method = StatisticsMethod
	StatReq.Header.Seperator = "up"
	StatReq.Header.Userkey = AESEncryptEncodingValue(authData.UserKey)
	StatReq.Header.Nodeid = AESEncryptEncodingValue(authData.NodeID)
	StatReq.Body.Data = ServerStatistic
	/*
		//Test--------------------{
		configData, err := GetProvisioningConfigData(db)
		if err != nil {
			return err
		}
		proviReq.Body.Data = configData
		//Test---------------------}
	*/

	authReqProto := jsonInputWebAPIAuthStatLocalPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "Statistics"
	authReqProto.MessageType = "request"
	authReqProto.UserKey = StatReq.Header.Userkey
	authReqProto.NodeID = StatReq.Header.Nodeid
	authReqProto.IP = GetOutboundIP().To4().String()

	macs, _ := GetNICMAC()
	if macs != nil {
		authReqProto.MACTotal = strings.Join(macs, "-")
	}

	authReqProto.AuthKey = authkey
	authReqProto.AuthToken = authtoken
	authReqProto.Data = StatReq

	jsonBytes, err := json.Marshal(authReqProto)
	if err != nil {
		return err
	}

	//fmt.Printf(">>>ProvisioningDownloadRequest(): Request json=%s\n", string(jsonBytes))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprint("Response Statistics Http error: %d", resp.Status))
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf(">>>StatisticsuploadRequest(): Response json=%s\n", string(bodyBytes))

	authResProto := jsonOutputWebAPIAuthStatLocalPack{}
	if err := json.Unmarshal(bodyBytes, &authResProto); err != nil {
		return err
	}

	if authResProto.Version != "1.0" {
		return errors.New("invailed auth protocol Version")
	}
	if authResProto.Method != authReqProto.Method {
		return errors.New("invailed auth protocol Method")
	}
	if authResProto.MsgType != "response" {
		return errors.New("invailed auth protocol MsgType")
	}
	if authResProto.SessionType != authReqProto.SessionType {
		return errors.New("invailed auth protocol SessionType")
	}

	return nil
}

func CheckStatisticsHeader(header *StatisticsHeader) error {
	if header.Version != StatisticsVersion {
		return errors.New("invalied header version in provisioning")
	}
	if header.Method != StatisticsMethod {
		return errors.New("invalied header method in provisioning")
	}

	return nil
}

func main() {
	DaemonFlag := 0
	ControlServerFlag = -1
	WebServerFlag := ""
	bindPort := "8080"

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-c":
			ControlServerFlag = 1
			WebServerFlag = os.Args[i]
		case "-l":
			ControlServerFlag = 0
			WebServerFlag = os.Args[i]
		case "-p":
			i++
			bindPort = os.Args[i]
		case "-d":
			DaemonFlag = 1

		default:
			ShowHelpCommand()
			return
		}
	}

	if ControlServerFlag == -1 {
		ShowHelpCommand()
		return
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)

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
		RunControlWebServer(bindPort)
	} else {
		RunLocalWebServer(bindPort)
	}

	finish := make(chan bool)
	<-finish
}
