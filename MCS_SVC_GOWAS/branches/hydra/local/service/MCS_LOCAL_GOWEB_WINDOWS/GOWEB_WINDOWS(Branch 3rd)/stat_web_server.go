package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	"github.com/judwhite/go-svc/svc"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mitchellh/mapstructure"
	"github.com/shirou/gopsutil/host"
	"gopkg.in/natefinch/lumberjack.v2"
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
var DefaultListenerPort = 9559
var ServiceListenerPort int

var LoginTimeout = 60 * 30 /* sec */
var SqliteDB = "./db/traffic.db"
var LocalWebServerDB = "./db/localwebserver.db"
var LicenseSqliteDB = "./db/license.db"
var DBPath, DBName string
var SettingUpdateLock = &sync.Mutex{}

//var ProcessLogFileName = "stat_web_server.log"
var ProcessLogFileName = "./logs/stat_web_server.log"
var Login = "SELECT COUNT(*) FROM Users WHERE ID=? AND PASSWORD=?"

var Stat_Serv_Common_ID int64
var Stat_Serv_Data_ID int64
var Stat_Clint_Common_ID int64
var Stat_Clint_Data_ID int64
var UpdateLock = &sync.Mutex{}
var db_cfg_path = "./cfg/db.cfg"
var LicenseFileSN int

var StatCycletime time.Duration
var Statcycletimeint int
var updateExtime time.Time
var GoWebVersion string
var autoincrementlimitnum = 4000000000

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

type InitWebConfig struct {
	WEB WebCFGData
}

type WebCFGData struct {
	ListenerPort int
}

type gowasaddrlisttoml struct {
	GOWASADDR   GOWASADDR
	UPGOWASADDR UPGOWASADDR
}
type GOWASADDR struct {
	GOWASADDR string
}
type UPGOWASADDR struct {
	UPGOWASADDR string
}

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
	NodeID    nodeidSection
	DeviceID  deviceidSection
	UserKeyID userkeyidSection
}

type nodeidSection struct {
	NodeID string
}

type deviceidSection struct {
	DeviceID string
}

type userkeyidSection struct {
	UserKeyID string
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
	LicenseManagement template.HTML

	//--- Provioning -----------------{
	PV_Version              string
	PV_Method               string
	PV_SessionType          string
	PV_MessageType          string
	PV_ControlServerAddress string
	PV_UserKey              string
	PV_UserKeyID            string
	PV_NodeID               string
	PV_DeviceID             string
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

	Disk_Limit int
	Max_Size   int
	LogPath    string
	ErrorPath  string

	Statistic_Send_Control_Server string
	//StatSelectHTMLList           []HTMLType
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
	Params       SettingsInformation `"json:"params"`
	Pv_rsp_code  string              `"json:"pv_rsp_code"`
	Pv_rsp_seq   string              `"json:"pv_rsp_seq"`
	Pv_userkeyid string              `"json:"pv_userkeyid"`
	Pv_deviceid  string              `"json:"pv_deviceid"`
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

func WebListenerPortSetup() {

	var listener_port_cfg_path = "./cfg/web.cfg"
	var InitWebCFGInfo InitWebConfig

	ServiceListenerPort = DefaultListenerPort

	if _, err := toml.DecodeFile(listener_port_cfg_path, &InitWebCFGInfo); err != nil {
		ServiceListenerPort = DefaultListenerPort
		log.Print("Fail to Loading Configure File (web.cfg) -> (Fixed default port:", ServiceListenerPort, ")")
	} else {
		if InitWebCFGInfo.WEB.ListenerPort == 0 {
			ServiceListenerPort = DefaultListenerPort
			log.Print("Fail to Loading Configure File (web.cfg) -> (Fixed default port:", ServiceListenerPort, ")")
		} else {
			ServiceListenerPort = InitWebCFGInfo.WEB.ListenerPort
			log.Print("Web Config File (web.cfg) -> WEB Listener port:", ServiceListenerPort)
		}
	}
}

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
	var ConfGlobal, ConfLogFile, ConfStatistics, ConfNode, ConfNodeID, ConfFrontend, ConfBackend string
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

		_, err = stmt.Exec(Settings.Password)
		if err != nil {
			stmt.Close()
			log.Println("Exec Fail!:", err)
			return DB_RET_FAIL, err
		}

		stmt.Close()
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
	ConfLogFile = strings.Replace(ConfLogFile, "<LOGFILE_LOCATION>", Settings.Logfile_Path, -1)
	ConfLogFile = strings.Replace(ConfLogFile, "<ERRORLOGFILE_LOCATION>", Settings.Err_Logfile_Path, -1)

	Whole_Config_File += ConfLogFile

	ConfStatistics = strings.Replace(ConfStatistics, "<STATISTICS_INTERVAL>", Settings.Statistic_Collection_Cycle, -1)

	Whole_Config_File += ConfStatistics

	ConfNode = strings.Replace(ConfNode, "<Node_BUFF_SIZE>", Settings.Bridge_Buf_Size, -1)

	var encrypt string
	if Settings.Encrypt_Mode == "None" {
		encrypt = "none"
	} else if Settings.Encrypt_Mode == "AES_128" {
		encrypt = "aes128"
	} else if Settings.Encrypt_Mode == "AES_256" {
		encrypt = "aes256"
	} else {
		encrypt = "none"
	}

	ConfNode = strings.Replace(ConfNode, "<Node_ENCRYPT>", encrypt, -1)

	if Settings.Change_Client_IP == "Disable" {
		Settings.Change_Client_IP = "disable"
	} else {
		Settings.Change_Client_IP = "enable"
	}

	//ConfNode = strings.Replace(ConfNode, "<CHANGE_IP_FUNC>", Settings.Change_Client_IP, -1)
	ConfNode = strings.Replace(ConfNode, "<CHANGE_IP_FUNC>", "disable", -1)

	Whole_Config_File += ConfNode

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

func UpdateNodeFiles(Settings SettingsInformation, userkeyid string, deviceid string) (int32, error) {
	var fd *os.File
	var EncText string
	var err error
	var CRLF string
	var ConfNodeID string

	userkeyid = AESDecryptDecodeValue(userkeyid)
	deviceid = AESDecryptDecodeValue(deviceid)

	log.Println("userkeyid", userkeyid)
	log.Println("deviceid", deviceid)

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
	ConfNodeID += "[UserKeyID]" + CRLF
	ConfNodeID += "UserKeyID = \"<UserKeyID>\"" + CRLF
	ConfNodeID += "[DeviceID]" + CRLF
	ConfNodeID += "DeviceID = \"<DeviceID>\"" + CRLF
	ConfNodeID += CRLF

	ConfNodeID = strings.Replace(ConfNodeID, "<NODE_ID>", Settings.Node_ID, -1)
	ConfNodeID = strings.Replace(ConfNodeID, "<UserKeyID>", userkeyid, -1)
	ConfNodeID = strings.Replace(ConfNodeID, "<DeviceID>", deviceid, -1)

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

	_, err = UpdateNodeFiles(Settings.Params, Settings.Pv_userkeyid, Settings.Pv_deviceid)
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
	var MacArrary []string
	var MacTotalString string
	log.Println("Setting", req.URL)

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
		return
	}

	if ControlServerFlag == 0 {

		//----------------- get gowas addr-----------------------
		gowasaddr, updategowasaddr, err := GetGoWasAddr()
		if err != nil {
			log.Println("[LOG] :", gowasaddr)
			log.Println("[LOG] :", updategowasaddr)
			log.Println("[ERR] :", err)
		}
		log.Println("[LOG] :", gowasaddr)
		log.Println("[LOG] :", updategowasaddr)

		arrgowasarr := strings.Split(gowasaddr, ":")
		if len(arrgowasarr) == 2 {
			SetPageInfo.Control_Server_IP = arrgowasarr[0]
			SetPageInfo.Control_Server_Port, _ = strconv.Atoi(arrgowasarr[1])
		}
		//----------------- get gowas addr-----------------------

		cfgdata, err := ioutil.ReadFile("./cfg/app.cfg")
		if err != nil {
			log.Println(err)
		}

		cfgdataStr = AESDecryptDecodeValuePrefix(string(cfgdata))

		if _, err = toml.Decode(cfgdataStr, &cfginfo); err != nil {
			log.Println(err)
		}

		SetPageInfo.Max_Conn, _ = strconv.Atoi(cfginfo.Global.Max_conn)
		SetPageInfo.Recv_Buffer_Size, _ = strconv.Atoi(cfginfo.Global.Recv_buffer_size)
		SetPageInfo.Send_Buffer_Size, _ = strconv.Atoi(cfginfo.Global.Send_buffer_size)
		SetPageInfo.Timeout_Connect, _ = strconv.Atoi(cfginfo.Global.Timeout_connect)
		SetPageInfo.Timeout_Client, _ = strconv.Atoi(cfginfo.Global.Timeout_client)
		SetPageInfo.Timeout_Server, _ = strconv.Atoi(cfginfo.Global.Timeout_server)

		SetPageInfo.Disk_Limit, _ = strconv.Atoi(cfginfo.Logfile.Disk_limit)
		cfginfo.Logfile.Max_size = strings.TrimRight(cfginfo.Logfile.Max_size, "MB")
		SetPageInfo.Max_Size, _ = strconv.Atoi(cfginfo.Logfile.Max_size)
		SetPageInfo.LogPath = cfginfo.Logfile.Log
		SetPageInfo.ErrorPath = cfginfo.Logfile.Error

		SetPageInfo.Interval, _ = strconv.Atoi(cfginfo.Statistics.Interval)

		SetPageInfo.Statistic_Send_Control_Server = "Enable"
		if Statcycletimeint == 0 {
			SetPageInfo.Control_Server_Send_Interval = 60
		} else {
			SetPageInfo.Control_Server_Send_Interval = Statcycletimeint
		}

		TempHTML.Value_HTML = template.HTML(TempStr)

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
			/*
				TempStr = "<option>RC4</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
			*/
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
			/*
				TempStr = "<option>RC4</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
			*/
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
			/*
				TempStr = "<option>RC4</option>"
				TempHTML.Value_HTML = template.HTML(TempStr)
				SetPageInfo.EncModeSelectHTMLList = append(SetPageInfo.EncModeSelectHTMLList, TempHTML)
			*/
		} /*else if UseEnc == ENC_RC4 {
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
		*/
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
			log.Println("[Log] ", AESDecryptDecodeValuePrefix(nodeiddataStr))
			nodeiddataStr = AESDecryptDecodeValuePrefix(nodeiddataStr)
			if _, err = toml.Decode(nodeiddataStr, &nodeidinfo); err != nil {
				log.Println(err)
			}
			SetPageInfo.Node_ID = nodeidinfo.NodeID.NodeID
			SetPageInfo.PV_UserKeyID = nodeidinfo.UserKeyID.UserKeyID
		}

		kmsserveraddr = strings.Split(gowasaddr, ":")
		if len(kmsserveraddr) == 2 {
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
				OptionStr += fmt.Sprintf("<option value=\"%d\">SML Client</option>", Node_MODE_CLIENT)
				if DeviceOSFlag == GENERAL_OS {
					OptionStr += fmt.Sprintf("<option value=\"%d\">SML Server</option>", Node_MODE_SERVER)
				}
			} else if Node_Mode == Node_MODE_CLIENT {
				OptionStr = fmt.Sprintf("<option value=\"%d\">선택해주세요</option>", Node_MODE_NONE)
				OptionStr += fmt.Sprintf("<option selected=\"selected\" value=\"%d\">SML Client</option>", Node_MODE_CLIENT)
				if DeviceOSFlag == GENERAL_OS {
					OptionStr += fmt.Sprintf("<option value=\"%d\">SML Server</option>", Node_MODE_SERVER)
				}
			} else {
				OptionStr = fmt.Sprintf("<option value=\"%d\">선택해주세요</option><option value=\"%d\">SML Client</option><option selected=\"selected\" value=\"%d\">SML Server</option>", Node_MODE_NONE, Node_MODE_CLIENT, Node_MODE_SERVER)
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
			TempStr = fmt.Sprintf("%s<div data-SiteType=\"1\">%s<h2>Frontend<div>%s</div></h2><table class=\"input\"><colgroup><col width=\"250\"><col></colgroup><tbody><tr><th>Symbol</th><td><input type=\"text\" class=\"s100\" Frontendsymbol reserve=\"ko en number space length\" min=\"2\" max=\"32\" msg=\"글자 2 - 32 까지만 입력이 가능 합니다.\" group=\"all\" value=\"%s\"></td></tr><tr><th>Bind Port</th><td><input type=\"text\" class=\"s100\" FrontendPort reserve=\"between\" min=\"1\" max=\"65535\" msg=\"숫자 1 - 65535 까지만 입력이 가능 합니다.\" group=\"all\" value=\"%d\"/></td></tr><tr><th>SML Mode</th><td><select Node_Mode>%s</select><button type=\"button\" act=\"btnFrontendConfirm\" >Confirm</button></td></tr></tbody></table>", IDTagStart, HRTag, Button, Symbol_Name, Bind, OptionStr)
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
		SetPageInfo.PV_UserKeyID = "0"
		if nodeidinfo.UserKeyID.UserKeyID != "" {
			SetPageInfo.PV_UserKeyID = nodeidinfo.UserKeyID.UserKeyID
		}
		SetPageInfo.PV_DeviceID = "0"
		if nodeidinfo.DeviceID.DeviceID != "" {
			SetPageInfo.PV_DeviceID = nodeidinfo.DeviceID.DeviceID
		}

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

//------------------------------------------------------------------------- [ WEB API:gkwon ] {--------//

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

type jsonInputWebAPIAuthTokenPack struct {
	Method      string `json:"method"`
	SessionType string `json:"sessiontype"`
	UserKey     string `json:"userkey"`
	AuthKey     string `json:"authkey"`
	UserKeyID   string `json:"userkeyid"`
	DeviceID    string `json:"deviceid"`
}

type jsonOutputWebAPIAuthTokenPack struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	InputValue  string `json:"input"`
	OutputValue string `json:"output"`
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
		ConditionArray = append(ConditionArray, ID, EncryptGoWebPassword(Pass))

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
				log.Println("no user or wrong password", ID, Pass, EncryptGoWebPassword(Pass))
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
		WebServer_Redirect(w, req, "/setting")
	} else {
		WebServer_Redirect(w, req, "/statistics/client/?page_num=1&sort=0")
	}
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

func SqliteDBInsertUserIDPwd(Database *sql.DB, ID string, Password string) {
	var DB_Flag int64

	InsertDataStr := fmt.Sprintf("INSERT INTO Users (ID, Password) VALUES ('%s','%s')", ID, EncryptGoWebPassword(Password))

	log.Println("Insert Configure", InsertDataStr)

	DB_Flag, _ = sqlitedb_lib.Insert_Data(Database, InsertDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("sqlitedb Insert Fail!")
	}
}

func EncryptGoWebPassword(password string) string {
	salt := "goweb_login_password"

	hashing_algorithm := md5.New()
	HashingText := salt + ":" + password
	hashing_algorithm.Write([]byte(HashingText))
	hashingpassword := hex.EncodeToString(hashing_algorithm.Sum(nil))
	return hashingpassword
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
	var RowCount int32
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
	DB_Flag, _ = sqlitedb_lib.Create_Table(Database, "CREATE TABLE IF NOT EXISTS StatIdxTbl (seq INTEGER PRIMARY KEY AUTOINCREMENT, ClntIdx TEXT, ServIdx TEXT)")
	if DB_RET_FAIL == DB_Flag {
		log.Println("Create Table Fail!")
	}
	RowCount, _ = sqlitedb_lib.RowCount(Database, "StatIdxTbl")
	if RowCount == 0 {
		SqliteDBInsertStatIdx(Database, "StatIdxTbl")
	}

	return Database
}

func SqliteDBInsertStatIdx(Database *sql.DB, Tablename string) {
	var DB_Flag int64

	InsertDataStr := fmt.Sprintf("INSERT INTO %s (ClntIdx, ServIdx) VALUES ('%s','%s')", Tablename, AESEncryptEncodingValue("0"), AESEncryptEncodingValue("0"))

	log.Println("Insert Configure", InsertDataStr)

	DB_Flag, _ = sqlitedb_lib.Insert_Data(Database, InsertDataStr)
	if DB_RET_FAIL == DB_Flag {
		log.Println("sqlitedb Insert Fail!")
	}
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
		"Stat_StatDataSendCycle TEXT NOT NULL DEFAULT '60'," +
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

func RunLocalWebServer() {
	log.Print("Run Local Web Server..\n")

	PrepareSqliteDB()

	WebListenerPortSetup()

	lwsDatabase := LocalWebServerSqliteDBInit(LocalWebServerDB)
	trafficDatabase := TrafficSqliteDBInit(SqliteDB)

	if _, err := os.Stat("./cfg/app.cfg"); os.IsNotExist(err) {
		Make_cfg_File()
	}

	GetProxyInfos()
	GetNodeModes()
	Node_Change_Client_IP_Mode, _ = GetChangeClientIPModes()
	ProvisioningUploadLocalPorcess(lwsDatabase)
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

	WebServerMux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Forbidden(w, req, lwsDatabase)
	})

	WebServerMux.HandleFunc("/provisioning_upload/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Provisioning_Upload(w, req, lwsDatabase)
	})

	WebServerMux.Handle("/pages/", http.StripPrefix("/pages/", http.FileServer(http.Dir("pages"))))

	bind := fmt.Sprintf(":%s", strconv.Itoa(ServiceListenerPort))
	go HttpListen(0, bind, "", "", WebServerMux)

	go ProvisioningDownloadLocalPorcess(lwsDatabase)

	go transclienttraffic(lwsDatabase, trafficDatabase)
	go transservertraffic(lwsDatabase, trafficDatabase)

}
func transclienttraffic(lwsDatabase *sql.DB, trafficDatabase *sql.DB) {
	StatCycletime = 60
	for {
		select {
		case <-time.After(time.Second * StatCycletime):
		}

		authData, err := GetAuthData()
		if err != nil {
			log.Println("[ERR] GetAuthData err :", err)
			continue
		}
		if authData.NodeID == "" || authData.DeviceID == "" || authData.DeviceID == "0" || authData.UserKeyID == "" {
			log.Println("[LOG] NodeID or DeviceID or UserKeyID is zero and empty")
			continue
		}

		QueryStr := "select ifnull(ClntIdx , '%s') from StatIdxTbl"
		QueryStr = fmt.Sprintf(QueryStr, AESEncryptEncodingValue("0"))
		log.Println("[LOG] QueryStr : ", QueryStr)
		Rows, err := sqlitedb_lib.Query_DB(trafficDatabase, QueryStr)
		if err != nil {
			log.Println("[ERR] Query err : ", err)
			continue
		}

		var encryptidxcnt, decryptidxcnt string
		var idxcnt string
		for Rows.Next() {
			err = Rows.Scan(&encryptidxcnt)
			if err != nil {
				log.Println("[ERR] Scan error", err)
				Rows.Close()
				break
			}
		}
		if Rows != nil {
			Rows.Close()
		}
		log.Println("[LOG] encryptidxcnt : ", encryptidxcnt)

		if encryptidxcnt != "" {
			decryptidxcnt = AESDecryptDecodeValue(encryptidxcnt)
			log.Println("[LOG] decryptidxcnt : ", decryptidxcnt)
			idxcnt = decryptidxcnt
			if err != nil {
				log.Println("[ERR] ParseInt error", err)
				continue
			}
		} else {
			log.Println("[ERR] encryptidxcnt empty")
			continue
		}

		var limitnum int
		var traffselcnt int64
		var trafficinfoarr []StatisticInformation
		var gowasaddr, updategowasaddr, url, authkey, authtoken string
		var readidx string
		for {
			traffselcnt, err = selectclienttrafficcount(trafficDatabase, idxcnt)
			if err != nil {
				log.Println("[ERR] selectclienttrafficcount func : ", err)
				break
			}
			if traffselcnt == 0 {
				log.Println("[LOG] Select Client statistic Count is Zero")
				break
			}

			limitnum = 100
			trafficinfoarr, readidx, err = selectclienttraffic(trafficDatabase, idxcnt, limitnum)
			if err != nil {
				log.Println("[ERR] selectclienttraffic func : ", err)
				trafficinfoarr = nil
				break
			}

			if len(trafficinfoarr) == 0 {
				log.Println("[LOG] Select Client statistic array length is Zero")
				trafficinfoarr = nil
				break
			}

			gowasaddr, updategowasaddr, err = GetGoWasAddr()
			if err != nil {
				log.Println("[ERR] :", err)
				trafficinfoarr = nil
				break
			}
			log.Println("[LOG] :", gowasaddr)
			log.Println("[LOG] :", updategowasaddr)

			url = fmt.Sprintf("http://%s/auth_api/statistics/v1.0/", gowasaddr)
			authkey, authtoken, err = StatisticsAuthRequest(lwsDatabase, url, authData)
			if err != nil {
				log.Println("[ERR] StatisticsAuthRequest func :", err)
				trafficinfoarr = nil
				break
			}
			log.Println("[LOG] authkey:", authkey)
			log.Println("[LOG] authtoken:", authtoken)

			if err = StatisticsUploadRequest(lwsDatabase, url, authData, authkey, authtoken, trafficinfoarr); err != nil {
				log.Println("[ERR] StatisticsUploadRequest func :", err)
				trafficinfoarr = nil
				break
			} else {
				log.Println("[LOG] readidx:", readidx)
				err = updateclienttrafficidx(trafficDatabase, AESEncryptEncodingValue(readidx))
				if err != nil {
					log.Println("[ERR] updateclienttrafficidx func :", err)
					trafficinfoarr = nil
					break
				}

				err = deleteclienttraffic(trafficDatabase, readidx)
				if err != nil {
					log.Println("[ERR] deleteclienttraffic func :", err)
					trafficinfoarr = nil
					break
				}

				idxcnt = readidx
				trafficinfoarr = nil

			}
		}
	}
}

func deleteclienttraffic(db *sql.DB, readidx string) error {
	var err error
	var tx *sql.Tx

	tx, err = sqlitedb_lib.DB_Begin(db)
	if err != nil {
		log.Println("[ERR] Begin err:", err)
		return err
	}
	defer sqlitedb_lib.DB_Rollback(tx)

	QueryStr := "delete from Client_Statistics_Common where ID <= ? "
	log.Println("[LOG] QueryStr : ", QueryStr)

	var stmt *sql.Stmt
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("[ERR] Prepare err:", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(readidx)
	if err != nil {
		log.Println("[ERR] Exec err:", err)
		return err
	}

	QueryStr = "delete from Client_Statistics_Data where ID <= ? "
	log.Println("[LOG] QueryStr : ", QueryStr)

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("[ERR] Prepare err:", err)
		return err
	}
	_, err = stmt.Exec(readidx)
	if err != nil {
		log.Println("[ERR] Exec err:", err)
		return err
	}

	sqlitedb_lib.DB_Commit(tx)

	return err
}

func updateclienttrafficidx(db *sql.DB, encryptidxcnt string) error {
	var err error

	var tx *sql.Tx
	tx, err = sqlitedb_lib.DB_Begin(db)
	if err != nil {
		log.Println("[ERR] Begin err:", err)
		return err
	}
	defer sqlitedb_lib.DB_Rollback(tx)

	QueryStr := "update  StatIdxTbl set ClntIdx = ?"
	log.Println("[LOG] QueryStr : ", QueryStr)

	var stmt *sql.Stmt
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("[ERR] Prepare err:", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(encryptidxcnt)
	if err != nil {
		log.Println("[ERR] Exec err:", err)
		return err
	}

	sqlitedb_lib.DB_Commit(tx)

	return nil
}

func selectclienttrafficcount(db *sql.DB, idxcnt string) (int64, error) {
	var traffselcnt int64
	var err error
	var tx *sql.Tx

	tx, err = sqlitedb_lib.DB_Begin(db)
	if err != nil {
		log.Println("[ERR] Begin err:", err)
		return 0, err
	}
	defer sqlitedb_lib.DB_Rollback(tx)

	QueryStr := "select Count(*)\n" +
		"from Client_Statistics_Common A, Client_Statistics_Data B where A.ID = B.ID AND A.ID > %s"
	QueryStr = fmt.Sprintf(QueryStr, idxcnt)
	log.Println("[LOG] QueryStr : ", QueryStr)
	Rows, err := tx.Query(QueryStr)
	if err != nil {
		log.Println("[ERR] Query err : ", err)
		return 0, err
	}
	for Rows.Next() {
		err = Rows.Scan(&traffselcnt)
		if err != nil {
			log.Println("[ERR] Scan error", err)
			Rows.Close()
			break
		}
	}
	if Rows != nil {
		Rows.Close()
	}

	var stmt *sql.Stmt
	var idxcntnum, initautoincrementnum int

	idxcntnum = 0
	initautoincrementnum = 0

	idxcntnum, err = strconv.Atoi(idxcnt)
	if err != nil {
		log.Println("[ERR] strconv.Atoi error", err)
		return 0, err
	}

	if traffselcnt == 0 {
		if idxcntnum >= autoincrementlimitnum {
			QueryStr = "UPDATE SQLITE_SEQUENCE SET SEQ = ? WHERE name = 'Client_Statistics_Common'"
			log.Println("[LOG] QueryStr : ", QueryStr)

			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("[ERR] Prepare err:", err)
				return 0, err
			}

			_, err = stmt.Exec(initautoincrementnum)
			if err != nil {
				log.Println("[ERR] Exec err:", err)
				return 0, err
			}

			QueryStr = "UPDATE SQLITE_SEQUENCE SET SEQ = ? WHERE name = 'Client_Statistics_Data'; "
			log.Println("[LOG] QueryStr : ", QueryStr)

			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("[ERR] Prepare err:", err)
				return 0, err
			}
			_, err = stmt.Exec(initautoincrementnum)
			if err != nil {
				log.Println("[ERR] Exec err:", err)
				return 0, err
			}

			QueryStr = "update  StatIdxTbl set ClntIdx = ?"
			log.Println("[LOG] QueryStr : ", QueryStr)

			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("[ERR] Prepare err:", err)
				return 0, err
			}

			_, err = stmt.Exec(AESEncryptEncodingValue("0"))
			if err != nil {
				log.Println("[ERR] Exec err:", err)
				return 0, err
			}
		}
	}

	sqlitedb_lib.DB_Commit(tx)

	return traffselcnt, nil

}

func selectclienttraffic(db *sql.DB, idxcnt string, limitnum int) ([]StatisticInformation, string, error) {
	var trafficinfo StatisticInformation
	var trafficinfoarr []StatisticInformation
	var readidx string
	QueryStr := "select A.ID, A.Time, A.Node_ID_TEXT , A.Client_IP_INT, A.Client_IP_TEXT, A.Node_IP_INT,\n" +
		"A.Node_IP_TEXT, A.Node_Listen_Port, B.Proxy_IP_INT, B.Proxy_IP_TEXT, B.Proxy_Listen_Port,\n" +
		"B.Inbound, B.Outbound\n" +
		"from Client_Statistics_Common A, Client_Statistics_Data B where A.ID = B.ID AND A.ID > %s LIMIT %d "
	QueryStr = fmt.Sprintf(QueryStr, idxcnt, limitnum)
	log.Println("[LOG] QueryStr : ", QueryStr)

	Rows, err := sqlitedb_lib.Query_DB(db, QueryStr)
	if err != nil {
		log.Println("[ERR] Query err :", err)
		return nil, "", err
	}
	defer Rows.Close()
	for Rows.Next() {
		err = Rows.Scan(&trafficinfo.ID, &trafficinfo.Time, &trafficinfo.Node_ID_Text, &trafficinfo.Client_IP_Int, &trafficinfo.Client_IP_Text, &trafficinfo.Node_IP_Int,
			&trafficinfo.Node_IP_Text, &trafficinfo.Node_Listen_Port, &trafficinfo.Proxy_IP_Int, &trafficinfo.Proxy_IP_Text, &trafficinfo.Proxy_Listen_Port,
			&trafficinfo.Inbound, &trafficinfo.Outbound)
		if err != nil {
			log.Println("[ERR] Scan error", err)
			break
		}

		trafficinfo.Type = "002"
		log.Println("clienttraffic:", trafficinfo)
		trafficinfoarr = append(trafficinfoarr, trafficinfo)
		readidx = trafficinfo.ID
	}

	return trafficinfoarr, readidx, nil
}

func transservertraffic(lwsDatabase *sql.DB, trafficDatabase *sql.DB) {
	StatCycletime = 60
	for {
		select {
		case <-time.After(time.Second * StatCycletime):
		}

		authData, err := GetAuthData()
		if err != nil {
			log.Println("[ERR] GetAuthData err :", err)
			continue
		}
		if authData.NodeID == "" || authData.DeviceID == "" || authData.DeviceID == "0" || authData.UserKeyID == "" {
			continue
		}

		QueryStr := "select ifnull(ServIdx , '%s') from StatIdxTbl"
		QueryStr = fmt.Sprintf(QueryStr, AESEncryptEncodingValue("0"))
		log.Println("[LOG] QueryStr : ", QueryStr)
		Rows, err := sqlitedb_lib.Query_DB(trafficDatabase, QueryStr)
		if err != nil {
			log.Println("[ERR] Query err : ", err)
			continue
		}
		var encryptidxcnt, decryptidxcnt string
		var idxcnt string
		for Rows.Next() {
			err = Rows.Scan(&encryptidxcnt)
			if err != nil {
				log.Println("[ERR] Scan error", err)
				Rows.Close()
				break
			}
		}
		if Rows != nil {
			Rows.Close()
		}

		log.Println("[LOG] encryptidxcnt:", encryptidxcnt)
		if encryptidxcnt != "" {
			decryptidxcnt = AESDecryptDecodeValue(encryptidxcnt)
			log.Println("[LOG] decryptidxcnt:", decryptidxcnt)
			idxcnt = decryptidxcnt
		} else {
			log.Println("[ERR] encryptidxcnt empty")
			continue
		}

		var limitnum int
		var traffselcnt int64
		var trafficinfoarr []StatisticInformation
		var gowasaddr, updategowasaddr, url, authkey, authtoken string
		var readidx string
		for {
			traffselcnt, err = selectservertrafficcount(trafficDatabase, idxcnt)
			if err != nil {
				log.Println("[ERR] selectservertrafficcount func : ", err)
				break
			}
			if traffselcnt == 0 {
				log.Println("[LOG] Select Server statistic Count is Zero")
				break
			}
			log.Println("[LOG] traffselcnt:", traffselcnt)
			limitnum = 100
			trafficinfoarr, readidx, err = selectservertraffic(trafficDatabase, idxcnt, limitnum)
			if err != nil {
				log.Println("[ERR] selectservertraffic func : ", err)
				trafficinfoarr = nil
				break
			}

			if len(trafficinfoarr) == 0 {
				log.Println("[LOG] Select Server statistic array length is Zero")
				trafficinfoarr = nil
				break
			}

			gowasaddr, updategowasaddr, err = GetGoWasAddr()
			if err != nil {
				log.Println("[ERR] :", err)
				trafficinfoarr = nil
				break
			}
			log.Println("[LOG] :", gowasaddr)
			log.Println("[LOG] :", updategowasaddr)

			url = fmt.Sprintf("http://%s/auth_api/statistics/v1.0/", gowasaddr)
			authkey, authtoken, err = StatisticsAuthRequest(lwsDatabase, url, authData)
			if err != nil {
				log.Println("[ERR] StatisticsAuthRequest func :", err)
				trafficinfoarr = nil
				break
			}
			log.Println("[LOG] authkey:", authkey)
			log.Println("[LOG] authtoken:", authtoken)

			if err = StatisticsUploadRequest(lwsDatabase, url, authData, authkey, authtoken, trafficinfoarr); err != nil {
				log.Println("[ERR] StatisticsUploadRequest func :", err)
				trafficinfoarr = nil
				break
			} else {
				log.Println("[LOG] readldx:", readidx)
				err = updateservertrafficidx(trafficDatabase, AESEncryptEncodingValue(readidx))
				if err != nil {
					log.Println("[ERR] updateservertrafficidx func :", err)
					trafficinfoarr = nil
					break
				}

				err = deleteservertraffic(trafficDatabase, readidx)
				if err != nil {
					log.Println("[ERR] deleteservertraffic func :", err)
					trafficinfoarr = nil
					break
				}

				idxcnt = readidx
				trafficinfoarr = nil
			}
		}
	}
}

func deleteservertraffic(db *sql.DB, readidx string) error {
	var err error
	var tx *sql.Tx

	tx, err = sqlitedb_lib.DB_Begin(db)
	if err != nil {
		log.Println("[ERR] Begin err:", err)
		return err
	}
	defer sqlitedb_lib.DB_Rollback(tx)

	QueryStr := "delete from Server_Statistics_Common where ID <= ? "
	log.Println("[LOG] QueryStr : ", QueryStr)

	var stmt *sql.Stmt
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("[ERR] Prepare err:", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(readidx)
	if err != nil {
		log.Println("[ERR] Exec err:", err)
		return err
	}

	QueryStr = "delete from Server_Statistics_Data where ID <= ? "
	log.Println("[LOG] QueryStr : ", QueryStr)

	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("[ERR] Prepare err:", err)
		return err
	}
	_, err = stmt.Exec(readidx)
	if err != nil {
		log.Println("[ERR] Exec err:", err)
		return err
	}

	sqlitedb_lib.DB_Commit(tx)

	return nil
}

func updateservertrafficidx(db *sql.DB, encryptidxcnt string) error {
	var err error

	var tx *sql.Tx
	tx, err = sqlitedb_lib.DB_Begin(db)
	if err != nil {
		log.Println("[ERR] Begin err:", err)
		return err
	}
	defer sqlitedb_lib.DB_Rollback(tx)

	QueryStr := "update  StatIdxTbl set ServIdx = ?"
	log.Println("[LOG] QueryStr : ", QueryStr)

	var stmt *sql.Stmt
	stmt, err = tx.Prepare(QueryStr)
	if err != nil {
		log.Println("[ERR] Prepare err:", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(encryptidxcnt)
	if err != nil {
		log.Println("[ERR] Exec err:", err)
		return err
	}

	sqlitedb_lib.DB_Commit(tx)

	return nil
}

func selectservertrafficcount(db *sql.DB, idxcnt string) (int64, error) {
	var traffselcnt int64
	var err error
	var tx *sql.Tx

	tx, err = sqlitedb_lib.DB_Begin(db)
	if err != nil {
		log.Println("[ERR] Begin err:", err)
		return 0, err
	}
	defer sqlitedb_lib.DB_Rollback(tx)

	QueryStr := "select Count(*)\n" +
		"from Server_Statistics_Common A, Server_Statistics_Data B where A.ID = B.ID AND A.ID > %s"
	QueryStr = fmt.Sprintf(QueryStr, idxcnt)
	log.Println("[LOG] QueryStr : ", QueryStr)
	Rows, err := tx.Query(QueryStr)
	if err != nil {
		log.Println("[ERR] Query err : ", err)
		return 0, err
	}
	for Rows.Next() {
		err = Rows.Scan(&traffselcnt)
		if err != nil {
			log.Println("[ERR] Scan error", err)
			Rows.Close()
			break
		}
	}
	if Rows != nil {
		Rows.Close()
	}

	var stmt *sql.Stmt
	var idxcntnum, initautoincrementnum int

	idxcntnum = 0
	initautoincrementnum = 0

	idxcntnum, err = strconv.Atoi(idxcnt)
	if err != nil {
		log.Println("[ERR] strconv.Atoi error", err)
		return 0, err
	}

	if traffselcnt == 0 {
		if idxcntnum >= autoincrementlimitnum {

			QueryStr = "UPDATE SQLITE_SEQUENCE SET SEQ = ? WHERE name = 'Server_Statistics_Common'"
			log.Println("[LOG] QueryStr : ", QueryStr)

			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("[ERR] Prepare err:", err)
				return 0, err
			}

			_, err = stmt.Exec(initautoincrementnum)
			if err != nil {
				log.Println("[ERR] Exec err:", err)
				return 0, err
			}

			QueryStr = "UPDATE SQLITE_SEQUENCE SET SEQ = ? WHERE name = 'Server_Statistics_Data'; "
			log.Println("[LOG] QueryStr : ", QueryStr)

			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("[ERR] Prepare err:", err)
				return 0, err
			}
			_, err = stmt.Exec(initautoincrementnum)
			if err != nil {
				log.Println("[ERR] Exec err:", err)
				return 0, err
			}

			QueryStr = "update  StatIdxTbl set ServIdx = ?"
			log.Println("[LOG] QueryStr : ", QueryStr)

			stmt, err = tx.Prepare(QueryStr)
			if err != nil {
				log.Println("[ERR] Prepare err:", err)
				return 0, err
			}

			_, err = stmt.Exec(AESEncryptEncodingValue("0"))
			if err != nil {
				log.Println("[ERR] Exec err:", err)
				return 0, err
			}
		}
	}

	sqlitedb_lib.DB_Commit(tx)

	return traffselcnt, nil

}

func selectservertraffic(db *sql.DB, idxcnt string, limitnum int) ([]StatisticInformation, string, error) {
	var trafficinfo StatisticInformation
	var trafficinfoarr []StatisticInformation
	var readidx string
	QueryStr := "select A.ID, A.Time, A.Bridge_ID_TEXT , A.Proxy_IP_INT, A.Proxy_IP_TEXT, A.Node_IP_INT,\n" +
		"A.Node_IP_TEXT, A.Node_Listen_Port, A.Server_IP_INT, A.Server_IP_TEXT, A.Server_Listen_Port,\n" +
		"B.Client_IP_INT, B.Client_IP_TEXT, B.Inbound, B.Outbound\n" +
		"from Server_Statistics_Common A, Server_Statistics_Data B where A.ID = B.ID AND A.ID > %s LIMIT %d "
	QueryStr = fmt.Sprintf(QueryStr, idxcnt, limitnum)
	log.Println("[LOG] QueryStr : ", QueryStr)

	Rows, err := sqlitedb_lib.Query_DB(db, QueryStr)
	if err != nil {
		log.Println("[ERR] Query err :", err)
		return nil, "", err
	}
	defer Rows.Close()
	for Rows.Next() {
		err = Rows.Scan(&trafficinfo.ID, &trafficinfo.Time, &trafficinfo.Bridge_ID_Text, &trafficinfo.Proxy_IP_Int, &trafficinfo.Proxy_IP_Text, &trafficinfo.Node_IP_Int,
			&trafficinfo.Node_IP_Text, &trafficinfo.Node_Listen_Port, &trafficinfo.Server_IP_Int, &trafficinfo.Server_IP_Text, &trafficinfo.Server_Listen_Port,
			&trafficinfo.Client_IP_Int, &trafficinfo.Client_IP_Text, &trafficinfo.Inbound, &trafficinfo.Outbound)
		if err != nil {
			log.Println("[ERR] Scan error", err)

			break
		}

		trafficinfo.Type = "001"
		log.Println("servertraffic:", trafficinfo)
		trafficinfoarr = append(trafficinfoarr, trafficinfo)
		readidx = trafficinfo.ID
	}

	return trafficinfoarr, readidx, nil
}

func Make_cfg_File() {
	var CRLF string
	var ConfGlobal, ConfLogFile, ConfStatistics, ConfNode, ConfNodeID, ConfFrontend, ConfBackend string
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

	ConfStatistics = strings.Replace(ConfStatistics, "<STATISTICS_INTERVAL>", strconv.Itoa(30), -1)

	Whole_Config_File += ConfStatistics

	ConfNode = strings.Replace(ConfNode, "<Bridge_MODE>", strconv.Itoa(2), -1)
	ConfNode = strings.Replace(ConfNode, "<Node_BUFF_SIZE>", strconv.Itoa(8388608), -1)
	ConfNode = strings.Replace(ConfNode, "<Node_ENCRYPT>", "aes256", -1)
	ConfNode = strings.Replace(ConfNode, "<CHANGE_IP_FUNC>", "disable", -1)

	Whole_Config_File += ConfNode

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
	_, err = sqlitedb_lib.DB_Exec(tx, "DELETE FROM Client_Statistics_Common WHERE "+strconv.FormatInt(Standard_ID, 10)+">=ID")
	if err != nil {
		log.Println("Delete Client_Statistics_Common Fail! ", err)
		return err
	}

	_, err = sqlitedb_lib.DB_Exec(tx, "DELETE FROM Client_Statistics_Data WHERE "+strconv.FormatInt(Standard_ID, 10)+">=ID")
	if err != nil {
		log.Println("Delete Client_Statistics_Common Fail!")
		return err
	}

	sqlitedb_lib.DB_Commit(tx)

	return nil
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

	_, err = sqlitedb_lib.DB_Exec(tx, "DELETE FROM Server_Statistics_Common WHERE "+strconv.FormatInt(Standard_ID, 10)+">=ID")
	if err != nil {
		log.Println("Delete Client_Statistics_Common Fail!")
		return err
	}

	_, err = sqlitedb_lib.DB_Exec(tx, "DELETE FROM Server_Statistics_Data WHERE "+strconv.FormatInt(Standard_ID, 10)+">=ID")
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
	Version        string `json:"version"`
	Method         string `json:"method"`
	Seperator      string `json:"seperator"`
	Msgtype        string `json:"msgtype"`
	Userkey        string `json:"userkey"`
	UserKeyID      string `json:"userkeyid"`
	Nodeid         string `json:"nodeid"`
	DeviceID       string `json:"deviceid"`
	OSVersion      string `json:"osversion"`
	CurPkgVersion  string `json:"curpkgversion"`
	NewPkgVersion  string `json:"newpkgversion"`
	UpdateFileName string `json:"updatefilename"`
	CurSeq         int64  `mapstructure:"cur_seq" json:"cur_seq"`
	Seq            int64  `json:"seq"`
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
	Version    string `json:"version"`
	Method     string `json:"method"`
	Seperator  string `json:"seperator"`
	Msgtype    string `json:"msgtype"`
	Userkey    string `json:"userkey"`
	UserKeyID  string `json:"userkeyid"`
	Nodeid     string `json:"nodeid"`
	DeviceID   string `json:"deviceid"`
	PkgVersion string `json:"pkgversion"`
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
	log.Println("[LOG] cfgdata1:", AESDecryptDecodeValuePrefix(string(cfgdata)))
	decryption := AESDecryptDecodeValuePrefix(string(cfgdata))

	var cfginfo Settingtoml
	if _, err = toml.Decode(decryption, &cfginfo); err != nil {
		return nil, err
	}

	return &cfginfo, nil
}

func GetUsersTlbData(db *sql.DB) (data *UsersTlbData, err error) {
	query := "SELECT Seq, ID, Password, Stat_StatDataSendCycle, Stat_Send_Flag FROM Users LIMIT 1;"
	rows, err := sqlitedb_lib.Query_DB(db, query)
	if err != nil {
		log.Println(err)
	}
	defer rows.Close()

	data = new(UsersTlbData)
	for rows.Next() {
		err = rows.Scan(&data.Seq, &data.ID, &data.Password, &data.Stat_StatDataSendCycle, &data.Stat_Send_Flag)
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

type UserKeyIDFile struct {
	UserKeyID string
}
type NodeIDFile struct {
	NodeID string
}
type DeviceIDFile struct {
	DeviceID string
}

type AuthTokenFile struct {
	AuthToken string
}

type UserKeyFileData struct {
	UserKey UserKeyFile
}

type NodeIDFileData struct {
	NodeID    NodeIDFile
	UserKeyID UserKeyIDFile
	DeviceID  DeviceIDFile
}

type AuthTokenFileData struct {
	AuthToken AuthTokenFile
}

type AuthData struct {
	UserKey   string
	UserKeyID string
	NodeID    string
	DeviceID  string
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

	log.Println("userkey", string(userkey))
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
	data.UserKeyID = nodeidfiledata.UserKeyID.UserKeyID
	data.NodeID = nodeidfiledata.NodeID.NodeID
	data.DeviceID = nodeidfiledata.DeviceID.DeviceID
	data.AuthToken = authtokenfiledata.AuthToken.AuthToken

	log.Println("[LOG] USERKEYID :", data.UserKeyID)
	log.Println("[LOG] DEVICEID :", data.DeviceID)

	err = nil
	return
}

/*
 *	Provisioning Local DOWNLOAD -----------------------------------------------------------------
 */

func WebServer_Auth_API_Hashing_Provisioning(UserKeyID string, DeviceID string, Method string, GenerateAuthKey string) string {

	var HashingText string
	var HA1, HA2 string
	var authtoken string
	var EventValue string

	userkeyid := UserKeyID
	if userkeyid == "" {
		userkeyid = "0"
	}
	deviceid := DeviceID
	if deviceid == "" {
		deviceid = "0"
	}

	hashing_algorithm := md5.New()
	HashingText = userkeyid + ":" + deviceid
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
	authtoken = hex.EncodeToString(hashing_algorithm.Sum(nil))
	EventValue += "[" + HashingText + " >> authtoken:" + authtoken + "]"

	return authtoken
}

func ProvisioningDownloadLocalPorcess(db *sql.DB) {

	log.Println("[LOG] : here is in ProvisioningDownloadLocalPorcess")
	for {
		select {
		case <-time.After(time.Second * 30):
		}

		authData, err := GetAuthData()
		if err != nil {
			log.Println(err)
			continue
		}

		if authData.NodeID == "" {
			continue
		}

		if authData.DeviceID == "" || authData.DeviceID == "0" {
			continue
		}

		syncSeqNo, err := GetLocalSyncSeqNo(db, "ConfigData")
		if err != nil {
			log.Println(err)
			continue
		}
		gowasaddr, updategowasaddr, err := GetGoWasAddr()
		if err != nil {
			log.Println("[LOG] :", gowasaddr)
			log.Println("[LOG] :", updategowasaddr)
			log.Println("[ERR] :", err)
			continue
		}
		log.Println("[LOG] :", gowasaddr)
		log.Println("[LOG] :", updategowasaddr)

		url := fmt.Sprintf("http://%s/auth_api/provisioning/v1.0/", gowasaddr)
		authkey, authtoken, err := ProvisioningAuthRequest(db, url, authData)
		if err != nil {
			log.Println(err)
			continue
		}

		if err := ProvisioningDownloadRequest(db, url, authData, authkey, authtoken, syncSeqNo); err != nil {
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
	authReqProto.UserKeyID = AESEncryptEncodingValue(authData.UserKeyID)
	authReqProto.NodeID = AESEncryptEncodingValue(authData.NodeID)
	authReqProto.DeviceID = AESEncryptEncodingValue(authData.DeviceID)
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
	log.Println("json", string(jsonBytes))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	var retrynum int
	var resp *http.Response
	for {
		resp, err = client.Do(req)
		if err != nil {
			retrynum++
			log.Println("[ERR] : ", err)
			if retrynum == 3 {
				return "", "", err
			}
		} else {
			if resp.StatusCode != 200 {
				retrynum++
				log.Println("[LOG] resp.StatusCode : ", resp.StatusCode)
				if retrynum == 3 {
					return "", "", errors.New(fmt.Sprintf("Response Auth Provisioning Http error: %d", resp.Status))
				}
			} else {
				log.Println("[LOG] : Success client do")
				break
			}
		}
		time.Sleep(time.Second * 5)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", errors.New(fmt.Sprintf("Response Auth Provisioning Http error: %d", resp.Status))
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

	if authResProto.Code != "200" {
		log.Println("[ERR] Code : ", authResProto.Code)
		log.Println("[ERR] Message : ", authResProto.Message)
		return "", "", errors.New("failed auth request")
	}

	authtoken := WebServer_Auth_API_Hashing_Provisioning(authData.UserKeyID, authData.DeviceID, authResProto.Method, authResProto.AuthKey)

	return authResProto.AuthKey, authtoken, nil
}

func ProvisioningDownloadRequest(db *sql.DB, url string, authData *AuthData, authkey string, authtoken string, syncSeqNo int64) error {
	proviReq := ProvisionProtocol{}
	proviReq.Header.Version = ProvisionVersion
	proviReq.Header.Msgtype = "request"
	proviReq.Header.Method = ProvisionMethod
	proviReq.Header.Seperator = "down"
	proviReq.Header.Userkey = AESEncryptEncodingValue(authData.UserKey)
	proviReq.Header.UserKeyID = AESEncryptEncodingValue(authData.UserKeyID)
	proviReq.Header.Nodeid = AESEncryptEncodingValue(authData.NodeID)
	proviReq.Header.DeviceID = AESEncryptEncodingValue(authData.DeviceID)
	proviReq.Header.OSVersion = GetOSVersion()
	proviReq.Header.CurPkgVersion = GetCurPkgVersion()
	proviReq.Header.CurSeq = syncSeqNo

	authReqProto := jsonInputWebAPIAuthProvisioningPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "ConfigData"
	authReqProto.MessageType = "request"
	authReqProto.UserKey = proviReq.Header.Userkey
	authReqProto.UserKeyID = proviReq.Header.UserKeyID
	authReqProto.NodeID = proviReq.Header.Nodeid
	authReqProto.DeviceID = proviReq.Header.DeviceID
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

	log.Println(">>>ProvisioningDownloadRequest(): Request json=%s\n", string(jsonBytes))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	var retrynum int
	var resp *http.Response
	for {
		resp, err = client.Do(req)
		if err != nil {
			retrynum++
			log.Println("[ERR] : ", err)
			if retrynum == 3 {
				return err
			}
		} else {
			if resp.StatusCode != 200 {
				retrynum++
				log.Println("[LOG] resp.StatusCode : ", resp.StatusCode)
				if retrynum == 3 {
					return errors.New(fmt.Sprintf("Response Auth Provisioning Down Http error: %d", resp.Status))
				}
			} else {
				log.Println("[LOG] : Success client do")
				break
			}
		}
		time.Sleep(time.Second * 5)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Response Provisioning Down Http error: %d", resp.Status))
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	log.Println(">>>ProvisioningDownloadResponse(): Response json=%s\n", string(bodyBytes))

	authResProto := jsonOutputWebAPIAuthProvisioningPack{}
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

	if authResProto.Code != "200" {
		log.Println("[ERR] Code : ", authResProto.Code)
		log.Println("[ERR] Message : ", authResProto.Message)
		return errors.New("failed auth request")
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
	Statcycletimestr := AESDecryptDecodeValue(authResProto.StatCycleTime)
	Statcycletimeint, _ = strconv.Atoi(Statcycletimestr)
	StatCycletime = time.Duration(Statcycletimeint)

	if proviRes.Header.NewPkgVersion != "" {
		WebServer_Service_Update(proviRes.Header.NewPkgVersion, proviRes.Header.UpdateFileName, db)
	}
	return nil
}
func GetGoWasAddr() (string, string, error) {
	var gowasaddrdata []byte
	var err error
	var decgowasaddr, gowasaddr, updategowasaddr string
	var tomlgowaslist gowasaddrlisttoml
	gowasaddrdata, err = ioutil.ReadFile("./cfg/addr.dat")
	if err != nil {
		log.Println("[ERR] : ", err)
		return "", "", err
	}

	decgowasaddr = AESDecryptDecodeValuePrefix(string(gowasaddrdata))

	if _, err = toml.Decode(decgowasaddr, &tomlgowaslist); err != nil {
		log.Println("[ERR] : ", err)
		return "", "", err
	}

	gowasaddr = tomlgowaslist.GOWASADDR.GOWASADDR
	updategowasaddr = tomlgowaslist.UPGOWASADDR.UPGOWASADDR

	return gowasaddr, updategowasaddr, err
}

func WebServer_Service_Update(newpkgversion string, updatefilename string, database *sql.DB) {
	var updateexe, svctype, osversion string
	var err error

	if updateExtime.IsZero() == true {
		updateExtime = time.Now().Add(time.Minute * 3)
	} else {
		if time.Now().After(updateExtime) == true {
			updateExtime = time.Now().Add(time.Minute * 3)
			log.Println("failed updating")
			log.Println("start updating")
		} else {
			log.Println("is updating")
			return
		}
	}

	gowasaddr, updategowasaddr, err := GetGoWasAddr()
	if err != nil {
		log.Println("[LOG] :", gowasaddr)
		log.Println("[LOG] :", updategowasaddr)
		log.Println("[ERR] :", err)
	}
	log.Println("[LOG] :", gowasaddr)
	log.Println("[LOG] :", updategowasaddr)

	svctype = "service"
	//--------------os version select------------------------
	if runtime.GOOS == "linux" {
		osversion = "linux"
		updateexe = "./updater"
		v, _ := host.Info()
		osversion += "_" + v.Platform
	} else if runtime.GOOS == "windows" {
		updateexe = "./updater.exe"
		osversion = "windows"
	}
	//--------------os version select------------------------

	cmd := exec.Command(updateexe, svctype, updategowasaddr, osversion, newpkgversion, updatefilename)
	err = cmd.Start()
	if err != nil {
		log.Println(fmt.Sprint(err))
		return
	}

	return
}

type pkgversion struct {
	Package string `"json:"package"`
}

func GetOSVersion() string {
	var osversion string

	//--------------os version select------------------------

	if runtime.GOOS == "linux" {
		osversion = "linux"
		v, _ := host.Info()
		osversion += "_" + v.Platform
	} else if runtime.GOOS == "windows" {
		osversion = "windows"
	}
	//--------------os version select------------------------

	return osversion
}
func GetCurPkgVersion() string {
	var Packageinfo pkgversion
	var pkgversionjson string
	pkgdata, err := ioutil.ReadFile("./verinfo.json")

	if err != nil {
		log.Println(err)
		return ""
	}
	pkgversionjson = AESDecryptDecodeValuePrefix(string(pkgdata))
	err = json.Unmarshal([]byte(pkgversionjson), &Packageinfo)
	if err != nil {
		log.Println("error Settings json parser:", Packageinfo)
		return ""
	}
	log.Println("Packageinfo.Package", Packageinfo.Package)
	return Packageinfo.Package
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
	gowasaddr, updategowasaddr, err := GetGoWasAddr()
	if err != nil {
		log.Println("[LOG] :", gowasaddr)
		log.Println("[LOG] :", updategowasaddr)
		log.Println("[ERR] :", err)
	}
	log.Println("[LOG] :", gowasaddr)
	log.Println("[LOG] :", updategowasaddr)

	arrgowasarr := strings.Split(gowasaddr, ":")
	if len(arrgowasarr) == 2 {
		data.Statistic_Server_Ip = arrgowasarr[0]
		data.Statistic_Server_Port = arrgowasarr[1]
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

	if userstlbData.Stat_Send_Flag == ENABLE {
		data.Statistic_Send_Control_Server = "Enable"
	} else {
		data.Statistic_Send_Control_Server = "Disable"
	}
	data.Statistic_Collection_Cycle = settingData.Statistics.Interval
	data.Statistic_Send_Cycle = userstlbData.Stat_StatDataSendCycle

	data.Bridge_Buf_Size = settingData.Node.Buffer_size
	data.Encrypt_Mode = settingData.Node.Encrypt
	data.Change_Client_IP = settingData.Node.Cp_tunneling
	data.Node_ID = authData.NodeID

	data.KMS_Address = arrgowasarr[0]
	data.KMS_Port = arrgowasarr[1]

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
		log.Println("[LOG] settingdata:", data)
		i++
	}

	log.Println("Uploading config data:", data)

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

func WebServer_Auth_API_Hashing_Statistic(UserKeyID string, DeviceID string, Method string, GenerateAuthKey string) string {

	var HashingText string
	var HA1, HA2 string
	var authtoken string
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
	authtoken = hex.EncodeToString(hashing_algorithm.Sum(nil))
	EventValue += "[" + HashingText + " >> authtoken:" + authtoken + "]"

	return authtoken
}

func StatisticsAuthRequest(db *sql.DB, url string, authData *AuthData) (string, string, error) {
	authReqProto := jsonInputWebAPIAuthStatLocalPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "Statistics"
	authReqProto.MessageType = "request"
	authReqProto.UserKey = AESEncryptEncodingValue(authData.UserKey)
	authReqProto.UserKeyID = AESEncryptEncodingValue(authData.UserKeyID)
	authReqProto.NodeID = AESEncryptEncodingValue(authData.NodeID)
	authReqProto.DeviceID = AESEncryptEncodingValue(authData.DeviceID)
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
	var retrynum int
	var resp *http.Response
	for {
		resp, err = client.Do(req)
		if err != nil {
			retrynum++
			log.Println("[ERR] : ", err)
			if retrynum == 3 {
				return "", "", err
			}
		} else {
			if resp.StatusCode != 200 {
				retrynum++
				log.Println("[LOG] resp.StatusCode : ", resp.StatusCode)
				if retrynum == 3 {
					return "", "", errors.New(fmt.Sprintf("Response Auth Statistic Http error: %d", resp.Status))
				}
			} else {
				log.Println("[LOG] : Success client do")
				break
			}
		}
		time.Sleep(time.Second * 5)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", errors.New(fmt.Sprintf("Response Auth Statistic Http error: %d", resp.Status))
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

	if authResProto.Code != "200" {
		log.Println("[ERR] Code : ", authResProto.Code)
		log.Println("[ERR] Message : ", authResProto.Message)
		return "", "", errors.New("failed auth request")
	}

	authtoken := WebServer_Auth_API_Hashing_Statistic(authData.UserKeyID, authData.DeviceID, authResProto.Method, authResProto.AuthKey)
	log.Println("authResProto.AuthKey", authResProto.AuthKey)
	log.Println("authtoken", authtoken)
	return authResProto.AuthKey, authtoken, nil
}

func StatisticsUploadRequest(db *sql.DB, url string, authData *AuthData, authkey string, authtoken string, ServerStatistic []StatisticInformation) error {
	StatReq := StatisticsProtocol{}
	StatReq.Header.Version = StatisticsVersion
	StatReq.Header.Msgtype = "request"
	StatReq.Header.Method = StatisticsMethod
	StatReq.Header.Seperator = "up"
	StatReq.Header.Userkey = AESEncryptEncodingValue(authData.UserKey)
	StatReq.Header.UserKeyID = AESEncryptEncodingValue(authData.UserKeyID)
	StatReq.Header.Nodeid = AESEncryptEncodingValue(authData.NodeID)
	StatReq.Header.DeviceID = AESEncryptEncodingValue(authData.DeviceID)
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
	authReqProto.UserKeyID = StatReq.Header.UserKeyID
	authReqProto.NodeID = StatReq.Header.Nodeid
	authReqProto.DeviceID = StatReq.Header.DeviceID
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
	var retrynum int
	var resp *http.Response
	for {
		resp, err = client.Do(req)
		if err != nil {
			retrynum++
			log.Println("[ERR] : ", err)
			if retrynum == 3 {
				return err
			}
		} else {
			if resp.StatusCode != 200 {
				retrynum++
				log.Println("[LOG] resp.StatusCode : ", resp.StatusCode)
				if retrynum == 3 {
					return errors.New(fmt.Sprintf("Response Statistics Http error: %d", resp.Status))
				}
			} else {
				log.Println("[LOG] : Success client do")
				break
			}
		}
		time.Sleep(time.Second * 5)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Response Statistics Http error: %d", resp.Status))
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

	if authResProto.Code != "200" {
		log.Println("[ERR] Code : ", authResProto.Code)
		log.Println("[ERR] Message : ", authResProto.Message)
		return errors.New("failed auth request")
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
func InitLogger() {
	logStruct := &lumberjack.Logger{
		Filename:   ProcessLogFileName, // Filename is the file to write logs to
		MaxSize:    100,                // MaxSize is the maximum size in megabytes of the log file before it gets rotated
		MaxBackups: (10),               // MaxBackups is the maximum number of old log files to retain
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

func WebServer_Provisioning_Upload(w http.ResponseWriter, req *http.Request, db *sql.DB) {
	var OutputData jsonOutputWebAPIAuthProvisioningPack
	var cfginfo SettingsInformation
	var err error
	var OutputBody string

	res := Cookie_Check(w, req)
	if res < 0 {
		log.Println("Failed to Cookie_Check")
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

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&cfginfo)
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

	authData, err := GetAuthData()
	if err != nil {
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

	syncSeqNo, err := GetLocalSyncSeqNo(db, "ConfigData")
	if err != nil {
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

	gowasaddr, updategowasaddr, err := GetGoWasAddr()
	if err != nil {
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

	log.Println("[LOG} gowasaddr : ", gowasaddr)
	log.Println("[LOG} updategowasaddr : ", updategowasaddr)

	url := fmt.Sprintf("http://%s/auth_api/provisioning/v1.0/", gowasaddr)
	authkey, authtoken, err := PassiveProvisioninguploadAuthRequest(db, url, authData)
	if err != nil {
		log.Println(err)
		goto err_res
	}

	if err := PassiveProvisioningUploadRequest(db, url, authData, authkey, authtoken, cfginfo, syncSeqNo); err != nil {
		log.Println(err)
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
func PassiveProvisioninguploadAuthRequest(db *sql.DB, url string, authData *AuthData) (string, string, error) {
	authReqProto := jsonInputWebAPIAuthProvisioningPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "ConfigData"
	authReqProto.MessageType = "request"

	authReqProto.UserKey = AESEncryptEncodingValue(authData.UserKey)

	userkeyid := authData.UserKeyID
	if userkeyid == "" {
		userkeyid = "0"
	}
	authReqProto.UserKeyID = AESEncryptEncodingValue(userkeyid)
	authReqProto.NodeID = AESEncryptEncodingValue(authData.NodeID)
	log.Println("authReqProto.NodeID:", authReqProto.NodeID)
	log.Println("authReqProto.UserKeyID:", authReqProto.UserKeyID)
	deviceid := authData.DeviceID
	if deviceid == "" {
		deviceid = "0"
	}
	authReqProto.DeviceID = AESEncryptEncodingValue(deviceid)
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
	log.Println("json", string(jsonBytes))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	var retrynum int
	var resp *http.Response
	for {
		resp, err = client.Do(req)
		if err != nil {
			retrynum++
			log.Println("[ERR] : ", err)
			if retrynum == 3 {
				return "", "", err
			}
		} else {
			if resp.StatusCode != 200 {
				retrynum++
				log.Println("[LOG] resp.StatusCode : ", resp.StatusCode)
				if retrynum == 3 {
					return "", "", errors.New(fmt.Sprintf("Response Auth Provisioning UP Http error: %d", resp.Status))
				}
			} else {
				log.Println("[LOG] : Success client do")
				break
			}
		}
		time.Sleep(time.Second * 5)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", errors.New(fmt.Sprintf("Response Auth Provisioning UP Http error: %d", resp.Status))
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

	if authResProto.Code != "200" {
		log.Println("[ERR] Code : ", authResProto.Code)
		log.Println("[ERR] Message : ", authResProto.Message)
		return "", "", errors.New("failed auth request")
	}
	authtoken := WebServer_Auth_API_Hashing_Provisioning(authData.UserKeyID, authData.DeviceID, authResProto.Method, authResProto.AuthKey)
	return authResProto.AuthKey, authtoken, nil
}

func PassiveProvisioningUploadRequest(db *sql.DB, url string, authData *AuthData, authkey string, authtoken string, cfginfo SettingsInformation, syncSeqNo int64) error {
	proviReq := ProvisionProtocol{}
	proviReq.Header.Version = ProvisionVersion
	proviReq.Header.Msgtype = "request"
	proviReq.Header.Method = ProvisionMethod
	proviReq.Header.Seperator = "up"
	proviReq.Header.Userkey = AESEncryptEncodingValue(authData.UserKey)

	userkeyid := authData.UserKeyID
	log.Println("[LOG] UserKeyID : ", authData.UserKeyID)
	if userkeyid == "" {
		userkeyid = "0"
	}
	proviReq.Header.UserKeyID = AESEncryptEncodingValue(userkeyid)
	proviReq.Header.Nodeid = AESEncryptEncodingValue(authData.NodeID)
	deviceid := authData.DeviceID
	log.Println("[LOG] : DeviceID : ", authData.DeviceID)
	if deviceid == "" {
		deviceid = "0"
	}
	proviReq.Header.DeviceID = AESEncryptEncodingValue(deviceid)
	proviReq.Header.OSVersion = GetOSVersion()
	proviReq.Header.CurPkgVersion = GetCurPkgVersion()
	proviReq.Header.CurSeq = syncSeqNo
	proviReq.Header.Seq = syncSeqNo + 1
	configData := &cfginfo

	if configData.Encrypt_Mode == "None" {
		configData.Encrypt_Mode = "none"
	} else if configData.Encrypt_Mode == "AES_128" {
		configData.Encrypt_Mode = "aes_128"
	} else if configData.Encrypt_Mode == "AES_256" {
		configData.Encrypt_Mode = "aes_256"
	}

	log.Println("[LOG] : Encrypt_Mode", configData.Encrypt_Mode)

	for fidx, frontend := range configData.SiteList {
		if frontend.NodeMode == "1" {
			configData.SiteList[fidx].NodeMode = "1"
		} else if frontend.NodeMode == "2" {
			configData.SiteList[fidx].NodeMode = "2"
		} else {
			configData.SiteList[fidx].NodeMode = "0"
		}
	}

	configData.Statistic_Send_Control_Server = strconv.Itoa(ENABLE)

	proviReq.Body.Data = configData
	authReqProto := jsonInputWebAPIAuthProvisioningPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "ConfigData"
	authReqProto.MessageType = "request"
	authReqProto.UserKey = proviReq.Header.Userkey
	authReqProto.UserKeyID = proviReq.Header.UserKeyID
	authReqProto.NodeID = proviReq.Header.Nodeid
	authReqProto.DeviceID = proviReq.Header.DeviceID
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
		log.Println("[ERR] ProvisioningUploadRequest:", err)
		return err
	}

	log.Println("[LOG] ProvisioningUploadRequest [REQ]:  ", string(jsonBytes))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		log.Println("[ERR] ProvisioningUploadRequest:", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	var retrynum int
	var resp *http.Response
	for {
		resp, err = client.Do(req)
		if err != nil {
			retrynum++
			log.Println("[ERR] : ", err)
			if retrynum == 3 {
				return err
			}
		} else {
			if resp.StatusCode != 200 {
				retrynum++
				log.Println("[LOG] resp.StatusCode : ", resp.StatusCode)
				if retrynum == 3 {
					return errors.New(fmt.Sprintf("Response Auth Provisioning Up Http error: %d", resp.Status))
				}
			} else {
				log.Println("[LOG] : Success client do")
				break
			}
		}
		time.Sleep(time.Second * 5)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Response Provisioning Up Http error: %d", resp.Status))
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	log.Println("[LOG]ProvisioningUploadRequest [RES]: ", string(bodyBytes))

	authResProto := jsonOutputWebAPIAuthProvisioningPack{}
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

	if authResProto.Code != "200" {
		log.Println("[ERR] Code : ", authResProto.Code)
		log.Println("[ERR] Message : ", authResProto.Message)
		return errors.New("failed auth request")
	}

	_, err = updateNodefd(proviReq.Header.Nodeid, authResProto.UserkeyID, authResProto.DeviceID)
	if err != nil {
		log.Println("[ERR] UpdateNodeFile : ", err)
		return err
	}

	if configData.Encrypt_Mode == "aes_128" {
		configData.Encrypt_Mode = "AES_128"
	} else if configData.Encrypt_Mode == "aes_256" {
		configData.Encrypt_Mode = "AES_256"
	} else {
		configData.Encrypt_Mode = "None"
	}
	if cfginfo.Password == "" {
	} else {
		cfginfo.Password = EncryptGoWebPassword(cfginfo.Password)
	}
	_, err = UpdateConfigFiles(db, cfginfo, proviReq.Header.Seq)
	if err != nil {
		log.Println("[ERR] UpdateConfigFile :", err)
		return err
	}

	_, err = GetProxyInfos()
	if err != nil {
		log.Println("[ERR] GetProxyInfo :", err)
		return err
	}

	_, err = GetNodeModes()
	if err != nil {
		log.Println("[ERR] GetNodeMode :", err)
		return err
	}

	/*
		proviRes := ProvisionProtocol{}

		if err := mapstructure.Decode(authResProto.Data, &proviRes); err != nil {
			return err
		}

		if err := CheckProvisionHeader(&proviRes.Header); err != nil {
			return err
		}
	*/
	return nil
}

func ProvisioningUploadLocalPorcess(db *sql.DB) {
	var gowasaddr, updategowasaddr string
	var err error
	log.Println("[LOG] here is in ProvisioningUploadLocalPorcess")

	gowasaddr, updategowasaddr, err = GetGoWasAddr()
	if err != nil {
		log.Println("[ERR] :", err)
		return
	}
	log.Println("[LOG] :", gowasaddr)
	log.Println("[LOG] :", updategowasaddr)

	authData, err := GetAuthData()
	if err != nil {
		log.Println("[ERR] :", err)
		return
	}
	syncSeqNo, err := GetLocalSyncSeqNo(db, "ConfigData")
	if err != nil {
		log.Println("[ERR] :", err)
		return
	}

	url := fmt.Sprintf("http://%s/auth_api/provisioning/v1.0/", gowasaddr)

	authkey, authtoken, err := AutoProvisioninguploadAuthRequest(db, url, authData)
	if err != nil {
		log.Println("[ERR] ProvisioninguploadAuthRequest:", err)
		return
	}

	if err := AutoProvisioningUploadRequest(db, url, authData, authkey, authtoken, syncSeqNo); err != nil {
		log.Println("[ERR] ProvisioningUploadRequest:", err)
		return
	}
}

func AutoProvisioninguploadAuthRequest(db *sql.DB, url string, authData *AuthData) (string, string, error) {
	authReqProto := jsonInputWebAPIAuthProvisioningPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "ConfigData"
	authReqProto.MessageType = "request"

	authReqProto.UserKey = AESEncryptEncodingValue(authData.UserKey)

	userkeyid := authData.UserKeyID
	if userkeyid == "" {
		userkeyid = "0"
	}
	authReqProto.UserKeyID = AESEncryptEncodingValue(userkeyid)
	authReqProto.NodeID = AESEncryptEncodingValue(authData.NodeID)
	log.Println("authReqProto.NodeID:", authReqProto.NodeID)
	log.Println("authReqProto.UserKeyID:", authReqProto.UserKeyID)
	deviceid := authData.DeviceID
	if deviceid == "" {
		deviceid = "0"
	}
	authReqProto.DeviceID = AESEncryptEncodingValue(deviceid)
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
	log.Println("json", string(jsonBytes))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	var retrynum int
	var resp *http.Response
	for {
		resp, err = client.Do(req)
		if err != nil {
			retrynum++
			log.Println("[ERR] : ", err)
			if retrynum == 3 {
				return "", "", err
			}
		} else {
			if resp.StatusCode != 200 {
				retrynum++
				log.Println("[LOG] resp.StatusCode : ", resp.StatusCode)
				if retrynum == 3 {
					return "", "", errors.New(fmt.Sprintf("Response Auth Provisioning UP Http error: %d", resp.Status))
				}
			} else {
				log.Println("[LOG] : Success client do")
				break
			}
		}
		time.Sleep(time.Second * 5)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", errors.New(fmt.Sprintf("Response Auth Provisioning UP Http error: %d", resp.Status))
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

	if authResProto.Code != "200" {
		log.Println("[ERR] Code : ", authResProto.Code)
		log.Println("[ERR] Message : ", authResProto.Message)
		return "", "", errors.New("failed auth request")
	}

	authtoken := WebServer_Auth_API_Hashing_Provisioning(authData.UserKeyID, authData.DeviceID, authResProto.Method, authResProto.AuthKey)
	return authResProto.AuthKey, authtoken, nil
}

func AutoProvisioningUploadRequest(db *sql.DB, url string, authData *AuthData, authkey string, authtoken string, syncSeqNo int64) error {
	proviReq := ProvisionProtocol{}
	proviReq.Header.Version = ProvisionVersion
	proviReq.Header.Msgtype = "request"
	proviReq.Header.Method = ProvisionMethod
	proviReq.Header.Seperator = "up"
	proviReq.Header.Userkey = AESEncryptEncodingValue(authData.UserKey)

	userkeyid := authData.UserKeyID
	log.Println("[LOG] : UserKeyID", authData.UserKeyID)
	if userkeyid == "" {
		userkeyid = "0"
	}
	proviReq.Header.UserKeyID = AESEncryptEncodingValue(userkeyid)
	proviReq.Header.Nodeid = AESEncryptEncodingValue(authData.NodeID)
	deviceid := authData.DeviceID
	log.Println("[LOG] : NODEID", authData.DeviceID)
	if deviceid == "" {
		deviceid = "0"
	}
	proviReq.Header.DeviceID = AESEncryptEncodingValue(deviceid)
	proviReq.Header.OSVersion = GetOSVersion()
	proviReq.Header.CurPkgVersion = GetCurPkgVersion()
	proviReq.Header.CurSeq = syncSeqNo
	proviReq.Header.Seq = syncSeqNo + 1
	configData, err := GetProvisioningConfigData(db)
	if err != nil {
		log.Println("[ERR] ProvisioningUploadRequest : ", err)
		return err
	}

	if configData.Encrypt_Mode == "aes128" {
		configData.Encrypt_Mode = "aes_128"
	} else if configData.Encrypt_Mode == "aes256" {
		configData.Encrypt_Mode = "aes_256"
	} else {
		configData.Encrypt_Mode = "none"
	}

	log.Println("[LOG] : Encrypt_Mode", configData.Encrypt_Mode)

	for fidx, frontend := range configData.SiteList {
		if frontend.NodeMode == "client" {
			configData.SiteList[fidx].NodeMode = "1"
		} else if frontend.NodeMode == "server" {
			configData.SiteList[fidx].NodeMode = "2"
		} else {
			configData.SiteList[fidx].NodeMode = "0"
		}
	}

	if configData.Statistic_Send_Control_Server == "Enable" {
		configData.Statistic_Send_Control_Server = strconv.Itoa(ENABLE)
	} else {
		configData.Statistic_Send_Control_Server = strconv.Itoa(DISABLE)
	}

	log.Println("[LOG] : Statistic_Send_Control_Server", configData.Statistic_Send_Control_Server)
	proviReq.Body.Data = configData
	log.Println("[LOG] settingdata 2 :", configData)
	authReqProto := jsonInputWebAPIAuthProvisioningPack{}
	authReqProto.Version = "1.0"
	authReqProto.Method = "Auth"
	authReqProto.SessionType = "ConfigData"
	authReqProto.MessageType = "request"
	authReqProto.UserKey = proviReq.Header.Userkey
	authReqProto.UserKeyID = proviReq.Header.UserKeyID
	authReqProto.NodeID = proviReq.Header.Nodeid
	authReqProto.DeviceID = proviReq.Header.DeviceID
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
		log.Println("[Error] ProvisioningUploadRequest:", err)
		return err
	}

	log.Println("[LOG] ProvisioningUploadRequest [REQ]:  ", string(jsonBytes))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		log.Println("[Error] ProvisioningUploadRequest:", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	var retrynum int
	var resp *http.Response
	for {
		resp, err = client.Do(req)
		if err != nil {
			retrynum++
			log.Println("[ERR] : ", err)
			if retrynum == 3 {
				return err
			}
		} else {
			if resp.StatusCode != 200 {
				retrynum++
				log.Println("[LOG] resp.StatusCode : ", resp.StatusCode)
				if retrynum == 3 {
					return errors.New(fmt.Sprintf("Response Auth Provisioning Up Http error: %d", resp.Status))
				}
			} else {
				log.Println("[LOG] : Success client do")
				break
			}
		}
		time.Sleep(time.Second * 5)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Response Provisioning Up Http error: %d", resp.Status))
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	log.Println("[LOG]ProvisioningUploadRequest [RES]: ", string(bodyBytes))

	authResProto := jsonOutputWebAPIAuthProvisioningPack{}
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

	if authResProto.Code != "200" {
		log.Println("[ERR] Code : ", authResProto.Code)
		log.Println("[ERR] Message : ", authResProto.Message)
		return errors.New("failed auto upload auth request")
	}

	tx, err := db.Begin()
	if err != nil {
		log.Println("Transaction Begin err:", err)
		return err
	}

	defer sqlitedb_lib.DB_Rollback(tx)
	if syncSeqNo > 0 {
		query := "UPDATE SyncSeqNoTbl\n" +
			"SET SeqNo = ?\n" +
			"WHERE SeqNoName = 'ConfigData';"

		stmt, err := tx.Prepare(query)
		if err != nil {
			return err
		}

		_, err = stmt.Exec(proviReq.Header.Seq)
		if err != nil {
			stmt.Close()
			return err
		}
		stmt.Close()
	}

	err = sqlitedb_lib.DB_Commit(tx)
	if err != nil {
		log.Println("Commit Fail!:", err)
		return err
	}
	_, err = updateNodefd(proviReq.Header.Nodeid, authResProto.UserkeyID, authResProto.DeviceID)
	if err != nil {
		log.Println("UpdateNodeFile err:", err)
		return err
	}

	/*
		proviRes := ProvisionProtocol{}

		if err := mapstructure.Decode(authResProto.Data, &proviRes); err != nil {
			return err
		}

		if err := CheckProvisionHeader(&proviRes.Header); err != nil {
			return err
		}
	*/
	return nil
}

func updateNodefd(nodeid string, userkeyid string, deviceid string) (int32, error) {
	var fd *os.File
	var EncText string
	var err error
	var CRLF string
	var ConfNodeID string

	userkeyid = AESDecryptDecodeValue(userkeyid)
	deviceid = AESDecryptDecodeValue(deviceid)
	nodeid = AESDecryptDecodeValue(nodeid)

	log.Println("userkeyid", userkeyid)
	log.Println("deviceid", deviceid)

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
	ConfNodeID += "[UserKeyID]" + CRLF
	ConfNodeID += "UserKeyID = \"<UserKeyID>\"" + CRLF
	ConfNodeID += "[DeviceID]" + CRLF
	ConfNodeID += "DeviceID = \"<DeviceID>\"" + CRLF
	ConfNodeID += CRLF

	ConfNodeID = strings.Replace(ConfNodeID, "<NODE_ID>", nodeid, -1)
	ConfNodeID = strings.Replace(ConfNodeID, "<UserKeyID>", userkeyid, -1)
	ConfNodeID = strings.Replace(ConfNodeID, "<DeviceID>", deviceid, -1)

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

type program struct {
	LogFile *os.File
}

func main() {
	prg := program{}
	defer func() {
		if prg.LogFile != nil {
			if closeErr := prg.LogFile.Close(); closeErr != nil {
				log.Printf("error closing '%s': %v\r\n", prg.LogFile.Name(), closeErr)
			}
		}
	}()
	if err := svc.Run(&prg); err != nil {
		log.Fatal(err)
	}
}

func (p *program) Init(env svc.Environment) error {
	log.Printf("is win service? %v\r\n", env.IsWindowsService())

	// write to "example.log" when running as a Windows Service
	if env.IsWindowsService() {
		dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			return err
		}

		logPath := filepath.Join(dir, "excute.log")

		f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return err
		}

		p.LogFile = f

		log.SetOutput(f)
	}

	return nil
}

func (p *program) Start() error {
	log.Printf("Starting...\r\n")

	ControlServerFlag = -1

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-v":
			fmt.Println("Version Info : ", GoWebVersion)
			return nil
		case "-l":
			ControlServerFlag = 0
		default:
			ShowHelpCommand()
			return nil
		}
	}

	if ControlServerFlag == -1 {
		ShowHelpCommand()
		return nil
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	InitLogger()
	log.Println("Start Logger")

	go SigHandler()
	go CheckLogFile()

	GetNICInfo()
	DeviceOSFlag = GetDevOSFlag()
	if DeviceOSFlag == DEVICE_OS {
		log.Println("OS : Device OS")
	} else if DeviceOSFlag == GENERAL_OS {
		log.Println("OS : General OS")
	}

	log.Println("Version Info : ", GoWebVersion)
	RunLocalWebServer()

	return nil
}

func (p *program) Stop() error {
	log.Printf("Stopped.\r\n")
	return nil
}
