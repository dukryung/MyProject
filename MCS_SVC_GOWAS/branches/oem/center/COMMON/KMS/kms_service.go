package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/sevlyar/go-daemon"
  "github.com/BurntSushi/toml"
  "net/smtp"
	"html/template"
	"bytes"
  "bufio"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"math"
	"time"
	"./library/security/aes_cfb"
	"./library/utility/product_rand_key"
	"./library/utility/disk"
	"./library/make_package"
	"./library/db/mariadb_lib"
)

var DeviceOSFlag int
var ControlServerFlag int
var CommonIDArray []int
var ProxyIPStrArray []string
var NICInfoArray []NICInformation
var ControlServerIP, ControlServerPort, ControlServerSendInterval string
var RowCountPerPage = 25
var MaxPageCountInPage = 10
var LoginTimeout = 60*30 /* sec */
var DBPath, DBName string
var UpdateLock = &sync.Mutex{}
var ProcessLogFileName = "kms_service.log"

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
  CookieUserID string 
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

type PreparedStatementObject        func () *PreparedStatementPack
type PreparedStatementSetInt32      func (*PreparedStatementPack, int, int32) 
type PreparedStatementSetInt64      func (*PreparedStatementPack, int, int64) 
type PreparedStatementSetUInt32     func (*PreparedStatementPack, int, uint32) 
type PreparedStatementSetUInt64     func (*PreparedStatementPack, int, uint64) 
type PreparedStatementSetString     func (*PreparedStatementPack, int, string) 
type PreparedStatementExecuteQuery  func (*PreparedStatementPack) *sql.Rows
type PreparedStatementExecuteCMD    func (*PreparedStatementPack) int
type PreparedStatementClose         func (*PreparedStatementPack) 

type PreparedStatementPack struct {
  SQLQuery          string

  ArgumentCnt       int
  ArgumentArrary[]  string

  SetInt32          PreparedStatementSetInt32
  SetInt64          PreparedStatementSetInt64 
  SetUInt32         PreparedStatementSetUInt32
  SetUInt64         PreparedStatementSetUInt64
  SetString         PreparedStatementSetString

  ExecuteQuery      PreparedStatementExecuteQuery
  ExecuteCMD        PreparedStatementExecuteCMD

  Close             PreparedStatementClose
}



type ExceptionPage struct {
  ExceptionCode int
  ExceptionURL string
  ExceptionContent string
  ExceptionAction string
}

type UserHtmlMainMenu struct {
	Setting template.HTML
	UserIDMenu template.HTML
	UserKeyIDMenu template.HTML
	NodeIDMenu template.HTML
	ServerAuthDashboardMenu template.HTML
}

type HtmlPageListComponent struct {
  ParamPageNumItem string
  ParamPageNumString string
  ParamPageNum int

  ParamPageSortItem string
  ParamPageSortString string
  ParamPageSort int

  MaxPageCount int
  MaxRowCountPage int
  PageCount int
  RowCountTotal int
  RowOffset int

  PageIndexStart int
  PageBeginNum int
  PageEndNum int
  PrevPageNum int
  NextPageNum int

	TempleteViewBeginPage template.HTML   // <<
	TempleteViewEndPage template.HTML     // >>
	TempleteViewPrevPage template.HTML    // <
	TempleteViewNextPage template.HTML    // >
	TempleteViewPageList[] template.HTML  // ...
  PageLinkURL string
  PageAdditionParams string

  returnCode int

  errPage ExceptionPage
}

type OEMInformation struct {
  OEMName string 
  OEMWEBHeadInfo string 
  OEMWEBTailInfo string 
}

type CommonHTML struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  SQLQuery string
  SQLQueryCondition string
}

type NodeKeyList struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  SearchParamUserID string
  SearchParamUserKey string
  SearchParamEndDateFrom string
  SearchParamEndDateTo string
  SearchParamUserKeyStatus string

  TempletePage HtmlPageListComponent

  NodeKey[] NodeKeyListItem
  SQLQuery string
  SQLQueryCondition string
}

type NodeKeyListItem struct {
	UserID string 
  NodeKey string
  ServiceNodeCount string
  EndDate string 
  CreateDate string
  UpdateDate string 
  Status string
  NodeKeyModifyLinkURL string
  NodeKeyReGenerateLinkURL string
  NodeKeyNodeIDLinkURL string
  NodeKeyLicenseLinkURL string
  NodeKeyPackageLinkURL string
  NodeKeyDeleteLinkURL string
}

type NodeKeyCreate struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  SearchParamUserID string
  SearchParamUserKey string
  SearchParamEndDateFrom string
  SearchParamEndDateTo string
  SearchParamUserKeyStatus string

  TempletePage HtmlPageListComponent

  NodeKeyData NodeKeyCreateItem
  SQLQuery string
  SQLQueryCondition string
}

type NodeKeyCreateItem struct {
	UserID string 
  NodeKeyNew string
  NodeIDCount string
  PeriodOfUse string 
}

type jsonInputNodeKeyGenerate struct {
  ActionMode string           `json:"action_mode"`
  UserID string               `json:"user_id"`
  NodeKey string              `json:"node_key"`
  NodeIDCount string          `json:"node_id_count"`
  PeriodOfUse string          `json:"period_of_use"`
}

type NodeKeyRegenerate struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  NodeKeyRegenerate NodeKeyRegenerateItem 
  SQLQuery string
  SQLQueryCondition string
}

type NodeKeyRegenerateItem struct {
	UserID string 
  NodeKeyOld string
  NodeKeyNew string
  ResultMsg string
}

type jsonInputNodeKeyRegenerate struct {
  ActionMode string           `json:"action_mode"`
  UserID string               `json:"user_id"`
  NodeKeyOld string           `json:"node_key_old"`
  NodeKeyNew string           `json:"node_key_new"`
}

type NodeKeyLicense struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  NodeKeyLicense NodeKeyLicenseItem 
  SQLQuery string
  SQLQueryCondition string
}

type NodeKeyLicenseItem struct {
	UserID string 
  NodeKey string
  NodeID[] string
  NodeIDMaxCount int
  NodeIDCount int
  EndDate string
  ResultMsg string
}

type NodeKeyLicenseEmail struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  NodeKeyLicense NodeKeyLicenseEmailItem 
  SQLQuery string
  SQLQueryCondition string
}

type NodeKeyLicenseEmailItem struct {
	UserID string 
  NodeKey string
  NodeID[] string
  NodeIDMaxCount int
  NodeIDCount int
  EndDate string
  ActionMode string
  EmailSMTPServer string
  EmailAuth string
  EmailFrom string
  EmailTo[] string
  EmailHeaderSubject string
  EmailHeaderBlank string
  EmailBody string
  EmailMessageByte[] byte
  ResultMsg string
}

type NodeKeyPackage struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  NodeKeyPackage NodeKeyPackageItem
  SQLQuery string
  SQLQueryCondition string
}

type NodeKeyPackageItem struct {
	UserID string 
  NodeKey string
  NodeIDCount int
  NodeIDMaxCount int
  ActionMode string
  ResultMsg string
}

type NodeKeyDelete struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  SearchParamUserID string
  SearchParamUserKey string
  SearchParamEndDateFrom string
  SearchParamEndDateTo string
  SearchParamUserKeyStatus string

  TempletePage HtmlPageListComponent

  NodeKeyData NodeKeyDeleteItem 
  SQLQuery string
  SQLQueryCondition string
}

type NodeKeyModify struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  NodeKeyData NodeKeyModifyItem
  SQLQuery string
  SQLQueryCondition string
}

type NodeKeyModifyItem struct {
	UserID string 
  NodeKey string
  NodeID[] string
  NodeIDMaxCount int
  NodeIDCount int
  EndDateYear string
  EndDateMonth string
  EndDateDay string
  Status string
  ResultMsg string
}

type jsonInputNodeKeyModifyPack struct {
  UserID string                       `json:"user_id"`
  NodeKey string                      `json:"node_key"`
  NodeKeyNodeIDMaxCount string        `json:"node_key_node_id_max_count"`
  NodeKeyNodeIDCurrentCount string    `json:"node_key_node_id_current_count"`
  NodeKeyEndDateCurrentYear string    `json:"node_key_enddate_current_year"`
  NodeKeyEndDateCurrentMonth string   `json:"node_key_enddate_current_month"`
  NodeKeyEndDateCurrentDay string     `json:"node_key_enddate_current_day"`
  NodeKeyCurrentStatus string         `json:"node_key_current_status"`
  NodeKeyNodeIDModifyCount string     `json:"node_key_node_id_modify_count"`
  NodeKeyEndDateModifyYear string     `json:"node_key_enddate_modify_year"`
  NodeKeyEndDateModifyMonth string    `json:"node_key_enddate_modify_month"`
  NodeKeyEndDateModifyDay string      `json:"node_key_enddate_modify_day"`
  NodeKeyModifyStatus string          `json:"node_key_modify_status"`
}

type NodeKeyDeleteItem struct {
	UserID string 
  NodeKey string
  NodeID[] string
  NodeIDMaxCount int
  NodeIDCount int
  EndDate string
  ResultMsg string
}

type jsonInputNodeKeyDeletePack struct {
  UserID string               `json:"user_id"`
  NodeKey string              `json:"node_key"`
}

type UserIDList struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  SearchParamUserID string
  SearchParamUserEmail string
  SearchParamUserProperty string
  SearchParamUserStatus string

  TempletePage HtmlPageListComponent

  UserID[] UserIDListItem
  SQLQuery string
  SQLQueryCondition string
}

type UserIDListItem struct {
	UserID string 
  UserEmail string
  UserProperty string
  CreateDate string
  UpdateDate string 
  UserStatus string
  UserKeyLinkURL string
  UserIDModifyLinkURL string
  UserIDDeleteLinkURL string
}

type NodeIDList struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  SearchParamUserID string
  SearchParamUserKey string
  SearchParamUserNodeID string
  SearchParamUserNodeStatus string

  TempletePage HtmlPageListComponent

  NodeID[] NodeIDListItem
  SQLQuery string
  SQLQueryCondition string
}

type NodeIDListItem struct {
	UserID string 
  UserKey string
  NodeClientNumber string
  NodeID string
  CreateDate string 
  UpdateDate string 
  NodeStatus string
  NodeIDLicenseLinkURL string
  NodeIDCreateLinkURL string
  NodeIDModifyLinkURL string
  NodeIDDeleteLinkURL string
}

type NodeIDCreate struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  NodeData NodeIDCreateItem
  SQLQuery string
  SQLQueryCondition string
}

type NodeIDCreateItem struct {
	UserID string 
  NodeKey string
  NodeIDOldCount int
  NodeIDNewCount int
  NodeIDDetail[] NodeIDDetailItem
}

type NodeIDDetailItem struct {
  NodeID string
}

type NodeIDModify struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  NodeData NodeIDModifyItem 
  SQLQuery string
  SQLQueryCondition string
}

type NodeIDModifyItem struct {
	UserID string 
  NodeKey string
  NodeIDOld string
  NodeIDNew string
}

type jsonInputNodeModifyPack struct {
  UserID string               `json:"user_id"`
  NodeKey string              `json:"node_key"`
  NodeIDOld string            `json:"node_id_old"`
  NodeIDNew string            `json:"node_id_new"`
}

type NodeIDDelete struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  NodeData NodeIDDeleteItem 
  SQLQuery string
  SQLQueryCondition string
}

type NodeIDDeleteItem struct {
	UserID string 
  NodeKey string
  NodeID string
}

type jsonInputNodeIDDeletePack struct {
  ActionMode string           `json:"action_mode"`
  UserID string               `json:"user_id"`
  NodeKey string              `json:"node_key"`
  NodeID string               `json:"node_id"`
}

type jsonInputNodeIDGenerate struct {
  ActionMode string           `json:"action_mode"`
  UserID string               `json:"user_id"`
  NodeKey string              `json:"node_key"`
  NodeIDList string           `json:"node_id_list"`
}

type UserIDCreate struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  UserData UserIDCreateItem 
  SQLQuery string
  SQLQueryCondition string
}

type UserIDCreateItem struct {
	UserID string 
  UserPW string
  UserEmail string
  UserProperty string
  UserStatus string
  UserServiceName string
}

type UserIDModify struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  UserData UserIDModifyItem
  SQLQuery string
  SQLQueryCondition string
}

type UserIDModifyItem struct {
	UserID string 
  UserPW string
  UserNewPW string
  UserNewConfirmPW string
  UserEmail string
  UserProperty string
  UserStatus string
  UserServiceName string
}

type UserIDDelete struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  UserDataParam string
  UserDataCount int
  UserData []UserIDDeleteItem
  SQLQuery string
  SQLQueryCondition string
}

type UserIDDeleteItem struct {
	UserID string 
}

type SettingSMTP struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  TempletePage HtmlPageListComponent

  SMTPItem SettingSMTPItem
  SQLQuery string
  SQLQueryCondition string
}

type SettingSMTPItem struct {
	SMTPServerAddress string 
	SMTPServerHost string 
	SMTPSenderEmail string 
	SMTPSenderPassword string 
  CurrentUserProperty string
}

type MonitoringNodeAuth struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  SearchType string

  TempletePage HtmlPageListComponent

  MonitoringItem[] MonitoringNodeAuthItem
  SQLQuery string
  SQLQueryCondition string
}

type MonitoringNodeAuthItem struct {
  Num int
	NodeID string 
	NodeIP string 
	AuthenticationTime string 
	AuthToken string 
	AuthTokenExpiretime int
}

type MonitoringNodeAuthDetail struct {
  CookiesData CookiesUserData
  MainMenu UserHtmlMainMenu
  OEMData OEMInformation

  SearchNodeID string

  TempletePage HtmlPageListComponent

  MonitoringItem[] MonitoringNodeAuthDetailItem
  SQLQuery string
  SQLQueryCondition string
}

type MonitoringNodeAuthDetailItem struct {
  Num int
	NodeID string 
	NodeIP string 
	AuthenticationTime string 
	AuthRspCode string 
	AuthRspMessage string 
	AuthToken string 
	AuthTokenExpiretime int
}

type jsonInputSMTP struct {
  ActionMode string           `json:"action_mode"`
  SMTPServerAddress string    `json:"smtpaddress"`
  SMTPServerHost string       `json:"smtphost"`
  SMTPSenderEmail string      `json:"smtpemail"`
  SMTPSenderPassword string   `json:"smtppasswd"`
}

type jsonInputWebAPIEncodeValue struct {
  InputValue string           `json:"input"`
}

type jsonOutputWebAPIEncodeValue struct {
  Code string                 `json:"code"`
  Message string              `json:"message"`
  InputValue string           `json:"input"`
  OutputValue string          `json:"output"`
}

type jsonInputWebAPIAuthPack struct {
  Method string               `json:"method"`
  MessageType string          `json:"msgtype"`
  NodeKey string              `json:"userkey"`
  NodeID string               `json:"nodeid"`
  AuthToken string            `json:"authtoken"`
}

type jsonOutputWebAPIAuthPack struct {
  Method string               `json:"method"`
  MsgType string              `json:"msgtype"`
  Code string                 `json:"code"`
  Message string              `json:"msg"`
  AuthKey string              `json:"authkey"`
  ExpireTime string           `json:"expiretime"`
  Event string                `json:"event"`
}
//-----{ defined struct } -----// }


//---- {
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

type ServerStatisticData struct {
	ID             int
	Client_IP_Int  uint32
	Client_IP_Str  string
	Client_IP_HTML template.HTML
	Inbound        int
	Inbound_HTML   template.HTML
	Outbound       int
	Outbound_HTML  template.HTML
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

type ClientStatisticData struct {
	ID                int
	Proxy_IP_Int      uint32
	Proxy_IP_Str      string
	Proxy_Listen_Port int
	Inbound           int
	Outbound          int
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

type BackendInformationList struct {
	LAN_Interface string
	BackendIP     string
	BackendPort   string
}
//---- }

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



//----------------------------------------------{ KMS


func GetCipherText(PlainText string) string {
	block, err := aes.NewCipher([]byte(aes_key))
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, 12)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(PlainText), nil)
	log.Printf("PlainText %s -> %x\n", PlainText, ciphertext)

	return fmt.Sprintf("%x", ciphertext)
}


func IPtoStr(ipaddr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ipaddr>>24), byte(ipaddr>>16), byte(ipaddr>>8), byte(ipaddr))
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


func GetOEMName () string {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var OEMName string
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_NAME FROM kms_configure"

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&OEMName)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem name data db scan error:", err)

      return ""
    }
  }
  ResultSetRows.Close()

  if len(OEMName) == 0 {
    log.Println("oem name data db return value is empty string")
    return ""  
  }

  return OEMName
}

func GetOEMPackageFileName () string {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var OEMPackageFileName string
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_PACKAGE_FILENAME FROM kms_configure"

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&OEMPackageFileName)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem name data db scan error:", err)

      return ""
    }
  }
  ResultSetRows.Close()

  if len(OEMPackageFileName) == 0 {
    log.Println("oem name data db return value is empty string")
    return ""  
  }

  return OEMPackageFileName
}


func GetOEMPackageEncryptKey () string {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var PackageEncryptKey string
  var FORCE_FIX_AES_KEY = []byte{109, 56, 85, 44, 248, 44, 18, 128, 236, 116, 13, 250, 243, 45, 122, 133, 199, 241, 124, 188, 188, 93, 65, 153, 214, 193, 127, 85, 132, 147, 193, 68}
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_PACKAGE_ENCRYPTION_KEY FROM kms_configure"

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&PackageEncryptKey)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem name data db scan error:", err)

      return ""
    }
  }
  ResultSetRows.Close()

  /*--------------------------------------------------------------
  if len(PackageEncryptKey) == 0 {
    log.Println("oem name data db return value is empty string")
    return ""  
  }
  --------------------------------------------------------------*/
  
  PackageEncryptKey = string(FORCE_FIX_AES_KEY)
  log.Println("Force EncryptKey:" +  PackageEncryptKey)

  return PackageEncryptKey 
}

func GetOEMPackageEncryptIV () string {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var PackageEncryptIV string
  var FORCE_FIX_IV = []byte{89, 93, 106, 165, 128, 137, 36, 38, 122, 121, 249, 59, 151, 133, 155, 148}
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_PACKAGE_ENCRYPTION_IV FROM kms_configure"

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&PackageEncryptIV)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem name data db scan error:", err)

      return ""
    }
  }
  ResultSetRows.Close()

  /*--------------------------------------------------------------
  if len(PackageEncryptIV) == 0 {
    log.Println("oem name data db return value is empty string")
    return ""  
  }
  --------------------------------------------------------------*/

  PackageEncryptIV = string(FORCE_FIX_IV)
  log.Println("Force EncryptIV:" +  PackageEncryptIV)

  return PackageEncryptIV
}


func GetOEMSMTPServerAddress() string {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var SMTPServerAddress string
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_SMTP_SERVER_ADDRESS FROM kms_configure"

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&SMTPServerAddress)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem name data db scan error:", err)

      return ""
    }
  }
  ResultSetRows.Close()

  if len(SMTPServerAddress) == 0 {
    log.Println("oem smtp server data db return value is empty string")
    return ""  
  }

  return SMTPServerAddress 
}


func GetOEMSMTPServerHost() string {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var SMTPServerName string
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_SMTP_SERVER_HOST FROM kms_configure"

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&SMTPServerName)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem name data db scan error:", err)

      return ""
    }
  }
  ResultSetRows.Close()

  if len(SMTPServerName) == 0 {
    log.Println("oem smtp server name data db return value is empty string")
    return ""  
  }

  return SMTPServerName 
}


func GetOEMSMTPSenderEmail() string {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var SMTPSenderEmail string
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_SMTP_SENDER_EMAIL FROM kms_configure"

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&SMTPSenderEmail)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem name data db scan error:", err)

      return ""
    }
  }
  ResultSetRows.Close()

  if len(SMTPSenderEmail) == 0 {
    log.Println("oem smtp server data db return value is empty string")
    return ""  
  }

  return SMTPSenderEmail 
}


func GetOEMSMTPSenderPassword() string {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var SMTPSenderPassword string
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_SMTP_SENDER_PASSWORD FROM kms_configure"

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&SMTPSenderPassword)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem name data db scan error:", err)

      return ""
    }
  }
  ResultSetRows.Close()

  if len(SMTPSenderPassword) == 0 {
    log.Println("oem smtp server data db return value is empty string")
    return ""  
  }

  return SMTPSenderPassword 
}


func GetUserIDEmail (UserID string) string {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var EmailAddress string
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT email FROM user where user_id = '%s' "
  QueryString = fmt.Sprintf(QueryString, UserID)
  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&EmailAddress)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem name data db scan error:", err)

      return ""
    }
  }
  ResultSetRows.Close()

  if len(EmailAddress) == 0 {
    log.Println("user id email data db return value is empty string")
    return ""  
  }

  return EmailAddress 
}


func GetOEMPackageHomePath () string {
  var PackageHomePath string

  ProcessPWD, err := os.Getwd()
  if err != nil {
    log.Println("oem process pwd return value error")
    return ""
  }

  PackageHomePath = ProcessPWD + "/database" + "/package_home/"
  return PackageHomePath
}


func GetOEMAuthExpiretimeInterval () int {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var AuthExpiretimeInterval int
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_AUTH_EXPIRETIME_INTERVAL FROM kms_configure"

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
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


func CreateLicenseFile (OSType string, HomeDirPath string, FilePath string, EncryptFlag bool, EncryptKey string, EncryptIV string,  UserID string, UserKey string, NodeIDMaxCount int, NodeIDCount int, EndDateYear string, EndDateMonth string, EndDateDay string, NodeIDArrary[] string) bool {
  var LineContextArrary[] string
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
    if (Result != true) {
      log.Println("failed to delete exist file (filepath:", FilePath, ")")
    }
  }

  if OSType == "LINUX" {
    CRLF = "\n"
  } else if OSType == "WINDOWS" {
    CRLF = "\r\n"
  }

  LineContextArrary = append(LineContextArrary, "[UserKey]" + CRLF)
  LineContextArrary = append(LineContextArrary, "UserID = \"" + UserID + "\"" + CRLF)
  LineContextArrary = append(LineContextArrary, "UserKey = \"" + UserKey + "\"" + CRLF)
  LineContextArrary = append(LineContextArrary, "NodeID_Total = " + strconv.Itoa(NodeIDMaxCount) + CRLF)
  LineContextArrary = append(LineContextArrary, "NodeID_Current = " + strconv.Itoa(NodeIDCount) + CRLF)
  LineContextArrary = append(LineContextArrary, "EndDateYear = " + EndDateYear + CRLF)
  LineContextArrary = append(LineContextArrary, "EndDateMonth = " + EndDateMonth + CRLF)
  LineContextArrary = append(LineContextArrary, "EndDateDay = " + EndDateDay + CRLF)
  LineContextArrary = append(LineContextArrary, CRLF)

  LineContextArrary = append(LineContextArrary, "[NodeID]" + CRLF)

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

  if (Result == false) {
    log.Println("failed to license file - (file path:", FilePath ,", user id:", UserID, ", user key:", UserKey , ")")
    return false
  }

  log.Println("success creating license file - (file path:", FilePath ,", user id:", UserID, ", user key:", UserKey , ")")
  return true
}


func DBSetTmpGenerateNodeID (UserID, NodeKey, TmpGenerateNodeID string) (int) {
  var Database *sql.DB
  var QueryString string
  
  if UserID == "" || NodeKey == "" {
    log.Println("DBSetTmpGenerateNodeID - invalid argument")
    return 0
  }
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)
  
  if Database == nil {
    log.Println("GenerateNodeKey - failed to db connect")
    return 0
  }

  // Update Temp Generator UserID of 'node_key' db table by user_id, node_key //
  QueryString = "UPDATE user_key " +
                "SET nodeid_generate_tmp_key = '%s' " +
                "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                "                         FROM (SELECT b.user_key_id_seq " +
                "                               FROM user a, user_key b " +
                "                               WHERE a.user_id = '%s' " +
                "                               and b.user_key_id = '%s' " +
                "                               and a.user_id_seq = b.user_id_seq) tmp)"
  QueryString = fmt.Sprintf(QueryString, TmpGenerateNodeID, UserID, NodeKey)
  log.Println("DBSetTmpGenerateNodeID - update query:", QueryString)
	mariadb_lib.Update_Data(Database, QueryString)
  // TODO: DB Excxception

  log.Println("DBSetTmpGenerateNodeID - update TempGenerateNodeID:", TmpGenerateNodeID)

  return 1
}


func GenerateNodeID (DB *sql.DB, NodeKey string) (string) {
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
    Database = MariaDB_Open()
    defer MariaDB_Close(Database)
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

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
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


func DBSetTmpGenerateNodeKey (UserID, TmpGenerateNodeKey string) (int) {
  var Database *sql.DB
  var QueryString string
  
  if UserID == "" {
    log.Println("DBSetTmpGenerateNodeKey - invalid argument")
    return 0
  }
  
	Database = MariaDB_Open()
  defer MariaDB_Close(Database)
  
  if Database == nil {
    log.Println("GenerateNodeKey - failed to db connect")
    return 0
  }

  // Update Temp Generator NodeKey of 'user' db table by user_id //
  QueryString = "UPDATE user SET nodekey_generate_tmp_key = '%s' WHERE user_id = '%s'"

  QueryString = fmt.Sprintf(QueryString, TmpGenerateNodeKey, UserID)
  log.Println("DBSetTmpGenerateNodeKey - update query:", QueryString)
	mariadb_lib.Update_Data(Database, QueryString)
  // TODO: DB Excxception

  log.Println("DBSetTmpGenerateNodeKey - update TempGenerateNodeID:", TmpGenerateNodeKey)

  return 1
}


func GenerateNodeKey (DB *sql.DB, UserID string) (string) {
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
    Database = MariaDB_Open()
    defer MariaDB_Close(Database)
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

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
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


func WebServer_Service_Popup(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	var tmpl *template.Template
	var err error

  log.Println("KMS Web Server - Service_Popup", req.Method)

  tmpl, err = template.ParseFiles("./html/kms_popup_window.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_popup_window.html)")
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


func WebServer_Login(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	var tmpl *template.Template
	var err error

  log.Println("KMS Web Server - Login", req.Method)

  res := Cookie_Check(w, req) 
  if res >= 0 {
    WebServer_Redirect(w, req, "/nodekey/management/?page_num=1&page_sort=0")
    return
  }

  tmpl, err = template.ParseFiles("./html/kms_login_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_login_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	tmpl.Execute(w, nil)
}


func WebServer_Login_Check(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var ID, Password, QueryStr string
	var CookieName string
	var CommonRows *sql.Rows
	var UserIDSeq int64
  var UserID, Property string

  log.Println("KMS Web Server - Login_Check", req.Method)

  res := Cookie_Check(w, req) 
  if res >= 0 {
    WebServer_Redirect(w, req, "/nodekey/management/?page_num=1&page_sort=0")
    return
  }

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

	if req.Method == "POST" {

		req.ParseForm()

		// check id and passwd if ok keep going
		ID = fmt.Sprintf("%s", req.Form["id"])
		ID = strings.Replace(ID, "[", "", -1)
		ID = strings.Replace(ID, "]", "", -1)
		Password = fmt.Sprintf("%s", req.Form["password"])
		Password = strings.Replace(Password, "[", "", -1)
		Password = strings.Replace(Password, "]", "", -1)

		QueryStr = fmt.Sprintf("SELECT user_id_seq, user_id, property FROM user WHERE user_id = '%s' AND password = '%s'", ID, GetCipherText(Password))

		log.Println("Login_Check Query -> ", QueryStr)

		CommonRows = mariadb_lib.Query_DB(Database, QueryStr)

		for CommonRows.Next() {
			err := CommonRows.Scan(&UserIDSeq, &UserID, &Property)
			if err != nil {
		    CommonRows.Close()
				log.Println("[error] data Scan error:", err)
				WebServer_Redirect(w, req, "/service_stop/")
				return
			}

			if UserID == "" {
		    CommonRows.Close()
				log.Println("mismatching user information (ID:", ID, ", Password:",  Password, "|", GetCipherText(Password), ")")
				WebServer_Redirect(w, req, "/login")
				return
			}
		}
    
		CommonRows.Close()

    if UserID == "" {
	    log.Println("mismatching user information (ID:", ID, ", Password:",  Password, "|", GetCipherText(Password), ")")
      WebServer_Redirect(w, req, "/login/")
      return
    }

		CookieName = "GSESSION"
		session, err := store.Get(req, CookieName)
		if err != nil {
			log.Println("[error] store.get Error:", err)
      WebServer_Redirect(w, req, "/service_stop/")
      return
		}

		session.Values["id"] = UserID
		session.Values["property"] = Property
		session.Options.MaxAge = LoginTimeout
		session.Save(req, w)

	} else {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  WebServer_Redirect(w, req, "/nodekey/management/?page_num=1&page_sort=0")
}


func WebServer_Logout(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

  log.Println("KMS Web Server - Logout", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

	cookies := req.Cookies()

	for i := range cookies {
		session, _ := store.Get(req, cookies[i].Name)
		if session != nil {
	    log.Println("Cookie Check:", session.Values)

			id, ok := session.Values["id"].(string)
			if !ok || len(id) <= 0 {
		    log.Println("Exist Cookies")
			}

			id, ok = session.Values["id"].(string)

      log.Println("Logout - Cookie id :", id)
      session.Values["id"] = ""   // destory
			session.Options.MaxAge = 0  // destory
			session.Save(req, w)
		}
	}

  WebServer_Redirect(w, req, "/login/")
}


func HtmlDataPage (inPack *HtmlPageListComponent, pageNumName string, pageNumString string, pageSortName string, pageSortString string, currentPageNum int, maxCountPage int, maxRowCountPage int, rowCountTotal int, pageLinkURL string, pageAdditionParams string, exceptionURL string, exceptionContent string, exceptionURLAction string) *HtmlPageListComponent {
  
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
    if inPack.PageEndNum > inPack.PageCount { inPack.PageEndNum = inPack.PageCount }
  } else {
    inPack.PageEndNum = inPack.PageCount
    if inPack.PageEndNum > inPack.PageCount { inPack.PageEndNum = inPack.PageCount }
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


func SessionCookieUserData (cookies *CookiesUserData, req *http.Request) int {
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


func WebServerMainMenu (UserKeyMainMenu *UserHtmlMainMenu, CurrentMenu string) int {
  var TempString string

  if UserKeyMainMenu == nil {
    log.Println("input argument is invalid")
    return RET_INT_FAIL
  }

  if CurrentMenu == "setting" {
    TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/setting/smtp_display/\">Setting</a></li>")
    UserKeyMainMenu.Setting = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/userid/management/\">User ID</a></li>")
    UserKeyMainMenu.UserIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodekey/management/\">User Key</a></li>")
    UserKeyMainMenu.UserKeyIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodeid/management/\">Node ID</a></li>")
    UserKeyMainMenu.NodeIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/monitoring/node_auth/\">MCSE Server Auth Dashboard</a></li>")
    UserKeyMainMenu.ServerAuthDashboardMenu = template.HTML(TempString)
  } else if CurrentMenu == "userid" {
    TempString = fmt.Sprintf("<li><a href=\"/setting/smtp_display/\">Setting</a></li>")
    UserKeyMainMenu.Setting = template.HTML(TempString)
    TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/userid/management/\">User ID</a></li>")
    UserKeyMainMenu.UserIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodekey/management/\">User Key</a></li>")
    UserKeyMainMenu.UserKeyIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodeid/management/\">Node ID</a></li>")
    UserKeyMainMenu.NodeIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/monitoring/node_auth/\">MCSE Server Auth</a></li>")
    UserKeyMainMenu.ServerAuthDashboardMenu = template.HTML(TempString)
  } else if CurrentMenu == "nodekey" {
    TempString = fmt.Sprintf("<li><a href=\"/setting/smtp_display/\">Setting</a></li>")
    UserKeyMainMenu.Setting = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/userid/management/\">User ID</a></li>")
    UserKeyMainMenu.UserIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/nodekey/management/\">User Key</a></li>")
    UserKeyMainMenu.UserKeyIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodeid/management/\">Node ID</a></li>")
    UserKeyMainMenu.NodeIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/monitoring/node_auth/\">MCSE Server Auth</a></li>")
    UserKeyMainMenu.ServerAuthDashboardMenu = template.HTML(TempString)
  } else if CurrentMenu == "nodeid" {
    TempString = fmt.Sprintf("<li><a href=\"/setting/smtp_display/\">Setting</a></li>")
    UserKeyMainMenu.Setting = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/userid/management/\">User ID</a></li>")
    UserKeyMainMenu.UserIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodekey/management/\">User Key</a></li>")
    UserKeyMainMenu.UserKeyIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/nodeid/management/\">Node ID</a></li>")
    UserKeyMainMenu.NodeIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/monitoring/node_auth/\">MCSE Server Auth</a></li>")
    UserKeyMainMenu.ServerAuthDashboardMenu = template.HTML(TempString)
  } else if CurrentMenu == "serverauth" {
    TempString = fmt.Sprintf("<li><a href=\"/setting/smtp_display/\">Setting</a></li>")
    UserKeyMainMenu.Setting = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/userid/management/\">User ID</a></li>")
    UserKeyMainMenu.UserIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodekey/management/\">User Key</a></li>")
    UserKeyMainMenu.UserKeyIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodeid/management/\">Node ID</a></li>")
    UserKeyMainMenu.NodeIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li class=\"current\"><a href=\"/monitoring/node_auth/\">MCSE Server Auth</a></li>")
    UserKeyMainMenu.ServerAuthDashboardMenu = template.HTML(TempString)
  } else {
    TempString = fmt.Sprintf("<li><a href=\"/setting/smtp_display/\">Setting</a></li>")
    UserKeyMainMenu.Setting = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/userid/management/\">User ID</a></li>")
    UserKeyMainMenu.UserIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodekey/management/\">User Key</a></li>")
    UserKeyMainMenu.UserKeyIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/nodeid/management/\">Node ID</a></li>")
    UserKeyMainMenu.NodeIDMenu = template.HTML(TempString)
    TempString = fmt.Sprintf("<li><a href=\"/monitoring/node_auth/\">MCSE Server Auth</a></li>")
    UserKeyMainMenu.ServerAuthDashboardMenu = template.HTML(TempString)
  }
  
  return RET_INT_SUCC
}


func WebServerOEMInformation (OEMData *OEMInformation) int {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var OEMName string
  var OEMWEBHeadInformation string
  var OEMWEBTailInformation string

  if OEMData == nil {
    log.Println("input argument is invalid")
    return RET_INT_FAIL
  }

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  QueryString = "SELECT OEM_NAME, OEM_WEB_HEAD_INFORMATION, OEM_WEB_TAIL_INFORMATION FROM kms_configure"
  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&OEMName, &OEMWEBHeadInformation, &OEMWEBTailInformation)
    if err != nil {
      ResultSetRows.Close()
      log.Println("oem web information db scan error:", err)
      return RET_INT_FAIL
    }
  }
  ResultSetRows.Close()

  OEMData.OEMName = OEMName
  OEMData.OEMWEBHeadInfo = OEMWEBHeadInformation 
  OEMData.OEMWEBTailInfo = OEMWEBTailInformation

  return RET_INT_SUCC
}


func WebServer_NodeKey_List(w http.ResponseWriter, req *http.Request){
	defer req.Body.Close()
  var Database *sql.DB
	var HtmlNodeKeyList NodeKeyList
  var NodeKey NodeKeyListItem
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var ResultSetRowCount int
  var URLGetParam string
  var PageNumString string
  var PageSortString string
  var SearchParamInitFlag bool
  var QueryString string
	var err error

  var MaxCountPage int = 10
  var MaxRowCountPerPage int = 25

  log.Println("KMS Web Server - Userkey_Management", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyList.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyList.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyList.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  PageNumString = HTTPReq_ReturnParamValue (req, "GET", "page_num")
  if len(PageNumString) == 0 {
    PageNumString = "1"  
  }
  
  PageSortString = HTTPReq_ReturnParamValue (req, "GET", "page_sort")
  if len(PageSortString) == 0 {
    PageSortString = "default"  
  }

  if req.Method == "GET" {
    HtmlNodeKeyList.SearchParamUserID = HTTPReq_ReturnParamValue(req, "GET", "user_id")
    HtmlNodeKeyList.SearchParamUserKey = HTTPReq_ReturnParamValue(req, "GET", "user_key")
    HtmlNodeKeyList.SearchParamEndDateFrom = HTTPReq_ReturnParamValue(req, "GET", "enddate_from")
    HtmlNodeKeyList.SearchParamEndDateTo = HTTPReq_ReturnParamValue(req, "GET", "enddate_to")
    HtmlNodeKeyList.SearchParamUserKeyStatus = HTTPReq_ReturnParamValue(req, "GET", "nodekey_status")
  } else {
    HtmlNodeKeyList.SearchParamUserID = HTTPReq_ReturnParamValue(req, "POST", "user_id")
    HtmlNodeKeyList.SearchParamUserKey = HTTPReq_ReturnParamValue(req, "POST", "user_key")
    HtmlNodeKeyList.SearchParamEndDateFrom = HTTPReq_ReturnParamValue(req, "POST", "enddate_from")
    HtmlNodeKeyList.SearchParamEndDateTo = HTTPReq_ReturnParamValue(req, "POST", "enddate_to")
    HtmlNodeKeyList.SearchParamUserKeyStatus = HTTPReq_ReturnParamValue(req, "POST", "nodekey_status")
  }

  SearchParamInitFlag = false

  if len(HtmlNodeKeyList.SearchParamUserID) > 0 {
    URLGetParam += fmt.Sprintf("&user_id=%s", HtmlNodeKeyList.SearchParamUserID)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (a.user_id = \"%s\")", HtmlNodeKeyList.SearchParamUserID)
    } else {
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (a.user_id = \"%s\")", HtmlNodeKeyList.SearchParamUserID)
    }
  }

  if len(HtmlNodeKeyList.SearchParamUserKey) > 0 {
    URLGetParam += fmt.Sprintf("&user_key=%s", HtmlNodeKeyList.SearchParamUserKey)
    
    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (b.user_key_id = \"%s\")", HtmlNodeKeyList.SearchParamUserKey)
    } else {
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (b.user_key_id = \"%s\")", HtmlNodeKeyList.SearchParamUserKey)
    }
  }

  if len(HtmlNodeKeyList.SearchParamEndDateFrom) > 0 {
    URLGetParam += fmt.Sprintf("&enddate_from=%s", HtmlNodeKeyList.SearchParamEndDateFrom)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (b.pkg_end_date >= STR_TO_DATE('%s','%%Y%%m%%d'))", HtmlNodeKeyList.SearchParamEndDateFrom)
    } else {
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (b.pkg_end_date >= STR_TO_DATE('%s','%%Y%%m%%d'))", HtmlNodeKeyList.SearchParamEndDateFrom)
    }
  }

  if len(HtmlNodeKeyList.SearchParamEndDateTo) > 0 {
    URLGetParam += fmt.Sprintf("&enddate_to=%s", HtmlNodeKeyList.SearchParamEndDateTo)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (b.pkg_end_date <= STR_TO_DATE('%s','%%Y%%m%%d'))", HtmlNodeKeyList.SearchParamEndDateTo)
    } else {
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (b.pkg_end_date <= STR_TO_DATE('%s','%%Y%%m%%d'))", HtmlNodeKeyList.SearchParamEndDateTo)
    }
  }

  if len(HtmlNodeKeyList.SearchParamUserKeyStatus) > 0 {
    URLGetParam += fmt.Sprintf("&nodekey_status=%s", HtmlNodeKeyList.SearchParamUserKeyStatus)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (b.status = \"%s\")", HtmlNodeKeyList.SearchParamUserKeyStatus)
    } else {
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (b.status = \"%s\")", HtmlNodeKeyList.SearchParamUserKeyStatus)
    }
  }

/*
  if len(HtmlNodeKeyList.SearchParamEndDateFrom) > 0 && len(HtmlNodeKeyList.SearchParamEndDateTo) > 0 {
    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (pkg_start_date >= \"%s\" AND pkg_end_date <=\"%s\")", HtmlNodeKeyList.SearchParamEndDateFrom, HtmlNodeKeyList.SearchParamEndDateTo)
    } else {
      HtmlNodeKeyList.SQLQueryCondition += " AND"
      HtmlNodeKeyList.SQLQueryCondition += fmt.Sprintf(" (pkg_start_date >= \"%s\" AND pkg_end_date <=\"%s\")", HtmlNodeKeyList.SearchParamEndDateFrom, HtmlNodeKeyList.SearchParamEndDateTo)
    }
  }
*/

  if len(HtmlNodeKeyList.SQLQueryCondition) > 0 {
    if HtmlNodeKeyList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT COUNT(b.user_key_id) " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id_seq = b.user_id_seq " +
                          "%s " +
                          "GROUP BY b.user_key_id " +
                          "ORDER BY b.create_date "
      HtmlNodeKeyList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyList.SQLQueryCondition)
    } else {
      QueryString = "SELECT COUNT(b.user_key_id) " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id = '%s' " +
                          "AND a.user_id_seq = b.user_id_seq " +
                          "%s " +
                          "GROUP BY b.user_key_id " +
                          "ORDER BY b.create_date "
      HtmlNodeKeyList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyList.CookiesData.CookieUserID, HtmlNodeKeyList.SQLQueryCondition)
    }
  
  } else {
    if HtmlNodeKeyList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT COUNT(b.user_key_id) " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id_seq = b.user_id_seq " +
                          "GROUP BY b.user_key_id " +
                          "ORDER BY b.create_date "
      HtmlNodeKeyList.SQLQuery = fmt.Sprintf(QueryString)
    } else {
      QueryString = "SELECT COUNT(b.user_key_id) " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id = '%s' " +
                          "AND a.user_id_seq = b.user_id_seq " +
                          "GROUP BY b.user_key_id " +
                          "ORDER BY b.create_date "
      HtmlNodeKeyList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyList.CookiesData.CookieUserID)
    }
  }

  log.Println("NodeKey List Count Query ->", HtmlNodeKeyList.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyList.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&ResultSetRowCount)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
  }
  ResultSetRows.Close()
  
  HtmlDataPage (&(HtmlNodeKeyList.TempletePage), "UserKeyPageNum", PageNumString, "UserKeySort", PageSortString, 0, MaxCountPage, MaxRowCountPerPage, ResultSetRowCount, "/nodekey/management/", URLGetParam, "/service_stop/", "[exception]", "redirect")

  if len(HtmlNodeKeyList.SQLQueryCondition) > 0 {
    if HtmlNodeKeyList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT a.user_id, b.user_key_id, b.node_client_count, b.pkg_end_date, b.create_date, b.update_date, b.status " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id_seq = b.user_id_seq " +
                          "%s " +
                    "GROUP BY b.user_key_id " +
                    "ORDER BY b.create_date " +
                    "LIMIT %d OFFSET %d "
      HtmlNodeKeyList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyList.SQLQueryCondition, HtmlNodeKeyList.TempletePage.MaxRowCountPage, HtmlNodeKeyList.TempletePage.RowOffset)

    } else {
      QueryString = "SELECT a.user_id, b.user_key_id, b.node_client_count, b.pkg_end_date, b.create_date, b.update_date, b.status " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id = '%s' " +
                          "AND a.user_id_seq = b.user_id_seq " +
                          "%s " +
                    "GROUP BY b.user_key_id " +
                    "ORDER BY b.create_date " +
                    "LIMIT %d OFFSET %d "
      HtmlNodeKeyList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyList.CookiesData.CookieUserID, HtmlNodeKeyList.SQLQueryCondition, HtmlNodeKeyList.TempletePage.MaxRowCountPage, HtmlNodeKeyList.TempletePage.RowOffset)
    }

  } else {
    if HtmlNodeKeyList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT a.user_id, b.user_key_id, b.node_client_count, b.pkg_end_date, b.create_date, b.update_date, b.status " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id_seq = b.user_id_seq " +
                    "GROUP BY b.user_key_id " +
                    "ORDER BY b.create_date " +
                    "LIMIT %d OFFSET %d "
      HtmlNodeKeyList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyList.TempletePage.MaxRowCountPage, HtmlNodeKeyList.TempletePage.RowOffset)
    } else {
      QueryString = "SELECT a.user_id, b.user_key_id, b.node_client_count, b.pkg_end_date, b.create_date, b.update_date, b.status " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id = '%s' " +
                          "AND a.user_id_seq = b.user_id_seq " +
                    "GROUP BY b.user_key_id " +
                    "ORDER BY b.create_date " +
                    "LIMIT %d OFFSET %d "
      HtmlNodeKeyList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyList.CookiesData.CookieUserID, HtmlNodeKeyList.TempletePage.MaxRowCountPage, HtmlNodeKeyList.TempletePage.RowOffset)
    }
  }

  log.Println("NodeKey List Limit Query ->", HtmlNodeKeyList.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyList.SQLQuery)
  for i := 0; ResultSetRows.Next(); i++ {
    err := ResultSetRows.Scan(&(NodeKey.UserID), 
                              &(NodeKey.NodeKey), 
                              &(NodeKey.ServiceNodeCount), 
                              &(NodeKey.EndDate), 
                              &(NodeKey.CreateDate), 
                              &(NodeKey.UpdateDate), 
                              &(NodeKey.Status))
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
  
    NodeKey.NodeKeyModifyLinkURL = fmt.Sprintf("/nodekey/modify_input/?user_id=%s&node_key=%s", NodeKey.UserID, NodeKey.NodeKey)
    NodeKey.NodeKeyReGenerateLinkURL = fmt.Sprintf("/nodekey/recreate_input/?user_id=%s&node_key=%s", NodeKey.UserID, NodeKey.NodeKey)
    NodeKey.NodeKeyNodeIDLinkURL = fmt.Sprintf("/nodeid/management/?user_id=%s&node_key=%s", NodeKey.UserID, NodeKey.NodeKey)
    NodeKey.NodeKeyLicenseLinkURL = fmt.Sprintf("/nodekey/license/?user_id=%s&node_key=%s", NodeKey.UserID, NodeKey.NodeKey)
    NodeKey.NodeKeyPackageLinkURL = fmt.Sprintf("/nodekey/package_input/?user_id=%s&node_key=%s", NodeKey.UserID, NodeKey.NodeKey)
    NodeKey.NodeKeyDeleteLinkURL = fmt.Sprintf("/nodekey/delete_input/?user_id=%s&node_key=%s", NodeKey.UserID, NodeKey.NodeKey)
    
    HtmlNodeKeyList.NodeKey = append(HtmlNodeKeyList.NodeKey, NodeKey)
  }

  for i := range HtmlNodeKeyList.NodeKey {
    log.Println("ResultRows Data :", HtmlNodeKeyList.NodeKey[i].UserID, HtmlNodeKeyList.NodeKey[i].NodeKey, HtmlNodeKeyList.NodeKey[i].ServiceNodeCount, HtmlNodeKeyList.NodeKey[i].EndDate, HtmlNodeKeyList.NodeKey[i].CreateDate, HtmlNodeKeyList.NodeKey[i].UpdateDate, HtmlNodeKeyList.NodeKey[i].Status)
  }

  ResultSetRows.Close()

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_list.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodekey_list.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlNodeKeyList)
}


func WebServer_NodeKey_Create_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var HtmlNodeKeyCreate NodeKeyCreate 
	var HtmlTemplate *template.Template
	var err error

  log.Println("KMS Web Server - Node_Key Create_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyCreate.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyCreate.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyCreate.OEMData)

  /*------------------------------------------------------------------------------------------
  if req.Method == "GET" {
    HtmlNodeKeyCreate.NodeKeyData.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
  } else if req.Method == "POST" {
    HtmlNodeKeyCreate.NodeKeyData.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }
  ------------------------------------------------------------------------------------------*/

  if HtmlNodeKeyCreate.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeKeyCreate.CookiesData.CookieUserProperty == "normal" {
    HtmlNodeKeyCreate.NodeKeyData.UserID = HtmlNodeKeyCreate.CookiesData.CookieUserID
    HtmlNodeKeyCreate.NodeKeyData.NodeKeyNew = GenerateNodeKey(nil, HtmlNodeKeyCreate.CookiesData.CookieUserID)
    log.Println("New NodeKey:", HtmlNodeKeyCreate.NodeKeyData.NodeKeyNew)

    if HtmlNodeKeyCreate.NodeKeyData.NodeKeyNew == "" {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }

    if DBSetTmpGenerateNodeKey(HtmlNodeKeyCreate.CookiesData.CookieUserID, HtmlNodeKeyCreate.NodeKeyData.NodeKeyNew) != 1 {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_create_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodekey_create_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlNodeKeyCreate)
}


func WebServer_NodeKey_Create_Proc (w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var ResultSetRows *sql.Rows
  var InputData jsonInputNodeKeyGenerate
  var InputNodeIDCount int
  var InputNodeKeyPeriodOfUse int
  var OutputData jsonOutputPack 
  var OutputBody string
  var TempGenerateNodeKeyHomePath string
  var TempGenerateNodeKey string
  var TempGenerateNodeID string
  var QueryString string
	var err error

  log.Println("KMS Web Server - NodeID Create Proc", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodekey")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "NODE ID CREATE"
    OutputData.MsgTitle = "NodeID Create"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if InputData.ActionMode == "" || InputData.ActionMode != "SET" || InputData.UserID == "" || InputData.NodeKey == "" || InputData.NodeIDCount == "" || InputData.PeriodOfUse == "" {
    OutputData.MsgType = "NODE KEY CREATE"
    OutputData.MsgTitle = "Node Key Create"
    OutputData.MsgMsg = "failed to decoding data of input json data (invalidion checking)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data (invalidion checking)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  InputNodeIDCount, err = strconv.Atoi(InputData.NodeIDCount)
  if err != nil {
    OutputData.MsgType = "NODE KEY CREATE"
    OutputData.MsgTitle = "Node Key Create"
    OutputData.MsgMsg = "failed to convert string to int (invalidion node id count)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to convert string to int (invalidion node id count)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  InputNodeKeyPeriodOfUse, err = strconv.Atoi(InputData.PeriodOfUse)
  if err != nil {
    OutputData.MsgType = "NODE KEY CREATE"
    OutputData.MsgTitle = "Node Key Create"
    OutputData.MsgMsg = "failed to convert string to int (invalidion node key period of use)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to convert string to int (invalidion node key period of use)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if (InputNodeIDCount <= 0 || InputNodeIDCount > 100 || InputNodeKeyPeriodOfUse <= 0 || InputNodeKeyPeriodOfUse > 1095) {
    OutputData.MsgType = "NODE KEY CREATE"
    OutputData.MsgTitle = "Node Key Create"
    OutputData.MsgMsg = "failed to convert string to int (invalidion input value)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to convert string to int (invalidion input value)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  log.Println("Input Data ( ActionMode:", InputData.ActionMode, ", UserID:", InputData.UserID, ", NodeKey:", InputData.NodeKey, ", NodeIDCount:", InputNodeIDCount, ", PeriodOfUse:", InputNodeKeyPeriodOfUse, ")")

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {
    
  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      OutputData.MsgType = "NODE KEY CREATE"
      OutputData.MsgTitle = "Node Key Create"
      OutputData.MsgMsg = "invalid user id access"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "invalid user id access"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
  } else {
    OutputData.MsgType = "NODE KEY CREATE"
    OutputData.MsgTitle = "Node Key Create"
    OutputData.MsgMsg = "invalid user id access"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid user id access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  QueryString = "SELECT nodekey_generate_tmp_key FROM user WHERE user_id = '%s' "
  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID)
  log.Println("Tmp Generating NodeKey Query -> ", CommonTemplete.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&TempGenerateNodeKey)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      OutputData.MsgType = "NODE KEY CREATE"
      OutputData.MsgTitle = "Node Key Create"
      OutputData.MsgMsg = "exception db query (tmp sync buffer)"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception db query (tmp sync buffer)"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      return
    }
  }
  ResultSetRows.Close()

  if TempGenerateNodeKey == "" || TempGenerateNodeKey != InputData.NodeKey {
    log.Println("Mismatching Tmp Generating NodeIDList:", InputData.NodeKey)

    OutputData.MsgType = "NODE KEY CREATE"
    OutputData.MsgTitle = "Node Key Create"
    OutputData.MsgMsg = "invalid input node_id (mismatching tmp generating node_key)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid input node_id (mismatching tmp generating node_key)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  mariadb_lib.DB_AutoCommit_Disable(Database)
  defer mariadb_lib.DB_Rollback(Database)
  defer mariadb_lib.DB_AutoCommit_Enable(Database)


  QueryString = "INSERT INTO user_key " +
                " (user_key_id, node_client_count, create_date, update_date, pkg_start_date, pkg_end_date, create_user_id, update_user_id, package_home_path, user_id_seq, nodeid_generate_tmp_key, status) " +
                " VALUES ('%s', %d, NOW(), NOW(), NOW(), DATE_ADD(NOW(), INTERVAL %d DAY), '%s', '%s', '%s', (SELECT user_id_seq FROM user WHERE user_id = '%s'), '', 'ENABLE') "

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.NodeKey, 0, InputNodeKeyPeriodOfUse, InputData.UserID, InputData.UserID, "", InputData.UserID)
  log.Println("NodeID Insert Query -> ", CommonTemplete.SQLQuery)
  mariadb_lib.Insert_Data(Database, CommonTemplete.SQLQuery)
  // TODO: DB Excxception (return cnt)

  ProcessPWD, err := os.Getwd()
  if err != nil {
    OutputData.MsgType = "NODE KEY CREATE"
    OutputData.MsgTitle = "Node Key Create"
    OutputData.MsgMsg = "system error (failed to process current exe path)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "system error (failed to process current exe path)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  // for easy directory movement
  ProcessPWD = "."  
  ProcessPWD = ProcessPWD + "/database" + "/package_home/"

  QueryString = "UPDATE user_key " +
                "SET package_home_path = CONCAT('%s', (SELECT home_path " +
                "                                      FROM (SELECT CONVERT(user_key_id_seq, CHAR) as home_path " +
                "                                            FROM user_key " +
                "                                            WHERE user_key_id = '%s') tmp)) " +
                "WHERE user_key_id = '%s' "

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, ProcessPWD, InputData.NodeKey, InputData.NodeKey)
  log.Println("NodeKey Package HomePath Update Query -> ", CommonTemplete.SQLQuery)
  mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
  // TODO: DB Excxception (return cnt)

  QueryString = "SELECT package_home_path FROM user_key WHERE user_key_id = '%s' "
  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.NodeKey)
  log.Println("NodeKey Package HomePath Query -> ", CommonTemplete.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for i := 0; ResultSetRows.Next(); i++ {
    err := ResultSetRows.Scan(&(TempGenerateNodeKeyHomePath))
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)
      return
    }
  }
  ResultSetRows.Close()

  if len(TempGenerateNodeKeyHomePath) == 0 {
    OutputData.MsgType = "NODE KEY CREATE"
    OutputData.MsgTitle = "Node Key Create"
    OutputData.MsgMsg = "db error (failed to node key pkg home path)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "db error (failed to node key pkg home path)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  // TODO
  err = os.Mkdir(TempGenerateNodeKeyHomePath, 0700)
  if err != nil {
    OutputData.MsgType = "NODE KEY CREATE"
    OutputData.MsgTitle = "Node Key Create"
    OutputData.MsgMsg = "db error (failed to mkdir node key pkg home path)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "db error (failed to mkdir node key pkg home path)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return

  } else if os.IsExist(err) {
    log.Println("Checking Message (Existed Node Key Package Home of Node key (path:", TempGenerateNodeKeyHomePath, ")")
  }



  for i := 0; i < InputNodeIDCount; i++ {
    TempGenerateNodeID = GenerateNodeID(Database, InputData.NodeKey)
    log.Println("Temporary Generate Node ID:", TempGenerateNodeID)

    if TempGenerateNodeID != "" && len(TempGenerateNodeID) >= 38 {

      log.Println("Insert NodeID IDX:", i, ", NodeID:", TempGenerateNodeID)

      QueryString = "INSERT INTO node_id " +
                    "(node_id, create_date, user_id_seq, create_user_id, update_user_id, user_key_id_seq, user_key_id, web_api_auth_key, web_api_auth_token, web_api_auth_token_expire_time_date) " +
                    "VALUES ('%s', " +
                    "        NOW(), " +
                    "        (SELECT user_id_seq FROM user WHERE user_id = '%s'), " +
                    "        '%s', " +
                    "        '%s', " +
                    "        (SELECT user_key_id_seq FROM user_key WHERE user_key_id = '%s'), " +
                    "        '%s', " +
                    "        '%s', " +
                    "        '%s', " +
                    "        NOW()) "
      CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, TempGenerateNodeID, InputData.UserID, InputData.UserID, InputData.UserID, InputData.NodeKey, InputData.NodeKey, "", "")
      log.Println("NodeID Insert Query -> ", CommonTemplete.SQLQuery)
	    mariadb_lib.Insert_Data(Database, CommonTemplete.SQLQuery)
      // TODO: DB Excxception (return cnt)

      QueryString = "UPDATE user_key " +
                    "SET node_client_count = node_client_count + 1 " +
                    "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                    "                         FROM (SELECT b.user_key_id_seq " +
                    "                               FROM user a, user_key b " +
                    "                               WHERE a.user_id = '%s' " +
                    "                                     and b.user_key_id = '%s' " +
                    "                                     and a.user_id_seq = b.user_id_seq) tmp)"
      CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey)
      log.Println("NodeID Count Update Query -> ", CommonTemplete.SQLQuery)
      mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
      // TODO: DB Excxception (return cnt)
    }
  }
  //------------------------------------//

  mariadb_lib.DB_Commit(Database)
  mariadb_lib.DB_AutoCommit_Enable(Database)

  OutputData.MsgType = "NODE KEY GENERATE"
  OutputData.MsgTitle = "Node Key Generate"
  OutputData.MsgMsg = "Generate NodeKey Success"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = "insert success"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


func WebServer_NodeKey_ReCreate_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlNodeKeyRegenerate NodeKeyRegenerate
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var ResultSetRowCount int
  var QueryString string
	var err error

  log.Println("KMS Web Server - Node_Key ReCreate_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyRegenerate.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyRegenerate.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyRegenerate.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeKeyRegenerate.NodeKeyRegenerate.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeKeyRegenerate.NodeKeyRegenerate.NodeKeyOld = HTTPReq_ReturnParamValue (req, "GET", "node_key")
  } else if req.Method == "POST" {
    HtmlNodeKeyRegenerate.NodeKeyRegenerate.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeKeyRegenerate.NodeKeyRegenerate.NodeKeyOld = HTTPReq_ReturnParamValue (req, "POST", "node_key")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if len(HtmlNodeKeyRegenerate.NodeKeyRegenerate.UserID) == 0 || len(HtmlNodeKeyRegenerate.NodeKeyRegenerate.NodeKeyOld) == 0 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyRegenerate.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeKeyRegenerate.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeKeyRegenerate.CookiesData.CookieUserID != HtmlNodeKeyRegenerate.NodeKeyRegenerate.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT count(b.user_key_id_seq) " +
                "FROM user a, user_key b " +
                "WHERE a.user_id = '%s' " +
                      "and b.user_key_id = '%s' " +
                      "and a.user_id_seq = b.user_id_seq "

  HtmlNodeKeyRegenerate.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyRegenerate.NodeKeyRegenerate.UserID, HtmlNodeKeyRegenerate.NodeKeyRegenerate.NodeKeyOld)
  log.Println("NodeKey List Count Query (by user_id, node_key): ", HtmlNodeKeyRegenerate.SQLQuery)
  
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyRegenerate.SQLQuery)
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

  if ResultSetRowCount != 1 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  HtmlNodeKeyRegenerate.NodeKeyRegenerate.NodeKeyNew = GenerateNodeKey(nil, HtmlNodeKeyRegenerate.NodeKeyRegenerate.UserID)
  log.Println("New NodeKey:", HtmlNodeKeyRegenerate.NodeKeyRegenerate.NodeKeyNew)

  if HtmlNodeKeyRegenerate.NodeKeyRegenerate.NodeKeyNew == "" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if DBSetTmpGenerateNodeKey(HtmlNodeKeyRegenerate.NodeKeyRegenerate.UserID, HtmlNodeKeyRegenerate.NodeKeyRegenerate.NodeKeyNew) != 1 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_recreate_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodekey_recreate_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlNodeKeyRegenerate)
}


func WebServer_NodeKey_ReCreate_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var ResultSetRows *sql.Rows
  var InputData jsonInputNodeKeyRegenerate
  var OutputData jsonOutputPack 
  var OutputBody string
  var TmpGenerateNodeKey string
  var QueryString string
	var err error

  log.Println("KMS Web Server - Node_Key ReCreate_Proc", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodekey")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    OutputData.MsgType = "NODE KEY REGENERATE"
    OutputData.MsgTitle = "Node Key Regenerate"
    OutputData.MsgMsg = "invalid request method"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid request method"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "NODE KEY REGENERATE"
    OutputData.MsgTitle = "Node Key Regenerate"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if InputData.ActionMode == "" || InputData.UserID == "" || InputData.NodeKeyOld == "" || InputData.NodeKeyNew == "" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {

  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT nodekey_generate_tmp_key " +
                "FROM user " +
                "WHERE user_id = '%s' " +
                      "and user_id_seq = (SELECT user_id_seq " +
                                         "FROM user_key " +
                                         "WHERE user_key_id = '%s') "

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKeyOld)
  log.Println("Tmp Generating NodeKey Query -> ", CommonTemplete.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&TmpGenerateNodeKey)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      OutputData.MsgType = "NODE KEY REGENERATE"
      OutputData.MsgTitle = "Node Key Regenerate"
      OutputData.MsgMsg = "exception db query"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception db query"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      return
    }
  }
  ResultSetRows.Close()

  if TmpGenerateNodeKey == "" || TmpGenerateNodeKey != InputData.NodeKeyNew {
    log.Println("Mismatching Tmp Generating NodeKey:", TmpGenerateNodeKey, ", Input NodeKeyNew:", InputData.NodeKeyNew)

    OutputData.MsgType = "NODE KEY REGENERATE"
    OutputData.MsgTitle = "Node Key Regenerate"
    OutputData.MsgMsg = "invalid input node_key (mismatching tmp generating node_key)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid input node_key (mismatching tmp generating node_key)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  QueryString = "UPDATE user_key " +
                "SET user_key_id = '%s' " +
                "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                                         "FROM (SELECT b.user_key_id_seq " +
                                               "FROM user a, user_key b " +
                                               "WHERE a.user_id = '%s' " +
                                                     "and b.user_key_id = '%s' " +
                                                     "and a.user_id_seq = b.user_id_seq) tmp) "

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.NodeKeyNew, InputData.UserID, InputData.NodeKeyOld)
  log.Println("Tmp Generating NodeKey Update Query -> ", CommonTemplete.SQLQuery)

	mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
  // TODO: DB Excxception

  log.Println("Update Success : Change NodeKey Information (", InputData.NodeKeyOld, "->", InputData.NodeKeyNew)

  if DBSetTmpGenerateNodeKey(InputData.UserID, "") != 1 {
    OutputData.MsgType = "NODE KEY REGENERATE"
    OutputData.MsgTitle = "Node Key Regenerate"
    OutputData.MsgMsg = "exception db query"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "exception db query"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  OutputData.MsgType = "NODE KEY REGENERATE"
  OutputData.MsgTitle = "Node Key Regenerate"
  OutputData.MsgMsg = "Generate NodeKey"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = TmpGenerateNodeKey

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


func WebServer_NodeKey_Modify_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var HtmlNodeKeyModify NodeKeyModify
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var NodeKeyNodeIDCountMax int
  var NodeKeyNodeIDCount int
  var NodeKeyStatus string
  var NodeKeyPackageEndYear string
  var NodeKeyPackageEndMonth string
  var NodeKeyPackageEndDay string
  var NodeKeyPackageHomePath string
  var NodeIDRowData string
  var QueryString string
	var err error

  log.Println("KMS Web Server - Node_Key Modify_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyModify.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyModify.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyModify.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeKeyModify.NodeKeyData.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeKeyModify.NodeKeyData.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
  } else if req.Method == "POST" {
    HtmlNodeKeyModify.NodeKeyData.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeKeyModify.NodeKeyData.NodeKey = HTTPReq_ReturnParamValue (req, "POST", "node_key")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyModify.NodeKeyData.UserID == "" || HtmlNodeKeyModify.NodeKeyData.NodeKey == "" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyModify.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeKeyModify.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeKeyModify.CookiesData.CookieUserID != HtmlNodeKeyModify.NodeKeyData.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT 100, node_client_count, status, DATE_FORMAT(pkg_end_date, '%%Y'), DATE_FORMAT(pkg_end_date, '%%m'), DATE_FORMAT(pkg_end_date, '%%d'), package_home_path " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " +
                "      and user_id_seq = (SELECT user_id_seq " +
                "                         FROM user " +
                "                         WHERE user_id = '%s') "
  HtmlNodeKeyModify.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyModify.NodeKeyData.NodeKey, HtmlNodeKeyModify.NodeKeyData.UserID)
  log.Println("NodeKey Information Query :", HtmlNodeKeyModify.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyModify.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeKeyNodeIDCountMax,
                              &NodeKeyNodeIDCount,
                              &NodeKeyStatus,
                              &NodeKeyPackageEndYear,
                              &NodeKeyPackageEndMonth,
                              &NodeKeyPackageEndDay,
                              &NodeKeyPackageHomePath)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }
  }
  ResultSetRows.Close()
  
  if NodeKeyNodeIDCountMax == 0 || len(NodeKeyPackageEndYear) == 0 || len(NodeKeyPackageEndMonth) == 0 || len(NodeKeyPackageEndDay) == 0 || len(NodeKeyPackageHomePath) == 0 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  HtmlNodeKeyModify.NodeKeyData.NodeIDMaxCount = NodeKeyNodeIDCountMax
  HtmlNodeKeyModify.NodeKeyData.NodeIDCount = NodeKeyNodeIDCount 
  HtmlNodeKeyModify.NodeKeyData.Status = NodeKeyStatus
  HtmlNodeKeyModify.NodeKeyData.EndDateYear = NodeKeyPackageEndYear
  HtmlNodeKeyModify.NodeKeyData.EndDateMonth = NodeKeyPackageEndMonth
  HtmlNodeKeyModify.NodeKeyData.EndDateDay = NodeKeyPackageEndDay

  QueryString = "SELECT b.node_id " +
                "FROM user_key a, node_id b " +
                "WHERE a.user_key_id = '%s' " +
                "      and a.user_id_seq = (SELECT user_id_seq  " +
                "                           FROM user " +
                "                           WHERE user_id = '%s') " +
                "      and a.user_key_id_seq = b.user_key_id_seq "
  HtmlNodeKeyModify.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyModify.NodeKeyData.NodeKey, HtmlNodeKeyModify.NodeKeyData.UserID)
  log.Println("NodeID List Information Query :", HtmlNodeKeyModify.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyModify.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeIDRowData)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }

    if len(NodeIDRowData) > 0 {
      HtmlNodeKeyModify.NodeKeyData.NodeID = append (HtmlNodeKeyModify.NodeKeyData.NodeID, NodeIDRowData)
    }
  }
  ResultSetRows.Close()

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_modify_input.html")
  if err != nil {
    log.Println("failed to HtmlTemplate.ParseFiles (./html/kms_nodekey_modify_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

  HtmlNodeKeyModify.NodeKeyData.ResultMsg = "Create Package Data"
	HtmlTemplate.Execute(w, HtmlNodeKeyModify)
}


func WebServer_NodeKey_Modify_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var InputData jsonInputNodeKeyModifyPack 
  var OutputData jsonOutputPack 
  var OutputBody string
  var ResultSetRows *sql.Rows
  var QueryString string
  var NodeKeyCheck string
  var NodeIDCreateCount int
  var TempGenerateNodeID string
  var NodeIDCurrentCount int
  var NodeIDModifyCount int
	var err error

  log.Println("KMS Web Server - Node_Key Modify_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodekey")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "NODE KEY MODIFY"
    OutputData.MsgTitle = "NodeKey Modify"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  log.Println("InputData.UserID-", InputData.UserID)
  log.Println("InputData.NodeKey-", InputData.NodeKey)
  log.Println("InputData.NodeKeyNodeIDMaxCount-", InputData.NodeKeyNodeIDMaxCount)
  log.Println("InputData.NodeKeyNodeIDCurrentCount-", InputData.NodeKeyNodeIDCurrentCount)
  log.Println("InputData.NodeKeyEndDateCurrentYear-", InputData.NodeKeyEndDateCurrentYear)
  log.Println("InputData.NodeKeyEndDateCurrentMonth-", InputData.NodeKeyEndDateCurrentMonth)
  log.Println("InputData.NodeKeyEndDateCurrentDay-", InputData.NodeKeyEndDateCurrentDay)
  log.Println("InputData.NodeKeyCurrentStatus-", InputData.NodeKeyCurrentStatus)
  log.Println("InputData.NodeKeyNodeIDModifyCount-", InputData.NodeKeyNodeIDModifyCount)
  log.Println("InputData.NodeKeyEndDateModifyYear-", InputData.NodeKeyEndDateModifyYear)
  log.Println("InputData.NodeKeyEndDateModifyMonth-", InputData.NodeKeyEndDateModifyMonth)
  log.Println("InputData.NodeKeyEndDateModifyDay-", InputData.NodeKeyEndDateModifyDay)
  log.Println("InputData.NodeKeyModifyStatus-", InputData.NodeKeyModifyStatus)
  


  if InputData.UserID == "" || InputData.NodeKey == "" || InputData.NodeKeyNodeIDMaxCount == "" ||
      InputData.NodeKeyNodeIDCurrentCount == "" || InputData.NodeKeyEndDateCurrentYear == "" || InputData.NodeKeyEndDateCurrentMonth == "" || InputData.NodeKeyEndDateCurrentDay == "" || InputData.NodeKeyCurrentStatus == "" ||
      InputData.NodeKeyNodeIDModifyCount == "" || InputData.NodeKeyEndDateModifyYear == "" || InputData.NodeKeyEndDateModifyMonth == "" || InputData.NodeKeyEndDateModifyDay == "" || InputData.NodeKeyModifyStatus == "" {

    OutputData.MsgType = "NODE KEY MODIFY"
    OutputData.MsgTitle = "NodeKey Modify"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {
    
  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      OutputData.MsgType = "NODE KEY MODIFY"
      OutputData.MsgTitle = "NodeKey Modify"
      OutputData.MsgMsg = "invalid user id access"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "invalid user id access"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
  } else {
    OutputData.MsgType = "NODE KEY MODIFY"
    OutputData.MsgTitle = "NodeKey Modify"
    OutputData.MsgMsg = "invalid user id access"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid user id access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  NodeIDCurrentCount, err = strconv.Atoi(InputData.NodeKeyNodeIDCurrentCount)
  if err != nil {
    OutputData.MsgType = "NODE KEY MODIFY"
    OutputData.MsgTitle = "NodeKey Modify"
    OutputData.MsgMsg = "err strconv node id current count"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "err strconv node id current count"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  NodeIDModifyCount, err = strconv.Atoi(InputData.NodeKeyNodeIDModifyCount)
  if err != nil {
    OutputData.MsgType = "NODE KEY MODIFY"
    OutputData.MsgTitle = "NodeKey Modify"
    OutputData.MsgMsg = "err strconv node id modify count"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "err strconv node id modify count"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  NodeIDCreateCount = NodeIDModifyCount - NodeIDCurrentCount
  if NodeIDCreateCount < 0 {
    OutputData.MsgType = "NODE KEY MODIFY"
    OutputData.MsgTitle = "NodeKey Modify"
    OutputData.MsgMsg = "invalid node id count"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid node id count"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  mariadb_lib.DB_AutoCommit_Disable(Database)
  defer mariadb_lib.DB_Rollback(Database)
  defer mariadb_lib.DB_AutoCommit_Enable(Database)

  QueryString = "SELECT user_key_id " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " +
                      "and node_client_count = %s " +
                      "and DATE_FORMAT(pkg_end_date, '%%Y-%%m-%%d') = '%s-%s-%s' " +
                      "and status = '%s' " +
                      "and user_id_seq = (SELECT user_id_seq " +
                                         "FROM user " +
                                         "WHERE user_id = '%s') " 

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.NodeKey, 
                                        InputData.NodeKeyNodeIDCurrentCount, 
                                        InputData.NodeKeyEndDateCurrentYear, 
                                        InputData.NodeKeyEndDateCurrentMonth, 
                                        InputData.NodeKeyEndDateCurrentDay, 
                                        InputData.NodeKeyCurrentStatus, 
                                        InputData.UserID)
  log.Println("NodeKey Information Query :", CommonTemplete.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeKeyCheck)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }
  }
  ResultSetRows.Close()

  if len(NodeKeyCheck) == 0 {
    OutputData.MsgType = "NODE KEY MODIFY"
    OutputData.MsgTitle = "NodeKey Modify"
    OutputData.MsgMsg = "db query failed to database query (checking node key)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "db query failed to database query (checking valid node key)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  QueryString = "UPDATE user_key " +
                "SET node_client_count = %s, pkg_end_date = STR_TO_DATE('%s-%s-%s','%%Y-%%m-%%d'), update_date = now(), status = '%s' " +
                "WHERE user_key_id = '%s' " +
                      "and node_client_count = %s " +
                      "and DATE_FORMAT(pkg_end_date, '%%Y-%%m-%%d') = '%s-%s-%s' " +
                      "and status = '%s' " +
                      "and user_id_seq = (SELECT user_id_seq " +
                                         "FROM user " +
                                         "WHERE user_id = '%s') "
  
  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, 
                                        InputData.NodeKeyNodeIDModifyCount, 
                                        InputData.NodeKeyEndDateModifyYear, 
                                        InputData.NodeKeyEndDateModifyMonth, 
                                        InputData.NodeKeyEndDateModifyDay, 
                                        InputData.NodeKeyModifyStatus,
                                        InputData.NodeKey,
                                        InputData.NodeKeyNodeIDCurrentCount, 
                                        InputData.NodeKeyEndDateCurrentYear, 
                                        InputData.NodeKeyEndDateCurrentMonth, 
                                        InputData.NodeKeyEndDateCurrentDay, 
                                        InputData.NodeKeyCurrentStatus,
                                        InputData.UserID)
  log.Println("NodeKey Update Query -> ", CommonTemplete.SQLQuery)

	mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
  // TODO: DB Excxception

  for i := 0; i < NodeIDCreateCount; i++ {
    TempGenerateNodeID = GenerateNodeID(Database, InputData.NodeKey)
    log.Println("Temporary Generate Node ID:", TempGenerateNodeID)

    if TempGenerateNodeID != "" && len(TempGenerateNodeID) >= 38 {

      log.Println("Insert NodeID IDX:", i, ", NodeID:", TempGenerateNodeID)

      QueryString = "INSERT INTO node_id " +
                    "(node_id, create_date, user_id_seq, create_user_id, update_user_id, user_key_id_seq, user_key_id) " +
                    "VALUES ('%s', " +
                    "        NOW(), " +
                    "        (SELECT user_id_seq FROM user WHERE user_id = '%s'), " +
                    "        '%s', " +
                    "        '%s', " +
                    "        (SELECT user_key_id_seq FROM user_key WHERE user_key_id = '%s'), " +
                    "        '%s') "
      CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, TempGenerateNodeID, InputData.UserID, InputData.UserID, InputData.UserID, InputData.NodeKey, InputData.NodeKey)
      log.Println("NodeID Insert Query -> ", CommonTemplete.SQLQuery)
	    mariadb_lib.Insert_Data(Database, CommonTemplete.SQLQuery)
      // TODO: DB Excxception (return cnt)
    }
  }

  mariadb_lib.DB_Commit(Database)
  mariadb_lib.DB_AutoCommit_Enable(Database)

  OutputData.MsgType = "NODE KEY MODIFY"
  OutputData.MsgTitle = "NodeKey Modify"
  OutputData.MsgMsg = "node key delete and node id delete"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = "node key delete and node id delete"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


func WebServer_NodeKey_Delete_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlNodeKeyDelete NodeKeyDelete
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var NodeKeyNodeIDCountMax int
  var NodeKeyNodeIDCount int
  var NodeKeyPackageEndYear string
  var NodeKeyPackageEndMonth string
  var NodeKeyPackageEndDay string
  var NodeKeyPackageHomePath string
  var NodeIDRowData string
  var QueryString string
	var err error

  log.Println("KMS Web Server - Node_Key Delete_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyDelete.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyDelete.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyDelete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeKeyDelete.NodeKeyData.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeKeyDelete.NodeKeyData.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
  } else if req.Method == "POST" {
    HtmlNodeKeyDelete.NodeKeyData.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeKeyDelete.NodeKeyData.NodeKey = HTTPReq_ReturnParamValue (req, "POST", "node_key")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if len(HtmlNodeKeyDelete.NodeKeyData.UserID) == 0 || len(HtmlNodeKeyDelete.NodeKeyData.NodeKey) == 0 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyDelete.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeKeyDelete.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeKeyDelete.CookiesData.CookieUserID != HtmlNodeKeyDelete.NodeKeyData.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT 100, node_client_count, DATE_FORMAT(pkg_end_date, '%%Y'), DATE_FORMAT(pkg_end_date, '%%m'), DATE_FORMAT(pkg_end_date, '%%d'), package_home_path " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " +
                      "and user_id_seq = (SELECT user_id_seq " +
                                         "FROM user " +
                                         "WHERE user_id = '%s') "
  HtmlNodeKeyDelete.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyDelete.NodeKeyData.NodeKey, HtmlNodeKeyDelete.NodeKeyData.UserID)
  log.Println("NodeKey Information Query :", HtmlNodeKeyDelete.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyDelete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeKeyNodeIDCountMax,
                              &NodeKeyNodeIDCount,
                              &NodeKeyPackageEndYear,
                              &NodeKeyPackageEndMonth,
                              &NodeKeyPackageEndDay,
                              &NodeKeyPackageHomePath)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }
  }
  ResultSetRows.Close()
  
  if NodeKeyNodeIDCountMax == 0 || len(NodeKeyPackageEndYear) == 0 || len(NodeKeyPackageEndMonth) == 0 || len(NodeKeyPackageEndDay) == 0 || len(NodeKeyPackageHomePath) == 0 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  HtmlNodeKeyDelete.NodeKeyData.NodeIDMaxCount = NodeKeyNodeIDCountMax
  HtmlNodeKeyDelete.NodeKeyData.NodeIDCount = NodeKeyNodeIDCount 
  HtmlNodeKeyDelete.NodeKeyData.EndDate = NodeKeyPackageEndYear + "-" + NodeKeyPackageEndMonth + "-" + NodeKeyPackageEndDay

  QueryString = "SELECT b.node_id " +
                "FROM user_key a, node_id b " +
                "WHERE a.user_key_id = '%s' " +
                      "and a.user_id_seq = (SELECT user_id_seq  " +
                                           "FROM user " +
                                           "WHERE user_id = '%s') " +
                                                 "and a.user_key_id_seq = b.user_key_id_seq "
  HtmlNodeKeyDelete.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyDelete.NodeKeyData.NodeKey, HtmlNodeKeyDelete.NodeKeyData.UserID)
  log.Println("NodeID List Information Query :", HtmlNodeKeyDelete.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyDelete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeIDRowData)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }

    if len(NodeIDRowData) > 0 {
      HtmlNodeKeyDelete.NodeKeyData.NodeID = append (HtmlNodeKeyDelete.NodeKeyData.NodeID, NodeIDRowData)
    }
  }
  ResultSetRows.Close()

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_delete_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodekey_delete_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

  HtmlNodeKeyDelete.NodeKeyData.ResultMsg = "Delete NodeKey Data"
	HtmlTemplate.Execute(w, HtmlNodeKeyDelete)
}


func WebServer_NodeKey_Delete_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var InputData jsonInputNodeKeyDeletePack 
  var OutputData jsonOutputPack 
  var OutputBody string
  var NodeKeyPackageHomePath string
  var ResultSetRows *sql.Rows
  var QueryString string
  var RetResult bool
	var err error

  log.Println("KMS Web Server - Node_Key Delete_Proc", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodekey")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "NODE KEY DELETE"
    OutputData.MsgTitle = "NodeKey Delete"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if InputData.UserID == "" || InputData.NodeKey == "" {
    OutputData.MsgType = "NODE KEY DELETE"
    OutputData.MsgTitle = "NodeKey Delete"
    OutputData.MsgMsg = "1failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "1failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {
    
  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      OutputData.MsgType = "NODE KEY DELETE"
      OutputData.MsgTitle = "NodeKey Delete"
      OutputData.MsgMsg = "invalid user id access"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "invalid user id access"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
  } else {
    OutputData.MsgType = "NODE KEY DELETE"
    OutputData.MsgTitle = "NodeKey Delete"
    OutputData.MsgMsg = "invalid user id access"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid user id access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  mariadb_lib.DB_AutoCommit_Disable(Database)
  defer mariadb_lib.DB_Rollback(Database)
  defer mariadb_lib.DB_AutoCommit_Enable(Database)

  QueryString = "SELECT package_home_path " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " +
                "      and user_id_seq = (SELECT user_id_seq " +
                "                         FROM user " +
                "                         WHERE user_id = '%s') "
  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.NodeKey, InputData.UserID)
  log.Println("NodeKey Information Query :", CommonTemplete.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeKeyPackageHomePath)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }
  }
  ResultSetRows.Close()

  if len(NodeKeyPackageHomePath) == 0 {
    OutputData.MsgType = "NODE KEY DELETE"
    OutputData.MsgTitle = "NodeKey Delete"
    OutputData.MsgMsg = "db query failed to database query (package_home_path)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "db query failed to database query (package_home_path)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  QueryString = "DELETE FROM node_id " +
                "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                                         "FROM user a, user_key b " +
                                         "WHERE a.user_id = '%s' " +
                                               "and a.user_id_seq = b.user_id_seq " +
                                               "and b.user_key_id = '%s') "

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey)
  log.Println("NodeID Delete Query -> ", CommonTemplete.SQLQuery)

	mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
  // TODO: DB Excxception

  QueryString = "DELETE FROM user_key " +
                "WHERE user_key.user_key_id = '%s' " +
                      "and user_id_seq = (SELECT user_id_seq " +
                                         "FROM user " +
                                         "WHERE user_id = '%s') "

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.NodeKey, InputData.UserID)
  log.Println("NodeID Count Update Query -> ", CommonTemplete.SQLQuery)

	mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
  // TODO: DB Excxception

  RetResult = disk.IsExistDirectoryPath(NodeKeyPackageHomePath)
  if RetResult != true {
    log.Println("Failed to Checking NodeKey Package Home Directory (path:", NodeKeyPackageHomePath, ")")
  } else {
    RetResult = disk.RemoveDirectoryPath(NodeKeyPackageHomePath)
    if RetResult != true {
      log.Println("Delete Fail - Directory of NodeKey Package Home Path (path:", NodeKeyPackageHomePath, ")")
    } else {
      log.Println("Delete Succ - Directory of NodeKey Package Home Path (path:", NodeKeyPackageHomePath, ")")
    }
  }

  mariadb_lib.DB_Commit(Database)
  mariadb_lib.DB_AutoCommit_Enable(Database)

  OutputData.MsgType = "NODE KEY DELETE"
  OutputData.MsgTitle = "NodeKey Delete"
  OutputData.MsgMsg = "node key delete and node id delete"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = "node key delete and node id delete"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


func WebServer_NodeKey_License(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var HtmlNodeKeyLicense NodeKeyLicense
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var NodeKeyNodeIDCountMax int
  var NodeKeyNodeIDCount int
  var NodeKeyPackageEndYear string
  var NodeKeyPackageEndMonth string
  var NodeKeyPackageEndDay string
  var NodeKeyPackageHomePath string
  var NodeIDRowData string
  var QueryString string
	var err error

  log.Println("KMS Web Server - Node_Key License", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyLicense.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyLicense.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyLicense.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeKeyLicense.NodeKeyLicense.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeKeyLicense.NodeKeyLicense.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
  } else if req.Method == "POST" {
    HtmlNodeKeyLicense.NodeKeyLicense.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeKeyLicense.NodeKeyLicense.NodeKey = HTTPReq_ReturnParamValue (req, "POST", "node_key")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyLicense.NodeKeyLicense.UserID == "" || HtmlNodeKeyLicense.NodeKeyLicense.NodeKey == "" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyLicense.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeKeyLicense.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeKeyLicense.CookiesData.CookieUserID != HtmlNodeKeyLicense.NodeKeyLicense.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT 100, node_client_count, DATE_FORMAT(pkg_end_date, '%%Y'), DATE_FORMAT(pkg_end_date, '%%m'), DATE_FORMAT(pkg_end_date, '%%d'), package_home_path " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " +
                "      and user_id_seq = (SELECT user_id_seq " +
                "                         FROM user " +
                "                         WHERE user_id = '%s') "
  HtmlNodeKeyLicense.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyLicense.NodeKeyLicense.NodeKey, HtmlNodeKeyLicense.NodeKeyLicense.UserID)
  log.Println("NodeKey Information Query :", HtmlNodeKeyLicense.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyLicense.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeKeyNodeIDCountMax,
                              &NodeKeyNodeIDCount,
                              &NodeKeyPackageEndYear,
                              &NodeKeyPackageEndMonth,
                              &NodeKeyPackageEndDay,
                              &NodeKeyPackageHomePath)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }
  }
  ResultSetRows.Close()
  
  if NodeKeyNodeIDCountMax == 0 || len(NodeKeyPackageEndYear) == 0 || len(NodeKeyPackageEndMonth) == 0 || len(NodeKeyPackageEndDay) == 0 || len(NodeKeyPackageHomePath) == 0 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  HtmlNodeKeyLicense.NodeKeyLicense.NodeIDMaxCount = NodeKeyNodeIDCountMax
  HtmlNodeKeyLicense.NodeKeyLicense.NodeIDCount = NodeKeyNodeIDCount 
  HtmlNodeKeyLicense.NodeKeyLicense.EndDate = NodeKeyPackageEndYear + "-" + NodeKeyPackageEndMonth + "-" + NodeKeyPackageEndDay

  QueryString = "SELECT b.node_id " +
                "FROM user_key a, node_id b " +
                "WHERE a.user_key_id = '%s' " +
                "      and a.user_id_seq = (SELECT user_id_seq  " +
                "                           FROM user " +
                "                           WHERE user_id = '%s') " +
                "      and a.user_key_id_seq = b.user_key_id_seq "
  HtmlNodeKeyLicense.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyLicense.NodeKeyLicense.NodeKey, HtmlNodeKeyLicense.NodeKeyLicense.UserID)
  log.Println("NodeID List Information Query :", HtmlNodeKeyLicense.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyLicense.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeIDRowData)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }

    if len(NodeIDRowData) > 0 {
      HtmlNodeKeyLicense.NodeKeyLicense.NodeID = append (HtmlNodeKeyLicense.NodeKeyLicense.NodeID, NodeIDRowData)
    }
  }
  ResultSetRows.Close()


  HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_license.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodekey_license.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }
  
  HtmlNodeKeyLicense.NodeKeyLicense.ResultMsg = "Create Package Data"
  HtmlTemplate.Execute(w, HtmlNodeKeyLicense)
}


func WebServer_NodeKey_Package_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlNodeKeyPackage NodeKeyPackage 
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var NodeKeyNodeIDCountMax int
  var NodeKeyNodeIDCount int
  var QueryString string
	var err error

  log.Println("KMS Web Server - Node_Key Package_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyPackage.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyPackage.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyPackage.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeKeyPackage.NodeKeyPackage.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeKeyPackage.NodeKeyPackage.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
  } else if req.Method == "POST" {
    HtmlNodeKeyPackage.NodeKeyPackage.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeKeyPackage.NodeKeyPackage.NodeKey = HTTPReq_ReturnParamValue (req, "POST", "node_key")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyPackage.NodeKeyPackage.UserID == "" || HtmlNodeKeyPackage.NodeKeyPackage.NodeKey == "" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyPackage.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeKeyPackage.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeKeyPackage.CookiesData.CookieUserID != HtmlNodeKeyPackage.NodeKeyPackage.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT 100, node_client_count " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " +
                "      and user_id_seq = (SELECT user_id_seq " +
                "                         FROM user " +
                "                         WHERE user_id = '%s') "
  HtmlNodeKeyPackage.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyPackage.NodeKeyPackage.NodeKey, HtmlNodeKeyPackage.NodeKeyPackage.UserID)
  log.Println("NodeKey Information Query :", HtmlNodeKeyPackage.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyPackage.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeKeyNodeIDCountMax, &NodeKeyNodeIDCount)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }
  }
  ResultSetRows.Close()

  HtmlNodeKeyPackage.NodeKeyPackage.NodeIDCount = NodeKeyNodeIDCount 
  HtmlNodeKeyPackage.NodeKeyPackage.NodeIDMaxCount = NodeKeyNodeIDCountMax

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_package_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodekey_package_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlNodeKeyPackage)
}


func WebServer_NodeKey_License_Email_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlNodeKeyLicenseEmail NodeKeyLicenseEmail 
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var NodeIDRowData string
  var QueryString string
	var err error

  log.Println("KMS Web Server - Node_Key Package_Proc", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyLicenseEmail.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyLicenseEmail.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyLicenseEmail.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.ActionMode = HTTPReq_ReturnParamValue (req, "GET", "action_mode")
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
  } else if req.Method == "POST" {
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.ActionMode = HTTPReq_ReturnParamValue (req, "POST", "action_mode")
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeKey = HTTPReq_ReturnParamValue (req, "POST", "node_key")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyLicenseEmail.NodeKeyLicense.ActionMode == "" || HtmlNodeKeyLicenseEmail.NodeKeyLicense.ActionMode != "LICENSE" || HtmlNodeKeyLicenseEmail.NodeKeyLicense.UserID == "" || HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeKey == "" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  log.Println("Input Data ( ActionMode:", HtmlNodeKeyLicenseEmail.NodeKeyLicense.ActionMode, ", UserID:", HtmlNodeKeyLicenseEmail.NodeKeyLicense.UserID, ", NodeKey:", HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeKey, ")")

  if HtmlNodeKeyLicenseEmail.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeKeyLicenseEmail.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeKeyLicenseEmail.CookiesData.CookieUserID != HtmlNodeKeyLicenseEmail.NodeKeyLicense.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT 100, node_client_count, DATE_FORMAT(pkg_end_date, '%%Y-%%m-%%d') " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " +
                "      and user_id_seq = (SELECT user_id_seq " +
                "                         FROM user " +
                "                         WHERE user_id = '%s') "
  HtmlNodeKeyLicenseEmail.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeKey, HtmlNodeKeyLicenseEmail.NodeKeyLicense.UserID)
  log.Println("NodeKey Information Query :", HtmlNodeKeyLicenseEmail.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyLicenseEmail.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeIDMaxCount,
                              &HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeIDCount,
                              &HtmlNodeKeyLicenseEmail.NodeKeyLicense.EndDate)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }
  }
  ResultSetRows.Close()

  if HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeIDMaxCount == 0 || HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeIDCount == 0 || len(HtmlNodeKeyLicenseEmail.NodeKeyLicense.EndDate) == 0 {
    // TODO
    HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_create_input.html")
    if err != nil {
      log.Println("failed to template.ParseFiles (./html/kms_nodekey_create_input.html)")
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
    
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.ResultMsg = "Create Package Error"
    HtmlTemplate.Execute(w, HtmlNodeKeyLicenseEmail)
    return
  }

  QueryString = "SELECT b.node_id " +
                "FROM user_key a, node_id b " +
                "WHERE a.user_key_id = '%s' " +
                "      and a.user_id_seq = (SELECT user_id_seq  " +
                "                           FROM user " +
                "                           WHERE user_id = '%s') " +
                "      and a.user_key_id_seq = b.user_key_id_seq "
  HtmlNodeKeyLicenseEmail.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeKey, HtmlNodeKeyLicenseEmail.NodeKeyLicense.UserID)
  log.Println("NodeID List Information Query :", HtmlNodeKeyLicenseEmail.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyLicenseEmail.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeIDRowData)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }

    if len(NodeIDRowData) > 0 {
      HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeID = append (HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeID, NodeIDRowData)    
    }
  }
  ResultSetRows.Close()

  if HtmlNodeKeyLicenseEmail.NodeKeyLicense.ActionMode == "LICENSE" {

    HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailSMTPServer = GetOEMSMTPServerAddress()
    //HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailAuth = smtp.PlainAuth("", GetOEMSMTPSenderEmail(), GetOEMSMTPSenderPassword(), GetOEMSMTPServerHost())
    EmailAuth := smtp.PlainAuth("", GetOEMSMTPSenderEmail(), GetOEMSMTPSenderPassword(), GetOEMSMTPServerHost())
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailFrom = GetOEMSMTPSenderEmail()
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailTo = append(HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailTo, GetUserIDEmail(HtmlNodeKeyLicenseEmail.NodeKeyLicense.UserID))
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailHeaderSubject = "Subject: License Information \r\n"
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailHeaderBlank = "\r\n"


    HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailBody += "User Key : " + HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeKey + "\r\n"
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailBody += "NODE ID Count : " + strconv.Itoa(HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeIDCount) + " / 100" + "\r\n"
    HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailBody += "End Date : " + HtmlNodeKeyLicenseEmail.NodeKeyLicense.EndDate + "\r\n"
    for i := range HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeID {
      HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailBody += strconv.Itoa(i + 1) +". " + HtmlNodeKeyLicenseEmail.NodeKeyLicense.NodeID[i] + "\r\n"
    }

    HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailMessageByte = []byte(HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailHeaderSubject +
                                                                     HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailHeaderBlank +
                                                                     HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailBody)

    err = smtp.SendMail(HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailSMTPServer,
                        //HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailAuth,
                        EmailAuth,
                        HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailFrom,
                        HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailTo,
                        HtmlNodeKeyLicenseEmail.NodeKeyLicense.EmailMessageByte)
    if err != nil {
      // TODO  
      log.Println("fail SMTP SendEmail")
      HtmlNodeKeyLicenseEmail.NodeKeyLicense.ResultMsg = "License Email delivery fail"
    } else {
      log.Println("succ SMTP SendEmail")
      HtmlNodeKeyLicenseEmail.NodeKeyLicense.ResultMsg = "License Email delivery success"
    }

  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }
  
  HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_license_email.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodekey_license_email.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }
  
  //HtmlNodeKeyLicenseEmail.NodeKeyLicense.ResultMsg = "License Email Send"
  HtmlTemplate.Execute(w, HtmlNodeKeyLicenseEmail)
  return
}


func WebServer_NodeKey_License_Download_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlNodeKeyPackage NodeKeyPackage 
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var PackageEncryptKey string
  var PackageEncryptIV string
  var NodeKeyNodeIDCountMax int
  var NodeKeyNodeIDCount int
  var NodeKeyPackageEndYear string
  var NodeKeyPackageEndMonth string
  var NodeKeyPackageEndDay string
  var NodeKeyPackageHomePath string
  var NodeIDArrary []string
  var NodeIDRowData string
  var ProcResult bool
  var LicenseFileName string
  var OutputFilePath string
  var QueryString string
	var err error

  log.Println("KMS Web Server - Node_Key Package_Proc", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyPackage.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyPackage.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyPackage.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeKeyPackage.NodeKeyPackage.ActionMode = HTTPReq_ReturnParamValue (req, "GET", "action_mode")
    HtmlNodeKeyPackage.NodeKeyPackage.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeKeyPackage.NodeKeyPackage.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
  } else if req.Method == "POST" {
    HtmlNodeKeyPackage.NodeKeyPackage.ActionMode = HTTPReq_ReturnParamValue (req, "POST", "action_mode")
    HtmlNodeKeyPackage.NodeKeyPackage.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeKeyPackage.NodeKeyPackage.NodeKey = HTTPReq_ReturnParamValue (req, "POST", "node_key")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyPackage.NodeKeyPackage.ActionMode == "" || HtmlNodeKeyPackage.NodeKeyPackage.UserID == "" || HtmlNodeKeyPackage.NodeKeyPackage.NodeKey == "" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  log.Println("Input Data ( ActionMode:", HtmlNodeKeyPackage.NodeKeyPackage.ActionMode, ", UserID:", HtmlNodeKeyPackage.NodeKeyPackage.UserID, ", NodeKey:", HtmlNodeKeyPackage.NodeKeyPackage.NodeKey, ")")

  if HtmlNodeKeyPackage.NodeKeyPackage.ActionMode != "LICENSE_LINUX" && HtmlNodeKeyPackage.NodeKeyPackage.ActionMode != "LICENSE_WINDOWS" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyPackage.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeKeyPackage.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeKeyPackage.CookiesData.CookieUserID != HtmlNodeKeyPackage.NodeKeyPackage.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT 100, node_client_count, DATE_FORMAT(pkg_end_date, '%%Y'), DATE_FORMAT(pkg_end_date, '%%m'), DATE_FORMAT(pkg_end_date, '%%d'), package_home_path " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " +
                "      and user_id_seq = (SELECT user_id_seq " +
                "                         FROM user " +
                "                         WHERE user_id = '%s') "
  HtmlNodeKeyPackage.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyPackage.NodeKeyPackage.NodeKey, HtmlNodeKeyPackage.NodeKeyPackage.UserID)
  log.Println("NodeKey Information Query :", HtmlNodeKeyPackage.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyPackage.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeKeyNodeIDCountMax,
                              &NodeKeyNodeIDCount,
                              &NodeKeyPackageEndYear,
                              &NodeKeyPackageEndMonth,
                              &NodeKeyPackageEndDay,
                              &NodeKeyPackageHomePath)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }
  }
  ResultSetRows.Close()

  if NodeKeyNodeIDCountMax == 0 || NodeKeyNodeIDCount == 0 || len(NodeKeyPackageEndYear) == 0 || len(NodeKeyPackageEndMonth) == 0 || len(NodeKeyPackageEndDay) == 0 || len(NodeKeyPackageHomePath) == 0 {
    HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_create_input.html")
    if err != nil {
      log.Println("failed to template.ParseFiles (./html/kms_nodekey_create_input.html)")
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
    
    HtmlNodeKeyPackage.NodeKeyPackage.ResultMsg = "Create Package Error"
    HtmlTemplate.Execute(w, HtmlNodeKeyPackage)
    return
  }

  QueryString = "SELECT b.node_id " +
                "FROM user_key a, node_id b " +
                "WHERE a.user_key_id = '%s' " +
                "      and a.user_id_seq = (SELECT user_id_seq  " +
                "                           FROM user " +
                "                           WHERE user_id = '%s') " +
                "      and a.user_key_id_seq = b.user_key_id_seq "
  HtmlNodeKeyPackage.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyPackage.NodeKeyPackage.NodeKey, HtmlNodeKeyPackage.NodeKeyPackage.UserID)
  log.Println("NodeID List Information Query :", HtmlNodeKeyPackage.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyPackage.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeIDRowData)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }

    if len(NodeIDRowData) > 0 {
      NodeIDArrary = append (NodeIDArrary, NodeIDRowData)    
    }
  }
  ResultSetRows.Close()

  PackageEncryptKey = GetOEMPackageEncryptKey()
  PackageEncryptIV = GetOEMPackageEncryptIV()

  if PackageEncryptKey == "" || PackageEncryptIV == "" {
    HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_create_input.html")
    if err != nil {
      log.Println("failed to template.ParseFiles (./html/kms_nodekey_create_input.html)")
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
    
    HtmlNodeKeyPackage.NodeKeyPackage.ResultMsg = "Create License Error"
    HtmlTemplate.Execute(w, HtmlNodeKeyPackage)
    return
  }

  if HtmlNodeKeyPackage.NodeKeyPackage.ActionMode == "LICENSE_LINUX" {
    LicenseFileName = "license_linux.lic"
    OutputFilePath = NodeKeyPackageHomePath + "/" + LicenseFileName

    ProcResult = CreateLicenseFile("LINUX", 
                                   NodeKeyPackageHomePath, OutputFilePath, 
                                   true, PackageEncryptKey, PackageEncryptIV,
                                   //false, PackageEncryptKey, PackageEncryptIV,
                                   HtmlNodeKeyPackage.NodeKeyPackage.UserID,
                                   HtmlNodeKeyPackage.NodeKeyPackage.NodeKey,
                                   NodeKeyNodeIDCountMax, NodeKeyNodeIDCount,
                                   NodeKeyPackageEndYear, NodeKeyPackageEndMonth, NodeKeyPackageEndDay,
                                   NodeIDArrary);
  } else if HtmlNodeKeyPackage.NodeKeyPackage.ActionMode == "LICENSE_WINDOWS" {
    LicenseFileName = "license_windows.lic"
    OutputFilePath = NodeKeyPackageHomePath + "/" + LicenseFileName

    ProcResult = CreateLicenseFile("WINDOWS", 
                                   NodeKeyPackageHomePath, OutputFilePath, 
                                   true, PackageEncryptKey, PackageEncryptIV,
                                   //false, PackageEncryptKey, PackageEncryptIV,
                                   HtmlNodeKeyPackage.NodeKeyPackage.UserID,
                                   HtmlNodeKeyPackage.NodeKeyPackage.NodeKey,
                                   NodeKeyNodeIDCountMax, NodeKeyNodeIDCount,
                                   NodeKeyPackageEndYear, NodeKeyPackageEndMonth, NodeKeyPackageEndDay,
                                   NodeIDArrary);
  }

  if ProcResult != true {
    HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_create_input.html")
    if err != nil {
      log.Println("failed to template.ParseFiles (./html/kms_nodekey_create_input.html)")
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
    
    HtmlNodeKeyPackage.NodeKeyPackage.ResultMsg = "Create License Error"
    HtmlTemplate.Execute(w, HtmlNodeKeyPackage)
    return
  }

  downloadBytes, err := ioutil.ReadFile(OutputFilePath)
  if err != nil {
    HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_create_input.html")
    if err != nil {
      log.Println("failed to template.ParseFiles (./html/kms_nodekey_create_input.html)")
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }

    HtmlNodeKeyPackage.NodeKeyPackage.ResultMsg = "Create Package Error"
    HtmlTemplate.Execute(w, HtmlNodeKeyPackage)
    return
  }

  mime := http.DetectContentType(downloadBytes)

  fileSize := len(string(downloadBytes))

  w.Header().Set("Content-Type", mime)
  w.Header().Set("Content-Disposition", "attachment; filename="+ LicenseFileName +"")
  w.Header().Set("Expires", "0")
  w.Header().Set("Content-Transfer-Encoding", "binary")
  w.Header().Set("Content-Length", strconv.Itoa(fileSize))
  w.Header().Set("Content-Control", "private, no-transform, no-store, must-revalidate")

  http.ServeContent(w, req, OutputFilePath, time.Now(), bytes.NewReader(downloadBytes))
}


func WebServer_NodeKey_Package_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlNodeKeyPackage NodeKeyPackage 
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var NodeKeyNodeIDCountMax int
  var NodeKeyNodeIDCount int
  var NodeKeyPackageEndYear string
  var NodeKeyPackageEndMonth string
  var NodeKeyPackageEndDay string
  var NodeKeyPackageHomePath string
  var NodeIDArrary []string
  var NodeIDRowData string
  //var ProcResult bool
  var OutputFilePath string
  var OutputFileName string
  var QueryString string
  var Result bool
	var err error

  log.Println("KMS Web Server - Node_Key Package_Proc", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeKeyPackage.CookiesData, req)
  WebServerMainMenu (&HtmlNodeKeyPackage.MainMenu, "nodekey")
  WebServerOEMInformation(&HtmlNodeKeyPackage.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeKeyPackage.NodeKeyPackage.ActionMode = HTTPReq_ReturnParamValue (req, "GET", "action_mode")
    HtmlNodeKeyPackage.NodeKeyPackage.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeKeyPackage.NodeKeyPackage.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
  } else if req.Method == "POST" {
    HtmlNodeKeyPackage.NodeKeyPackage.ActionMode = HTTPReq_ReturnParamValue (req, "POST", "action_mode")
    HtmlNodeKeyPackage.NodeKeyPackage.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeKeyPackage.NodeKeyPackage.NodeKey = HTTPReq_ReturnParamValue (req, "POST", "node_key")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeKeyPackage.NodeKeyPackage.ActionMode == "" || HtmlNodeKeyPackage.NodeKeyPackage.UserID == "" || HtmlNodeKeyPackage.NodeKeyPackage.NodeKey == "" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  log.Println("Input Data ( ActionMode:", HtmlNodeKeyPackage.NodeKeyPackage.ActionMode, ", UserID:", HtmlNodeKeyPackage.NodeKeyPackage.UserID, ", NodeKey:", HtmlNodeKeyPackage.NodeKeyPackage.NodeKey, ")")

  if HtmlNodeKeyPackage.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeKeyPackage.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeKeyPackage.CookiesData.CookieUserID != HtmlNodeKeyPackage.NodeKeyPackage.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT 100, node_client_count, DATE_FORMAT(pkg_end_date, '%%Y'), DATE_FORMAT(pkg_end_date, '%%m'), DATE_FORMAT(pkg_end_date, '%%d'), package_home_path " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " +
                "      and user_id_seq = (SELECT user_id_seq " +
                "                         FROM user " +
                "                         WHERE user_id = '%s') "
  HtmlNodeKeyPackage.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyPackage.NodeKeyPackage.NodeKey, HtmlNodeKeyPackage.NodeKeyPackage.UserID)
  log.Println("NodeKey Information Query :", HtmlNodeKeyPackage.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyPackage.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeKeyNodeIDCountMax,
                              &NodeKeyNodeIDCount,
                              &NodeKeyPackageEndYear,
                              &NodeKeyPackageEndMonth,
                              &NodeKeyPackageEndDay,
                              &NodeKeyPackageHomePath)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }
  }
  ResultSetRows.Close()

  if NodeKeyNodeIDCountMax == 0 || NodeKeyNodeIDCount == 0 || len(NodeKeyPackageEndYear) == 0 || len(NodeKeyPackageEndMonth) == 0 || len(NodeKeyPackageEndDay) == 0 || len(NodeKeyPackageHomePath) == 0 {
    HtmlTemplate, err = template.ParseFiles("./html/kms_nodekey_create_input.html")
    if err != nil {
      log.Println("failed to template.ParseFiles (./html/kms_nodekey_create_input.html)")
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
    
    HtmlNodeKeyPackage.NodeKeyPackage.ResultMsg = "Create Package Error"
    HtmlTemplate.Execute(w, HtmlNodeKeyPackage)
    return
  }

  if HtmlNodeKeyPackage.NodeKeyPackage.ActionMode != "WINDOWS" && HtmlNodeKeyPackage.NodeKeyPackage.ActionMode != "LINUX" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT b.node_id " +
                "FROM user_key a, node_id b " +
                "WHERE a.user_key_id = '%s' " +
                "      and a.user_id_seq = (SELECT user_id_seq  " +
                "                           FROM user " +
                "                           WHERE user_id = '%s') " +
                "      and a.user_key_id_seq = b.user_key_id_seq "
  HtmlNodeKeyPackage.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeKeyPackage.NodeKeyPackage.NodeKey, HtmlNodeKeyPackage.NodeKeyPackage.UserID)
  log.Println("NodeID List Information Query :", HtmlNodeKeyPackage.SQLQuery)
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeKeyPackage.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&NodeIDRowData)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      return
    }

    if len(NodeIDRowData) > 0 {
      NodeIDArrary = append (NodeIDArrary, NodeIDRowData)    
    }
  }
  ResultSetRows.Close()

  PackageOEMName := GetOEMName()
  PackageOEMFileName := GetOEMPackageFileName()
  PackageEncryptKey := GetOEMPackageEncryptKey()
  PackageEncryptIV := GetOEMPackageEncryptIV()
  PackageHomePath :=  GetOEMPackageHomePath()

  Result = disk.IsExistDirectoryPath(NodeKeyPackageHomePath)
  if Result != true {
    Result = disk.CreateDirectoryPath(NodeKeyPackageHomePath)
    if Result != true {
      HtmlNodeKeyPackage.NodeKeyPackage.ResultMsg = "Create Package Error"
      HtmlTemplate.Execute(w, HtmlNodeKeyPackage)
      return
    }
  }

  if HtmlNodeKeyPackage.NodeKeyPackage.ActionMode == "WINDOWS" {
    OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Windows("Create", 
                                                        PackageEncryptKey, PackageEncryptIV, 
                                                        HtmlNodeKeyPackage.NodeKeyPackage.UserID, HtmlNodeKeyPackage.NodeKeyPackage.NodeKey, 
                                                        strconv.Itoa(NodeKeyNodeIDCountMax), strconv.Itoa(NodeKeyNodeIDCount), 
                                                        NodeKeyPackageEndYear, NodeKeyPackageEndMonth, NodeKeyPackageEndDay, 
                                                        NodeIDArrary, 
                                                        NodeKeyPackageHomePath, PackageHomePath, 
                                                        PackageOEMFileName, PackageOEMName)
    if err != nil {
      log.Println("failed to Make_Pkg_Windows")
      return
    }

    log.Println("Create Windows Package File Full Path : ", OutputFilePath, "(FileName : ", OutputFileName, ")")

  } else if HtmlNodeKeyPackage.NodeKeyPackage.ActionMode == "LINUX" {
    OutputFilePath, OutputFileName, err = make_package.Make_Pkg_Linux("Create", 
                                                        PackageEncryptKey, PackageEncryptIV, 
                                                        HtmlNodeKeyPackage.NodeKeyPackage.UserID, HtmlNodeKeyPackage.NodeKeyPackage.NodeKey, 
                                                        strconv.Itoa(NodeKeyNodeIDCountMax), strconv.Itoa(NodeKeyNodeIDCount), 
                                                        NodeKeyPackageEndYear, NodeKeyPackageEndMonth, NodeKeyPackageEndDay, 
                                                        NodeIDArrary, 
                                                        NodeKeyPackageHomePath, PackageHomePath, 
                                                        PackageOEMFileName, PackageOEMName)
    if err != nil {
      log.Println("failed to Make_Pkg_Linux")
      return
    }

    log.Println("Create Linux Package File Full Path : ", OutputFilePath, "(FileName : ", OutputFileName, ")")
  }

  downloadBytes, err := ioutil.ReadFile(OutputFilePath)
  if err != nil {
    HtmlNodeKeyPackage.NodeKeyPackage.ResultMsg = "Create Package Error"
    HtmlTemplate.Execute(w, HtmlNodeKeyPackage)
    return
  }

  mime := http.DetectContentType(downloadBytes)

  fileSize := len(string(downloadBytes))

  w.Header().Set("Content-Type", mime)
  w.Header().Set("Content-Disposition", "attachment; filename="+OutputFileName+"")
  w.Header().Set("Expires", "0")
  w.Header().Set("Content-Transfer-Encoding", "binary")
  w.Header().Set("Content-Length", strconv.Itoa(fileSize))
  w.Header().Set("Content-Control", "private, no-transform, no-store, must-revalidate")

  http.ServeContent(w, req, OutputFilePath, time.Now(), bytes.NewReader(downloadBytes))
  return
}


func WebServer_NodeKey_Ajax_NodeKeyGenerate (w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var CommonTemplete CommonHTML
  var InputData jsonInputNodeKeyGenerate 
  var OutputData jsonOutputPack 
  var OutputBody string
  var TempGenerateNodeKey string
	var err error

  log.Println("KMS Web Server - WebServer_NodeKey_Ajax_NodeKeyGenerate", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    OutputData.MsgType = "NODE KEY GENERATE"
    OutputData.MsgTitle = "Node Key Generate"
    OutputData.MsgMsg = "Cookie expiretime timed out"
    OutputData.MsgCode = "1100"
    OutputData.MsgMsg = "Cookie expiretime timed out"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodekey")
  WebServerOEMInformation(&CommonTemplete.OEMData)

  if req.Method != "POST" {
    OutputData.MsgType = "NODE KEY GENERATE"
    OutputData.MsgTitle = "Node Key Generate"
    OutputData.MsgMsg = "invalid request method"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid request method"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "NODE KEY GENERATE"
    OutputData.MsgTitle = "Node Key Generate"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if (InputData.ActionMode == "" || InputData.ActionMode != "GET" || InputData.UserID == "") {
    OutputData.MsgType = "NODE KEY GENERATE"
    OutputData.MsgTitle = "Node Key Generate"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {

  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      OutputData.MsgType = "NODE KEY GENERATE"
      OutputData.MsgTitle = "Node Key Generate"
      OutputData.MsgMsg = "invalid user id access"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "invalid user id access"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
  } else {
    OutputData.MsgType = "NODE KEY GENERATE"
    OutputData.MsgTitle = "Node Key Generate"
    OutputData.MsgMsg = "invalid user property access"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid user property access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  /*-------------------------------------------------------------------------------
  QueryString = "SELECT nodekey_generate_tmp_key FROM user WHERE user_id ='%s' "
  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID)
  log.Println("Tmp Generating NodeKey Query -> ", CommonTemplete.SQLQuery)
  
  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&TempGenerateNodeKey)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      OutputData.MsgType = "NODE KEY GENERATE"
      OutputData.MsgTitle = "Node Key Generate"
      OutputData.MsgMsg = "exception db query (tmp sync buffer)"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception db query (tmp sync buffer)"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      return
    }
  }
  ResultSetRows.Close()
  -------------------------------------------------------------------------------*/

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {
    TempGenerateNodeKey = GenerateNodeKey(nil, InputData.UserID)
  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    TempGenerateNodeKey = GenerateNodeKey(nil, CommonTemplete.CookiesData.CookieUserID)
  }

  log.Println("Tmp Generate NodeKey:", TempGenerateNodeKey)

  if TempGenerateNodeKey == "" {
    OutputData.MsgType = "NODE KEY GENERATE"
    OutputData.MsgTitle = "Node Key Generate"
    OutputData.MsgMsg = "exception db query (can not generate node key)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "exception db query (can not generate node key)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {
    if DBSetTmpGenerateNodeKey(InputData.UserID, TempGenerateNodeKey) != 1 {
      OutputData.MsgType = "NODE KEY GENERATE"
      OutputData.MsgTitle = "Node Key Generate"
      OutputData.MsgMsg = "exception db query (failed to set tmp generate node key buffer)"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception db query (failed to set tmp generate node key buffer)"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    if DBSetTmpGenerateNodeKey(CommonTemplete.CookiesData.CookieUserID, TempGenerateNodeKey) != 1 {
      OutputData.MsgType = "NODE KEY GENERATE"
      OutputData.MsgTitle = "Node Key Generate"
      OutputData.MsgMsg = "exception db query (failed to set tmp generate node key buffer)"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception db query (failed to set tmp generate node key buffer)"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
  }

  OutputData.MsgType = "NODE KEY GENERATE"
  OutputData.MsgTitle = "Node Key Generate"
  OutputData.MsgMsg = "exception db query (failed to set tmp generate node key buffer)"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = TempGenerateNodeKey

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
  return
}


func WebServer_UserID_List(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var HtmlUserIDList UserIDList
  var UserID UserIDListItem
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var ResultSetRowCount int
  var URLGetParam string
  var PageNumString string
  var PageSortString string
  var SearchParamInitFlag bool
  var QueryString string
	var err error

  var MaxCountPage int = 10
  var MaxRowCountPerPage int = 25

  log.Println("KMS Web Server - UserID_Management", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }
  
  SessionCookieUserData(&HtmlUserIDList.CookiesData, req)
  WebServerMainMenu (&HtmlUserIDList.MainMenu, "userid")
  WebServerOEMInformation(&HtmlUserIDList.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  ParamPageNum, ok := req.URL.Query()["page_num"]
  if !ok || len (ParamPageNum) < 1 {
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
  if !ok || len (ParamPageSort) < 1 {
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
    HtmlUserIDList.SearchParamUserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlUserIDList.SearchParamUserEmail = HTTPReq_ReturnParamValue (req, "GET", "user_email")
    HtmlUserIDList.SearchParamUserProperty = HTTPReq_ReturnParamValue (req, "GET", "user_property")
    HtmlUserIDList.SearchParamUserStatus = HTTPReq_ReturnParamValue (req, "GET", "user_status")
  } else if req.Method == "POST" {
    HtmlUserIDList.SearchParamUserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlUserIDList.SearchParamUserEmail = HTTPReq_ReturnParamValue (req, "POST", "user_email")
    HtmlUserIDList.SearchParamUserProperty = HTTPReq_ReturnParamValue (req, "POST", "user_property")
    HtmlUserIDList.SearchParamUserStatus = HTTPReq_ReturnParamValue (req, "POST", "user_status")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }
  
  SearchParamInitFlag = false

  if len(HtmlUserIDList.SearchParamUserID) > 0 {
    URLGetParam += fmt.Sprintf("&user_id=%s", HtmlUserIDList.SearchParamUserID)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlUserIDList.SQLQueryCondition += fmt.Sprintf(" (user_id = \"%s\") ", HtmlUserIDList.SearchParamUserID)
    } else {
      HtmlUserIDList.SQLQueryCondition += " AND"
      HtmlUserIDList.SQLQueryCondition += fmt.Sprintf(" (user_id = \"%s\") ", HtmlUserIDList.SearchParamUserID)
    }
  }

  if len(HtmlUserIDList.SearchParamUserEmail) > 0 {
    URLGetParam += fmt.Sprintf("&user_email=%s", HtmlUserIDList.SearchParamUserEmail)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlUserIDList.SQLQueryCondition += fmt.Sprintf(" (email = \"%s\") ", HtmlUserIDList.SearchParamUserEmail)
    } else {
      HtmlUserIDList.SQLQueryCondition += " AND"
      HtmlUserIDList.SQLQueryCondition += fmt.Sprintf(" (email = \"%s\") ", HtmlUserIDList.SearchParamUserEmail)
    }
  }

  if len(HtmlUserIDList.SearchParamUserProperty) > 0 {
    URLGetParam += fmt.Sprintf("&user_property=%s", HtmlUserIDList.SearchParamUserProperty)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlUserIDList.SQLQueryCondition += fmt.Sprintf(" (property = \"%s\") ", HtmlUserIDList.SearchParamUserProperty)
    } else {
      HtmlUserIDList.SQLQueryCondition += " AND"
      HtmlUserIDList.SQLQueryCondition += fmt.Sprintf(" (property = \"%s\") ", HtmlUserIDList.SearchParamUserProperty)
    }

  }

  if len(HtmlUserIDList.SearchParamUserStatus) > 0 {
    URLGetParam += fmt.Sprintf("&user_status=%s", HtmlUserIDList.SearchParamUserStatus)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlUserIDList.SQLQueryCondition += fmt.Sprintf(" (status = \"%s\")", HtmlUserIDList.SearchParamUserStatus)
    } else {
      HtmlUserIDList.SQLQueryCondition += " AND"
      HtmlUserIDList.SQLQueryCondition += fmt.Sprintf(" (status = \"%s\")", HtmlUserIDList.SearchParamUserStatus)
    }
  }

  if len(HtmlUserIDList.SQLQueryCondition) > 0 {
    if HtmlUserIDList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT COUNT(user_id) FROM user WHERE %s"
      HtmlUserIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlUserIDList.SQLQueryCondition)
    } else {
      QueryString = "SELECT COUNT(user_id) FROM user WHERE user_id = '%s' AND %s"
      HtmlUserIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlUserIDList.CookiesData.CookieUserID, HtmlUserIDList.SQLQueryCondition)
    }
  } else {
    if HtmlUserIDList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT COUNT(user_id) FROM user"
      HtmlUserIDList.SQLQuery = fmt.Sprintf(QueryString)
    } else {
      QueryString = "SELECT COUNT(user_id) FROM user WHERE user_id = '%s'"
      HtmlUserIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlUserIDList.CookiesData.CookieUserID)
    }
  }

  log.Println("UserID List Count Query -> ", HtmlUserIDList.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlUserIDList.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&ResultSetRowCount)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
  }
  ResultSetRows.Close()
  
  HtmlDataPage (&(HtmlUserIDList.TempletePage), "UserKeyPageNum", PageNumString, "UserKeySort", PageSortString, 0, MaxCountPage, MaxRowCountPerPage, ResultSetRowCount, "/userid/management/", URLGetParam, "/service_stop/", "[exception]", "redirect")

  if len(HtmlUserIDList.SQLQueryCondition) > 0 {
    if HtmlUserIDList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT user_id, email, property, create_date, update_date, status FROM user WHERE %s " +
                    "ORDER BY user_id " +
                    "LIMIT %d OFFSET %d"
      HtmlUserIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlUserIDList.SQLQueryCondition, HtmlUserIDList.TempletePage.MaxRowCountPage, HtmlUserIDList.TempletePage.RowOffset)

    } else {
      QueryString = "SELECT user_id, email, property, create_date, update_date, status FROM user WHERE user_id = '%s' AND %s " +
                    "ORDER BY user_id " +
                    "LIMIT %d OFFSET %d"
      HtmlUserIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlUserIDList.CookiesData.CookieUserID, HtmlUserIDList.SQLQueryCondition, HtmlUserIDList.TempletePage.MaxRowCountPage, HtmlUserIDList.TempletePage.RowOffset)
    }
  } else {
    if HtmlUserIDList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT user_id, email, property, create_date, update_date, status FROM user " +
                    "ORDER BY user_id " +
                    "LIMIT %d OFFSET %d"
      HtmlUserIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlUserIDList.TempletePage.MaxRowCountPage, HtmlUserIDList.TempletePage.RowOffset)

    } else {
      QueryString = "SELECT user_id, email, property, create_date, update_date, status FROM user WHERE user_id = '%s' " +
                    "ORDER BY user_id " +
                    "LIMIT %d OFFSET %d"
      HtmlUserIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlUserIDList.CookiesData.CookieUserID, HtmlUserIDList.TempletePage.MaxRowCountPage, HtmlUserIDList.TempletePage.RowOffset)
    }
  }

  log.Println("UserID List Limit Query -> ", HtmlUserIDList.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlUserIDList.SQLQuery)
  for i := 0; ResultSetRows.Next(); i++ {
    err := ResultSetRows.Scan(&(UserID.UserID), 
                              &(UserID.UserEmail), 
                              &(UserID.UserProperty), 
                              &(UserID.CreateDate), 
                              &(UserID.UpdateDate), 
                              &(UserID.UserStatus))
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }

    UserID.UserIDModifyLinkURL = fmt.Sprintf("/userid/modify_input/?user_id=%s", UserID.UserID)
    UserID.UserIDDeleteLinkURL = fmt.Sprintf("/userid/delete_input/?user_id=%s", UserID.UserID)
    UserID.UserKeyLinkURL = fmt.Sprintf("/nodekey/management/?user_id=%s", UserID.UserID)

    HtmlUserIDList.UserID = append(HtmlUserIDList.UserID, UserID)
  }

  for i := range HtmlUserIDList.UserID {
    log.Println("ResultRows Data :", HtmlUserIDList.UserID[i].UserID, 
                                     HtmlUserIDList.UserID[i].UserEmail, 
                                     HtmlUserIDList.UserID[i].UserProperty, 
                                     HtmlUserIDList.UserID[i].CreateDate, 
                                     HtmlUserIDList.UserID[i].UpdateDate, 
                                     HtmlUserIDList.UserID[i].UserStatus,
                                     HtmlUserIDList.UserID[i].UserKeyLinkURL,
                                     HtmlUserIDList.UserID[i].UserIDModifyLinkURL,
                                     HtmlUserIDList.UserID[i].UserIDDeleteLinkURL)
  }

  ResultSetRows.Close()

  HtmlTemplate, err = template.ParseFiles("./html/kms_userid_list.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_userid_list.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlUserIDList)
}


func WebServer_UserID_Create_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var CommonTemplete CommonHTML
	var tmpl *template.Template
	var err error

  log.Println("KMS Web Server - Create_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "userid")
  WebServerOEMInformation(&CommonTemplete.OEMData)

  tmpl, err = template.ParseFiles("./html/kms_userid_create_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_userid_create_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	tmpl.Execute(w, CommonTemplete)
}


func WebServer_UserID_Create_Proc (w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var HtmlUserCreate UserIDCreate
	//var HtmlTemplate *template.Template
  //var ResultSetRows *sql.Rows
  //var ResultSetRowCount int
  //var URLGetParam string
  var QueryString string
	//var err error

  log.Println("KMS Web Server - UserID Create Proc", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }
  
  SessionCookieUserData(&HtmlUserCreate.CookiesData, req)
  WebServerMainMenu (&HtmlUserCreate.MainMenu, "userid")
  WebServerOEMInformation (&HtmlUserCreate.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlUserCreate.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlUserCreate.CookiesData.CookieUserProperty == "normal" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  HtmlUserCreate.UserData.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
  HtmlUserCreate.UserData.UserPW = HTTPReq_ReturnParamValue (req, "POST", "user_password")
  HtmlUserCreate.UserData.UserEmail = HTTPReq_ReturnParamValue (req, "POST", "user_email")
  HtmlUserCreate.UserData.UserProperty = HTTPReq_ReturnParamValue (req, "POST", "user_property")
  HtmlUserCreate.UserData.UserServiceName = HTTPReq_ReturnParamValue (req, "POST", "user_program_name")
  HtmlUserCreate.UserData.UserStatus = "ENABLE"

  if len(HtmlUserCreate.UserData.UserID) == 0 || 
      len(HtmlUserCreate.UserData.UserPW) == 0 || 
      len(HtmlUserCreate.UserData.UserEmail) == 0 || 
      len(HtmlUserCreate.UserData.UserProperty) == 0 || 
      len(HtmlUserCreate.UserData.UserServiceName) == 0 {

    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "INSERT INTO user (user_id, password, email, property, create_date, update_date, program_name, status) values ('%s', '%s', '%s', '%s', NOW(), NOW(), '%s', '%s')"
  HtmlUserCreate.SQLQuery = fmt.Sprintf(QueryString, 
                                        HtmlUserCreate.UserData.UserID, 
                                        GetCipherText(HtmlUserCreate.UserData.UserPW), 
                                        HtmlUserCreate.UserData.UserEmail, 
                                        HtmlUserCreate.UserData.UserProperty, 
                                        HtmlUserCreate.UserData.UserServiceName,
                                        HtmlUserCreate.UserData.UserStatus)
  
	mariadb_lib.Insert_Data(Database, HtmlUserCreate.SQLQuery)

  // TODO: DB Excxception

  WebServer_Redirect(w, req, "/userid/management/?page_num=1&page_sort=0")
}


func WebServer_UserID_Modify_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlUserModify UserIDModify
	var tmpl *template.Template
	var err error

  log.Println("KMS Web Server - UserID Modify Input", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlUserModify.CookiesData, req)
  WebServerMainMenu (&HtmlUserModify.MainMenu, "userid")
  WebServerOEMInformation(&HtmlUserModify.OEMData)

  if req.Method == "GET" {
    HtmlUserModify.UserData.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
  } else if req.Method == "POST" {
    HtmlUserModify.UserData.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }
  
  if HtmlUserModify.CookiesData.CookieUserProperty == "admin" {
    
  } else if HtmlUserModify.CookiesData.CookieUserProperty == "normal" {
    if HtmlUserModify.CookiesData.CookieUserID != HtmlUserModify.UserData.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return;
    }
    
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }



  tmpl, err = template.ParseFiles("./html/kms_userid_modify_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_userid_modify_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	tmpl.Execute(w, HtmlUserModify)
}


type jsonInputUserModifyPack struct {
  UserID string               `json:"user_id"`
  UserPW string               `json:"user_current_password"`
  UserNewPW string            `json:"user_new_password"`
  UserNewConfirmPW string     `json:"user_new_confirm_password"`
  UserEmail string            `json:"user_email"`
  UserProperty string         `json:"user_property"`
  UserStatus string           `json:"user_status"`
  UserProgramName string      `json:"user_program_name"`
 }


func WebServer_UserID_Modify_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var InputData jsonInputUserModifyPack
  var OutputData jsonOutputPack 
  var OutputBody string
  var QueryString string
  var err error

  log.Println("KMS Web Server - UserID_Ajax_Modify_Proc", req.Method, ", URL:", req.URL)

  //data, _ := httputil.DumpRequest(req, true);
  //log.Println(string(data))

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }
  
  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "userid")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "USERMODIFY"
    OutputData.MsgTitle = "User Information Modify"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  log.Println("Input Data[ user_id:" + InputData.UserID + ", user_pw:" + InputData.UserPW + ", user_new_pw:" + InputData.UserNewPW + ", user_new_confirm_pw:" + InputData.UserNewConfirmPW + 
                        ", user_email:" + InputData.UserEmail + ", user_property:" + InputData.UserProperty + ", user_status:" + InputData.UserStatus + ", user_program_name:" + InputData.UserProgramName)

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {

    if len(InputData.UserID) == 0 || 
        //len(InputData.UserPW) == 0 || 
        len(InputData.UserNewPW) == 0 || 
        len(InputData.UserNewConfirmPW) == 0 || 
        len(InputData.UserEmail) == 0 || 
        len(InputData.UserProperty) == 0 || 
        len(InputData.UserStatus) == 0 || 
        len(InputData.UserProgramName) == 0 {

      OutputData.MsgType = "USERMODIFY"
      OutputData.MsgTitle = "User Information Modify"
      OutputData.MsgMsg = "failed to decoding data of input json data"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "failed to decoding data of input json data"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }

    if InputData.UserNewPW != InputData.UserNewConfirmPW {
      OutputData.MsgType = "USERMODIFY"
      OutputData.MsgTitle = "User Information Modify"
      OutputData.MsgMsg = "failed to decoding data of input json data"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "failed to decoding data of input json data"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
    
    /*---------------------------------------------------------------------------------------------------------------------------------
    QueryString = "UPDATE user " +
                  "SET password = '%s', email = '%s', property= '%s', status = '%s', program_name = '%s', update_date = now() " +
                  "WHERE user_id = '%s' and password = '%s'"

    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, GetCipherText(InputData.UserNewPW), InputData.UserEmail, strings.ToLower(InputData.UserProperty), strings.ToUpper(InputData.UserStatus), InputData.UserProgramName, InputData.UserID, GetCipherText(InputData.UserPW))
    ---------------------------------------------------------------------------------------------------------------------------------*/
    QueryString = "UPDATE user " +
                  "SET password = '%s', email = '%s', property= '%s', status = '%s', program_name = '%s', update_date = now() " +
                  "WHERE user_id = '%s' "

    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, GetCipherText(InputData.UserNewPW), InputData.UserEmail, strings.ToLower(InputData.UserProperty), strings.ToUpper(InputData.UserStatus), InputData.UserProgramName, InputData.UserID)
  } else {

    if len(InputData.UserID) == 0 || 
        len(InputData.UserNewPW) == 0 || 
        len(InputData.UserNewConfirmPW) == 0 || 
        len(InputData.UserEmail) == 0 || 
        len(InputData.UserProperty) == 0 || 
        len(InputData.UserStatus) == 0 || 
        len(InputData.UserProgramName) == 0 {
      OutputData.MsgType = "USERMODIFY"
      OutputData.MsgTitle = "User Information Modify"
      OutputData.MsgMsg = "failed to decoding data of input json data"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "failed to decoding data of input json data"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }

    if InputData.UserProperty != "NORMAL" {
      OutputData.MsgType = "USERMODIFY"
      OutputData.MsgTitle = "User Information Modify"
      OutputData.MsgMsg = "No access authority"
      OutputData.MsgCode = "1090"
      OutputData.MsgValue = "No access authority"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }

    if InputData.UserNewPW != InputData.UserNewConfirmPW {
      OutputData.MsgType = "USERMODIFY"
      OutputData.MsgTitle = "User Information Modify"
      OutputData.MsgMsg = "failed to decoding data of input json data"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "failed to decoding data of input json data"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }

    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      OutputData.MsgType = "USERMODIFY"
      OutputData.MsgTitle = "User Information Modify"
      OutputData.MsgMsg = "failed to decoding data of input json data"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "failed to decoding data of input json data"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }

    QueryString = "UPDATE user " +
                  "SET password = '%s', email = '%s', property= '%s', status = '%s', program_name = '%s', update_date = now() " +
                  "WHERE user_id = '%s' "

    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, GetCipherText(InputData.UserNewPW), InputData.UserEmail, strings.ToLower(InputData.UserProperty), strings.ToUpper(InputData.UserStatus), InputData.UserProgramName, InputData.UserID)
  }

	mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)

  // TODO: DB Excxception

  OutputData.MsgType = "USERMODIFY"
  OutputData.MsgTitle = "User Information Modify"
  OutputData.MsgMsg = "User Information is Changed Successful"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = "OK"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


func WebServer_UserID_Delete_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlUserDelete UserIDDelete
	var tmpl *template.Template
	var err error

  log.Println("KMS Web Server - UserID_Delete_Input", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlUserDelete.CookiesData, req)
  WebServerMainMenu (&HtmlUserDelete.MainMenu, "userid")
  WebServerOEMInformation(&HtmlUserDelete.OEMData)

  if HtmlUserDelete.CookiesData.CookieUserProperty == "admin" {
    
  } else if HtmlUserDelete.CookiesData.CookieUserProperty == "normal" {
    
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if req.Method == "GET" {
    HtmlUserDelete.UserDataParam = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    if HtmlUserDelete.UserDataParam != "" {
      HtmlUserDelete.UserDataCount = 1
      TmpUserData :=UserIDDeleteItem {UserID: HtmlUserDelete.UserDataParam}
      HtmlUserDelete.UserData = append(HtmlUserDelete.UserData, TmpUserData)
    } else {
      HtmlUserDelete.UserDataParam = HTTPReq_ReturnParamValue (req, "GET", "user_id_list")
      splitUserIDArray := strings.Split(HtmlUserDelete.UserDataParam, ",")
      HtmlUserDelete.UserDataCount = len(splitUserIDArray)
      for i := 0; i < HtmlUserDelete.UserDataCount; i++ {
        TmpUserData :=UserIDDeleteItem {UserID: HtmlUserDelete.UserDataParam}
        HtmlUserDelete.UserData = append(HtmlUserDelete.UserData, TmpUserData)
      }
    }
  } else if req.Method == "POST" {
    HtmlUserDelete.UserDataParam = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    if HtmlUserDelete.UserDataParam != "" {
      HtmlUserDelete.UserDataCount = 1
      TmpUserData :=UserIDDeleteItem {UserID: HtmlUserDelete.UserDataParam}
      HtmlUserDelete.UserData = append(HtmlUserDelete.UserData, TmpUserData)
    } else {
      HtmlUserDelete.UserDataParam = HTTPReq_ReturnParamValue (req, "POST", "user_id_list")
      splitUserIDArray := strings.Split(HtmlUserDelete.UserDataParam, ",")
      HtmlUserDelete.UserDataCount = len(splitUserIDArray)
      for i := 0; i < HtmlUserDelete.UserDataCount; i++ {
        TmpUserData :=UserIDDeleteItem {UserID: HtmlUserDelete.UserDataParam}
        HtmlUserDelete.UserData = append(HtmlUserDelete.UserData, TmpUserData)
      }
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }
 
  tmpl, err = template.ParseFiles("./html/kms_userid_delete_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_userid_delete_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	tmpl.Execute(w, HtmlUserDelete)
}


type jsonInputUserDeletePack struct {
  UserID string               `json:"user_id"`
}


func WebServer_UserID_Delete_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var InputData jsonInputUserDeletePack
  var OutputData jsonOutputPack 
  var OutputBody string
  var QueryString string
  var err error

  log.Println("KMS Web Server - UserID_Ajax_Delete_Proc", req.Method, ", URL:", req.URL)

  //data, _ := httputil.DumpRequest(req, true);
  //log.Println(string(data))

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }
  
  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "userid")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "USERDELETE"
    OutputData.MsgTitle = "User Information Delete"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  log.Println("Input Data[ user_id:" + InputData.UserID)

  mariadb_lib.DB_AutoCommit_Disable(Database)
  defer mariadb_lib.DB_Rollback(Database)
  defer mariadb_lib.DB_AutoCommit_Enable(Database)

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {
    if len(InputData.UserID) == 0 {

      OutputData.MsgType = "USERDELETE"
      OutputData.MsgTitle = "User Information Delete"
      OutputData.MsgMsg = "failed to decoding data of input json data"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "failed to decoding data of input json data"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }

    QueryString = "DELETE " +
                  "FROM node_id " +
                  "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                  "                         FROM user_key " +
                  "                         WHERE user_id_seq = (SELECT user_id_seq " +
                  "                                              FROM user " +
                  "                                              WHERE user_id = '%s')) "
    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID)
    mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
    // TODO : return result

    QueryString = "DELETE FROM user_key WHERE user_id_seq = (SELECT user_id_seq " +
                  "                                          FROM user " +
                  "                                          WHERE user_id = '%s') "
    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID)
    mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
    // TODO : return result
    
    QueryString = "DELETE FROM user WHERE user_id = '%s'"
    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID)
    mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
    // TODO : return result

  } else {

    if len(InputData.UserID) == 0 {
      OutputData.MsgType = "USERDELETE"
      OutputData.MsgTitle = "User Information Delete"
      OutputData.MsgMsg = "failed to decoding data of input json data"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "failed to decoding data of input json data"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }

    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      OutputData.MsgType = "USERDELETE"
      OutputData.MsgTitle = "User Information Delete"
      OutputData.MsgMsg = "failed to decoding data of input json data"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "failed to decoding data of input json data"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }

    QueryString = "DELETE " +
                  "FROM node_id " +
                  "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                  "                         FROM user_key " +
                  "                         WHERE user_id_seq = (SELECT user_id_seq " +
                  "                                              FROM user " +
                  "                                              WHERE user_id = '%s')) "
    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID)
    mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
    // TODO : return result

    QueryString = "DELETE FROM user_key WHERE user_id_seq = (SELECT user_id_seq " +
                  "                                          FROM user " +
                  "                                          WHERE user_id = '%s') "
    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID)
    mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
    // TODO : return result
    
    QueryString = "DELETE FROM user WHERE user_id = '%s'"
    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID)
    mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
    // TODO : return result
  }

  //DB_Commit(Database)

  OutputData.MsgType = "USERDELETE"
  OutputData.MsgTitle = "User Information Delete"
  OutputData.MsgMsg = "User Information is Changed Successful"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = "OK"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


type jsonInputIDCheckPack struct {
  UserID string     `json:"user_id"`
  ActionMode string `json:"action_mode"`
}


type jsonOutputPack struct {
  MsgType string    // Message Class type
  MsgTitle string   // Window Display Title Message
  MsgMsg string     // Window Display Result Message
  MsgCode string    // Processing Result Code
  MsgValue string   // Processing Result Value
}


func WebServer_UserID_Ajax_UserIDCheck (w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var ResultSetRows *sql.Rows
  var ResultSetRowCount int
  var InputData jsonInputIDCheckPack 
  var OutputData jsonOutputPack 
  var OutputBody string
  var QueryString string
	var err error

  log.Println("KMS Web Server - UserID_Ajax_UserIDCheck", req.Method)

  //data, _ := httputil.DumpRequest(req, true);
  //log.Println(string(data))

  res := Cookie_Check(w, req) 
  if res < 0 {
    OutputData.MsgType = "IDCHECK"
    OutputData.MsgTitle = ""
    OutputData.MsgMsg = "Cookie expiretime timed out"
    OutputData.MsgCode = "1100"
    OutputData.MsgValue = "Cookie expiretime timed out"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "userid")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)


  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "IDCHECK"
    OutputData.MsgTitle = ""
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  log.Println("ID Checking Input UserID:" + InputData.UserID)

  if InputData.ActionMode == "CREATE_USERID" && CommonTemplete.CookiesData.CookieUserProperty != "admin" {
    log.Println("invalid userid property:" + CommonTemplete.CookiesData.CookieUserProperty)

    OutputData.MsgType = "IDCHECK"
    OutputData.MsgTitle = ""
    OutputData.MsgMsg = "invalid user property access"
    OutputData.MsgCode = "1090"
    OutputData.MsgValue = "invalid user property access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
    return
  }

  if InputData.ActionMode == "CREATE_NODEKEY" && CommonTemplete.CookiesData.CookieUserProperty != "admin" {
    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      log.Println("invalid userid property:" + CommonTemplete.CookiesData.CookieUserProperty)

      OutputData.MsgType = "IDCHECK"
      OutputData.MsgTitle = ""
      OutputData.MsgMsg = "invalid user property access"
      OutputData.MsgCode = "1090"
      OutputData.MsgValue = "invalid user property access"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
      return
    }
  }

  QueryString = "SELECT COUNT(a.user_id) " +
                "FROM user a " +
                "WHERE a.user_id = '%s' "

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID)
  log.Println("UserIDCheck Query -> ", CommonTemplete.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&ResultSetRowCount)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      OutputData.MsgType = "IDCHECK"
      OutputData.MsgTitle = "ID Check"
      OutputData.MsgMsg = "exception db query"
      OutputData.MsgCode = "1080"
      OutputData.MsgValue = ""

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      return
    }
  }
  ResultSetRows.Close()

  if ResultSetRowCount == 1 {
    log.Println("Invalid UserID - ResultSetRowCount:", ResultSetRowCount)

    OutputData.MsgType = "IDCHECK"
    OutputData.MsgTitle = "ID Check"
    OutputData.MsgMsg = "invalid user id"
    OutputData.MsgCode = "1011"
    OutputData.MsgValue = "user id existed"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  } else if ResultSetRowCount > 1 {
    log.Println("Invalid UserID - ResultSetRowCount:", ResultSetRowCount)

    OutputData.MsgType = "IDCHECK"
    OutputData.MsgTitle = "ID Check"
    OutputData.MsgMsg = "UserID Check Type"
    OutputData.MsgCode = "1081"
    OutputData.MsgValue = "user id existed many"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  log.Println("Valid UserID - ResultSetRowCount:", ResultSetRowCount)

  OutputData.MsgType = "IDCHECK"
  OutputData.MsgTitle = "ID Check"
  OutputData.MsgMsg = "UserID Check Type"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = "user id not existed"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))

/*
INVALID_ACCESS:
  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(InputJsonData))
  return

EXIST_USERID:
  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(InputJsonData))
  return
  */

}


func WebServer_NodeID_List(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var HtmlNodeIDList NodeIDList 
  var NodeID NodeIDListItem 
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var ResultSetRowCount int
  var URLGetParam string
  var PageNumString string
  var PageSortString string
  var SearchParamInitFlag bool
  var QueryString string
	var err error

  var MaxCountPage int = 10
  var MaxRowCountPerPage int = 25

  log.Println("KMS Web Server - NodeID_Management", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }
  
  SessionCookieUserData(&HtmlNodeIDList.CookiesData, req)
  WebServerMainMenu (&HtmlNodeIDList.MainMenu, "nodeid")
  WebServerOEMInformation(&HtmlNodeIDList.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  ParamPageNum, ok := req.URL.Query()["page_num"]
  if !ok || len (ParamPageNum) < 1 {
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
  if !ok || len (ParamPageSort) < 1 {
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
    HtmlNodeIDList.SearchParamUserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeIDList.SearchParamUserKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
    HtmlNodeIDList.SearchParamUserNodeID = HTTPReq_ReturnParamValue (req, "GET", "node_id")
    HtmlNodeIDList.SearchParamUserNodeStatus = HTTPReq_ReturnParamValue (req, "GET", "node_status")
  } else {
    HtmlNodeIDList.SearchParamUserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeIDList.SearchParamUserKey = HTTPReq_ReturnParamValue (req, "POST", "node_key")
    HtmlNodeIDList.SearchParamUserNodeID = HTTPReq_ReturnParamValue (req, "POST", "node_id")
    HtmlNodeIDList.SearchParamUserNodeStatus = HTTPReq_ReturnParamValue (req, "POST", "node_status")
  }

  SearchParamInitFlag = false
  
  if len(HtmlNodeIDList.SearchParamUserID) > 0 {
    URLGetParam += fmt.Sprintf("&user_id=%s", HtmlNodeIDList.SearchParamUserID)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeIDList.SQLQueryCondition += " AND"
      HtmlNodeIDList.SQLQueryCondition += fmt.Sprintf(" (a.user_id = '%s') ", HtmlNodeIDList.SearchParamUserID)
    } else {
      HtmlNodeIDList.SQLQueryCondition += " AND"
      HtmlNodeIDList.SQLQueryCondition += fmt.Sprintf(" (a.user_id = '%s') ", HtmlNodeIDList.SearchParamUserID)
    }
  }

  if len(HtmlNodeIDList.SearchParamUserKey) > 0 {
    URLGetParam += fmt.Sprintf("&node_key=%s", HtmlNodeIDList.SearchParamUserKey)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeIDList.SQLQueryCondition += " AND"
      HtmlNodeIDList.SQLQueryCondition += fmt.Sprintf(" (b.user_key_id = '%s') ", HtmlNodeIDList.SearchParamUserKey)
    } else {
      HtmlNodeIDList.SQLQueryCondition += " AND"
      HtmlNodeIDList.SQLQueryCondition += fmt.Sprintf(" (b.user_key_id = '%s') ", HtmlNodeIDList.SearchParamUserKey)
    }
  }

  if len(HtmlNodeIDList.SearchParamUserNodeID) > 0 {
    URLGetParam += fmt.Sprintf("&node_id=%s", HtmlNodeIDList.SearchParamUserNodeID)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeIDList.SQLQueryCondition += " AND"
      HtmlNodeIDList.SQLQueryCondition += fmt.Sprintf(" (c.node_id = '%s') ", HtmlNodeIDList.SearchParamUserNodeID)
    } else {
      HtmlNodeIDList.SQLQueryCondition += " AND"
      HtmlNodeIDList.SQLQueryCondition += fmt.Sprintf(" (c.node_id = '%s') ", HtmlNodeIDList.SearchParamUserNodeID)
    }
  }

  if len(HtmlNodeIDList.SearchParamUserNodeStatus) > 0 {
    URLGetParam += fmt.Sprintf("&node_status=%s", HtmlNodeIDList.SearchParamUserNodeStatus)

    if SearchParamInitFlag == false {
      SearchParamInitFlag = true 
      HtmlNodeIDList.SQLQueryCondition += " AND"
      HtmlNodeIDList.SQLQueryCondition += fmt.Sprintf(" (b.status = \"%s\")", HtmlNodeIDList.SearchParamUserNodeStatus)
    } else {
      HtmlNodeIDList.SQLQueryCondition += " AND"
      HtmlNodeIDList.SQLQueryCondition += fmt.Sprintf(" (b.status = \"%s\")", HtmlNodeIDList.SearchParamUserNodeStatus)
    }
  }

  if len(HtmlNodeIDList.SQLQueryCondition) > 0 {
    if HtmlNodeIDList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT COUNT(a.user_id) " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id_seq = b.user_id_seq " +
                          "%s "
      HtmlNodeIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDList.SQLQueryCondition)
    } else {
      QueryString = "SELECT COUNT(a.user_id) " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id = '%s' " +
                          "AND a.user_id_seq = b.user_id_seq " + 
                          "%s "
      HtmlNodeIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDList.CookiesData.CookieUserID, HtmlNodeIDList.SQLQueryCondition)
    }
  } else {
    if HtmlNodeIDList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT COUNT(a.user_id) " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id_seq = b.user_id_seq "
      HtmlNodeIDList.SQLQuery = fmt.Sprintf(QueryString)
    } else {
      QueryString = "SELECT COUNT(a.user_id) " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id = '%s' " +
                          "AND a.user_id_seq = b.user_id_seq "
      HtmlNodeIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDList.CookiesData.CookieUserID)
    }
  }

  log.Println("NodeID List Count Query -> ", HtmlNodeIDList.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeIDList.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&ResultSetRowCount)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
  }
  ResultSetRows.Close()
  
  HtmlDataPage (&(HtmlNodeIDList.TempletePage), "UserKeyPageNum", PageNumString, "UserKeySort", PageSortString, 0, MaxCountPage, MaxRowCountPerPage, ResultSetRowCount, "/nodeid/management/", URLGetParam, "/service_stop/", "[exception]", "redirect")

  if len(HtmlNodeIDList.SQLQueryCondition) > 0 {
    if HtmlNodeIDList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT a.user_id, b.user_key_id, b.node_client_count, IFNULL(c.node_id, \"\"), b.create_date, b.update_date, b.status " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id_seq = b.user_id_seq " +
                          "%s " +
                    "ORDER BY user_id " +
                    "LIMIT %d OFFSET %d"
      HtmlNodeIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDList.SQLQueryCondition, HtmlNodeIDList.TempletePage.MaxRowCountPage, HtmlNodeIDList.TempletePage.RowOffset)
    } else {
      QueryString = "SELECT a.user_id, b.user_key_id, b.node_client_count, IFNULL(c.node_id, \"\"), b.create_date, b.update_date, b.status " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id = '%s' " +
                          "AND a.user_id_seq = b.user_id_seq " +
                          "%s " +
                    "ORDER BY user_id " +
                    "LIMIT %d OFFSET %d"
      HtmlNodeIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDList.CookiesData.CookieUserID, HtmlNodeIDList.SQLQueryCondition, HtmlNodeIDList.TempletePage.MaxRowCountPage, HtmlNodeIDList.TempletePage.RowOffset)
    }
  } else {
    if HtmlNodeIDList.CookiesData.CookieUserProperty == "admin" {
      QueryString = "SELECT a.user_id, b.user_key_id, b.node_client_count, IFNULL(c.node_id, \"\"), b.create_date, b.update_date, b.status " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id_seq = b.user_id_seq " +
                    "ORDER BY user_id " +
                    "LIMIT %d OFFSET %d"
      HtmlNodeIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDList.TempletePage.MaxRowCountPage, HtmlNodeIDList.TempletePage.RowOffset)

    } else {
      QueryString = "SELECT a.user_id, b.user_key_id, b.node_client_count, IFNULL(c.node_id, \"\"), b.create_date, b.update_date, b.status " +
                    "FROM user a, node_id c " +
                    "RIGHT JOIN user_key b " +
                    "ON b.user_key_id_seq = c.user_key_id_seq " +
                    "WHERE a.user_id = '%s' " +
                          "AND a.user_id_seq = b.user_id_seq " +
                    "ORDER BY user_id " +
                    "LIMIT %d OFFSET %d"
      HtmlNodeIDList.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDList.CookiesData.CookieUserID, HtmlNodeIDList.TempletePage.MaxRowCountPage, HtmlNodeIDList.TempletePage.RowOffset)
    }
  }

  log.Println("NodeID List Limit Query -> ", HtmlNodeIDList.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeIDList.SQLQuery)
  for i := 0; ResultSetRows.Next(); i++ {
    err := ResultSetRows.Scan(&(NodeID.UserID), 
                              &(NodeID.UserKey), 
                              &(NodeID.NodeClientNumber), 
                              &(NodeID.NodeID), 
                              &(NodeID.CreateDate), 
                              &(NodeID.UpdateDate), 
                              &(NodeID.NodeStatus))
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }

    NodeID.NodeIDLicenseLinkURL = fmt.Sprintf("/nodekey/license/?user_id=%s&node_key=%s", NodeID.UserID, NodeID.UserKey)
    NodeID.NodeIDCreateLinkURL = fmt.Sprintf("/nodeid/create_input/?user_id=%s&node_key=%s", NodeID.UserID, NodeID.UserKey)
    NodeID.NodeIDModifyLinkURL = fmt.Sprintf("/nodeid/modify_input/?user_id=%s&node_key=%s&node_id=%s", NodeID.UserID, NodeID.UserKey, NodeID.NodeID)
    NodeID.NodeIDDeleteLinkURL = fmt.Sprintf("/nodeid/delete_input/?user_id=%s&node_key=%s&node_id=%s", NodeID.UserID, NodeID.UserKey, NodeID.NodeID)

    HtmlNodeIDList.NodeID = append(HtmlNodeIDList.NodeID, NodeID)
  }
  ResultSetRows.Close()

  for i := range HtmlNodeIDList.NodeID {
    log.Println("ResultRows Data :", HtmlNodeIDList.NodeID[i].UserID, 
                                     HtmlNodeIDList.NodeID[i].UserKey, 
                                     HtmlNodeIDList.NodeID[i].NodeClientNumber, 
                                     HtmlNodeIDList.NodeID[i].NodeID, 
                                     HtmlNodeIDList.NodeID[i].CreateDate, 
                                     HtmlNodeIDList.NodeID[i].UpdateDate, 
                                     HtmlNodeIDList.NodeID[i].NodeStatus,
                                     NodeID.NodeIDLicenseLinkURL, 
                                     NodeID.NodeIDCreateLinkURL, 
                                     NodeID.NodeIDModifyLinkURL, 
                                     NodeID.NodeIDDeleteLinkURL)
  }

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodeid_list.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodeid_list.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlNodeIDList)
}


func WebServer_NodeID_Create_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlNodeIDCreate NodeIDCreate
  var NodeIDDetail NodeIDDetailItem 
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var ResultSetRowCount int
  var QueryString string
	var err error

  log.Println("KMS Web Server - NodeID Create_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeIDCreate.CookiesData, req)
  WebServerMainMenu (&HtmlNodeIDCreate.MainMenu, "nodeid")
  WebServerOEMInformation(&HtmlNodeIDCreate.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeIDCreate.NodeData.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeIDCreate.NodeData.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
  } else if req.Method == "POST" {
    HtmlNodeIDCreate.NodeData.UserID = HTTPReq_ReturnParamValue (req, "POST", "user_id")
    HtmlNodeIDCreate.NodeData.NodeKey = HTTPReq_ReturnParamValue (req, "POST", "node_key")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if len(HtmlNodeIDCreate.NodeData.UserID) == 0 || len(HtmlNodeIDCreate.NodeData.NodeKey) == 0 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeIDCreate.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeIDCreate.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeIDCreate.CookiesData.CookieUserID != HtmlNodeIDCreate.NodeData.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT count(node_id) " +
                "FROM node_id " +
                "WHERE user_key_id_seq = (SELECT b.user_key_id_seq " +
                "                         FROM user a, user_key b " +
                "                         WHERE a.user_id_seq = b.user_id_seq " +
                "                               and a.user_id = '%s' " +
                "                               and b.user_key_id = '%s') "
  HtmlNodeIDCreate.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDCreate.NodeData.UserID, HtmlNodeIDCreate.NodeData.NodeKey)
  log.Println("NodeID List Count Query (by user_id, node_key): ", HtmlNodeIDCreate.SQLQuery)
  
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeIDCreate.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&ResultSetRowCount)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
  }
  ResultSetRows.Close()

  if ResultSetRowCount == 0 {
    HtmlNodeIDCreate.NodeData.NodeIDOldCount = 0
    HtmlNodeIDCreate.NodeData.NodeIDNewCount = 0
    log.Println("ResultRows Data [", HtmlNodeIDCreate.NodeData.NodeIDOldCount, "/", 100, "]", ": No Data")
  } else {
    HtmlNodeIDCreate.NodeData.NodeIDOldCount = ResultSetRowCount
    HtmlNodeIDCreate.NodeData.NodeIDNewCount = 0

    QueryString = "SELECT node_id " +
                  "FROM node_id " +
                  "WHERE user_key_id_seq = (SELECT b.user_key_id_seq " +
                  "                         FROM user a, user_key b " +
                  "                         WHERE a.user_id_seq = b.user_id_seq " +
                  "                               and a.user_id = '%s' " +
                  "                               and b.user_key_id = '%s') "
    HtmlNodeIDCreate.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDCreate.NodeData.UserID, HtmlNodeIDCreate.NodeData.NodeKey)
    log.Println("NodeID List Query (by user_id, node_key): ", HtmlNodeIDCreate.SQLQuery)
   
    ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeIDCreate.SQLQuery)
    for i := 0; ResultSetRows.Next(); i++ {
      err := ResultSetRows.Scan(&(NodeIDDetail.NodeID))
      if err != nil {
        ResultSetRows.Close()
        log.Println(" data Scan error:", err)
        WebServer_Redirect(w, req, "/service_stop/")
        return
      }

      HtmlNodeIDCreate.NodeData.NodeIDDetail = append(HtmlNodeIDCreate.NodeData.NodeIDDetail, NodeIDDetail)
    }
    ResultSetRows.Close()

    for i := range HtmlNodeIDCreate.NodeData.NodeIDDetail {
      log.Println("ResultRows Data [(", i, "/", ResultSetRowCount, ") /", 100, "]", ": NodeID -", HtmlNodeIDCreate.NodeData.NodeIDDetail[i].NodeID)
    }
  }

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodeid_create_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodeid_create_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlNodeIDCreate)
}


func WebServer_NodeID_Create_Proc (w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var ResultSetRows *sql.Rows
  var InputData jsonInputNodeIDGenerate
  var OutputData jsonOutputPack 
  var OutputBody string
  var TempGenerateNodeIDList string
  //var GenerateNodeIDSplitList[] string
  var QueryString string
	var err error

  log.Println("KMS Web Server - NodeID Create Proc", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodeid")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "NODE ID CREATE"
    OutputData.MsgTitle = "NodeID Create"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if InputData.ActionMode == "" || InputData.UserID == "" || InputData.NodeKey == "" || InputData.NodeIDList == "" {
    OutputData.MsgType = "NODE ID CREATE"
    OutputData.MsgTitle = "NodeID Create"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {
    
  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      OutputData.MsgType = "NODE ID CREATE"
      OutputData.MsgTitle = "NodeID Create"
      OutputData.MsgMsg = "invalid user id access"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "invalid user id access"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
  } else {
    OutputData.MsgType = "NODE ID CREATE"
    OutputData.MsgTitle = "NodeID Create"
    OutputData.MsgMsg = "invalid user id access"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid user id access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  QueryString = "SELECT nodeid_generate_tmp_key " +
                "FROM user_key " +
                "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                "                         FROM (SELECT b.user_key_id_seq " +               
                "                               FROM user a, user_key b " +                       
                "                               WHERE a.user_id = '%s' " +                               
                "                                     and b.user_key_id = '%s' " +
                "                                     and a.user_id_seq = b.user_id_seq) tmp) "

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey)
  log.Println("Tmp Generating NodeID Query -> ", CommonTemplete.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&TempGenerateNodeIDList)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      OutputData.MsgType = "NODE ID CREATE"
      OutputData.MsgTitle = "NodeID Create"
      OutputData.MsgMsg = "exception db query (tmp sync buffer)"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception db query (tmp sync buffer)"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      return
    }
  }
  ResultSetRows.Close()

  if TempGenerateNodeIDList == "" || TempGenerateNodeIDList != InputData.NodeIDList {
    log.Println("Mismatching Tmp Generating NodeIDList:", InputData.NodeIDList)

    OutputData.MsgType = "NODE ID CREATE"
    OutputData.MsgTitle = "NodeID Create"
    OutputData.MsgMsg = "invalid input node_id (mismatching tmp generating node_id)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid input node_id (mismatching tmp generating node_id)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  mariadb_lib.DB_AutoCommit_Disable(Database)
  defer mariadb_lib.DB_Rollback(Database)
  defer mariadb_lib.DB_AutoCommit_Enable(Database)

  GenerateNodeIDSplitList := strings.Split(TempGenerateNodeIDList, ";")
  TempGenerateNodeIDList = ""
  for i := range GenerateNodeIDSplitList {
    if len(GenerateNodeIDSplitList[i]) >= 38 {

      log.Println("Insert NodeID IDX:", i, ", NodeID:", GenerateNodeIDSplitList[i])

      QueryString = "INSERT INTO node_id " +
                    "(node_id, create_date, user_id_seq, create_user_id, update_user_id, user_key_id_seq, user_key_id, web_api_auth_key, web_api_auth_token, web_api_auth_token_expire_time_date) " +
                    "VALUES ('%s', " +
                    "        NOW(), " +
                    "        (SELECT user_id_seq FROM user WHERE user_id = '%s'), " +
                    "        '%s', " +
                    "        '%s', " +
                    "        (SELECT user_key_id_seq FROM user_key WHERE user_key_id = '%s'), " +
                    "        '%s', " +
                    "        '%s', " +
                    "        '%s', " +
                    "        NOW()) "
      CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, GenerateNodeIDSplitList[i], InputData.UserID, InputData.UserID, InputData.UserID, InputData.NodeKey, InputData.NodeKey, "", "")
      log.Println("NodeID Insert Query -> ", CommonTemplete.SQLQuery)
	    mariadb_lib.Insert_Data(Database, CommonTemplete.SQLQuery)
      // TODO: DB Excxception (return cnt)

      QueryString = "UPDATE user_key " +
                    "SET node_client_count = node_client_count + 1 " +
                    "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                    "                         FROM (SELECT b.user_key_id_seq " +
                    "                               FROM user a, user_key b " +
                    "                               WHERE a.user_id = '%s' " +
                    "                                     and b.user_key_id = '%s' " +
                    "                                     and a.user_id_seq = b.user_id_seq) tmp)"
      CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey)
      log.Println("NodeID Count Update Query -> ", CommonTemplete.SQLQuery)
      mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
      // TODO: DB Excxception (return cnt)

      TempGenerateNodeIDList += GenerateNodeIDSplitList[i] + ";"
    }
  }

  mariadb_lib.DB_Commit(Database)
  mariadb_lib.DB_AutoCommit_Enable(Database)
  
  if DBSetTmpGenerateNodeID(InputData.UserID, InputData.NodeKey, "") != 1 {
    OutputData.MsgType = "NODE ID GENERATE"
    OutputData.MsgTitle = "Node ID Generate"
    OutputData.MsgMsg = "exception db query (tmp sync buffer init)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "exception db query (tmp sync buffer init)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  OutputData.MsgType = "NODE ID GENERATE"
  OutputData.MsgTitle = "Node ID Generate"
  OutputData.MsgMsg = "Generate NodeID Success"
  OutputData.MsgCode = "1000"
  //OutputData.MsgValue = TempGenerateNodeIDList
  OutputData.MsgValue = "insert success"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


func WebServer_NodeID_Modify_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlNodeIDModify NodeIDModify
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var ResultSetRowCount int
  var QueryString string
	var err error

  log.Println("KMS Web Server - NodeID Modify_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeIDModify.CookiesData, req)
  WebServerMainMenu (&HtmlNodeIDModify.MainMenu, "nodeid")
  WebServerOEMInformation(&HtmlNodeIDModify.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeIDModify.NodeData.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeIDModify.NodeData.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
    HtmlNodeIDModify.NodeData.NodeIDOld = HTTPReq_ReturnParamValue (req, "GET", "node_id")
  } else if req.Method == "POST" {
    HtmlNodeIDModify.NodeData.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeIDModify.NodeData.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
    HtmlNodeIDModify.NodeData.NodeIDOld = HTTPReq_ReturnParamValue (req, "GET", "node_id")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if len(HtmlNodeIDModify.NodeData.UserID) == 0 || len(HtmlNodeIDModify.NodeData.NodeKey) == 0 || len(HtmlNodeIDModify.NodeData.NodeIDOld) == 0 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeIDModify.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeIDModify.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeIDModify.CookiesData.CookieUserID != HtmlNodeIDModify.NodeData.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT count(node_id) " +
                "FROM node_id " +
                "WHERE user_key_id_seq = (SELECT b.user_key_id_seq " +
                "                         FROM user a, user_key b " +
                "                         WHERE a.user_id = '%s' " +
                "                               and b.user_key_id = '%s' " +
                "                               and a.user_id_seq = b.user_id_seq) " +
                "      and node_id = '%s' "                              

  HtmlNodeIDModify.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDModify.NodeData.UserID, HtmlNodeIDModify.NodeData.NodeKey, HtmlNodeIDModify.NodeData.NodeIDOld)
  log.Println("NodeID List Count Query (by user_id, node_key, node_id): ", HtmlNodeIDModify.SQLQuery)
  
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeIDModify.SQLQuery)
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

  if ResultSetRowCount != 1 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  HtmlNodeIDModify.NodeData.NodeIDNew = GenerateNodeID(nil, HtmlNodeIDModify.NodeData.NodeKey)
  log.Println("Old NodeID:", HtmlNodeIDModify.NodeData.NodeIDOld, ", New NodeID:", HtmlNodeIDModify.NodeData.NodeIDNew)

  if HtmlNodeIDModify.NodeData.NodeIDNew == "" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if DBSetTmpGenerateNodeID(HtmlNodeIDModify.NodeData.UserID, HtmlNodeIDModify.NodeData.NodeKey, HtmlNodeIDModify.NodeData.NodeIDNew) != 1 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodeid_modify_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodeid_modify_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlNodeIDModify)
}


func WebServer_NodeID_Modify_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var ResultSetRows *sql.Rows
  var InputData jsonInputNodeModifyPack 
  var OutputData jsonOutputPack 
  var OutputBody string
  var TmpGenerateNodeID string
  var QueryString string
	var err error

  log.Println("KMS Web Server - NodeID Modify Proc", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodeid")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    OutputData.MsgType = "NODE ID MODIFY "
    OutputData.MsgTitle = "Node ID Modify"
    OutputData.MsgMsg = "invalid request method"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid request method"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "NODEIDMODIFYE"
    OutputData.MsgTitle = "NodeID Modify"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  log.Println("NodeID Modify Input NodeIDOld:", InputData.NodeIDOld, ", NodeIDNew:", InputData.NodeIDNew)

  if InputData.UserID == "" || InputData.NodeKey == "" || InputData.NodeIDOld == "" || InputData.NodeIDNew == "" {
    OutputData.MsgType = "NODEIDMODIFYE"
    OutputData.MsgTitle = "NodeID Modify"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {
    
  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      OutputData.MsgType = "NODEIDMODIFYE"
      OutputData.MsgTitle = "NodeID Modify"
      OutputData.MsgMsg = "invalid user id access"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "invalid user id access"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
  } else {
    OutputData.MsgType = "NODEIDMODIFYE"
    OutputData.MsgTitle = "NodeID Modify"
    OutputData.MsgMsg = "invalid user id access"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid user id access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  QueryString = "SELECT nodeid_generate_tmp_key " +
                "FROM user_key " +
                "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                                         "FROM (SELECT b.user_key_id_seq " +               
                                               "FROM user a, user_key b " +                       
                                               "WHERE a.user_id = '%s' " +                               
                                                      "and b.user_key_id = '%s' " +
                                                      "and a.user_id_seq = b.user_id_seq) tmp) "
  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey)
  log.Println("Tmp Generating NodeID Query -> ", CommonTemplete.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&TmpGenerateNodeID)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      OutputData.MsgType = "NODEIDMODIFYE"
      OutputData.MsgTitle = "NodeID Modify"
      OutputData.MsgMsg = "exception db query"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception db query"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      return
    }
  }
  ResultSetRows.Close()

  if TmpGenerateNodeID == "" || TmpGenerateNodeID != InputData.NodeIDNew {
    log.Println("Mismatching Tmp Generating NodeID:", TmpGenerateNodeID, ", Input NodeIDNew:", InputData.NodeIDNew)

    OutputData.MsgType = "NODEIDMODIFYE"
    OutputData.MsgTitle = "NodeID Modify"
    OutputData.MsgMsg = "invalid input node_id (mismatching tmp generating node_id)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid input node_id (mismatching tmp generating node_id)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  QueryString = "UPDATE node_id " +
                "SET node_id = '%s' " +
                "WHERE node_id_seq = (SELECT node_id_seq " +
                                    "FROM (SELECT node_id_seq " +
                                          "FROM user a, user_key b, node_id c " +
                                          "WHERE a.user_id = '%s' " +
                                                "and b.user_key_id = '%s' " +
                                                "and a.user_id_seq = b.user_id_seq " +
                                                "and b.user_key_id_seq = c.user_key_id_seq " +
                                                "and c.node_id = '%s') tmp)"

  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.NodeIDNew, InputData.UserID, InputData.NodeKey, InputData.NodeIDOld)
  log.Println("Tmp Generating NodeID Update Query -> ", CommonTemplete.SQLQuery)

	mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
  // TODO: DB Excxception

  log.Println("Update Success : Change NodeID Information (", InputData.NodeIDOld, "->", InputData.NodeIDNew)

  if DBSetTmpGenerateNodeID(InputData.UserID, InputData.NodeKey, "") != 1 {
    OutputData.MsgType = "NODEIDMODIFYE"
    OutputData.MsgTitle = "NodeID Modify"
    OutputData.MsgMsg = "exception db query"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "exception db query"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  OutputData.MsgType = "NODEIDMODIFYE"
  OutputData.MsgTitle = "NodeID Modify"
  OutputData.MsgMsg = "Change NodeID"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = "change new node_id"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


func WebServer_NodeID_Delete_Input(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlNodeIDDelete NodeIDDelete
	var HtmlTemplate *template.Template
	var err error

  log.Println("KMS Web Server - NodeID Delete_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlNodeIDDelete.CookiesData, req)
  WebServerMainMenu (&HtmlNodeIDDelete.MainMenu, "nodeid")
  WebServerOEMInformation(&HtmlNodeIDDelete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method == "GET" {
    HtmlNodeIDDelete.NodeData.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeIDDelete.NodeData.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
    HtmlNodeIDDelete.NodeData.NodeID = HTTPReq_ReturnParamValue (req, "GET", "node_id")
  } else if req.Method == "POST" {
    HtmlNodeIDDelete.NodeData.UserID = HTTPReq_ReturnParamValue (req, "GET", "user_id")
    HtmlNodeIDDelete.NodeData.NodeKey = HTTPReq_ReturnParamValue (req, "GET", "node_key")
    HtmlNodeIDDelete.NodeData.NodeID = HTTPReq_ReturnParamValue (req, "GET", "node_id")
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if len(HtmlNodeIDDelete.NodeData.UserID) == 0 || len(HtmlNodeIDDelete.NodeData.NodeKey) == 0 || len(HtmlNodeIDDelete.NodeData.NodeID) == 0 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  if HtmlNodeIDDelete.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlNodeIDDelete.CookiesData.CookieUserProperty == "normal" {
    if HtmlNodeIDDelete.CookiesData.CookieUserID != HtmlNodeIDDelete.NodeData.UserID {
      WebServer_Redirect(w, req, "/service_invalid_access/")
      return
    }
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  /*
  QueryString = "SELECT count(node_id) " +
                "FROM node_id " +
                "WHERE user_key_id_seq = (SELECT b.user_key_id_seq " +
                "                         FROM user a, user_key b " +
                "                         WHERE a.user_id = '%s' " +
                "                               and b.user_key_id = '%s' " +
                "                               and a.user_id_seq = b.user_id_seq) " +
                "      and node_id = '%s' "                              

  HtmlNodeIDDelete.SQLQuery = fmt.Sprintf(QueryString, HtmlNodeIDDelete.NodeData.UserID, HtmlNodeIDDelete.NodeData.NodeKey, HtmlNodeIDDelete.NodeData.NodeIDOld)
  log.Println("NodeID List Count Query (by user_id, node_key, node_id): ", HtmlNodeIDDelete.SQLQuery)
  
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlNodeIDDelete.SQLQuery)
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

  if ResultSetRowCount != 1 {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }
  */

  HtmlTemplate, err = template.ParseFiles("./html/kms_nodeid_delete_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_nodeid_delete_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlNodeIDDelete)
}


func WebServer_NodeID_Delete_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var ResultSetRows *sql.Rows
  var InputData jsonInputNodeIDDeletePack 
  var OutputData jsonOutputPack 
  var OutputBody string
  var CheckingNodeKey string
  var CheckingNodeID string
  var CheckingNodeIDCount int
  var QueryString string
	var err error

  log.Println("KMS Web Server - NodeID Delete_Proc", req.Method, ", URL:", req.URL)

  res := Cookie_Check(w, req) 
  if res < 0 {
    OutputData.MsgType = "NODE ID DELETE"
    OutputData.MsgTitle = "NodeID Delete"
    OutputData.MsgMsg = "Cookie expiretime timed out"
    OutputData.MsgCode = "1100"
    OutputData.MsgMsg = "Cookie expiretime timed out"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodeid")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "NODE ID DELETE"
    OutputData.MsgTitle = "NodeID Delete"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if InputData.ActionMode == "" || InputData.UserID == "" || InputData.NodeKey == "" || InputData.NodeID == "" {
    OutputData.MsgType = "NODE ID DELETE"
    OutputData.MsgTitle = "NodeID Delete"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  mariadb_lib.DB_AutoCommit_Disable(Database)
  defer mariadb_lib.DB_Rollback(Database)
  defer mariadb_lib.DB_AutoCommit_Enable(Database)

  if InputData.ActionMode == "DELETE_LIST" {

    DeleteNodeIDSplitList := strings.Split(InputData.NodeID, ",")

    for i := range DeleteNodeIDSplitList {
      log.Println("Delete NodeID IDX:", i, ", NodeID:", DeleteNodeIDSplitList[i])

      // TODO DML return checking 
      if CommonTemplete.CookiesData.CookieUserProperty == "admin" || CommonTemplete.CookiesData.CookieUserProperty == "normal" {

        QueryString = "SELECT a.user_key_id, a.node_client_count, b.node_id " +
                      "FROM user_key a, node_id b " +
                      "WHERE b.node_id = '%s' " +
                            "and b.user_key_id_seq = a.user_key_id_seq "

        CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, DeleteNodeIDSplitList[i])
        log.Println("Checking Delete NodeKey & NodeID Query -> ", CommonTemplete.SQLQuery)

        ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
        for ResultSetRows.Next() {
          err := ResultSetRows.Scan(&CheckingNodeKey, &CheckingNodeIDCount, &CheckingNodeID)
          if err != nil {
            ResultSetRows.Close()
            log.Println(" data Scan error:", err)

            OutputData.MsgType = "NODE ID REATE"
            OutputData.MsgTitle = "NodeID Create"
            OutputData.MsgMsg = "exception db query (tmp sync buffer)"
            OutputData.MsgCode = "1001"
            OutputData.MsgValue = "exception db query (tmp sync buffer)"

            jstrbyte, _ := json.Marshal(OutputData)
            OutputBody = string(jstrbyte)

            w.Header().Set("Content-Type", "application/json") 
            w.Write ([]byte(OutputBody))

            return
          }
        }
        ResultSetRows.Close()

        log.Println("[", i, "] Checking Data (NodeKey:", CheckingNodeKey, ", NodeID Count:", CheckingNodeIDCount, ", NodeID:", CheckingNodeID)

        if CheckingNodeKey != "" && CheckingNodeIDCount > 0 && CheckingNodeID != "" {
          
          QueryString = "DELETE FROM node_id " +
                        "WHERE node_id_seq = (SELECT node_id_seq " +
                                            "FROM (SELECT node_id_seq " +
                                                  "FROM user_key b, node_id c " +
                                                  "WHERE b.user_key_id = '%s' " +
                                                        "and b.user_key_id_seq = c.user_key_id_seq " +          
                                                        "and c.node_id = '%s') tmp) " 

          CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, CheckingNodeKey, CheckingNodeID)
          log.Println("NodeID Delete Query -> ", CommonTemplete.SQLQuery)

          mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
          // TODO: DB Excxception

          QueryString = "UPDATE user_key " +
                        "SET node_client_count = node_client_count - 1 " +
                        "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                                                 "FROM (SELECT b.user_key_id_seq " +
                                                       "FROM user_key b " +
                                                       "WHERE b.user_key_id = '%s') tmp)  "
          CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, CheckingNodeKey)
          log.Println("NodeID Count Update Query -> ", CommonTemplete.SQLQuery)

          mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
          // TODO: DB Excxception
        }
      }
    }
    
  } else if InputData.ActionMode == "DELETE" {
    
    if CommonTemplete.CookiesData.CookieUserProperty == "admin" {
     
      QueryString = "DELETE FROM node_id " +
                    "WHERE node_id_seq = (SELECT node_id_seq " +
                                        "FROM (SELECT node_id_seq " +
                                              "FROM user a, user_key b, node_id c " +
                                              "WHERE a.user_id = '%s' " +
                                                    "and b.user_key_id = '%s' " +
                                                    "and a.user_id_seq = b.user_id_seq " +
                                                    "and b.user_key_id_seq = c.user_key_id_seq " +          
                                                    "and c.node_id = '%s') tmp) " 

      CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey, InputData.NodeID)
      log.Println("NodeID Delete Query -> ", CommonTemplete.SQLQuery)

      mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
      // TODO: DB Excxception

      QueryString = "UPDATE user_key " +
                    "SET node_client_count = node_client_count - 1 " +
                    "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                                             "FROM (SELECT b.user_key_id_seq " +
                                                   "FROM user a, user_key b " +
                                                   "WHERE a.user_id = '%s' " +
                                                   "and b.user_key_id = '%s' " +
                                                   "and a.user_id_seq = b.user_id_seq) tmp) "
      CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey)
      log.Println("NodeID Count Update Query -> ", CommonTemplete.SQLQuery)

      mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
      // TODO: DB Excxception
      
    } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
      if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
        OutputData.MsgType = "NODE ID DELETE"
        OutputData.MsgTitle = "NodeID Delete"
        OutputData.MsgMsg = "invalid user id access"
        OutputData.MsgCode = "1001"
        OutputData.MsgValue = "invalid user id access"

        jstrbyte, _ := json.Marshal(OutputData)
        OutputBody = string(jstrbyte)

        w.Header().Set("Content-Type", "application/json") 
        w.Write ([]byte(OutputBody))
        return
      }

      QueryString = "DELETE FROM node_id " +
                    "WHERE node_id_seq = (SELECT node_id_seq " +
                                        "FROM (SELECT node_id_seq " +
                                              "FROM user a, user_key b, node_id c " +
                                              "WHERE a.user_id = '%s' " +
                                                    "and b.user_key_id = '%s' " +
                                                    "and a.user_id_seq = b.user_id_seq " +
                                                    "and b.user_key_id_seq = c.user_key_id_seq " +          
                                                    "and c.node_id = '%s') tmp) " 

      CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey, InputData.NodeID)
      log.Println("NodeID Delete Query -> ", CommonTemplete.SQLQuery)

      mariadb_lib.Delete_Data(Database, CommonTemplete.SQLQuery)
      // TODO: DB Excxception

      QueryString = "UPDATE user_key " +
                    "SET node_client_count = node_client_count - 1 " +
                    "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                                             "FROM (SELECT b.user_key_id_seq " +
                                                   "FROM user a, user_key b " +
                                                   "WHERE a.user_id = '%s' " +
                                                   "and b.user_key_id = '%s' " +
                                                   "and a.user_id_seq = b.user_id_seq) tmp) "
      CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey)
      log.Println("NodeID Count Update Query -> ", CommonTemplete.SQLQuery)

      mariadb_lib.Update_Data(Database, CommonTemplete.SQLQuery)
      // TODO: DB Excxception

    } else {
      OutputData.MsgType = "NODE ID DELETE"
      OutputData.MsgTitle = "NodeID Delete"
      OutputData.MsgMsg = "invalid user id access"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "invalid user id access"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }

  } else {
    OutputData.MsgType = "NODE ID DELETE"
    OutputData.MsgTitle = "NodeID Delete"
    OutputData.MsgMsg = "invalid action mode"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid action mode"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
    
  }

  mariadb_lib.DB_Commit(Database)
  mariadb_lib.DB_AutoCommit_Enable(Database)

  OutputData.MsgType = "NODE ID DELETE"
  OutputData.MsgTitle = "NodeID Delete"
  OutputData.MsgMsg = "node id delete and node id count degree"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = "node id delete and node id count degree"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


func WebServer_NodeID_Ajax_NodeIDGenerate (w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var ResultSetRows *sql.Rows
  var InputData jsonInputNodeIDGenerate
  var OutputData jsonOutputPack 
  var OutputBody string
  var TempGenerateNodeIDList string
  var TempGenerateNodeID string
  var QueryString string
	var err error

  log.Println("KMS Web Server - WebServer_NodeID_Ajax_NodeIDGenerate ", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    OutputData.MsgType = "NODE ID GENERATE"
    OutputData.MsgTitle = "Node ID Generate"
    OutputData.MsgMsg = "Cookie expiretime timed out"
    OutputData.MsgCode = "1100"
    OutputData.MsgValue = "Cookie expiretime timed out"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodeid")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    OutputData.MsgType = "NODE ID GENERATE"
    OutputData.MsgTitle = "Node ID Generate"
    OutputData.MsgMsg = "invalid request method"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid request method"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "NODE ID GENERATE"
    OutputData.MsgTitle = "Node ID Generate"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if (InputData.UserID == "" || InputData.UserID == "" || InputData.NodeKey == "") {
    OutputData.MsgType = "NODE ID GENERATE"
    OutputData.MsgTitle = "Node ID Generate"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {

  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    if CommonTemplete.CookiesData.CookieUserID != InputData.UserID {
      OutputData.MsgType = "NODE ID GENERATE"
      OutputData.MsgTitle = "Node ID Generate"
      OutputData.MsgMsg = "invalid user id access"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "invalid user id access"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))
      return
    }
  } else {
    OutputData.MsgType = "NODE ID GENERATE"
    OutputData.MsgTitle = "Node ID Generate"
    OutputData.MsgMsg = "invalid user property access"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid user property access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if InputData.NodeIDList == "" {
    log.Println("Temporary Generate Node ID List:", "no data")
  } else {
    log.Println("Temporary Generate Node ID List:", InputData.NodeIDList)
  }

  if InputData.NodeIDList == "" {
    if DBSetTmpGenerateNodeID(InputData.UserID, InputData.NodeKey, "") != 1 {
      OutputData.MsgType = "NODE ID GENERATE"
      OutputData.MsgTitle = "Node ID Generate"
      OutputData.MsgMsg = "exception db query (tmp sync buffer init)"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception db query (tmp sync buffer init)"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      return
    }
  } else {
    QueryString = "SELECT nodeid_generate_tmp_key " +
                  "FROM user_key " +
                  "WHERE user_key_id_seq = (SELECT user_key_id_seq " +
                  "                         FROM (SELECT b.user_key_id_seq " +               
                  "                               FROM user a, user_key b " +                       
                  "                               WHERE a.user_id = '%s' " +                               
                  "                                     and b.user_key_id = '%s' " +
                  "                                     and a.user_id_seq = b.user_id_seq) tmp) "

    CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.UserID, InputData.NodeKey)
    log.Println("Tmp Generating NodeID Query -> ", CommonTemplete.SQLQuery)
    
    ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
    for ResultSetRows.Next() {
      err := ResultSetRows.Scan(&TempGenerateNodeIDList)
      if err != nil {
        ResultSetRows.Close()
        log.Println(" data Scan error:", err)

        OutputData.MsgType = "NODE ID GENERATE"
        OutputData.MsgTitle = "Node ID Generate"
        OutputData.MsgMsg = "exception db query (tmp sync buffer)"
        OutputData.MsgCode = "1001"
        OutputData.MsgValue = "exception db query (tmp sync buffer)"

        jstrbyte, _ := json.Marshal(OutputData)
        OutputBody = string(jstrbyte)

        w.Header().Set("Content-Type", "application/json") 
        w.Write ([]byte(OutputBody))

        return
      }
    }
    ResultSetRows.Close()

    if InputData.NodeIDList != TempGenerateNodeIDList {
      OutputData.MsgType = "NODE ID GENERATE"
      OutputData.MsgTitle = "Node ID Generate"
      OutputData.MsgMsg = "exception sync nodeid list mismatching"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception sync nodeid list mismatching"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      return
    }
  }

  TempGenerateNodeID = GenerateNodeID(nil, InputData.NodeKey)
  log.Println("Temporary Generate Node ID:", TempGenerateNodeID)

  if (TempGenerateNodeID == "") {
    OutputData.MsgType = "NODE ID GENERATE"
    OutputData.MsgTitle = "Node ID Generate"
    OutputData.MsgMsg = "failed to generate node id"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to generate node id"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if DBSetTmpGenerateNodeID(InputData.UserID, InputData.NodeKey, InputData.NodeIDList + TempGenerateNodeID + ";") != 1 {
    OutputData.MsgType = "NODE ID GENERATE"
    OutputData.MsgTitle = "Node ID Generate"
    OutputData.MsgMsg = "exception db query (tmp sync buffer update)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "exception db query (tmp sync buffer update)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    return
  }

  OutputData.MsgType = "NODE ID GENERATE"
  OutputData.MsgTitle = "Node ID Generate"
  OutputData.MsgMsg = "Generate NodeID"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = TempGenerateNodeID

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
}


func WebServer_Setting_SMTP_Display(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var HtmlSMTPSetting SettingSMTP
	var HtmlTemplate *template.Template
  var ResultSetRows *sql.Rows
  var QueryString string
	var err error

  log.Println("KMS Web Server - WebServer_Setting_SMTP_Display", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  SessionCookieUserData(&HtmlSMTPSetting.CookiesData, req)
  WebServerMainMenu (&HtmlSMTPSetting.MainMenu, "setting")
  WebServerOEMInformation(&HtmlSMTPSetting.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if HtmlSMTPSetting.CookiesData.CookieUserProperty == "admin" {

  } else if HtmlSMTPSetting.CookiesData.CookieUserProperty == "normal" {
    //WebServer_Redirect(w, req, "/service_invalid_access/")
    //return
  } else {
    WebServer_Redirect(w, req, "/service_invalid_access/")
    return
  }

  QueryString = "SELECT OEM_SMTP_SERVER_ADDRESS, OEM_SMTP_SERVER_HOST, OEM_SMTP_SENDER_EMAIL, OEM_SMTP_SENDER_PASSWORD FROM kms_configure "

  HtmlSMTPSetting.SQLQuery = fmt.Sprintf(QueryString)
  log.Println("NodeID List Count Query (by user_id, node_key, node_id): ", HtmlSMTPSetting.SQLQuery)
  
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlSMTPSetting.SQLQuery)
  for ResultSetRows.Next() {
    err = ResultSetRows.Scan(&HtmlSMTPSetting.SMTPItem.SMTPServerAddress,
                             &HtmlSMTPSetting.SMTPItem.SMTPServerHost,
                             &HtmlSMTPSetting.SMTPItem.SMTPSenderEmail,
                             &HtmlSMTPSetting.SMTPItem.SMTPSenderPassword)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)
      WebServer_Redirect(w, req, "/service_stop/")
      return
    }
  }
  ResultSetRows.Close()
  
  HtmlSMTPSetting.SMTPItem.CurrentUserProperty = HtmlSMTPSetting.CookiesData.CookieUserProperty

  HtmlTemplate, err = template.ParseFiles("./html/kms_setting_smtp.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_setting_smtp.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, HtmlSMTPSetting)
}


func WebServer_Setting_SMTP_Setting(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
	var CommonTemplete CommonHTML
  var ResultSetRows *sql.Rows
  var InputData jsonInputSMTP 
  var OutputData jsonOutputPack 
  var OutputBody string
  var QueryString string
  var SMTPDataCount int
	var err error

  log.Println("KMS Web Server - WebServer_Setting_SMTP_Setting", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    OutputData.MsgType = "SMTP SETTING"
    OutputData.MsgTitle = "SMTP Setting"
    OutputData.MsgMsg = "Cookie expiretime timed out"
    OutputData.MsgCode = "1100"
    OutputData.MsgValue = "Cookie expiretime timed out"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  SessionCookieUserData(&CommonTemplete.CookiesData, req)
  WebServerMainMenu (&CommonTemplete.MainMenu, "nodeid")
  WebServerOEMInformation(&CommonTemplete.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  if req.Method != "POST" {
    OutputData.MsgType = "SMTP SETTING"
    OutputData.MsgTitle = "SMTP Setting"
    OutputData.MsgMsg = "invalid request method"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid request method"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.MsgType = "SMTP SETTING"
    OutputData.MsgTitle = "SMTP Setting"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if (InputData.SMTPServerAddress == "" || InputData.SMTPServerHost == "" || InputData.SMTPSenderEmail == "" || InputData.SMTPSenderPassword == "") {
    OutputData.MsgType = "SMTP SETTING"
    OutputData.MsgTitle = "SMTP Setting"
    OutputData.MsgMsg = "failed to decoding data of input json data"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "failed to decoding data of input json data"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if CommonTemplete.CookiesData.CookieUserProperty == "admin" {

  } else if CommonTemplete.CookiesData.CookieUserProperty == "normal" {
    OutputData.MsgType = "SMTP SETTING"
    OutputData.MsgTitle = "SMTP Setting"
    OutputData.MsgMsg = "invalid user id access"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid user id access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  } else {
    OutputData.MsgType = "SMTP SETTING"
    OutputData.MsgTitle = "SMTP Setting"
    OutputData.MsgMsg = "invalid user property access"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "invalid user property access"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  QueryString = "SELECT count(OEM_SMTP_SERVER_ADDRESS) FROM kms_configure "
  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString)
  log.Println("SMTP Data Count Query -> ", CommonTemplete.SQLQuery)

  ResultSetRows = mariadb_lib.Query_DB(Database, CommonTemplete.SQLQuery)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&SMTPDataCount)
    if err != nil {
      ResultSetRows.Close()
      log.Println(" data Scan error:", err)

      OutputData.MsgType = "SMTP SETTING"
      OutputData.MsgTitle = "SMTP Setting"
      OutputData.MsgMsg = "exception db query (no tuple data)"
      OutputData.MsgCode = "1001"
      OutputData.MsgValue = "exception db query (no tuple data)"

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      return
    }
  }
  ResultSetRows.Close()
    
  if SMTPDataCount != 1 {
    OutputData.MsgType = "SMTP SETTING"
    OutputData.MsgTitle = "SMTP Setting"
    OutputData.MsgMsg = "db smtp data exception (no one tuple)"
    OutputData.MsgCode = "1001"
    OutputData.MsgValue = "db smtp data exception (no one tuple)"

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  QueryString = "UPDATE kms_configure " +
                "SET OEM_SMTP_SERVER_ADDRESS = '%s', OEM_SMTP_SERVER_HOST = '%s', OEM_SMTP_SENDER_EMAIL = '%s', OEM_SMTP_SENDER_PASSWORD = '%s' "
  CommonTemplete.SQLQuery = fmt.Sprintf(QueryString, InputData.SMTPServerAddress, InputData.SMTPServerHost, InputData.SMTPSenderEmail, InputData.SMTPSenderPassword)
  //log.Println("SMTP Data Update Query -> ", CommonTemplete.SQLQuery)
  mariadb_lib.Update_Data (Database, CommonTemplete.SQLQuery)
  // TODO: DB Excxception (return cnt)

  OutputData.MsgType = "SMTP SETTING"
  OutputData.MsgTitle = "SMTP Setting"
  OutputData.MsgMsg = "smtp update ok"
  OutputData.MsgCode = "1000"
  OutputData.MsgValue = "smtp update ok"

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)

  w.Header().Set("Content-Type", "application/json") 
  w.Write ([]byte(OutputBody))
  return 

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
  WebServerMainMenu (&HtmlMonitoringNodeAuth.MainMenu, "serverauth")
  WebServerOEMInformation(&HtmlMonitoringNodeAuth.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  ParamPageNum, ok := req.URL.Query()["page_num"]
  if !ok || len (ParamPageNum) < 1 {
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
  if !ok || len (ParamPageSort) < 1 {
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
  log.Println ("Auth Access NodeID List Count Query : ", HtmlMonitoringNodeAuth.SQLQuery)
  
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlMonitoringNodeAuth.SQLQuery)
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

  HtmlDataPage (&(HtmlMonitoringNodeAuth.TempletePage), "AuthPageNum", PageNumString, "AuthNodeIDSort", PageSortString, 0, MaxCountPage, MaxRowCountPerPage, ResultSetRowCount, "/monitoring/node_auth/", URLGetParam, "/service_stop/", "[exception]", "redirect")

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
  
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlMonitoringNodeAuth.SQLQuery)
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
  WebServerMainMenu (&HtmlMonitoringNodeAuthDetail.MainMenu, "serverauth")
  WebServerOEMInformation(&HtmlMonitoringNodeAuthDetail.OEMData)

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  ParamPageNum, ok := req.URL.Query()["page_num"]
  if !ok || len (ParamPageNum) < 1 {
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
  if !ok || len (ParamPageSort) < 1 {
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
  log.Println ("Auth Access Detail NodeID List Count Query : ", HtmlMonitoringNodeAuthDetail.SQLQuery)
  
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlMonitoringNodeAuthDetail.SQLQuery)
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

  HtmlDataPage (&(HtmlMonitoringNodeAuthDetail.TempletePage), "AuthPageNum", PageNumString, "AuthNodeIDSort", PageSortString, 0, MaxCountPage, MaxRowCountPerPage, ResultSetRowCount, "/monitoring/node_auth_detail/", URLGetParam, "/service_stop/", "[exception]", "redirect")

  RowSeqNum = HtmlMonitoringNodeAuthDetail.TempletePage.RowOffset

  QueryString = "SELECT node_id, node_ip, DATE_FORMAT(auth_date, '%%Y-%%m-%%d %%H:%%i:%%S'), auth_response_code, auth_response_message, auth_token, auth_expire_time " +
                "FROM auth_access_node_list " +
                "WHERE node_id = '%s' " +
                "ORDER BY auth_date DESC " +
                "LIMIT %d OFFSET %d "

  HtmlMonitoringNodeAuthDetail.SQLQuery = fmt.Sprintf(QueryString, HtmlMonitoringNodeAuthDetail.SearchNodeID, HtmlMonitoringNodeAuthDetail.TempletePage.MaxRowCountPage, HtmlMonitoringNodeAuthDetail.TempletePage.RowOffset)
  log.Println("Auth Access Detail NodeID List Query : ", HtmlMonitoringNodeAuthDetail.SQLQuery)
  
  ResultSetRows = mariadb_lib.Query_DB(Database, HtmlMonitoringNodeAuthDetail.SQLQuery)
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


func WEBAuthGenerateAuthKey (NodeID string) (string) {
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


func WebServer_Service_Web_Auth_API_Test_Input (w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var HtmlTemplate *template.Template
	var err error

  log.Println("KMS Web Server - WebServer_Service_Web_Auth_API_Test_Input", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    WebServer_Redirect(w, req, "/login/")
    return
  }

  HtmlTemplate, err = template.ParseFiles("./html/kms_web_api_test_input.html")
  if err != nil {
    log.Println("failed to template.ParseFiles (./html/kms_web_api_test_input.html)")
    WebServer_Redirect(w, req, "/service_stop/")
    return
  }

	HtmlTemplate.Execute(w, "")
}


func AESEncryptEncodingValue (InputText string) string {
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


func AESDecryptDecodeValue (InputText string) string {
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


func WebServer_Service_Web_Auth_API_Encode_Value (w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var InputData jsonInputWebAPIEncodeValue 
  var OutputData jsonOutputWebAPIEncodeValue
  var OutputBody string
  var EncryptValue string
  var DecryptValue string
	var err error

  log.Println("KMS Web Server - WebServer_Service_Web_Auth_API_Encode_Value", req.Method)

  res := Cookie_Check(w, req) 
  if res < 0 {
    OutputData.Code = "600"
    OutputData.Message = "fail (session expiretimed)"
    OutputData.InputValue = ""
    OutputData.OutputValue = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
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
    w.Write ([]byte(OutputBody))
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
    w.Write ([]byte(OutputBody))
    return
  }

  DecryptValue = AESDecryptDecodeValue (EncryptValue)
  if DecryptValue == "" {
    OutputData.Code = "400"
    OutputData.Message = "failed to AESDecryptDecodeValue"
    OutputData.InputValue = InputData.InputValue
    OutputData.OutputValue = EncryptValue 

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
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
  w.Write ([]byte(OutputBody))
  return
}


func WebServer_Service_Web_Auth_API_Proc (w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var InputData jsonInputWebAPIAuthPack
  var OutputData jsonOutputWebAPIAuthPack
  var OutputBody string
  var DecryptUserKey string
  var DecryptNodeID string
  var GenerateAuthKey string
  var DBAuthUserKeySeq int
  var DBAuthUserKey string
  var DBAuthNodeID string
  var DBAuthNodeIDSeq int
  var DBAuthKey string
  var DBAuthToken string
  var DBAuthExpireTime uint64
  var DBAuthNOWTime uint64
  var DBAuthServiceStartDays uint64
  var DBAuthServiceEndDays uint64
  var DBAuthServiceNOWDays uint64
  var QueryString string
  var HashingText string
  var HA1 string
  var HA2 string
  var Response string
  var EventValue string
  var OEMAuthExpiretimeInterval int
  var AuthAccessIP string 
	var err error


  access_ip, _, err := net.SplitHostPort(req.RemoteAddr)
  if err != nil {
    AuthAccessIP = "0.0.0.0"
  } else {
    AuthAccessIP = access_ip
  }

  //log.Println("Auth Access Address IP:", AuthAccessIP)
  log.Println("KMS Web Server - WebServer_Service_Web_Auth_API_Proc - Access Address IP", req.Method, AuthAccessIP)

  Decoder := json.NewDecoder(req.Body)
  err = Decoder.Decode(&InputData)
  if err != nil {
    OutputData.Method = ""  // (security enhancement: tracking prevention)
    OutputData.MsgType = "" // (security enhancement: tracking prevention)
    OutputData.Code = "610"
    OutputData.Message = "json parameter parsing error (simplify Information)"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if req.Method != "POST" {
    OutputData.Method = ""  // (security enhancement: tracking prevention)
    OutputData.MsgType = "" // (security enhancement: tracking prevention)
    OutputData.Code = "610"
    OutputData.Message = "json parameter parsing error (simplify Information for security enhancement)"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  log.Println("Input Data : [method:" + InputData.Method + ", msgtype:" + InputData.MessageType + ", userkey encrypt:" + InputData.NodeKey + ", nodeid encrypt:" + InputData.NodeID + ", authtoken:" + InputData.AuthToken + "]")

  if InputData.Method == "" || InputData.MessageType == "" || InputData.NodeKey == "" || InputData.NodeID == "" {
    log.Println("invalid parmeter value: null")

    OutputData.Method = ""  // (security enhancement: tracking prevention)
    OutputData.MsgType = "" // (security enhancement: tracking prevention)
    OutputData.Code = "611"
    OutputData.Message = "json parameter is null (simplify Information for security enhancement)"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  if InputData.Method != "REGISTER" || InputData.MessageType != "request" {
    log.Println("invalid parmeter value: not supported value")

    OutputData.Method = ""  // (security enhancement: tracking prevention)
    OutputData.MsgType = "" // (security enhancement: tracking prevention)
    OutputData.Code = "612"
    OutputData.Message = "json parameter is invalid (simplify Information for security enhancement)"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }

  DecryptUserKey = AESDecryptDecodeValue(InputData.NodeKey) 
  if DecryptUserKey == "" {
    log.Println("invalid parmeter value: user key decrypt error")

    OutputData.Method = "REGISTER"
    OutputData.MsgType = "response"
    OutputData.Code = "620"
    OutputData.Message = "json parameter decript error"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }
	//log.Printf("WEB API Auth - UserKey Decrypt Value [%s] -> [%s]", InputData.NodeKey, DecryptUserKey)
  InputData.NodeKey = DecryptUserKey 
  
  DecryptNodeID = AESDecryptDecodeValue(InputData.NodeID) 
  if DecryptUserKey == "" {
    log.Println("invalid parmeter value: node id decrypt error")

    OutputData.Method = "REGISTER"
    OutputData.MsgType = "response"
    OutputData.Code = "620"
    OutputData.Message = "json parameter decript error"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))
    return
  }
	//log.Printf("WEB API Auth - NodeID Decrypt Value [%s] -> [%s]", InputData.NodeID, DecryptNodeID)
  InputData.NodeID = DecryptNodeID

  OEMAuthExpiretimeInterval = GetOEMAuthExpiretimeInterval()
  if OEMAuthExpiretimeInterval == 0 {
    OutputData.Method = "REGISTER"
    OutputData.MsgType = "response"
    OutputData.Code = "632"
    OutputData.Message = "db processing error"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
    return
  }

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  DBAuthUserKeySeq = 0
  QueryString = "SELECT a.user_key_id_seq, a.user_key_id, b.node_id, b.node_id_seq, b.web_api_auth_key, b.web_api_auth_token, TO_DAYS(b.web_api_auth_token_expire_time_date), TO_DAYS(NOW()) " +
                "FROM user_key a, node_id b " +
                "WHERE a.user_key_id = '%s' " +
                      "AND a.user_key_id_seq = b.user_key_id_seq " +
                      "AND b.node_id = '%s'"
  QueryString = fmt.Sprintf(QueryString, InputData.NodeKey, InputData.NodeID)
  //log.Println("WEB API Auth Query -> [", QueryString, "]")

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&DBAuthUserKeySeq, &DBAuthUserKey, &DBAuthNodeID, &DBAuthNodeIDSeq, &DBAuthKey, &DBAuthToken, &DBAuthExpireTime, &DBAuthNOWTime)
    if err != nil {
      ResultSetRows.Close()

      OutputData.Method = "REGISTER"
      OutputData.MsgType = "response"
      OutputData.Code = "630"
      OutputData.Message = "db processing error"
      OutputData.AuthKey = ""
      OutputData.ExpireTime = ""
      OutputData.Event = ""

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
      return
    }
  }
  ResultSetRows.Close()

  if DBAuthUserKeySeq == 0 || DBAuthUserKey == "" || DBAuthNodeID == "" {
    log.Println("data Scan error:", err)

    OutputData.Method = "REGISTER"
    OutputData.MsgType = "response"
    OutputData.Code = "631"
    OutputData.Message = "db processing error"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
    return
  }

  DBAuthServiceStartDays = 0
  DBAuthServiceEndDays = 0
  DBAuthServiceNOWDays = 0
  QueryString = "SELECT TO_DAYS(pkg_start_date) as service_start_date, TO_DAYS(pkg_end_date) as service_end_date, TO_DAYS(NOW()) as service_now_date " +
                "FROM user_key " +
                "WHERE user_key_id = '%s' " 
  QueryString = fmt.Sprintf(QueryString, InputData.NodeKey)
  //log.Println("WEB API Auth Query -> [", QueryString, "]")

  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
  for ResultSetRows.Next() {
    err := ResultSetRows.Scan(&DBAuthServiceStartDays, &DBAuthServiceEndDays, &DBAuthServiceNOWDays)
    if err != nil {
      ResultSetRows.Close()

      OutputData.Method = "REGISTER"
      OutputData.MsgType = "response"
      OutputData.Code = "630"
      OutputData.Message = "db processing error"
      OutputData.AuthKey = ""
      OutputData.ExpireTime = ""
      OutputData.Event = ""

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
      return
    }
  }
  ResultSetRows.Close()

  if DBAuthServiceStartDays == 0 || DBAuthServiceEndDays == 0 || DBAuthServiceNOWDays == 0 {
    log.Println("data Scan error:", err)

    OutputData.Method = "REGISTER"
    OutputData.MsgType = "response"
    OutputData.Code = "631"
    OutputData.Message = "db processing error"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
    return
  }

  if DBAuthServiceStartDays > DBAuthServiceNOWDays {
    OutputData.Method = "REGISTER"
    OutputData.MsgType = "response"
    OutputData.Code = "651"
    OutputData.Message = "service start waiting period"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    QueryString = "INSERT INTO auth_access_node_list (user_id_seq, node_id, node_ip, auth_date, auth_token, auth_expire_time, auth_response_code, auth_response_message) " +
                  "VALUES (%d, '%s', '%s', NOW(), '%s', %d, '%s', '%s') "
    QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.NodeID, AuthAccessIP, InputData.AuthToken, OEMAuthExpiretimeInterval, OutputData.Code, OutputData.Message)
    //log.Println("Auth Access History Insert Query -> [", QueryString, "]")
    mariadb_lib.Insert_Data(Database, QueryString)
    // TODO: DB Excxception (return cnt)

    log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
    return
  }

  if DBAuthServiceEndDays < DBAuthServiceNOWDays {
    OutputData.Method = "REGISTER"
    OutputData.MsgType = "response"
    OutputData.Code = "652"
    OutputData.Message = "end of service period"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = ""
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    QueryString = "INSERT INTO auth_access_node_list (user_id_seq, node_id, node_ip, auth_date, auth_token, auth_expire_time, auth_response_code, auth_response_message) " +
                  "VALUES (%d, '%s', '%s', NOW(), '%s', %d, '%s', '%s') "
    QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.NodeID, AuthAccessIP, InputData.AuthToken, OEMAuthExpiretimeInterval, OutputData.Code, OutputData.Message)
    //log.Println("Auth Access History Insert Query -> [", QueryString, "]")
    mariadb_lib.Insert_Data(Database, QueryString)
    // TODO: DB Excxception (return cnt)
    log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)

    return
  }

  if InputData.AuthToken == "" {
    if DBAuthToken != "" {
      //log.Println("WEB API Auth Expiretime(DBAuthExpireDays:", DBAuthExpireDays, ", DBAuthNOWTime:", DBAuthNOWTime, ")")

      if DBAuthExpireTime > DBAuthNOWTime {
        OutputData.Method = "REGISTER"
        OutputData.MsgType = "response"
        OutputData.Code = "640"
        OutputData.Message = "auth error"
        OutputData.AuthKey = ""
        OutputData.ExpireTime = ""
        OutputData.Event = ""

        jstrbyte, _ := json.Marshal(OutputData)
        OutputBody = string(jstrbyte)

        w.Header().Set("Content-Type", "application/json") 
        w.Write ([]byte(OutputBody))

        log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
        return
      }
    }

    GenerateAuthKey = WEBAuthGenerateAuthKey (strconv.Itoa(DBAuthNodeIDSeq))
    if GenerateAuthKey == "" {
      OutputData.Method = "REGISTER"
      OutputData.MsgType = "response"
      OutputData.Code = "643"
      OutputData.Message = "failed to generate auth key"
      OutputData.AuthKey = ""
      OutputData.ExpireTime = ""
      OutputData.Event = ""

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
      return
    }

    hashing_algorithm := md5.New()
    HashingText = InputData.NodeKey + ":" + InputData.NodeID
    hashing_algorithm.Write([]byte(HashingText))
    HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
    EventValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

    hashing_algorithm = md5.New()
    HashingText = InputData.Method + ":" + "/auth_api/v1.0/"
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

      QueryString = "UPDATE node_id " +
                    "SET web_api_auth_key = '%s', web_api_auth_token = '%s', web_api_auth_token_expire_time_date = DATE_ADD(NOW(), INTERVAL %d SECOND) " +
                    "WHERE node_id = '%s' "

      QueryString = fmt.Sprintf(QueryString, GenerateAuthKey, Response, OEMAuthExpiretimeInterval, InputData.NodeID)
      //log.Println("WEB API Auth Information Update Query -> ", QueryString)
      mariadb_lib.Update_Data (Database, QueryString)
      // TODO: DB Excxception (return cnt)
      //mariadb_lib.DB_AutoCommit_Disable(Database)

      OutputData.Method = "REGISTER"
      OutputData.MsgType = "response"
      OutputData.Code = "200"
      OutputData.Message = "auth success"
      OutputData.AuthKey = GenerateAuthKey
      OutputData.ExpireTime = strconv.Itoa(OEMAuthExpiretimeInterval)
      ///*---------------------------------
      //OutputData.Event = EventValue // For Node Debugging
      OutputData.Event = "" 
      //---------------------------------*/

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s, description:%s (expiretime sec:%d, authkey:%s, authtoken:%s)]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message, "create new authkey and authtoken", OEMAuthExpiretimeInterval, GenerateAuthKey, Response)
      return
    } else {
      OutputData.Method = "REGISTER"
      OutputData.MsgType = "response"
      OutputData.Code = "644"
      OutputData.Message = "failed to generate auth token"
      OutputData.AuthKey = ""
      OutputData.ExpireTime = ""
      OutputData.Event = ""

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
      return
    }

  } else {
    if DBAuthToken == "" { 
        OutputData.Method = "REGISTER"
        OutputData.MsgType = "response"
        OutputData.Code = "641"
        OutputData.Message = "auth error"
        OutputData.AuthKey = ""
        OutputData.ExpireTime = ""
        OutputData.Event = ""

        jstrbyte, _ := json.Marshal(OutputData)
        OutputBody = string(jstrbyte)

        w.Header().Set("Content-Type", "application/json") 
        w.Write ([]byte(OutputBody))

        log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
        return
    }
  
    if InputData.AuthToken != DBAuthToken { 
      OutputData.Method = "REGISTER"
      OutputData.MsgType = "response"
      OutputData.Code = "642"
      OutputData.Message = "auth error"
      OutputData.AuthKey = ""
      OutputData.ExpireTime = ""
      OutputData.Event = ""

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
      return
    }

    //log.Println("WEB API Auth Expiretime(DBAuthExpireTime:", DBAuthExpireTime, ", DBAuthNOWTime:", DBAuthNOWTime, ")")

    if DBAuthExpireTime < DBAuthNOWTime {

      QueryString = "UPDATE node_id " +
                    "SET web_api_auth_key = '%s', web_api_auth_token = '%s', web_api_auth_token_expire_time_date = NOW() " +
                    "WHERE node_id = '%s' "

      QueryString = fmt.Sprintf(QueryString, "", "", InputData.NodeID)
      //log.Println("WEB API Auth Information Update Query -> ", QueryString)
      mariadb_lib.Update_Data (Database, QueryString)
      // TODO: DB Excxception (return cnt)
      //mariadb_lib.DB_AutoCommit_Disable(Database)

      OutputData.Method = "REGISTER"
      OutputData.MsgType = "response"
      OutputData.Code = "643"
      OutputData.Message = "auth error"
      OutputData.AuthKey = ""
      OutputData.ExpireTime = ""
      OutputData.Event = ""

      jstrbyte, _ := json.Marshal(OutputData)
      OutputBody = string(jstrbyte)

      w.Header().Set("Content-Type", "application/json") 
      w.Write ([]byte(OutputBody))

      log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message)
      return
    }

    QueryString = "UPDATE node_id " +
                  "SET web_api_auth_token_expire_time_date = DATE_ADD(NOW(), INTERVAL %d SECOND) " +
                  "WHERE node_id = '%s' "

    QueryString = fmt.Sprintf(QueryString, OEMAuthExpiretimeInterval, InputData.NodeID)
    //log.Println("WEB API Auth Expiretime Update Query -> ", QueryString)
    mariadb_lib.Update_Data (Database, QueryString)
    // TODO: DB Excxception (return cnt)
    //mariadb_lib.DB_AutoCommit_Disable(Database)

    OutputData.Method = "REGISTER"
    OutputData.MsgType = "response"
    OutputData.Code = "200"
    OutputData.Message = "auth success"
    OutputData.AuthKey = ""
    OutputData.ExpireTime = strconv.Itoa(OEMAuthExpiretimeInterval)
    OutputData.Event = ""

    jstrbyte, _ := json.Marshal(OutputData)
    OutputBody = string(jstrbyte)

    w.Header().Set("Content-Type", "application/json") 
    w.Write ([]byte(OutputBody))

    QueryString = "INSERT INTO auth_access_node_list (user_id_seq, node_id, node_ip, auth_date, auth_token, auth_expire_time, auth_response_code, auth_response_message) " +
                  "VALUES (%d, '%s', '%s', NOW(), '%s', %d, '%s', '%s') "
    QueryString = fmt.Sprintf(QueryString, DBAuthUserKeySeq, InputData.NodeID, AuthAccessIP, InputData.AuthToken, OEMAuthExpiretimeInterval, OutputData.Code, OutputData.Message)
    //log.Println("Auth Access History Insert Query -> [", QueryString, "]")
    mariadb_lib.Insert_Data(Database, QueryString)
    // TODO: DB Excxception (return cnt)

    log.Printf("web api response [userkey:%s, nodeid:%s] [code:%s, msg:%s, description:%s (expiretime sec:%d, authtoken:%s)]", InputData.NodeKey, InputData.NodeID, OutputData.Code, OutputData.Message, "expiretime update", OEMAuthExpiretimeInterval, InputData.AuthToken)
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


func MariaDBInsertClientData(Database *sql.DB, StatData ClientStatisticData) {

	InsertDataStr := fmt.Sprintf("INSERT INTO CLIENT_STATISTICS_DATA (ID, Proxy_IP_INT, Proxy_IP_TEXT, Proxy_Listen_Port, Inbound, Outbound) VALUES (%d,%d,'%s',%d,%d,%d)", StatData.ID, StatData.Proxy_IP_Int, StatData.Proxy_IP_Str, StatData.Proxy_Listen_Port, StatData.Inbound, StatData.Outbound)

	mariadb_lib.Insert_Data(Database, InsertDataStr)
}


func MariaDBInit(Id string, Passwd string, DbAddr string, DbPort string, DbName string) *sql.DB {
  var sql string

	Database := mariadb_lib.Connection_DB(Id, Passwd, DbAddr, DbPort, DbName)

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

	return Database
}


func MariaDBInitDataSetup() {
  var Database *sql.DB
  var ResultSetRows *sql.Rows
  var QueryString string
  var CheckRowCount int

  log.Println("KMS DB Init Setup")

	Database = MariaDB_Open()
  defer MariaDB_Close(Database)

  CheckRowCount = 0

  QueryString = "SELECT COUNT(user_id) FROM user WHERE user_id = 'admin' "
  //log.Println("MariaDBInitDataSetup Query -> ", QueryString)
  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
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
  ResultSetRows = mariadb_lib.Query_DB(Database, QueryString)
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
}


func MariaDB_Open() (Database *sql.DB) {
  var DBObject *sql.DB

	DBObject = MariaDBInit(DBUSER, DBUSERPW, DBIP, DBPORT, DBNAME)
  if DBObject != nil {
    mariadb_lib.DB_AutoCommit_Enable (DBObject)   
  }

  return DBObject
}

func MariaDB_Close(Database *sql.DB) {
  if Database != nil {
    Database.Close()
    Database = nil
  }
}

func DBInformationSetup () {
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
    panic ("invalid db information")
  }

  if DBPORT == "" {
	  log.Print("[error report] invalid db port data")
    panic ("invalid db information")
  }

  if DBNAME == "" {
	  log.Print("[error report] invalid db name data")
    panic ("invalid db information")
  }

  if DBUSER == "" {
	  log.Print("[error report] invalid db user data")
    panic ("invalid db information")
  }

  if DBUSERPW == "" {
	  log.Print("[error report] invalid db user password data")
    panic ("invalid db information")
  }

	//log.Print("IP:", DBIP, ", PORT:", DBPORT, ", DBNAME:", DBNAME, ", DBUSER:", DBUSER, ", DBUSERPW:", DBUSERPW)
}


func RunWebContainer (ServicePort string) {
	log.Print("Run Web-Container\n")

  DBInformationSetup()

	Database := MariaDBInit(DBUSER, DBUSERPW, DBIP, DBPORT, DBNAME)
  MariaDB_Close(Database)
  MariaDBInitDataSetup ()

	WebServerMux := http.NewServeMux()

	WebServerMux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
	  log.Print("<<--- HTMP URL Not Founded Page --->>\n")
		WebServer_Redirect(w, req, "/login/")
	})

	WebServerMux.HandleFunc("/login/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Login(w, req)
	})

	WebServerMux.HandleFunc("/logging/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Login_Check(w, req)
	})

	WebServerMux.HandleFunc("/logout/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Logout(w, req)
	})

	WebServerMux.HandleFunc("/popup/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Service_Popup(w, req)
	})

  //----------------------------------------------------------------------------- [ USER Data ] {-------//
	WebServerMux.HandleFunc("/userid/management/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_UserID_List(w, req)
	})

	WebServerMux.HandleFunc("/userid/create_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_UserID_Create_Input(w, req)
	})

	WebServerMux.HandleFunc("/userid/create_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_UserID_Create_Proc(w, req)
	})

	WebServerMux.HandleFunc("/userid/modify_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_UserID_Modify_Input(w, req)
	})

	WebServerMux.HandleFunc("/userid/modify_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_UserID_Modify_Proc(w, req)
  })

	WebServerMux.HandleFunc("/userid/delete_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_UserID_Delete_Input(w, req)
	})

	WebServerMux.HandleFunc("/userid/delete_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_UserID_Delete_Proc(w, req)
  })

	WebServerMux.HandleFunc("/userid/ajax/userid_check/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_UserID_Ajax_UserIDCheck(w, req)
	})
  //----------------------------------------------------------------------------- [ USER Data ] }-------//


  //----------------------------------------------------------------------------- [ Node KEY ] {--------//
	WebServerMux.HandleFunc("/nodekey/management/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_List(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/create_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_Create_Input(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/create_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_Create_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/recreate_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_ReCreate_Input(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/recreate_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_ReCreate_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/modify_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_Modify_Input(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/modify_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_Modify_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/delete_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_Delete_Input(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/delete_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_Delete_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/license/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_License(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/license_email_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_License_Email_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/license_download_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_License_Download_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/package_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_Package_Input(w, req)
	})

	WebServerMux.HandleFunc("/nodekey/package_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_Package_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodeid/ajax/generate_nodekey/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeKey_Ajax_NodeKeyGenerate(w, req)
	})
  //----------------------------------------------------------------------------- [ Node KEY ] }--------//


  //------------------------------------------------------------------------- [ Service Node ] {--------//
	WebServerMux.HandleFunc("/nodeid/management/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeID_List(w, req)
	})

	WebServerMux.HandleFunc("/nodeid/create_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeID_Create_Input(w, req)
	})

	WebServerMux.HandleFunc("/nodeid/create_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeID_Create_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodeid/modify_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeID_Modify_Input(w, req)
	})

	WebServerMux.HandleFunc("/nodeid/modify_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeID_Modify_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodeid/delete_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeID_Delete_Input(w, req)
	})

	WebServerMux.HandleFunc("/nodeid/delete_proc/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeID_Delete_Proc(w, req)
	})

	WebServerMux.HandleFunc("/nodeid/ajax/generate_nodeid/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_NodeID_Ajax_NodeIDGenerate(w, req)
	})
  //------------------------------------------------------------------------- [ Service Node ] }--------//

  //------------------------------------------------------------------------- [ Setting ] {--------//
	WebServerMux.HandleFunc("/setting/smtp_display/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Setting_SMTP_Display(w, req)
	})

	WebServerMux.HandleFunc("/setting/smtp_setting/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Setting_SMTP_Setting(w, req)
	})
  //------------------------------------------------------------------------- [ Setting ] }--------//

  //------------------------------------------------------------------------- [ Monitoring ] {-----//
	WebServerMux.HandleFunc("/monitoring/node_auth/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Monitoring_Node_AuthDisplay(w, req)
	})

	WebServerMux.HandleFunc("/monitoring/node_auth_detail/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Monitoring_Node_AuthDetailDisplay(w, req)
	})
  //------------------------------------------------------------------------- [ Monitoring ] }-----//

  //------------------------------------------------------------------------- [ WEB API ] {--------//
	WebServerMux.HandleFunc("/auth_api_test_input/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Service_Web_Auth_API_Test_Input(w, req)
	})

	WebServerMux.HandleFunc("/auth_api_encode_value/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Service_Web_Auth_API_Encode_Value(w, req)
	})

	WebServerMux.HandleFunc("/auth_api/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Service_Web_Auth_API_Proc(w, req)
	})
  //------------------------------------------------------------------------- [ WEB API ] }--------//

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

	go HttpListen(0, ":"+ServicePort, "", "", WebServerMux)
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

	if len (os.Args) != (MustArgs + 1) {
		ShowHelpCommand()

		return
	}

	log.SetFlags (log.LstdFlags | log.Lshortfile | log.Lmicroseconds)

	for i = 0; i < MustArgs ; i++ {
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
			PidFileName: "kms_service.pid",
			PidFilePerm: 0644,
			LogFileName: ProcessLogFileName,
			LogFilePerm: 0640,
			WorkDir:     "./",
			Umask:       027,
			Args:        []string {"./kms_service", "-l", ListenerPort, "-p", ProcessType},
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

  RunWebContainer (ListenerPort)

	finish := make(chan bool)
	<-finish
}
