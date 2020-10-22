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
var ProcessLogFileName = "./log/setup_gowas.log"

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

type NICInformation struct {
  Name string
  IP   string
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
	Setup             template.HTML
	Statistics        template.HTML
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

type CommonHTML struct {
	CookiesData CookiesUserData
	MainMenu    SVCHtmlMainMenu

	SQLQuery          string
	SQLQueryCondition string
}

type jsonOutputWebAPIAuthInvalidAccess struct {
  Code      string      `json:"code"`
  Message   string      `json:"message"`
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

type jsonInputWebAPIAuthSvcSetupPack struct {
	Version       string      `json:"version"`
	Method        string      `json:"method"`
	SessionType   string      `json:"sessiontype"`
	Seperator     string      `json:"seperator"`
	MessageType   string      `json:"msgtype"`
	MessageSeq    string      `json:"msgseq"`
	LoginID       string      `json:"login_id"`
	LoginPW       string      `json:"login_pw"`
	OrderNum      string      `json:"order_num"`
	Checksum      string      `json:"checksum"`
	AuthKey       string      `json:"auth_key"`
	AuthToken     string      `json:"auth_token"`
}

type jsonOutputWebAPIAuthSVCSetup struct {
	Version                     string      `json:"version"`
	Method                      string      `json:"method"`
	SessionType                 string      `json:"sessiontype"`
	Seperator                   string      `json:"seperator"`
	MessageType                 string      `json:"msgtype"`
	MessageSeq                  string      `json:"msgseq"`
	Code                        string      `json:"code"`
	Message                     string      `json:"message"`
	AuthKey                     string      `json:"auth_key"`
	Expiretime                  string      `json:"expiretime"`
  Event                       string      `json:"event"`
  ParamUserKey                string      `json:"userkey"`
  ParamNodeID                 string      `json:"nodeid"`
  ParamServiceGoWas           string      `json:"service_gowas"`
  ParamUpdateGoWas            string      `json:"update_gowas"`
  ParamCKSum                  string      `json:"checksum"`
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

func WebServer_Auth_API_Setup_Invalid_Access_Response(w http.ResponseWriter, Code string, Message string) {
  var OutputData jsonOutputWebAPIAuthInvalidAccess
  var OutputBody string

  OutputData.Code = Code
  OutputData.Message = Message

  jstrbyte, _ := json.Marshal(OutputData)
  OutputBody = string(jstrbyte)
  w.Header().Set("Content-Type", "application/json")
  w.Write([]byte(OutputBody))
  return
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

func WebServer_Auth_API_SVC_Setup_Response(w http.ResponseWriter, Version string, Method string, SessionType string, Seperator string, MessageType string, MessageSeq string, Code string, Message string, AuthKey string, Expiretime string, Param string, Event string, UserKey string, NodeID string, ServiceGoWas string, UpdateGoWas string) {
	var OutputData jsonOutputWebAPIAuthSVCSetup
	var HashingText string
	var HashingValue string
  var ChecksumValue string
  var EncryptValue string
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
	OutputData.ParamUserKey = UserKey
	OutputData.ParamNodeID = NodeID
	OutputData.ParamServiceGoWas = ServiceGoWas
  OutputData.ParamUpdateGoWas = UpdateGoWas

  if UserKey != "" && NodeID != "" && ServiceGoWas != "" && UpdateGoWas != "" {
    //------------------------------------------------------------------------------//
    // Transaction - 200 OK Response  Msg (Validateion Hashing Value)
    //------------------------------------------------------------------------------//
    hashing_algorithm := md5.New()
    HashingText = UserKey + ":" + NodeID
    hashing_algorithm.Write([]byte(HashingText))
    ChecksumValue = hex.EncodeToString(hashing_algorithm.Sum(nil))
    HashingValue = HashingText + ":" + ChecksumValue

    EncryptValue = AESEncryptEncodingValue(HashingValue)
    if EncryptValue == "" {
      log.Println("failed to decrypt decode trial_id pattern")
      return
    }
	  OutputData.ParamCKSum = EncryptValue

    EncryptValue = AESEncryptEncodingValue(UserKey)
    if EncryptValue == "" { 
      log.Println("failed to decrypt decode userkey")
      return
    } 
    OutputData.ParamUserKey = EncryptValue 

    EncryptValue = AESEncryptEncodingValue(NodeID)
    if EncryptValue == "" { 
      log.Println("failed to decrypt decode nodeid")
      return
    } 
    OutputData.ParamNodeID = EncryptValue
    
    EncryptValue = AESEncryptEncodingValue(ServiceGoWas)
    if EncryptValue == "" { 
      log.Println("failed to decrypt decode ServiceGoWas")
      return
    } 
    OutputData.ParamServiceGoWas = EncryptValue

    EncryptValue = AESEncryptEncodingValue(UpdateGoWas)
    if EncryptValue == "" { 
      log.Println("failed to decrypt decode UpdateGoWas")
      return
    } 
    OutputData.ParamUpdateGoWas = EncryptValue
  }

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

func GenerateRandomNodeID(UserKey int) string {
	var NodeKeySeq int
	var TmpGenerateKey string

	NodeIDBuffer := bytes.Buffer{}

	NodeKeySeq = UserKey

	for i := 0; i < 5; i++ {
		if i == 0 {
			TmpGenerateKey = product_rand_key.Product_rand_key(8)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeIDBuffer.WriteString(TmpGenerateKey)
			NodeIDBuffer.WriteString("-")
		} else if i == 1 {
      if NodeKeySeq <= 9999 {
        TmpGenerateKey = fmt.Sprintf("%04d", NodeKeySeq)
        if TmpGenerateKey == "" {
          return ""
        }
      } else {
        TmpGenerateKey = product_rand_key.Product_rand_key(4)
        if TmpGenerateKey == "" {
          return ""
        }
      }
			NodeIDBuffer.WriteString(TmpGenerateKey)
			NodeIDBuffer.WriteString("-")
		} else if i == 2 {
      if NodeKeySeq > 9999 && NodeKeySeq <= 99999999 {
        TmpGenerateKey = fmt.Sprintf("%04d", NodeKeySeq)
        if TmpGenerateKey == "" {
          return ""
        }
      } else {
        TmpGenerateKey = product_rand_key.Product_rand_key(4)
        if TmpGenerateKey == "" {
          return ""
        }
      }

			NodeIDBuffer.WriteString(TmpGenerateKey)
			NodeIDBuffer.WriteString("-")
		} else if i == 3 {
      if NodeKeySeq > 99999999 && NodeKeySeq <= 999999999999 {
        TmpGenerateKey = fmt.Sprintf("%04d", NodeKeySeq)
        if TmpGenerateKey == "" {
          return ""
        }
      } else {
        TmpGenerateKey = product_rand_key.Product_rand_key(4)
        if TmpGenerateKey == "" {
          return ""
        }
      }

			NodeIDBuffer.WriteString(TmpGenerateKey)
			NodeIDBuffer.WriteString("-")
		} else if i == 4 {
			TmpGenerateKey = product_rand_key.Product_rand_key(8)
			if TmpGenerateKey == "" {
				return ""
			}

			NodeIDBuffer.WriteString(TmpGenerateKey)
		}
	}

	return NodeIDBuffer.String()
}

func WebServer_Auth_API_SVC_Setup_Proc(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var Database *sql.DB
	var InputData jsonInputWebAPIAuthSvcSetupPack 
	var ResponseMessage string

  var SiteID int
	var AuthExpiretimeInterval int
  var ServiceGOWASAddress string
  var UpdateGOWASAddress string

  var AccessClientIP string 
	var EncryptParam string
	var DecryptLoginID string
	var DecryptLoginPW string
	var DecryptOrderNum string
	var DecryptChecksum string
	var HashingText string
	var HashingValue string
	var HA1 string
	var HA2 string
	var GenerateAuthKey string
	var GenerateAuthToken string
  var EncryptValue string

	var DBAuthKey string
	var DBAuthToken string
	var DBAuthExpireTime uint64
	var DBAuthNOWTime uint64

	var DBSID int
	var DBLoginPW string
	var DBKeyID int
	var DBUserID int
	var DBUserKey string
	var DBDeviceID int
	var DBNodeID string

	var DBNewRandomDeviceID int
	var DBNewRandomNodeID string
	var DBNewWallID int

	var QueryString string
	var QueryTupleCount int
	var ResultSetRows *sql.Rows
  var tx *sql.Tx
	var err error

  forwarded := req.Header.Get("X-FORWARDED-FOR")
	if forwarded != "" {
    nodeips := strings.Split(forwarded, ",")
    if len(nodeips) != 0 {
      AccessClientIP = nodeips[0]
    } else {
      ip, _, err := net.SplitHostPort(req.RemoteAddr)
      if err != nil {
        AccessClientIP = ""
      } else {
        AccessClientIP = ip
      }
    }
	} else {
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			AccessClientIP = ""
		} else {
			AccessClientIP = ip
		}
	}

	log.Println("WebServer_Auth_API_Service_Setup_Proc", req.Method, ", Proxy Address:", req.RemoteAddr, ", Client Address:", AccessClientIP)

  SiteID = 1
	AuthExpiretimeInterval = 60
  ServiceGOWASAddress = "mcsservice.uxcloud.net:9094"
  UpdateGOWASAddress = "mcsupdate.uxcloud.net:9093"

	Decoder := json.NewDecoder(req.Body)
	err = Decoder.Decode(&InputData)
	if err != nil {
		log.Println("json parsing error:", err)
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error - (simplify Information for security enhancement)"
		WebServer_Auth_API_SVC_Setup_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}

	// comments: checking valid http method
	if req.Method != "POST" {
		log.Println("not supported request method")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json parameter parsing error (not support method) - (simplify Information for security enhancement)"
		WebServer_Auth_API_SVC_Setup_Response(w, "", "", "", "", "", "", "610", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}

	log.Println(">>> Input Data - version:" + InputData.Version + ", method:" + InputData.Method + ", sessiontype:" + InputData.SessionType + ", seperator:" + InputData.Seperator + ", msgtype:" + InputData.MessageType + ", msgseq:" + InputData.MessageSeq + ", login_id:" + InputData.LoginID + ", login_pw:" + InputData.LoginPW + ", order_num:" + InputData.OrderNum + ", checksum:" + InputData.Checksum + ", authkey:" + InputData.AuthKey + ", authtoken:" + InputData.AuthToken)

	// comments: checking mandatory input value
	if InputData.Version == "" || InputData.Method == "" || InputData.SessionType == "" || InputData.Seperator == "" || InputData.MessageType == "" || InputData.MessageSeq == "" || InputData.LoginID == "" || InputData.LoginPW == "" || InputData.OrderNum == "" || InputData.Checksum == "" {
		log.Println("invalid parmeter value: mandatory param is empty")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is empty (simplify Information for security enhancement)"
		WebServer_Auth_API_SVC_Setup_Response(w, "", "", "", "", "", "", "611", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}

	// comments: checking validation input value
	if InputData.Version != "1.0" || InputData.Method != "auth" || InputData.SessionType != "register" || InputData.Seperator != "init_setup" || InputData.MessageType != "request" {
		log.Println("invalid parmeter value: not supported value")
		// (security enhancement: tracking prevention) //
		ResponseMessage = "json mandatory parameter is invalid (simplify Information for security enhancement)"
		WebServer_Auth_API_SVC_Setup_Response(w, "", "", "", "", "", "", "612", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}

	// comments: decrypt and base32 input id value
	if InputData.LoginID != "" {
		EncryptParam = InputData.LoginID
		DecryptLoginID = AESDecryptDecodeValue(EncryptParam)

		if DecryptLoginID == "" {
			log.Println("invalid parmeter value: login id decrypt error")
			ResponseMessage = "json parameter decript error (login_id)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "612", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - LoginID Decrypt Value [%s] -> [%s]", EncryptParam, DecryptLoginID)
	}

	// comments: decrypt and base32 input pw value
	if InputData.LoginPW != "" {
		EncryptParam = InputData.LoginPW
		DecryptLoginPW = AESDecryptDecodeValue(EncryptParam)

		if DecryptLoginPW == "" {
			log.Println("invalid parmeter value: login pw decrypt error")
			ResponseMessage = "json parameter decript error (login_pw)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "612", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - LoginPW Decrypt Value [%s] -> [%s]", EncryptParam, DecryptLoginPW)
	}

	// comments: decrypt and base32 input ordernum value
	if InputData.OrderNum != "" {
		EncryptParam = InputData.OrderNum
		DecryptOrderNum = AESDecryptDecodeValue(EncryptParam)

		if DecryptOrderNum == "" {
			log.Println("invalid parmeter value: order num decrypt error")
			ResponseMessage = "json parameter decript error (order num)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "612", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - OrderNum Decrypt Value [%s] -> [%s]", EncryptParam, DecryptOrderNum)
	}

	// comments: decrypt and base32 input userkey value
	if InputData.Checksum != "" {
		EncryptParam = InputData.Checksum
		DecryptChecksum = AESDecryptDecodeValue(EncryptParam)

		if DecryptChecksum == "" {
			log.Println("invalid parmeter value: checksum decrypt error")
			ResponseMessage = "json parameter decript error (checksum)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "612", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}
		log.Printf("WEB API Auth - Checksum Decrypt Value [%s] -> [%s]", EncryptParam, DecryptChecksum)
	}

	Database = MssqlDB_Open()
	defer MssqlDB_Close(Database)
	//msdb_lib.DB_AutoCommit_Enable(Database)

	if Database == nil {
		log.Println("db connection error")
		ResponseMessage = "db connection error"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}

	//--[Query: Checking UserID]--------------------{
	QueryString = "SELECT s_id, login_pwd " +
                "FROM dbo.Login with(nolock) " +
                "wHERE login_id_hash = HASHBYTES('sha1','%s') and login_pwd = HASHBYTES('sha1','%s') and delete_yn = 0 and site_id = %d "
	QueryString = fmt.Sprintf(QueryString, DecryptLoginID, DecryptLoginPW, SiteID)
	log.Println("Auth UserKey Exist Query : ", QueryString)
	//----------------------------------------------}
	ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
	if err != nil {
		log.Println("db query error (not founded user id column of Login)")
		ResponseMessage = "db query error(not founded user id column of Login)"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}

	QueryTupleCount = 0
	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&DBSID, &DBLoginPW)
		if err != nil {
			ResultSetRows.Close()
			log.Println("data Scan error:", err)
			ResponseMessage = "db query error(not founded result set row that was key_id, user_key column of User_Key)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}
		QueryTupleCount++
	}
	ResultSetRows.Close()

  if QueryTupleCount == 0 {
		log.Println("db query error(not exist svc setup userid)")
		ResponseMessage = "setup creation failed (exist userid)"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "655", ResponseMessage, "", "", "", "", "", "", "", "")
		return
  }

	if QueryTupleCount > 1 {
		log.Println("db query error(muti-tuple svc setup userid)")
		ResponseMessage = "setup creation failed (multi-tuple userid)"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "654", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}
  
  //log.Printf("LoginID:%s, LoginSID:%d, LoginPW:%s", DecryptLoginID, DBSID, DBLoginPW)

  if DBSID == 0 || DBLoginPW == "" {
		log.Println("db query error(db invalid value of sid, pw)")
		ResponseMessage = "setup creation failed (db user invalid informaiton)"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "654", ResponseMessage, "", "", "", "", "", "", "", "")
		return
  }

	//--[Query: Checking OrderNum]--------------------{
	QueryString = "SELECT key_id, user_key, user_id " +
                "FROM mcs.User_Key with(nolock) " +
                "WHERE order_no = '%s' and delete_yn = 0 and site_id = %d "
	QueryString = fmt.Sprintf(QueryString, DecryptOrderNum, SiteID)
	log.Println("Auth UserKey Exist Query : ", QueryString)
	//------------------------------------------------}
	ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
	if err != nil {
		log.Println("db query error (not founded key_id, user_key column of User_Key)")
		ResponseMessage = "db query error(not founded UserKey by OrderNum)"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}

	QueryTupleCount = 0
	for ResultSetRows.Next() {
		err = ResultSetRows.Scan(&DBKeyID, &DBUserKey, &DBUserID)
		if err != nil {
			ResultSetRows.Close()
			log.Println("data Scan error:", err)
			ResponseMessage = "db query error(not founded keyid, userkey by orderNum)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}
		QueryTupleCount++
	}
	ResultSetRows.Close()

  if QueryTupleCount == 0 {
		log.Println("db query error(not exist svc userkey)")
		ResponseMessage = "setup creation failed (exist userid)"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "655", ResponseMessage, "", "", "", "", "", "", "", "")
		return
  }

	if QueryTupleCount > 1 {
		log.Println("db query error(muti-tuple svc setup userkey)")
		ResponseMessage = "setup creation failed (multi-tuple userid)"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "654", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}
  
  if DBKeyID == 0 || DBUserKey == "" {
		log.Println("db query error(db invalid value of keyid, userkey)")
		ResponseMessage = "setup creation failed (db userkey invalid informaiton)"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "654", ResponseMessage, "", "", "", "", "", "", "", "")
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
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}

		hashing_algorithm := md5.New()
		HashingText = DecryptLoginID + ":" + DecryptLoginPW
		hashing_algorithm.Write([]byte(HashingText))
		HA1 = hex.EncodeToString(hashing_algorithm.Sum(nil))
		HashingValue = "[" + HashingText + " >> HA1:" + HA1 + "]"

		hashing_algorithm = md5.New()
		HashingText = InputData.Method + ":" + "/auth_api/svc_setup/v1.0/"
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

			//--[Query: Delete Existed AuthKey & AuthToken]--{
			QueryString = "DELETE FROM mcs.CWS_Auth WHERE key_id = %d and user_id = %d and device_id = %d and method = '%s' and session_type = '%s' and seperator = '%s' "
			QueryString = fmt.Sprintf(QueryString, DBKeyID, 0, 0, InputData.Method, InputData.SessionType, InputData.Seperator)
			log.Println("CWS_AuthTbl Delete Query : ", QueryString)
			//-----------------------------------------------}
			_, err = msdb_lib.Delete_Data(Database, QueryString)
			if err != nil {
				log.Println("db processing error (delete CWS_Auth by key_id)")
				ResponseMessage = "db processing error (delete CWS_Auth by key_id)"
				WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
				return
			}

			//--[Query: Insert Temp AuthKey & AuthToken]-----{
			QueryString = "INSERT INTO mcs.CWS_Auth (key_id, user_id, device_id, method, session_type, seperator, ip, mac, auth_key, auth_token, expiretime, reg_date) " +
				"VALUES (%d, %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', DATEADD(second, %d, GETDATE()), GETDATE()) "
      if len (AccessClientIP) >= 64 {
        QueryString = fmt.Sprintf(QueryString, DBKeyID, 0, 0, InputData.Method, InputData.SessionType, InputData.Seperator, "InvalidIPLength", "none", GenerateAuthKey, GenerateAuthToken, AuthExpiretimeInterval)
      } else {
        QueryString = fmt.Sprintf(QueryString, DBKeyID, 0, 0, InputData.Method, InputData.SessionType, InputData.Seperator, AccessClientIP, "none", GenerateAuthKey, GenerateAuthToken, AuthExpiretimeInterval)
      }
			log.Println("AuthKey & AuthToken Insert Query : ", QueryString)
			//-----------------------------------------------}
			_, err = msdb_lib.Insert_Data(Database, QueryString)
			if err != nil {
				log.Println("db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)")
				ResponseMessage = "db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)"
				WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
				return
			}


			ResponseMessage = "success generation auth key"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "200", ResponseMessage, GenerateAuthKey, strconv.Itoa(AuthExpiretimeInterval), "", "", "", "", "", "")
			log.Printf("web api response [code:%s, msg:%s, description:%s (expiretime sec:%d, authkey:%s, authtoken:%s)]", "200", ResponseMessage, "create new authkey and authtoken", AuthExpiretimeInterval, GenerateAuthKey, GenerateAuthToken)
			return

		} else {
			log.Println("failed to create auth token:")
			ResponseMessage = "failed to generate auth token"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "644", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}

	} else if InputData.AuthKey != "" && InputData.AuthToken != "" {

		//--[Query: Checking Auth Information]-----------{
		QueryString = "SELECT auth_key, auth_token, " +
			"auth_expiretime=((DATEPART(HOUR,expiretime)*3600)+(DATEPART(MINUTE,expiretime)*60)+(DATEPART(Second,expiretime))), " +
			"auth_now=((DATEPART(HOUR,GETDATE())*3600)+(DATEPART(MINUTE,GETDATE())*60)+(DATEPART(Second,GETDATE()))) " +
			"FROM mcs.CWS_Auth " +
			"WHERE key_id = %d and user_id = %d and device_id = %d and auth_key = '%s' and auth_token = '%s' and method = '%s' and session_type = '%s' and seperator = '%s' "
		QueryString = fmt.Sprintf(QueryString, DBKeyID, 0, 0, InputData.AuthKey, InputData.AuthToken, InputData.Method, InputData.SessionType, InputData.Seperator)
		log.Println("Auth Information Checking Query : ", QueryString)
		//-----------------------------------------------}

		ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			log.Println("db processing error (not founded tuple by key_id, auth_key, auth_token)")
			ResponseMessage = "db processing error (not founded tuple by key_id, auth_key, auth_token)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}

		QueryTupleCount = 0
		for ResultSetRows.Next() {
			err = ResultSetRows.Scan(&DBAuthKey, &DBAuthToken, &DBAuthExpireTime, &DBAuthNOWTime)
			if err != nil {
				ResultSetRows.Close()
				log.Println("data Scan error:", err)
				ResponseMessage = "db processing error (not founded resultset row of tuple(auth_key, auth_token, expiretime, now))"
				WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
				return
			}
			QueryTupleCount++
		}
		ResultSetRows.Close()

		if QueryTupleCount == 0 {
			log.Println("db query error(auth data of AuthTable not founded)")
			ResponseMessage = "db query error(auth data of AuthTable not founded)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		} else if QueryTupleCount > 1 {
			log.Println("db query error(auth data of AuthTable is multi-tuple)")
			ResponseMessage = "db query error(auth data of AuthTable is multi-tuple)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}

		//--[Query: Delete Existed AuthKey & AuthToken]--{
		QueryString = "DELETE FROM mcs.CWS_Auth WHERE key_id = %d and user_id = %d and device_id = %d and auth_key = '%s' and auth_token = '%s' and method = '%s' and session_type = '%s' and seperator = '%s' "
		QueryString = fmt.Sprintf(QueryString, DBKeyID, 0, 0, InputData.AuthKey, InputData.AuthToken, InputData.Method, InputData.SessionType, InputData.Seperator)
		log.Println("CWS_Auth Delete Query : ", QueryString)
		//-----------------------------------------------}
		_, err = msdb_lib.Delete_Data(Database, QueryString)
		if err != nil {
			log.Println("db processing error (delete CWS_Auth by key_id)")
			ResponseMessage = "db processing error (delete CWS_Auth by key_id)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}


		if DBAuthExpireTime < DBAuthNOWTime {
			ResponseMessage = "auth_key has expired"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "643", ResponseMessage, "", "", "", "", "", "", "", "")
			log.Printf("web api response [code:%s, msg:%s] %d, %d", "643", ResponseMessage, DBAuthExpireTime, DBAuthNOWTime)
			return
		}

    //--[Query: Query Resource UserKey]-----{
    QueryString = "SELECT device_id, node_id " +
                  "FROM mcs.Node_ID " +
                  "WHERE key_id = %d and status = '002' " +
                  "ORDER BY device_id ASC "
    QueryString = fmt.Sprintf(QueryString, DBKeyID)
    log.Println("UserKey Resource Query : ", QueryString)
    //--------------------------------------}

		ResultSetRows, err = msdb_lib.Query_DB(Database, QueryString)
		if err != nil {
			log.Println("db processing error (not founded tuple by key_id, auth_key, auth_token)")
			ResponseMessage = "db processing error (not founded tuple by key_id, auth_key, auth_token)"
			WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
			return
		}

		QueryTupleCount = 0
		for ResultSetRows.Next() {
			err = ResultSetRows.Scan(&DBDeviceID, &DBNodeID)
			if err != nil {
				ResultSetRows.Close()
				log.Println("data Scan error:", err)
				ResponseMessage = "db processing error (not founded resultset row of tuple(auth_key, auth_token, expiretime, now))"
				WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
				return
			}
			QueryTupleCount++
		}
		ResultSetRows.Close()

    tx, err = msdb_lib.DB_TX_Begin(Database)
    if err != nil {
      log.Println("Transaction Begin err:", err)
      ResponseMessage = "Transaction Begin error"
      WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
      log.Printf("web api response [code:%s, msg:%s] %d, %d", "630", ResponseMessage, DBAuthExpireTime, DBAuthNOWTime)
      return
    }

	  defer msdb_lib.DB_TX_Rollback(tx)

  	if QueryTupleCount == 0 {
      
      DBNewRandomNodeID = GenerateRandomNodeID(DBKeyID)
      if DBNewRandomNodeID == "" {
				log.Println("failed to create random nodeid")
				ResponseMessage = "failed to create random node id"
				WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
				return
      }

			//--[Query: Insert NEW NodeID]-----{
      QueryString = "INSERT INTO mcs.Node_ID (key_id, node_id, status, reg_user, reg_date, upd_user, upd_date, site_id) " +
                    "VALUES (%d, '%s', '004', %d, GETDATE(), %d, GETDATE(), %d) "
      QueryString = fmt.Sprintf(QueryString, DBKeyID, DBNewRandomNodeID, 0, 0, SiteID)
			log.Println("New Random Node ID Query : ", QueryString)
			//---------------------------------}
			//_, err = msdb_lib.Insert_Data(Database, QueryString)
      _, err = tx.Exec(QueryString)
			if err != nil {
				log.Println("db processing error (failed to insert New Node Information)")
				ResponseMessage = "db processing error (failed to insert New Node Information)"
				WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
				return
			}
    
      //--[Query: Query Resource New DeviceID]-----{
      QueryString = "SELECT device_id FROM mcs.Node_ID WHERE key_id = %d and node_id = '%s' "
      QueryString = fmt.Sprintf(QueryString, DBKeyID, DBNewRandomNodeID)
      log.Println("Random DeviceID Resource Query : ", QueryString)
      //-------------------------------------------}
      ResultSetRows, err = tx.Query(QueryString)
      if err != nil {
        log.Println("db processing error (query node_id by key_id and node_id)")
        ResponseMessage = "db processing error (query node_id by key_id and node_id)"
        WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
        return
      }

      QueryTupleCount = 0
	    for ResultSetRows.Next() {
        err = ResultSetRows.Scan(&DBNewRandomDeviceID)
        if err != nil {
          ResultSetRows.Close()
          log.Println("data Scan error:", err)
          ResponseMessage = "db processing error (not founded resultset row of tuple(auth_key, auth_token, expiretime, now))"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }
        QueryTupleCount++
      }
      ResultSetRows.Close()

      if QueryTupleCount == 0 {
        log.Println("db processing error (not founded resultset row of tuple(random create device id))")
        ResponseMessage = "db processing error (not founded resultset row of tuple(random create device id))"
        WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
        return
      } else if QueryTupleCount > 1 {
        log.Println("db processing error (multi-resultset row of tuple(random create device id))")
        ResponseMessage = "db processing error (multi-resultset row of tuple(random create device id))"
        WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
        return
      }

      //--- gkwon...
			//--[Query: UserKey Unit Check Fire_Wall]-----{
      QueryString = "SELECT wall_id FROM mcs.Fire_Wall_IP WHERE key_id = %d and ip = '%s' "
      QueryString = fmt.Sprintf(QueryString, DBKeyID, AccessClientIP)
      log.Println("Random DeviceID Resource Query : ", QueryString)
			//--[Query: UserKey Unit Check Fire_Wall]-----}
      ResultSetRows, err = tx.Query(QueryString)
      if err != nil {
        log.Println("db processing error (query fire_wall_ip by key_id and access_ip)")
        ResponseMessage = "db processing error (query fire_wall_ip by key_id and access_ip)"
        WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
        return
      }

      QueryTupleCount = 0
	    for ResultSetRows.Next() {
        err = ResultSetRows.Scan(&DBNewWallID)
        if err != nil {
          ResultSetRows.Close()
          log.Println("dup firewall key_id and ip data Scan error:", err)
          ResponseMessage = "db processing error (firewall ip by key_id, access_ip)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }
        QueryTupleCount++
      }
      ResultSetRows.Close()

      if QueryTupleCount == 0 {

        //--[Query: Insert DeviceID Fire_Wall]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall (key_id, device_id, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBKeyID, DBNewRandomDeviceID, DBSID, SiteID)
        log.Println("New Random Node ID Query : ", QueryString)
        //-----------------------------------------}
        //_, err = msdb_lib.Insert_Data(Database, QueryString)
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)")
          ResponseMessage = "db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        //--[Query: Query Resource New WallID ]-----{
        QueryString = "SELECT wall_id FROM mcs.Fire_Wall WHERE key_id = %d and device_id = %d "
        QueryString = fmt.Sprintf(QueryString, DBKeyID, DBNewRandomDeviceID)
        log.Println("Random DeviceID Resource Query : ", QueryString)
        //------------------------------------------}
        ResultSetRows, err = tx.Query(QueryString)
        if err != nil {
          log.Println("db processing error (query fire_wall by key_id and access_ip)")
          ResponseMessage = "db processing error (query fire_wall by key_id and access_ip)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        QueryTupleCount = 0
	      for ResultSetRows.Next() {
          err = ResultSetRows.Scan(&DBNewWallID)
          if err != nil {
            ResultSetRows.Close()
            log.Println("data Scan error:", err)
            ResponseMessage = "db processing error (not founded resultset row of tuple(auth_key, auth_token, expiretime, now))"
            WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
            return
          }
          QueryTupleCount++
        }

        ResultSetRows.Close()

        if QueryTupleCount == 0 {
          log.Println("db processing error (not founded resultset row of tuple(new wallid))")
          ResponseMessage = "db processing error (not founded resultset row of tuple(new wallid))"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        } else if QueryTupleCount > 1 {
          log.Println("db processing error (multi-resultset row of tuple(new wallid))")
          ResponseMessage = "db processing error (multi-resultset row of tuple(new wallid))"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        //--[Query: Insert NEW WallIP]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall_IP (wall_id, key_id, ip, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, '%s', %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBNewWallID, DBKeyID, AccessClientIP, DBSID, SiteID)
        log.Println("New Random Node ID Query : ", QueryString)
        //---------------------------------}
        //_, err = msdb_lib.Insert_Data(Database, QueryString)
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert firewall ip)")
          ResponseMessage = "db processing error (insert firewall ip)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        //--[Query: Insert FireWall Log]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall_Log (wall_id, key_id, device_id, reg_firewall, description, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, %d, %d, '%s', %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBNewWallID, DBKeyID, DBNewRandomDeviceID, 1, "firewall ip registration", DBUserID, SiteID)
        log.Println("New Random Node ID Query : ", QueryString)
        //-----------------------------------}
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert firewall log - registration)")
          ResponseMessage = "db processing error (insert firewall log - unregistration)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        tx.Commit()

      } else if QueryTupleCount == 1 {

        //--[Query: Insert FireWall Log]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall_Log (wall_id, key_id, device_id, reg_firewall, description, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, %d, %d, '%s', %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBNewWallID, DBKeyID, DBNewRandomDeviceID, 0, "firewall ip unregistration (exist data)", DBUserID, SiteID)
        log.Println("New Random Node ID Query : ", QueryString)
        //-----------------------------------}
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert firewall log - unregistration)")
          ResponseMessage = "db processing error (insert firewall log - unregistration)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        tx.Commit()

      } else {

        //--[Query: Insert FireWall Log]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall_Log (wall_id, key_id, device_id, reg_firewall, description, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, %d, %d, '%s', %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBNewWallID, DBKeyID, DBNewRandomDeviceID, 0, "firewall ip unregistration (exist many data)", DBUserID, SiteID)
        log.Println("New Random Node ID Query : ", QueryString)
        //-----------------------------------}
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert firewall log - unregistration)")
          ResponseMessage = "db processing error (insert firewall log - unregistration)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        tx.Commit()

        log.Println("db processing error (no one tuple of firewall ip by key_id, access_ip)")
        //-------------------------------------------------------------------------------------------------//
        //ResponseMessage = "db processing error (no one tuple of firewall ip by key_id, access_ip)"
        //WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
        //return
        //-------------------------------------------------------------------------------------------------//
      }

      ResponseMessage = "success"
      WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "200", ResponseMessage, "", "", EncryptValue, "", DBUserKey, DBNewRandomNodeID, ServiceGOWASAddress, UpdateGOWASAddress)
      log.Printf("web api init trial response [UserKey:%s, NodeID:%s] [code:%s, msg:%s]", DBUserKey, DBNewRandomNodeID, "200", ResponseMessage)
      return

		} else if QueryTupleCount >= 1 {

      //--[Query: Update Resource UserKey Status]-----{
      QueryString = "UPDATE mcs.Node_ID SET status = '004' WHERE device_id = %d and status = '002' "
      QueryString = fmt.Sprintf(QueryString, DBDeviceID)
      log.Println("AuthKey & AuthToken Expiretime Update Query -> ", QueryString)
      //----------------------------------------------}
			//_, err = msdb_lib.Update_Data(Database, QueryString)
      _, err = tx.Exec(QueryString)
			if err != nil {
				log.Println("db processing error (update state of NodeID)")
				ResponseMessage = "db processing error (update state of NodeID)"
				WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
				return
			}

      //... gkwon....
			//--[Query: UserKey Unit Check Fire_Wall]-----{
      QueryString = "SELECT wall_id FROM mcs.Fire_Wall_IP WHERE key_id = %d and ip = '%s' "
      QueryString = fmt.Sprintf(QueryString, DBKeyID, AccessClientIP)
      log.Println("Random DeviceID Resource Query : ", QueryString)
			//--[Query: UserKey Unit Check Fire_Wall]-----}
      ResultSetRows, err = tx.Query(QueryString)
      if err != nil {
        log.Println("db processing error (query fire_wall_ip by key_id and access_ip)")
        ResponseMessage = "db processing error (query fire_wall_ip by key_id and access_ip)"
        WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
        return
      }

      QueryTupleCount = 0
	    for ResultSetRows.Next() {
        err = ResultSetRows.Scan(&DBNewWallID)
        if err != nil {
          ResultSetRows.Close()
          log.Println("dup firewall key_id and ip data Scan error:", err)
          ResponseMessage = "db processing error (firewall ip by key_id, access_ip)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }
        QueryTupleCount++
      }
      ResultSetRows.Close()

      if QueryTupleCount == 0 {

        //--[Query: Insert DeviceID Fire_Wall]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall (key_id, device_id, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBKeyID, DBDeviceID, DBSID, SiteID)
        log.Println("Inser Fire_Wal Query : ", QueryString)
        //---------------------------------}
        //_, err = msdb_lib.Insert_Data(Database, QueryString)
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)")
          ResponseMessage = "db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        //--[Query: Query Resource New WallID ]-----{
        QueryString = "SELECT wall_id FROM mcs.Fire_Wall WHERE key_id = %d and device_id = %d "
        QueryString = fmt.Sprintf(QueryString, DBKeyID, DBDeviceID)
        log.Println("Random DeviceID Resource Query : ", QueryString)
        //------------------------------------------}
        ResultSetRows, err = tx.Query(QueryString)
        if err != nil {
          log.Println("db processing error (query fire_wall by key_id and access_ip)")
          ResponseMessage = "db processing error (query fire_wall by key_id and access_ip)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        QueryTupleCount = 0
	      for ResultSetRows.Next() {
          err = ResultSetRows.Scan(&DBNewWallID)
          if err != nil {
            ResultSetRows.Close()
            log.Println("data Scan error:", err)
            ResponseMessage = "db processing error (not founded resultset row of tuple(auth_key, auth_token, expiretime, now))"
            WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
            return
          }
          QueryTupleCount++
        }
        ResultSetRows.Close()

        if QueryTupleCount == 0 {
          log.Println("db processing error (not founded resultset row of tuple(new wallid))")
          ResponseMessage = "db processing error (not founded resultset row of tuple(new wallid))"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        } else if QueryTupleCount > 1 {
          log.Println("db processing error (multi-resultset row of tuple(new wallid))")
          ResponseMessage = "db processing error (multi-resultset row of tuple(new wallid))"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        //--[Query: Insert NEW WallIP]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall_IP (wall_id, key_id, ip, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, '%s', %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBNewWallID, DBKeyID, AccessClientIP, DBSID, SiteID)
        log.Println("New Random Node ID Query : ", QueryString)
        //---------------------------------}
        //_, err = msdb_lib.Insert_Data(Database, QueryString)
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)")
          ResponseMessage = "db processing error (insert CWS_Auth setup by key_id, auth_key, auth_token)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        //--[Query: Insert FireWall Log]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall_Log (wall_id, key_id, device_id, reg_firewall, description, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, %d, %d, '%s', %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBNewWallID, DBKeyID, DBDeviceID, 1, "firewall ip registration", DBUserID, SiteID)
        log.Println("New Random Node ID Query : ", QueryString)
        //-----------------------------------}
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert firewall log - registration)")
          ResponseMessage = "db processing error (insert firewall log - unregistration)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        tx.Commit()

      } else if QueryTupleCount == 1 {

        //--[Query: Insert FireWall Log]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall_Log (wall_id, key_id, device_id, reg_firewall, description, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, %d, %d, '%s', %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBNewWallID, DBKeyID, DBDeviceID, 0, "firewall ip unregistration (exist data)", DBUserID, SiteID)
        log.Println("New Random Node ID Query : ", QueryString)
        //-----------------------------------}
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert firewall log - registration)")
          ResponseMessage = "db processing error (insert firewall log - unregistration)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        tx.Commit()

      } else {

        //--[Query: Insert FireWall Log]-----{
        QueryString = "INSERT INTO mcs.Fire_Wall_Log (wall_id, key_id, device_id, reg_firewall, description, reg_user, reg_date, site_id) " +
                      "VALUES (%d, %d, %d, %d, '%s', %d, GETDATE(), %d) "
        QueryString = fmt.Sprintf(QueryString, DBNewWallID, DBKeyID, DBDeviceID, 0, "firewall ip unregistration (exist many data)", DBUserID, SiteID)
        log.Println("New Random Node ID Query : ", QueryString)
        //-----------------------------------}
        _, err = tx.Exec(QueryString)
        if err != nil {
          log.Println("db processing error (insert firewall log - registration)")
          ResponseMessage = "db processing error (insert firewall log - unregistration)"
          WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
          return
        }

        tx.Commit()

        log.Println("db processing error (no one tuple of firewall ip by key_id, access_ip)")
        //-------------------------------------------------------------------------------------------------//
        //ResponseMessage = "db processing error (no one tuple of firewall ip by key_id, access_ip)"
        //WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "630", ResponseMessage, "", "", "", "", "", "", "", "")
        //return
        //-------------------------------------------------------------------------------------------------//
      }

      ResponseMessage = "success"
      WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "200", ResponseMessage, "", "", EncryptValue, "", DBUserKey, DBNodeID, ServiceGOWASAddress, UpdateGOWASAddress)
      log.Printf("web api init trial response [UserKey:%s, NodeID:%s] [code:%s, msg:%s]", DBUserKey, DBNodeID, "200", ResponseMessage)
      return
		}

	} else {
		log.Println("not supported auth information case")
		ResponseMessage = "not supported auth information case"
		WebServer_Auth_API_SVC_Setup_Response(w, InputData.Version, InputData.Method, InputData.SessionType, InputData.Seperator, "response", InputData.MessageSeq, "611", ResponseMessage, "", "", "", "", "", "", "", "")
		return
	}
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
    WebServer_Auth_API_Setup_Invalid_Access_Response(w, "403", "Forbidden")
	})

	//----- [ Svc Init Auth Processing ] {--------------------//
	WebServerMux.HandleFunc("/auth_api/svc_setup/v1.0/", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Auth_API_SVC_Setup_Proc(w, req)
	})
	//----- [ Svc Init Auth Processing ] }--------------------//

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

// UpdateDBNodeStatus ...

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
			PidFileName: "innogs_setup_gowas.pid",
			PidFilePerm: 0644,
			LogFileName: ProcessLogFileName,
			LogFilePerm: 0640,
			WorkDir:     "./",
			Umask:       027,
			Args:        []string{"./innogs_setup_gowas", "-l", ListenerPort, "-p", ProcessType},
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
