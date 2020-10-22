1. golang setup method three case: 
  (1) download web page : https://golang.org/dl/

2. .svn 삭제    

3. package install 
  #> go get "github.com/BurntSushi/toml"  

  #> go get "github.com/go-sql-driver/mysql"  

  #> go get "github.com/gorilla/sessions"

  #> go get "github.com/mattn/go-sqlite3"

  #> go get "github.com/mitchellh/mapstructure"

  #> go get "github.com/sevlyar/go-daemon"

  #> go get "github.com/shirou/gopsutil/host" 

  #> go get "gopkg.in/natefinch/lumberjack.v2"  



4. go build 
    - #> go build -ldflags "-X 'main.GoWebVersion=GOWEB Version (service): 1.0.1r14555'" Stat_Web_linux.go    

