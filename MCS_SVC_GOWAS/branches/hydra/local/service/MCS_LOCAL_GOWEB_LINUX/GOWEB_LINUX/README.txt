
1. golang setup method three case: 
  (1) download web page : https://golang.org/dl/
  (2) wget https://dl.google.com/go/go1.12.7.linux-amd64.tar.gz
  (3) sudo yum install golang

2. package install 
  #> go get "github.com/BurntSushi/toml"  

  #> go get "github.com/go-sql-driver/mysql"  

  #> go get "github.com/gorilla/sessions"

  #> go get "github.com/mattn/go-sqlite3"

  #> go get "github.com/mitchellh/mapstructure"

  #> go get "github.com/sevlyar/go-daemon"

  #> go get "github.com/shirou/gopsutil/host" 

  #> go get "gopkg.in/natefinch/lumberjack.v2"  


------< Packaging Process >--------------------------------------

1. .svn delete 
    - #> find ./ -name .svn -print0 | xargs -0 rm -rf

2. go build 
    - #> go build -ldflags "-X 'main.GoWebVersion=GOWEB Version (service): 1.0.1r14555'" -o Stat_Web_linux stat_web_server.go 

-----------------------------------------------------------------
