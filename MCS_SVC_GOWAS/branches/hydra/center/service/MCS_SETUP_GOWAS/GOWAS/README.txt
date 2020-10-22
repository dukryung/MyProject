
1. golang setup method three case: 
  (1) download web page : https://golang.org/dl/
  (2) wget https://dl.google.com/go/go1.12.1.linux-amd64.tar.gz
  (3) sudo yum install golang

2. package install 
  #> go get github.com/go-sql-driver/mysql
  #> cd ~/go/src/github.com/go-sql-driver/mysql
  #> git checkout tags/v1.4.1

  #> go get github.com/denisenkom/go-mssqldb
  #> cd ~/go/src/github.com/denisenkom/go-mssqldb

  #> go get github.com/mattn/go-sqlite3

  #> go get github.com/gorilla/sessions
  #> cd ~/go/src/github.com/gorilla/sessions
  #> git checkout tags/v1.1.1

  #> go get github.com/gorilla/context
  #> cd ~/go/src/github.com/gorilla/context

  #> go get github.com/sevlyar/go-daemon

  #> go get github.com/BurntSushi/toml
  #> cd ~/go/src/github.com/BurntSushi/toml

  #> go get gopkg.in/natefinch/lumberjack.v2
  #> cd ~/go/src/gopkg.in/natefinch/lumberjack.v2 


------< Packaging Process >--------------------------------------

1. .svn delete 
    - #> find ./ -name .svn -print0 | xargs -0 rm -rf

2. go build 
    - #> go build -o innogs_setup_gowas ./setup_gowas.go

3. delete go source 
    - #> rm -f ././setup_gowas.go
    - #> rm -rf ./library
    - #> rm -rf ./README.txt

4. packing tar
    - #> tar cvf ./setup_gowas.tar ./
    - #> mv ./setup_gowas.tar ./setup_gowas_vx.x.x.rxxx.tar
-----------------------------------------------------------------
