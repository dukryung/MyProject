< *Control Server* Packaging Process >
[must] : stat webserver 의 경우 go version 1.2 이상이여야 함 
golang install reference : https://github.com/golang-kr/golang-doc/wiki/%EC%84%A4%EC%B9%98-%EC%8B%9C%EC%9E%91%ED%95%98%EA%B8%B0
1. .svn delete
    - #> find ./ -name .svn -print0 | xargs -0 rm -rf
2. go build
    - #> mv ./stat_web_server.go ./Stat_Web_Control.go
    - #> go build ./Stat_Web_Control.go
3. delete go source
    - #> rm -rf ./Stat_Web_Control.go
    - #> rm -rf ./mips_cross_compile
    - #> rm -rf ./stat_web_server.log
    - #> rm -rf ./lib
    - #> rm -rf ./db
    - #> rm -rf ./cfg/app.cfg
    - #> rm -rf ./cfg/nodeid.key
    - #> rm -rf ./tags
    - #> rm -rf ./README.txt
4. packing tar
    - #> cd ..
    - #> tar cvf ./Stat_Web_Control.tar ./Stat_Web_Control
