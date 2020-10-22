package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"learngo/structcomp"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	var method string

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	fmt.Print("Method Type의 번호를 선택해 주세요 (1.Get 2.Post 3.Put 4.Delete) -> ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		method = scanner.Text()
	}

	if method == "1" {
		method = "GET"
	} else if method == "2" {
		method = "POST"
	} else if method == "3" {
		method = "PUT"
	} else if method == "4" {
		method = "DELETE"
	} else {
		log.Fatal(errors.New("you input invalid method"))
	}
	log.Println("Method : ", method)

	var uri string
	fmt.Print("uri를 입력하세요 (ip : 127.0.0.1(고정) port : 8080(고정) uri : 입력(ex:/movie)) -> ")
	scanner = bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		uri = scanner.Text()
	}

	var moviename, isdone string
	var movieid string
	var moviearr = new(structcomp.Postmovieinfo)
	var putmovieinfo = new(structcomp.Putmovieinfo)
	if method == "POST" {
		for {
			fmt.Print("Movie 명을 입력해주세요 -> ")
			scanner = bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				moviename = scanner.Text()
			}
			log.Println("[LOG] Movie name", moviename)
			moviearr.Name = append(moviearr.Name, moviename)
			for {
				fmt.Print("더 입력할 Movie가 있나요? 번호를 선택하세요 (1.yes 2.no) -> ")
				scanner = bufio.NewScanner(os.Stdin)
				if scanner.Scan() {
					isdone = scanner.Text()
				}
				if isdone == "1" {
					break
				} else if isdone == "2" {
					break
				} else {
					log.Println("잘못된 입력입니다. 다시 입력하세요.")
				}
			}
			if isdone == "1" {
				isdone = "1"
			} else if isdone == "2" {
				isdone = "2"
				break
			}
		}
	} else if method == "PUT" {
		for {
			fmt.Print("Movie 명을 입력해주세요 -> ")
			scanner = bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				moviename = scanner.Text()
			}
			fmt.Print("Update가 필요한 Movie_id의 숫자를 입력해주세요 -> ")
			scanner = bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				movieid = scanner.Text()
			}

			_, err := strconv.Atoi(movieid)
			if err != nil {
				log.Println("[ERR] strconv.Atoi :", err)
				log.Println("[ERR] movie_id : ", movieid)
				return
			}

			putmovieinfo.Name = append(putmovieinfo.Name, moviename)
			putmovieinfo.Movie_id = append(putmovieinfo.Movie_id, movieid)
			for {
				fmt.Print("더 입력할 Movie가 있나요? 번호를 선택하세요 (1.yes 2.no) -> ")
				scanner = bufio.NewScanner(os.Stdin)
				if scanner.Scan() {
					isdone = scanner.Text()
				}
				if isdone == "1" {
					break
				} else if isdone == "2" {
					break
				} else {
					log.Println("잘못된 입력입니다. 다시 입력하세요.")
				}
			}
			if isdone == "1" {

			} else if isdone == "2" {
				break
			}
		}
	}
	var jsoninfo []byte
	var err error
	if method == "POST" {
		jsoninfo, err = json.Marshal(moviearr)
		if err != nil {
			log.Println("[ERR] json.Marshal : ", err)
		}
	} else if method == "PUT" {
		jsoninfo, err = json.Marshal(putmovieinfo)
		if err != nil {
			log.Println("[ERR] json.Marshal : ", err)
		}
	}

	log.Println("[LOG] json info : ", string(jsoninfo))

	url := "http://127.0.0.1:8080" + uri
	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsoninfo))
	if err != nil {
		log.Println("[ERR] http.NewRequest : ", err)
	}

	var contenttype string
	if method == "PUT" {
		fmt.Print("Content-Type을 입력하세요. (ex : application/json) -> ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			contenttype = scanner.Text()
		}

		req.Header.Set("Content-Type", contenttype)
	} else if method == "GET" {
		fmt.Print("Content-Type을 입력하세요. (ex : application/json) -> ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			contenttype = scanner.Text()
		}

		req.Header.Set("Content-Type", contenttype)
	} else {
		req.Header.Set("Content-Type", "application/json")

	}

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		log.Println("[ERR] client.Do : ", err)
	}
	defer response.Body.Close()

	bodybytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("[ERR] ioutil.ReadAll : ", err)
	}

	var responseinfo = new(structcomp.Response)

	err = json.Unmarshal(bodybytes, &responseinfo)
	if err != nil {
		log.Println("[ERR] ioutil.ReadAll : ", err)
	}

	log.Println("[LOG] response result : ", string(bodybytes))
}
