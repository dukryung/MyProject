package main

import (
	"MCS_KMS_Create_Pkg/make_package"
	"log"
	"net/http"
	"strconv"
)

func main() {
	var Temp_MCSEID_Arr []string
	var err error
	var fullpath string
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	log.Println("Create License File..\n")

	Temp_MCSEID_Arr = append(Temp_MCSEID_Arr, "51EA6741-C1B0-4297-9F23-B36417B3C212", "52EA6741-C1B0-4297-9F23-B36417B3C212", "53EA6741-C1B0-4297-9F23-B36417B3C212", "54EA6741-C1B0-4297-9F23-B36417B3C212", "55EA6741-C1B0-4297-9F23-B36417B3C212")

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {

		go func() {

			for i := 1; i <= 1; i++ {
				for j := 1; j <= 1; j++ {
					log.Println("--------------------------------------------------------------------------------win 1")
					fullpath, err = MakePackage.Make_Pkg_Windows("Create", "12345678901234567890123456789012", "1234567890123456", "test01", "BFDC3CA9-C06E-E452A-8E42-2B35AD9DAC65", "100", "98", "2019", "11", "19", Temp_MCSEID_Arr, "/root/go/src/MCS_KMS_Create_Pkg/test_"+strconv.Itoa(i), "/root/go/src/MCS_KMS_Create_Pkg", "svc_node", "svc_corporation")
					if err != nil {
						log.Println("err!!!!", err)
					}
					log.Println("fullpath:", fullpath)
					log.Println("--------------------------------------------------------------------------------win 2")
				}
			}

		}()

		go func() {
			for i := 1; i <= 1; i++ {

				for j := 1; j <= 1; j++ {
					log.Println("--------------------------------------------------------------------------------lnx 1")
					fullpath, err = MakePackage.Make_Pkg_Linux("Create", "12345678901234567890123456789012", "1234567890123456", "test01", "BFDC3CA9-C06E-E452A-8E42-2B35AD9DAC65", "100", "98", "2019", "11", "19", Temp_MCSEID_Arr, "/root/go/src/MCS_KMS_Create_Pkg/test_"+strconv.Itoa(i), "/root/go/src/MCS_KMS_Create_Pkg", "svc_node", "svc_corporation")
					if err != nil {
						log.Println("err!!!!", err)
					}
					log.Println("fullpath:", fullpath)
					log.Println("--------------------------------------------------------------------------------lnx 2")
				}
			}
		}()

	})
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, req *http.Request) {
		WebServer_Forbidden(w, req)
	})

	http.ListenAndServe(":5000", nil)

	finish := make(chan bool)
	<-finish
}

func WebServer_Forbidden(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "Forbidden", http.StatusForbidden)
	return
}
