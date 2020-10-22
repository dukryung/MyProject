package main

import (
	"MCS_KMS_Create_Pkg/MakePackage"
	"log"
	"net/http"
	"strconv"
)

func main() {
	var Temp_MCSEID_Arr []string
	var err error
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	log.Println("Create License File..\n")

	Temp_MCSEID_Arr = append(Temp_MCSEID_Arr, "51EA6741-C1B0-4297-9F23-B36417B3C212", "52EA6741-C1B0-4297-9F23-B36417B3C212", "53EA6741-C1B0-4297-9F23-B36417B3C212", "54EA6741-C1B0-4297-9F23-B36417B3C212", "55EA6741-C1B0-4297-9F23-B36417B3C212")

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {

		go func() {

			for i := 1; i <= 1; i++ {
				for j := 1; j <= 1; j++ {
					log.Println("--------------------------------------------------------------------------------win 1")
					err = MakePackage.Make_Lic_And_Ist("Create", "test01", "BFDC3CA9-C06E-E452A-8E42-2B35AD9DAC65", "100", "98", "2019", "11", "19", Temp_MCSEID_Arr, "/root/go/src/MCS_KMS_Create_Pkg/test_"+strconv.Itoa(i), "./Origin/Win_Origin", "/win_Temp", "/lbsvc/cfg", "lbsvc-Setup-1.1.exe", "license.lic", "userkey.txt", "nsisscript-mcse.nsi", "bin/makensis")
					if err != nil {
						log.Println("err!!!!", err)
					}

					log.Println("--------------------------------------------------------------------------------win 2")
				}
			}

		}()

		go func() {
			for i := 1; i <= 1; i++ {

				for j := 1; j <= 1; j++ {
					log.Println("--------------------------------------------------------------------------------lnx 1")
					err = MakePackage.Make_Lic_And_Pkg("Create", "test01", "BFDC3CA9-C06E-E452A-8E42-2B35AD9DAC65", "100", "98", "2019", "11", "19", Temp_MCSEID_Arr, "/root/go/src/MCS_KMS_Create_Pkg/test_"+strconv.Itoa(i), "./Origin/MCSE_Origin", "/lnx_Temp", "test.sh", "license.lic", "userkey.txt", "lbsvc.tar.gz")
					if err != nil {
						log.Println("err!!!!", err)
					}
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
