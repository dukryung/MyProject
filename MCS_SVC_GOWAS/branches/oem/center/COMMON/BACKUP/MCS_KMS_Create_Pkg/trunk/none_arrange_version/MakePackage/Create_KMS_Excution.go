package MakePackage

import (
	"MCS_KMS_Create_Pkg/MakePackage/lib/aes_cfb"
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const (
	Create = "Create"
	Delete = "Delete"
	Modify = "Modify"
)

const (
//LicFileName     = "license.lic"
//PkgFileName     = "lbsvc.tar.gz"
//UserKeyFileName = "userkey.txt"
//NSISFileName    = "nsisscript-mcse.nsi"
//IstFileName     = "lbsvc.exe"
)
const (
	Win_Origin_Path   = "/Windows/Origin"
	Lnx_Origin_Path   = "/Linux/Origin"
	Win_Temp_Path     = "/win_Temp"
	Lnx_Temp_Path     = "/lnx_Temp"
	LicFileName       = "License.lic"
	UserKeyFileName   = "Userkey.txt"
	Key_Location_Path = "/service_common_name/cfg"
	nsiFileName       = "nsisscript-service_node.nsi"
	SscriptName       = "shellscript-service_node.sh"
	MakeNSISFileName  = "/Windows/NSIS/bin/makensis"
)

var (
	aes_key = []byte{109, 56, 85, 44, 248, 44, 18, 128, 236, 116, 13, 250, 243, 45, 122, 133, 199, 241, 124, 188, 188, 93, 65, 153, 214, 193, 127, 85, 132, 147, 193, 68}
	iv      = []byte{89, 93, 106, 165, 128, 137, 36, 38, 122, 121, 249, 59, 151, 133, 155, 148}

	base32_alphabet = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79}
)

var pkg_mutex = &sync.Mutex{}

func Make_Pkg_Windows(ActionFlag string, UserID string, UserKey string, DeviceIDTotalCnt string, DeviceIDCurCnt string, EnddateYear string, EnddateMon string, EnddateDay string, DeviceID []string, Basic_Path string, Home_Path string, IstFileName string, OEMName string) (string, error) {
	var IsNotExistFile bool
	var IsNotExistPath bool
	var err error

	log.Println("here is in Make_Win_Pkg func")
	pkg_mutex.Lock()
	switch ActionFlag {

	case Create:
		log.Println("Create!!")
		IsNotExistFile = Check_Existence_File(Basic_Path, LicFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, LicFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistFile = Check_Existence_File(Basic_Path, IstFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, IstFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", err
			}
		}

		err = Make_Lic_File(UserID, UserKey, DeviceIDTotalCnt, DeviceIDCurCnt, EnddateYear, EnddateMon, EnddateDay, DeviceID, Basic_Path, LicFileName)
		if err != nil {
			log.Println("Make License File Fail! (Reason-> ", err, ")")
			return "", err
		}
		err = Copy_Origin_File(Home_Path, Win_Origin_Path, Basic_Path, Win_Temp_Path)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Make_win_UserKey_File(UserKey, Basic_Path, Win_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make UserKey File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Move_UserKey_File(Basic_Path, Win_Temp_Path, Key_Location_Path, UserKeyFileName)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Rename_To_OEMName(Basic_Path, Win_Temp_Path, OEMName)
		if err != nil {
			log.Println("Rename File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Make_Ist_File(Home_Path, Basic_Path, Win_Temp_Path, nsiFileName, MakeNSISFileName)
		if err != nil {
			log.Println("Make win Install File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Move_Ist_File(Basic_Path, Win_Temp_Path, IstFileName)
		if err != nil {
			log.Println("Move win Install File Fail! (Reason-> ", err, ")")
			return "", err

		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", err
			}
		}

	case Delete:
		log.Println("Delete!!")
		IsNotExistFile = Check_Existence_File(Basic_Path, LicFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, LicFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistFile = Check_Existence_File(Basic_Path, IstFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, IstFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", err
			}
		}

		err = Make_Lic_File(UserID, UserKey, DeviceIDTotalCnt, DeviceIDCurCnt, EnddateYear, EnddateMon, EnddateDay, DeviceID, Basic_Path, LicFileName)
		if err != nil {
			log.Println("Make License File Fail! (Reason-> ", err, ")")
			return "", err
		}
		err = Copy_Origin_File(Home_Path, Win_Origin_Path, Basic_Path, Win_Temp_Path)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Make_win_UserKey_File(UserKey, Basic_Path, Win_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make UserKey File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Move_UserKey_File(Basic_Path, Win_Temp_Path, Key_Location_Path, UserKeyFileName)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Rename_To_OEMName(Basic_Path, Win_Temp_Path, OEMName)
		if err != nil {
			log.Println("Rename File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Make_Ist_File(Home_Path, Basic_Path, Win_Temp_Path, nsiFileName, MakeNSISFileName)
		if err != nil {
			log.Println("Make win Install File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Move_Ist_File(Basic_Path, Win_Temp_Path, IstFileName)
		if err != nil {
			log.Println("Move win Install File Fail! (Reason-> ", err, ")")
			return "", err

		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", err
			}
		}
	case Modify:
		log.Println("Modify!!")
		IsNotExistFile = Check_Existence_File(Basic_Path, LicFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, LicFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistFile = Check_Existence_File(Basic_Path, IstFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, IstFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", err
			}
		}

		err = Make_Lic_File(UserID, UserKey, DeviceIDTotalCnt, DeviceIDCurCnt, EnddateYear, EnddateMon, EnddateDay, DeviceID, Basic_Path, LicFileName)
		if err != nil {
			log.Println("Make License File Fail! (Reason-> ", err, ")")
			return "", err
		}
		err = Copy_Origin_File(Home_Path, Win_Origin_Path, Basic_Path, Win_Temp_Path)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Make_win_UserKey_File(UserKey, Basic_Path, Win_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make UserKey File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Move_UserKey_File(Basic_Path, Win_Temp_Path, Key_Location_Path, UserKeyFileName)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Rename_To_OEMName(Basic_Path, Win_Temp_Path, OEMName)
		if err != nil {
			log.Println("Rename File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Make_Ist_File(Home_Path, Basic_Path, Win_Temp_Path, nsiFileName, MakeNSISFileName)
		if err != nil {
			log.Println("Make win Install File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Move_Ist_File(Basic_Path, Win_Temp_Path, IstFileName)
		if err != nil {
			log.Println("Move win Install File Fail! (Reason-> ", err, ")")
			return "", err

		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", err
			}
		}
	}

	pkg_mutex.Unlock()
	return Basic_Path + "/" + IstFileName, nil
}

func Make_Pkg_Linux(ActionFlag string, UserID string, UserKey string, DeviceIDTotalCnt string, DeviceIDCurCnt string, EnddateYear string, EnddateMon string, EnddateDay string, DeviceID []string, Basic_Path string, Home_Path string, PkgFileName string, OEMName string) (string, error) {
	var IsNotExistFile bool
	var IsNotExistPath bool
	var err error

	log.Println("here is in Make_Lic_And_Pkg func")

	pkg_mutex.Lock()
	switch ActionFlag {
	case Create:

		log.Println("Create!!")
		IsNotExistFile = Check_Existence_File(Basic_Path, LicFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, LicFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistFile = Check_Existence_File(Basic_Path, PkgFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, PkgFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistFile = Check_Existence_File(Basic_Path, SscriptName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, SscriptName)
			if err != nil {
				return "", err
			}

		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", err
			}
		}

		err = Make_Lic_File(UserID, UserKey, DeviceIDTotalCnt, DeviceIDCurCnt, EnddateYear, EnddateMon, EnddateDay, DeviceID, Basic_Path, LicFileName)
		if err != nil {
			log.Println("Make License File Fail! (Reason-> ", err, ")")
			return "", err
		}

		err = Copy_Origin_File(Home_Path, Lnx_Origin_Path, Basic_Path, Lnx_Temp_Path)
		if err != nil {
			log.Println("Copy File Fail! (Reason-> ", err, ")")
			return "", err
		}
		err = Make_lnx_UserKey_File(UserKey, Basic_Path, Lnx_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make lnx File Fail! (Reason-> ", err, ")")
			return "", err
		}

		err = Rename_To_OEMName(Basic_Path, Lnx_Temp_Path, OEMName)
		if err != nil {
			log.Println("Rename File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Excute_Shell(Basic_Path, Lnx_Temp_Path, SscriptName)
		if err != nil {
			log.Println("Excute Shell Fail! (Reason-> ", err, ")")
			return "", err
		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", err
			}
		}

	case Delete:

		log.Println("Delete!!")

		IsNotExistFile = Check_Existence_File(Basic_Path, LicFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, LicFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistFile = Check_Existence_File(Basic_Path, PkgFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, PkgFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistFile = Check_Existence_File(Basic_Path, SscriptName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, SscriptName)
			if err != nil {
				return "", err
			}

		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", err
			}
		}

		err = Make_Lic_File(UserID, UserKey, DeviceIDTotalCnt, DeviceIDCurCnt, EnddateYear, EnddateMon, EnddateDay, DeviceID, Basic_Path, LicFileName)
		if err != nil {
			log.Println("Make License File Fail! (Reason-> ", err, ")")
			return "", err
		}

		err = Copy_Origin_File(Home_Path, Lnx_Origin_Path, Basic_Path, Lnx_Temp_Path)
		if err != nil {
			log.Println("Copy File Fail! (Reason-> ", err, ")")
			return "", err
		}
		err = Make_lnx_UserKey_File(UserKey, Basic_Path, Lnx_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make lnx File Fail! (Reason-> ", err, ")")
			return "", err
		}

		err = Rename_To_OEMName(Basic_Path, Lnx_Temp_Path, OEMName)
		if err != nil {
			log.Println("Rename File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Excute_Shell(Basic_Path, Lnx_Temp_Path, SscriptName)
		if err != nil {
			log.Println("Excute Shell Fail! (Reason-> ", err, ")")
			return "", err
		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", err
			}
		}

	case Modify:
		log.Println("Modify!!")
		IsNotExistFile = Check_Existence_File(Basic_Path, LicFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, LicFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistFile = Check_Existence_File(Basic_Path, PkgFileName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, PkgFileName)
			if err != nil {
				return "", err
			}
		}
		IsNotExistFile = Check_Existence_File(Basic_Path, SscriptName)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, SscriptName)
			if err != nil {
				return "", err
			}

		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", err
			}
		}

		err = Make_Lic_File(UserID, UserKey, DeviceIDTotalCnt, DeviceIDCurCnt, EnddateYear, EnddateMon, EnddateDay, DeviceID, Basic_Path, LicFileName)
		if err != nil {
			log.Println("Make License File Fail! (Reason-> ", err, ")")
			return "", err
		}

		err = Copy_Origin_File(Home_Path, Lnx_Origin_Path, Basic_Path, Lnx_Temp_Path)
		if err != nil {
			log.Println("Copy File Fail! (Reason-> ", err, ")")
			return "", err
		}
		err = Make_lnx_UserKey_File(UserKey, Basic_Path, Lnx_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make lnx File Fail! (Reason-> ", err, ")")
			return "", err
		}

		err = Rename_To_OEMName(Basic_Path, Lnx_Temp_Path, OEMName)
		if err != nil {
			log.Println("Rename File Fail! (Reason-> ", err, ")")
			return "", err

		}

		err = Excute_Shell(Basic_Path, Lnx_Temp_Path, SscriptName)
		if err != nil {
			log.Println("Excute Shell Fail! (Reason-> ", err, ")")
			return "", err
		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", err
			}
		}

	}
	pkg_mutex.Unlock()
	return Basic_Path + "/" + PkgFileName, nil
}

func Make_Ist_File(Home_Path string, Basic_Path string, Temp_Path string, nsiFileName string, MakeNSISFileName string) error {

	IsNotExistFile := Check_Existence_File(Basic_Path, nsiFileName)

	log.Println("IsNotExistFile:", IsNotExistFile)
	cmd := exec.Command(Home_Path+MakeNSISFileName, Basic_Path+Temp_Path+"/"+nsiFileName)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}
	//log.Println("Result: " + out.String())
	log.Println("Make Ist File Succ!")
	return nil

}

func Excute_Shell(Basic_Path string, Temp_Path string, SscriptName string) error {

	cmd := exec.Command("sh", SscriptName)
	cmd.Dir = Basic_Path + Temp_Path
	cmd.Stdin = strings.NewReader("")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Println("cmd.Run error:!", err)
		return err
	}
	//log.Println(out.String())
	return nil

}

func Make_Pkg_File(Basic_Path string, Temp_Path string, PkgFileName string) {

	var Files_Path_Arr []string

	Files_Path_Arr = append(Files_Path_Arr, Basic_Path+Temp_Path)

	log.Println("File_Path_Arr:", Files_Path_Arr)

	tartar(Basic_Path+"/"+PkgFileName, Files_Path_Arr)
}

func Make_win_UserKey_File(UserKey string, Basic_Path string, Temp_Path string, UserKeyFileName string) error {
	var Userkeyfile_Format []string
	var err error
	var whole_Userkey_File string
	var EncText string
	var fd *os.File

	Userkeyfile_Format = []string{"[UserKey]",
		"UserKey = " + UserKey,
	}

	//file, err := os.OpenFile(Basic_Path+Temp_Path+Key_Location_Path+UserKeyFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	fd, err = os.Create(Basic_Path + Temp_Path + "/" + UserKeyFileName)
	defer func() {
		if fd != nil {
			fd.Close()
		}
	}()
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
		return err
	}

	//datawriter := bufio.NewWriter(file)

	for _, UserKeyFormLine := range Userkeyfile_Format {
		whole_Userkey_File += UserKeyFormLine + "\n"
	}

	EncryptEncodingStr(whole_Userkey_File, &EncText)

	_, err = fd.Write([]byte("COD$_"))
	if err != nil {
		log.Println("fd Write error: COD$_")
		return err
	}

	_, err = fd.Write([]byte(EncText))
	if err != nil {
		log.Println("fd Write error: EncText")
		return err
	}

	//_, _ = datawriter.WriteString(Whole_License_File)

	//datawriter.Flush()
	//fd.Close()
	return nil
}

func Make_lnx_UserKey_File(UserKey string, Basic_Path string, Temp_Path string, UserKeyFileName string) error {
	var Userkeyfile_Format []string
	var err error
	var whole_Userkey_File string
	var EncText string
	var IsNotExistPath bool
	var fd *os.File

	IsNotExistPath = Check_Existence_Path(Basic_Path + Temp_Path)
	if IsNotExistPath == true {
		err = os.Mkdir(Basic_Path+Temp_Path, 0777)
		if err != nil {
			log.Println("Mkdir error:", err)
			return err
		}
	}

	Userkeyfile_Format = []string{"[UserKey]",
		"UserKey = " + UserKey,
	}

	//file, err := os.OpenFile(Basic_Path+Temp_Path+Key_Location_Path+UserKeyFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	fd, err = os.Create(Basic_Path + Temp_Path + "/" + UserKeyFileName)
	defer func() {
		if fd != nil {
			fd.Close()
		}
	}()
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
		return err
	}

	//datawriter := bufio.NewWriter(file)

	for _, UserKeyFormLine := range Userkeyfile_Format {
		whole_Userkey_File += UserKeyFormLine + "\n"
	}

	EncryptEncodingStr(whole_Userkey_File, &EncText)

	_, err = fd.Write([]byte("COD$_"))
	if err != nil {
		log.Println("fd Write error: COD$_")
		return err
	}

	_, err = fd.Write([]byte(EncText))
	if err != nil {
		log.Println("fd Write error: EncText")
		return err
	}

	//_, _ = datawriter.WriteString(Whole_License_File)

	//datawriter.Flush()
	return nil
}

/*
func Make_lnx_UserKey_File(UserKey string, Basic_Path string, Key_Location_Path string, Temp_Path string, UserKeyFileName string) {
	var Userkeyfile_Format []string
	var err error
	var whole_Userkey_File string
	var EncText string
	var fd *os.File


	err = os.Mkdir(Basic_Path+Temp_Path, 0777)
	if err != nil {
		log.Println("Mkdir error:", err)
		return
	}

	Userkeyfile_Format = []string{"[UserKey]",
		"UserKey = " + UserKey,
	}

	//file, err := os.OpenFile(Basic_Path+Temp_Path+Key_Location_Path+UserKeyFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	fd, err = os.Create(Basic_Path + Temp_Path + Key_Location_Path + "/" + UserKeyFileName)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	//datawriter := bufio.NewWriter(file)

	for _, UserKeyFormLine := range Userkeyfile_Format {
		whole_Userkey_File += UserKeyFormLine + "\n"
	}

	EncryptEncodingStr(whole_Userkey_File, &EncText)

	_, err = fd.Write([]byte("COD$_"))
	if err != nil {
		log.Println("fd Write error: COD$_")
		return
	}

	_, err = fd.Write([]byte(EncText))
	if err != nil {
		log.Println("fd Write error: EncText")
		return
	}

	//_, _ = datawriter.WriteString(Whole_License_File)

	//datawriter.Flush()
	fd.Close()

}
*/
func Make_Path(Path string) {
	var err error

	err = os.Mkdir(Path, 0777)
	if err != nil {
		log.Println("Make Path error :", err)
		return
	}
}

func Move_Ist_File(Basic_Path string, Temp_Path string, IstFileName string) error {

	err := os.Rename(Basic_Path+Temp_Path+"/"+IstFileName, Basic_Path+"/"+IstFileName)
	if err != nil {
		log.Println("Move err:", err)
		return err
	}
	return err
}
func Move_UserKey_File(Basic_Path string, Temp_Path string, Key_Location_Path string, UserKeyFileName string) error {

	err := os.Rename(Basic_Path+Temp_Path+"/"+UserKeyFileName, Basic_Path+Temp_Path+Key_Location_Path+"/"+UserKeyFileName)
	if err != nil {
		log.Println("Move err:", err)
		return err
	}
	return err
}
func Rename_To_OEMName(Basic_Path string, Temp_Path string, OEMName string) error {

	err := os.Rename(Basic_Path+Temp_Path+"/service_common_name", Basic_Path+Temp_Path+"/"+OEMName)
	if err != nil {
		log.Println("Move err:", err)
		return err
	}
	return err
}
func Copy_Origin_File(Home_Path string, Origin_Path string, Basic_Path string, Temp_Path string) error {

	var dstpath string
	var srcpath string
	var err error
	var src os.FileInfo
	log.Println("Temp_path", Temp_Path)

	dstpath = Basic_Path + Temp_Path
	srcpath = Home_Path + Origin_Path

	// check if the source dir exist
	src, err = os.Stat(srcpath)
	if err != nil {
		log.Println("Stat error:", err)
		return err
	}

	if !src.IsDir() {
		log.Println("Source is not a directory")
		return err
		//os.Exit(1)
	}

	// create the destination directory

	_, err = os.Open(dstpath)
	if !os.IsNotExist(err) {
		log.Println("Destination directory already exists!")
		return err
	}

	err = CopyDir(srcpath, dstpath)
	if err != nil {
		log.Println("Copy Dir error:", err)
		return err
	} else {
		log.Println("Directory copied")
	}
	return nil
}
func Change_File_Name(Basic_Path string, Temp_Path string, Copy_Top_Path string, Copy_Sub_Path string, Copy_bins_Path string, Copy_File_Name string, Rename_File_Name string) {
	err := os.Rename(Basic_Path+Temp_Path+Copy_Top_Path+Copy_Sub_Path+Copy_bins_Path+"/"+Copy_File_Name, Basic_Path+Temp_Path+Copy_Top_Path+Copy_Sub_Path+Copy_bins_Path+"/"+Rename_File_Name)
	if err != nil {
		log.Println("Move err:", err)
		return
	}
}
func Change_Path_Name(Basic_Path string, Temp_Path string, Copy_Top_Path string, Rename_File_Path string) {
	err := os.Rename(Basic_Path+Temp_Path+Copy_Top_Path, Basic_Path+Temp_Path+Copy_Top_Path+"/"+Rename_File_Path)
	if err != nil {
		log.Println("Move err:", err)
		return
	}
}

func CopyFile(source string, dest string) error {
	sourcefile, err := os.Open(source)
	defer func() {
		if sourcefile != nil {
			sourcefile.Close()
		}
	}()
	if err != nil {
		return err
	}

	destfile, err := os.Create(dest)
	defer func() {
		if sourcefile != nil {
			destfile.Close()
		}
	}()

	if err != nil {
		log.Println("Create error:", err)
		return err
	}

	_, err = io.Copy(destfile, sourcefile)
	if err == nil {
		sourceinfo, err := os.Stat(source)
		if err != nil {
			log.Println("Create error:", err)
			err = os.Chmod(dest, sourceinfo.Mode())
			return err
		}

	}

	return nil
}

func CopyDir(source string, dest string) error {

	// get properties of source dir
	sourceinfo, err := os.Stat(source)
	if err != nil {
		return err
	}

	// create dest dir

	err = os.MkdirAll(dest, sourceinfo.Mode())
	if err != nil {
		return err
	}

	directory, _ := os.Open(source)

	objects, err := directory.Readdir(-1)

	for _, obj := range objects {

		sourcefilepointer := source + "/" + obj.Name()

		destinationfilepointer := dest + "/" + obj.Name()

		if obj.IsDir() {
			// create sub-directories - recursively
			err = CopyDir(sourcefilepointer, destinationfilepointer)
			if err != nil {
				log.Println(err)
			}
		} else {
			// perform copy
			err = CopyFile(sourcefilepointer, destinationfilepointer)
			if err != nil {
				log.Println(err)
			}
		}

	}
	return nil
}
func Remove_File(Basic_Path string, FileName string) error {
	var err error

	log.Println("Remove\"", FileName, "\"File!")
	err = os.Remove(Basic_Path + "/" + FileName)
	if err != nil {
		log.Println("Remove err:", err)
		return err
	}
	return nil

}

func Remove_Path(Path string) error {
	var d *os.File
	var err error
	var names []string
	var name string

	d, err = os.Open(Path)
	if err != nil {
		log.Println("Open error:", err)
		return err
	}
	defer d.Close()
	names, err = d.Readdirnames(-1)
	if err != nil {
		log.Println("Readdirnames error:", err)
		return err
	}
	for _, name = range names {
		log.Println("name:", name)

		err = os.RemoveAll(filepath.Join(Path, name))
		if err != nil {
			log.Println("os.RemoveAll error:", err)
			return err
		}
	}
	return nil
}

func Check_Existence_File(FilePath string, FileName string) bool {
	var err error

	if _, err = os.Stat(FilePath + "/" + FileName); os.IsNotExist(err) {
		log.Println("File not exist! -> ", FileName)
		return true
	} else {
		log.Println("prev File exist! -> ", FileName)
		return false
	}
}

func Check_Existence_Path(Path string) bool {
	var err error
	log.Println("Path:", Path)

	if _, err = os.Stat(Path); os.IsNotExist(err) {
		// path/to/whatever does not exist
		log.Println("File Path not exist!")
		return true

	} else {
		log.Println("File Path exist!")
		return false
	}
}

func Make_Lic_File(UserID string, UserKey string, DeviceIDTotalCnt string, DeviceIDCurCnt string, EnddateYear string, EnddateMon string, EnddateDay string, DeviceID []string, Basic_Path string, LicFileName string) error {

	var Licfile_Format []string
	var err error
	var Whole_License_File string
	var EncText string
	var fd *os.File

	Licfile_Format = []string{"[UserKey]",
		"UserID = " + UserID,
		"UserKey = " + UserKey,
		"DeviceID_Total = " + DeviceIDTotalCnt,
		"DeviceID_Current = " + DeviceIDCurCnt,
		"EndDateYear = " + EnddateYear,
		"EndDateMonth = " + EnddateMon,
		"EndDateday = " + EnddateDay,
		"",
		"[DeviceID]",
	}

	//file, err := os.OpenFile(Basic_Path+LicFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	fd, err = os.Create(Basic_Path + "/" + LicFileName)
	defer func() {
		if fd != nil {
			fd.Close()
		}
	}()
	if err != nil {
		log.Println("Create error:", err)
		return err
	}

	//datawriter := bufio.NewWriter(file)

	for _, LicFormLine := range Licfile_Format {
		Whole_License_File += LicFormLine + "\n"
	}

	for _, LicDeviceID := range DeviceID {
		Whole_License_File += "DeviceID = " + LicDeviceID + "\n"
	}

	//log.Println("Whole_License_File:", Whole_License_File)
	err = EncryptEncodingStr(Whole_License_File, &EncText)
	if err != nil {
		log.Println("EncryptEncoding err:", err)
		return err
	}

	_, err = fd.Write([]byte("COD$_"))
	if err != nil {
		log.Println("Write error:", err)
		return err
	}

	_, err = fd.Write([]byte(EncText))
	if err != nil {
		log.Println("Write error:", err)
		return err
	}
	//_, _ = datawriter.WriteString(Whole_License_File)

	//datawriter.Flush()
	//file.Close()
	return nil

}

func EncryptEncodingStr(PlainText string, RetText *string) error {
	var err error
	encrypt := make([]byte, len(PlainText))
	err = aes_cfb.EncAES_CFB8_256(encrypt, []byte(PlainText), aes_key, iv)
	if err != nil {
		return err
	}

	new_encoder := base32.NewEncoding(string(base32_alphabet))
	*RetText = new_encoder.EncodeToString(encrypt)
	*RetText = strings.Replace(*RetText, "=", "", -1)

	return nil
	//log.Printf("Enc %s -> %x \nEncode %s\n", PlainText, encrypt, *RetText)
}

// tarrer walks paths to create tar file tarName
func tartar(tarName string, paths []string) (err error) {
	tarFile, err := os.Create(tarName)
	if err != nil {
		log.Println("Create File err:", err)
		return err
	}
	defer func() {
		err = tarFile.Close()
	}()

	// enable compression if file ends in .gz
	tw := tar.NewWriter(tarFile)
	if strings.HasSuffix(tarName, ".gz") || strings.HasSuffix(tarName, ".gzip") {
		gz := gzip.NewWriter(tarFile)
		defer gz.Close()
		tw = tar.NewWriter(gz)
	}
	defer tw.Close()

	// walk each specified path and add encountered file to tar
	for _, path := range paths {
		// validate path
		path = filepath.Clean(path)

		if path == "." {
			log.Println("continue")
			continue
		}

		walker := func(file string, finfo os.FileInfo, err error) error {
			if err != nil {
				log.Println("err:", err)
				return err
			}

			// fill in header info using func FileInfoHeader
			hdr, err := tar.FileInfoHeader(finfo, finfo.Name())
			if err != nil {
				log.Println("hdr:", hdr)
				//return err
			}

			relFilePath := file
			if filepath.IsAbs(path) {
				relFilePath, err = filepath.Rel(path, file)
				if err != nil {
					log.Println("rel error:", err)
					return err
				}
			}
			// ensure header has relative file path
			//relFilePath = path
			//relFilePath = finfo.Name()
			hdr.Name = relFilePath

			//log.Println("hdr name:", hdr.Name)

			if err := tw.WriteHeader(hdr); err != nil {
				log.Println("WriteHeader", err)
				return err
			}

			// add file to tar
			srcFile, err := os.Open(file)
			if err != nil {
				log.Println("Open error:", err)
				return err
			}

			// if path is a dir, dont continue
			if finfo.Mode().IsDir() {
				//log.Println("fifo err:", err)
				return nil
			}

			defer srcFile.Close()
			_, err = io.Copy(tw, srcFile)
			if err != nil {
				log.Println("io.Copy error:", err)
				return err
			}
			return nil
		}

		// build tar
		if err := filepath.Walk(path, walker); err != nil {
			fmt.Printf("failed to add %s to tar: %s\n", path, err)
		}
	}
	return nil
}

func untartar(tarName, xpath string) (err error) {
	tarFile, err := os.Open(tarName)
	if err != nil {
		return err
	}
	defer func() {
		err = tarFile.Close()
	}()

	absPath, err := filepath.Abs(xpath)
	if err != nil {
		return err
	}

	tr := tar.NewReader(tarFile)
	if strings.HasSuffix(tarName, ".gz") || strings.HasSuffix(tarName, ".gzip") {
		gz, err := gzip.NewReader(tarFile)
		if err != nil {
			return err
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	}

	// untar each segment
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// determine proper file path info
		finfo := hdr.FileInfo()
		fileName := hdr.Name
		if filepath.IsAbs(fileName) {
			fmt.Printf("removing / prefix from %s\n", fileName)
			fileName, err = filepath.Rel("/", fileName)
			if err != nil {
				return err
			}
		}
		absFileName := filepath.Join(absPath, fileName)

		if finfo.Mode().IsDir() {
			if err := os.MkdirAll(absFileName, 0755); err != nil {
				return err
			}
			continue
		}

		// create new file with original file mode
		file, err := os.OpenFile(absFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, finfo.Mode().Perm())
		if err != nil {
			return err
		}
		fmt.Printf("x %s\n", absFileName)
		n, cpErr := io.Copy(file, tr)
		if closeErr := file.Close(); closeErr != nil { // close file immediately
			return err
		}
		if cpErr != nil {
			return cpErr
		}
		if n != finfo.Size() {
			return fmt.Errorf("unexpected bytes written: wrote %d, want %d", n, finfo.Size())
		}
	}
	return nil
}
