package make_package

import (
	"./lib/aes_cfb"
	"bytes"
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
	Get = "Get"
	Create = "Create"
	Delete = "Delete"
	Modify = "Modify"
)
const EXE = ".exe"
const TAR = ".tar.gz"

const (
	Win_Origin_Path  = "/Package_tools/Windows/Origin"
	Lnx_Origin_Path  = "/Package_tools/Linux/Origin"
	Win_Temp_Path    = "/win_Temp"
	Lnx_Temp_Path    = "/lnx_Temp"
	Lnx_LicFileName  = "license_linux.lic"
	Win_LicFileName  = "license_windows.lic"
	UserKeyFileName  = "userkey.key"
	nsiFileName      = "nsisscript-service_node.nsi"
	SscriptName      = "shellscript-service_node.sh"
	MakeNSISFileName = "/Package_tools/Windows/NSIS/bin/makensis"
)

var (
	base32_alphabet = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79}
)



func Make_Pkg_Windows(ActionFlag string,PkgMutex *sync.Mutex, DecryptKey string, DecryptIV string, UserID string, UserKey string, NodeIDTotalCnt string, NodeIDCurCnt string, EnddateYear string, EnddateMon string, EnddateDay string, NodeID []string, Basic_Path string, Home_Path string, IstFileName string, OEMName string) (string, string, error) {
	var IsNotExistFile bool
	var IsNotExistPath bool
	var err error
	var Key_Location_Path string
	Key_Location_Path = "/" + OEMName + "/cfg"

	log.Println("here is in Make_Win_Pkg func")

	PkgMutex.Lock()
	defer PkgMutex.Unlock()

	if ActionFlag == "Get" || ActionFlag == "Create" || ActionFlag == "Delete" || ActionFlag == "Modify" {
	} else {
		log.Println("Invalid Action Flag")
		return "", "", nil

	}
	switch ActionFlag {
  
  case Get:
  log.Println("Get!!")
  
  if _, err = os.Stat(Basic_Path); os.IsNotExist(err) {
		log.Println("File Path not exist!->", Basic_Path)
		return "" ,"",err
	}else {
		log.Println("File Path exist!->", Basic_Path)
  }

	if _, err = os.Stat(Basic_Path + "/" + IstFileName+EXE); os.IsNotExist(err) {
		log.Println("File not exist!->", Basic_Path + "/" + IstFileName+EXE)
		return "" ,"",err
	} else {
	    return Basic_Path + "/" + IstFileName + EXE, IstFileName + EXE, nil
  }

	case Create:
		log.Println("Create!!")
		IsNotExistFile = Check_Existence_File(Basic_Path, IstFileName+EXE)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, IstFileName+EXE)
			if err != nil {
				return "", "", err
			}
		}
		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

		err = Copy_Origin_File(Home_Path, Win_Origin_Path, Basic_Path, Win_Temp_Path)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Make_win_UserKey_File(DecryptKey, DecryptIV, UserKey, Basic_Path, Win_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make UserKey File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Move_UserKey_File(Basic_Path, Win_Temp_Path, Key_Location_Path, UserKeyFileName)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", "", err

		}
		err = Make_Ist_File(Home_Path, Basic_Path, Win_Temp_Path, nsiFileName, MakeNSISFileName)
		if err != nil {
			log.Println("Make win Install File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Move_Ist_File(Basic_Path, Win_Temp_Path, IstFileName+EXE)
		if err != nil {
			log.Println("Move win Install File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

	case Delete:
		log.Println("Delete!!")
		IsNotExistFile = Check_Existence_File(Basic_Path, IstFileName+EXE)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, IstFileName+EXE)
			if err != nil {
				return "", "", err
			}
		}
		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

		err = Copy_Origin_File(Home_Path, Win_Origin_Path, Basic_Path, Win_Temp_Path)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Make_win_UserKey_File(DecryptKey, DecryptIV, UserKey, Basic_Path, Win_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make UserKey File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Move_UserKey_File(Basic_Path, Win_Temp_Path, Key_Location_Path, UserKeyFileName)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Make_Ist_File(Home_Path, Basic_Path, Win_Temp_Path, nsiFileName, MakeNSISFileName)
		if err != nil {
			log.Println("Make win Install File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Move_Ist_File(Basic_Path, Win_Temp_Path, IstFileName+EXE)
		if err != nil {
			log.Println("Move win Install File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}
	case Modify:
		log.Println("Modify!!")
		IsNotExistFile = Check_Existence_File(Basic_Path, IstFileName+EXE)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, IstFileName+EXE)
			if err != nil {
				return "", "", err
			}
		}
		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

		err = Copy_Origin_File(Home_Path, Win_Origin_Path, Basic_Path, Win_Temp_Path)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Make_win_UserKey_File(DecryptKey, DecryptIV, UserKey, Basic_Path, Win_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make UserKey File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Move_UserKey_File(Basic_Path, Win_Temp_Path, Key_Location_Path, UserKeyFileName)
		if err != nil {
			log.Println("Copy Origin File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Make_Ist_File(Home_Path, Basic_Path, Win_Temp_Path, nsiFileName, MakeNSISFileName)
		if err != nil {
			log.Println("Make win Install File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		err = Move_Ist_File(Basic_Path, Win_Temp_Path, IstFileName+EXE)
		if err != nil {
			log.Println("Move win Install File Fail! (Reason-> ", err, ")")
			return "", "", err

		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Win_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Win_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

	}

	return Basic_Path + "/" + IstFileName + EXE, IstFileName + EXE, nil
}

func Make_Pkg_Linux(ActionFlag string, PkgMutex *sync.Mutex, DecryptKey string, DecryptIV string, UserID string, UserKey string, NodeIDTotalCnt string, NodeIDCurCnt string, EnddateYear string, EnddateMon string, EnddateDay string, NodeID []string, Basic_Path string, Home_Path string, PkgFileName string, OEMName string) (string, string, error) {
	var IsNotExistFile bool
	var IsNotExistPath bool
	var err error

	log.Println("here is in Make_Lic_And_Pkg func")

	if ActionFlag == "Get" ||ActionFlag == "Create" || ActionFlag == "Delete" || ActionFlag == "Modify" {
	} else {
		log.Println("Invalid Action Flag")
		return "", "", nil

	}

	PkgMutex.Lock()
	defer PkgMutex.Unlock()
	switch ActionFlag {
  case Get:
  log.Println("Get!!")
  
  if _, err = os.Stat(Basic_Path); os.IsNotExist(err) {
		log.Println("File Path not exist!->", Basic_Path)
		return "" ,"",err
	} else {
		log.Println("File Path exist!->", Basic_Path)
  }

	if _, err = os.Stat(Basic_Path + "/" + PkgFileName+TAR); os.IsNotExist(err) {
		log.Println("File not exist!->", Basic_Path + "/" + PkgFileName+TAR)
		return "" ,"",err
	} else {
	    return Basic_Path + "/" + PkgFileName+TAR, PkgFileName+TAR, nil
  }

	case Create:

		log.Println("Create!!")
		IsNotExistFile = Check_Existence_File(Basic_Path, PkgFileName+TAR)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, PkgFileName+TAR)
			if err != nil {
				return "", "", err
			}
		}
		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

		err = Copy_Origin_File(Home_Path, Lnx_Origin_Path, Basic_Path, Lnx_Temp_Path)
		if err != nil {
			log.Println("Copy File Fail! (Reason-> ", err, ")")
			return "", "", err
		}
		err = Make_lnx_UserKey_File(DecryptKey, DecryptIV, UserKey, Basic_Path, Lnx_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make lnx File Fail! (Reason-> ", err, ")")
			return "", "", err
		}
		err = Excute_Shell(Basic_Path, Lnx_Temp_Path, SscriptName, PkgFileName, OEMName)
		if err != nil {
			log.Println("Excute Shell Fail! (Reason-> ", err, ")")
			return "", "", err
		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

	case Delete:

		log.Println("Delete!!")

		IsNotExistFile = Check_Existence_File(Basic_Path, PkgFileName+TAR)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, PkgFileName+TAR)
			if err != nil {
				return "", "", err
			}
		}
		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

		err = Copy_Origin_File(Home_Path, Lnx_Origin_Path, Basic_Path, Lnx_Temp_Path)
		if err != nil {
			log.Println("Copy File Fail! (Reason-> ", err, ")")
			return "", "", err
		}
		err = Make_lnx_UserKey_File(DecryptKey, DecryptIV, UserKey, Basic_Path, Lnx_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make lnx File Fail! (Reason-> ", err, ")")
			return "", "", err
		}
		err = Excute_Shell(Basic_Path, Lnx_Temp_Path, SscriptName, PkgFileName, OEMName)
		if err != nil {
			log.Println("Excute Shell Fail! (Reason-> ", err, ")")
			return "", "", err
		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

	case Modify:
		log.Println("Modify!!")

		IsNotExistFile = Check_Existence_File(Basic_Path, PkgFileName+TAR)
		if IsNotExistFile == false {
			err = Remove_File(Basic_Path, PkgFileName+TAR)
			if err != nil {
				return "", "", err
			}
		}
		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

		err = Copy_Origin_File(Home_Path, Lnx_Origin_Path, Basic_Path, Lnx_Temp_Path)
		if err != nil {
			log.Println("Copy File Fail! (Reason-> ", err, ")")
			return "", "", err
		}
		err = Make_lnx_UserKey_File(DecryptKey, DecryptIV, UserKey, Basic_Path, Lnx_Temp_Path, UserKeyFileName)
		if err != nil {
			log.Println("Make lnx File Fail! (Reason-> ", err, ")")
			return "", "", err
		}
		err = Excute_Shell(Basic_Path, Lnx_Temp_Path, SscriptName, PkgFileName, OEMName)
		if err != nil {
			log.Println("Excute Shell Fail! (Reason-> ", err, ")")
			return "", "", err
		}

		IsNotExistPath = Check_Existence_Path(Basic_Path + Lnx_Temp_Path)
		if IsNotExistPath == false {
			err = os.RemoveAll(Basic_Path + Lnx_Temp_Path)
			if err != nil {
				return "", "", err
			}
		}

	}
	return Basic_Path + "/" + PkgFileName + TAR, PkgFileName + TAR, nil
}

func Make_Ist_File(Home_Path string, Basic_Path string, Temp_Path string, nsiFileName string, MakeNSISFileName string) error {

	IsNotExistFile := Check_Existence_File(Basic_Path, nsiFileName)

	log.Println("IsNotExistFile:", IsNotExistFile)
	cmd := exec.Command(Home_Path+MakeNSISFileName, Basic_Path+Temp_Path+"/"+nsiFileName)
	cmd.Env = []string{"GOROOT=" + Home_Path}

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}
	return nil

}

func Excute_Shell(Basic_Path string, Temp_Path string, SscriptName string, PkgFileName string, OEMName string) error {

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
	return nil

}

func Make_win_UserKey_File(DecryptKey string, DecryptIV string, UserKey string, Basic_Path string, Temp_Path string, UserKeyFileName string) error {
	var Userkeyfile_Format []string
	var err error
	var whole_Userkey_File string
	var EncText string
	var fd *os.File

	Userkeyfile_Format = []string{"[UserKey]",
		"UserKey = \"" + UserKey + "\"",
	}

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

	for _, UserKeyFormLine := range Userkeyfile_Format {
		whole_Userkey_File += UserKeyFormLine + "\r\n"
	}

	EncryptEncodingStr(DecryptKey, DecryptIV, whole_Userkey_File, &EncText)

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

	return nil
}

func Make_lnx_UserKey_File(DecryptKey string, DecryptIV string, UserKey string, Basic_Path string, Temp_Path string, UserKeyFileName string) error {
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
		"UserKey = \"" + UserKey + "\"",
	}

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

	for _, UserKeyFormLine := range Userkeyfile_Format {
		whole_Userkey_File += UserKeyFormLine + "\n"
	}

	EncryptEncodingStr(DecryptKey, DecryptIV, whole_Userkey_File, &EncText)

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

	return nil
}

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

	dstpath = Basic_Path + Temp_Path
	srcpath = Home_Path + Origin_Path

	src, err = os.Stat(srcpath)
	if err != nil {
		log.Println("Stat error:", err)
		return err
	}

	if !src.IsDir() {
		log.Println("Source is not a directory")
		return err
	}

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

	sourceinfo, err := os.Stat(source)
	if err != nil {
		return err
	}

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
			err = CopyDir(sourcefilepointer, destinationfilepointer)
			if err != nil {
				log.Println(err)
			}
		} else {
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

	if _, err = os.Stat(Path); os.IsNotExist(err) {
		log.Println("File Path not exist!->", Path)
		return true

	} else {
		log.Println("File Path exist! ->", Path)
		return false
	}
}

func EncryptEncodingStr(DecryptKey string, DecryptIV string, PlainText string, RetText *string) error {
	var err error
	encrypt := make([]byte, len(PlainText))
	err = aes_cfb.EncAES_CFB8_256(encrypt, []byte(PlainText), []byte(DecryptKey), []byte(DecryptIV))
	if err != nil {
		return err
	}

	new_encoder := base32.NewEncoding(string(base32_alphabet))
	new_encoder = new_encoder.WithPadding(base32.NoPadding)
	*RetText = new_encoder.EncodeToString(encrypt)

	return nil
}
