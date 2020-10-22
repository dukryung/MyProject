package disk

import (
	//"io"
  //"io/ioutil"
	//"path/filepath"
	//"strings"
	//"fmt"
	"log"
	"os"
  "bufio"
)


func IsExistFilePath(FilePath string) bool {
	var err error
  
  if len(FilePath) == 0 {
    return false
  }

	if _, err = os.Stat(FilePath); os.IsNotExist(err) {
		log.Println("file not exist (", FilePath, ")")
		return false
	} else {
		log.Println("file exist (", FilePath, ")")
		return true
	}
}


func IsExistDirectoryPath(DirectoryPath string) bool {
	var err error
  
  if len(DirectoryPath) == 0 {
    return false
  }

	if _, err = os.Stat(DirectoryPath); os.IsNotExist(err) {
		log.Println("file not exist (", DirectoryPath, ")")
		return false
	} else {
		log.Println("file exist (", DirectoryPath, ")")
		return true
	}
}


func RemoveFilePath(FilePath string) bool {
	var err error

  if len(FilePath) == 0 {
    return false  
  }

	err = os.Remove(FilePath)
	if err != nil {
		log.Println("failed to remove file (path:", FilePath, ") err message:", err)
    return false  
	}

	return true
}


func RemoveDirectoryPath(DirectoryPath string) bool {
	var err error

  if len(DirectoryPath) == 0 {
    return false  
  }

	err = os.RemoveAll(DirectoryPath)
	if err != nil {
		log.Println("failed to remove file (path:", DirectoryPath, ") err message:", err)
    return false  
	}

	return true
}


func CreateDirectoryPath(DirectoryPath string) bool {
	var err error

  if len(DirectoryPath) == 0 {
    return false  
  }

  err = os.Mkdir(DirectoryPath, 0700)
	if err != nil {
		log.Println("failed to create directory (path:", DirectoryPath , ") err message:", err)
    return false  
	}

	return true
}


func CreateFilePath(FilePath string) bool {
	var fd *os.File
	var err error
  
	fd, err = os.Create(FilePath)
	defer func() { if fd != nil { fd.Close() } }()

	if err != nil {
		log.Println("failed to create file (path:", FilePath, ") err message:", err)
		return false
	}

  return true
}


func RenameFilePath(OriginalFilePath string, RenameFilePath string) bool {
	var err error

  if len(OriginalFilePath) == 0 || len(RenameFilePath) == 0 {
    return false  
  }

	err = os.Rename(OriginalFilePath, RenameFilePath)
	if err != nil {
		log.Println("err message:", err)
    return false  
	}

  return true
}


func RenameDirectoryPath(OriginalDirectoryPath string, RenameDirectoryPath string) bool {
	var err error

  if len(OriginalDirectoryPath) == 0 || len(RenameDirectoryPath) == 0 {
    return false  
  }

	err = os.Rename(OriginalDirectoryPath, RenameDirectoryPath)
	if err != nil {
		log.Println("err message:", err)
    return false  
	}

  return true
}


func CreateFileWriteString(FilePath string, Content string) bool {
	var fd *os.File
	var err error
  
	fd, err = os.Create(FilePath)
	defer func() { if fd != nil { fd.Close() } }()

	if err != nil {
		log.Println("file create error (err msg:", err, ")")
		return false
	}
  
  w := bufio.NewWriter(fd)
  if w == nil {
		log.Println("file create error (err msg: buffe resource)")
		return false
  }

  _, err = w.WriteString(Content)
  if err != nil {
    log.Println("failed to file write (err msg:", err, ")")
    return false
  }

  w.Flush()

  return true
}


func CreateFileWriteStringArrary(FilePath string, Content[] string) bool {
  var LineContent string
	var fd *os.File
	var err error
  
	fd, err = os.Create(FilePath)
	defer func() { if fd != nil { fd.Close() } }()

	if err != nil {
		log.Println("file create error (err msg:", err, ")")
		return false
	}
  
  w := bufio.NewWriter(fd)
  if w == nil {
		log.Println("file create error (err msg: buffe resource)")
		return false
  }

	for _, LineContent = range Content {

    //_, err = w.WriteString(LineContent + "\n")
    _, err = w.WriteString(LineContent)
    if err != nil {
      log.Println("failed to file write (err msg:", err, ")")
      return false
    }
	}
  w.Flush()

  return true
}


func CreateFileWriteByte(FilePath string, Content[] byte) bool {
	var fd *os.File
	var err error
  
	fd, err = os.Create(FilePath)
	defer func() { if fd != nil { fd.Close() } }()

	if err != nil {
		log.Println("file create error (err msg:", err, ")")
		return false
	}
  
  w := bufio.NewWriter(fd)
  if w == nil {
		log.Println("file create error (err msg: buffe resource)")
		return false
  }

  _, err = w.Write(Content)
  if err != nil {
    log.Println("failed to file write (err msg:", err, ")")
    return false
  }

  w.Flush()

  return true
}
