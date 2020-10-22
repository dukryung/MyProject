package main

import (
	//"fmt"
	"log"
)

type practice struct {
	i int
}

func main() {
	Practice(1)
	Practice(2)
}

func Practice(i int) {
	var test practice
	var Prac []practice
	test.i = i
	Prac = append(Prac, test)
	log.Println("Prac:", Prac)

}

/*package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

func main() {
	cmd := exec.Command("bash", "test.sh")
	cmd.Stdin = strings.NewReader("")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
		fmt.Println("cmd.Run error:!", err)
	}
	fmt.Printf(out.String())
	fmt.Println("hi")
}
*/
/*package main

import (
	"os/exec"
)

func main() {
	cmdStr := "sh aaa.sh"
	cmd := exec.Command(cmdStr, "fg")
	_ = cmd.Run()
}
*/
/*
package main

import (
	"os"
)

func main() {
	err := os.Rename("./example1.exe", "./test/example1.exe")
	if err != nil {
		panic(err)
	}
}
*/
/*package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
)

func main() {

	// Print Go Version

	//cmd := exec.Command("/root/go/src/nsis/nsis-3.04/Bin/makensis", "/root/go/src/nsis/nsis-3.04/Examples/example1.nsi")
	//	cmd := exec.Command("makensis", "/root/go/src/nsis/nsis-3.04/Examples/example1.nsi")
	//cmd := exec.Command("makensis", "./example1.nsi")
	cmd := exec.Command("mv", "./example1.exe ./test")

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Println(fmt.Sprint(err) + ": " + stderr.String())
		return
	}
	log.Println("Result: " + out.String())
}
*/
/*package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func CopyFile(source string, dest string) (err error) {
	sourcefile, err := os.Open(source)
	if err != nil {
		return err
	}

	defer sourcefile.Close()

	destfile, err := os.Create(dest)
	if err != nil {
		return err
	}

	defer destfile.Close()

	_, err = io.Copy(destfile, sourcefile)
	if err == nil {
		sourceinfo, err := os.Stat(source)
		if err != nil {
			err = os.Chmod(dest, sourceinfo.Mode())
		}

	}

	return
}

func CopyDir(source string, dest string) (err error) {

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
				fmt.Println(err)
			}
		} else {
			// perform copy
			err = CopyFile(sourcefilepointer, destinationfilepointer)
			if err != nil {
				fmt.Println(err)
			}
		}

	}
	return
}

func main() {
	flag.Parse() // get the source and destination directory

	source_dir := flag.Arg(0) // get the source directory from 1st argument

	dest_dir := flag.Arg(1) // get the destination directory from the 2nd argument

	fmt.Println("Source :" + source_dir)

	// check if the source dir exist
	src, err := os.Stat(source_dir)
	if err != nil {
		panic(err)
	}

	if !src.IsDir() {
		fmt.Println("Source is not a directory")
		os.Exit(1)
	}

	// create the destination directory
	fmt.Println("Destination :" + dest_dir)

	_, err = os.Open(dest_dir)
	if !os.IsNotExist(err) {
		fmt.Println("Destination directory already exists. Abort!")
		os.Exit(1)
	}

	err = CopyDir(source_dir, dest_dir)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Directory copied")
	}

}
*/
/*package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {

	var path []string
	//path = append(path, "./License_Dir/License_test.txt", "./Binary_Dir/Binary_test.txt")
	//path = append(path, "./License_Dir/License_test.txt", "./Binary_Dir/Binary_test.txt", "Create_Dir/Create_test.txt")
	path = append(path, "./License_Dir", "./lbsvc")
	//path = append(path, ".")

	if err := tartar("./Binary_Dir/FileName.tar", path); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
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
		var Cnt int
		log.Println("Cnt:", Cnt)
		walker := func(file string, finfo os.FileInfo, err error) error {
			if err != nil {
				log.Println("err:", err)
				return err
			}
			log.Println("path:", path)
			log.Println("file:", file)
			log.Println("finfo:", finfo)
			log.Println("finfo.Name:", finfo.Name())
			// fill in header info using func FileInfoHeader

			// if path is a dir, dont continue
			if finfo.Mode().IsDir() {
				log.Println("fifo err:", err)
				return nil
			}

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

			log.Println("relFilePath:", relFilePath)
			hdr.Name = relFilePath

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
			defer srcFile.Close()
			_, err = io.Copy(tw, srcFile)
			if err != nil {
				return err
			}
			return nil
		}

		// build tar
		if err := filepath.Walk(path, walker); err != nil {
			fmt.Printf("failed to add %s to tar: %s\n", path, err)
		}
		Cnt++
	}
	return nil
}

// untarrer extract contant of file tarName into location xpath
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
*/
/*
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		fmt.Println(path)
		return nil
	})
}
*/
