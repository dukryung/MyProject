package cmdrun

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
)

//Execcmd is to excute command.
func Execcmd(execcmd string, options string, execpath string) error {

	cmd := exec.Command(execcmd, options)
	cmd.Dir = execpath

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}
	log.Println("cmdStdout:", cmd.Stdout)

	return nil

}
