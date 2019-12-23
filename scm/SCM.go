package scm

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"

	"io/ioutil"
	"time"

	"golang.org/x/sys/windows/svc"
	//"golang.org/x/sys/windows/svc/debug"
)

// 서비스 Type
type scm struct {
}

// svc.Handler 인터페이스 구현
func (srv *scm) Execute(args []string, req <-chan svc.ChangeRequest, stat chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	stat <- svc.Status{State: svc.StartPending}

	// 실제 서비스 내용
	stopChan := make(chan bool, 1)
	go runBody(stopChan)

	stat <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

LOOP:
	for {
		// 서비스 변경 요청에 대해 핸들링
		switch r := <-req; r.Cmd {
		case svc.Stop, svc.Shutdown:
			stopChan <- true
			break LOOP

		case svc.Interrogate:
			stat <- r.CurrentStatus
			time.Sleep(100 * time.Millisecond)
			stat <- r.CurrentStatus
			//case svc.Pause:
			//case svc.Continue:
		}
	}

	stat <- svc.Status{State: svc.StopPending}
	return
}

/*** 서비스에서 실제 하는 일 ***/
func runBody(stopChan chan bool) {
	for {
		select {
		case <-stopChan:
			return
		default:
			// 10초 마다 현재시간 새로 쓰기
			time.Sleep(10 * time.Second)
			ioutil.WriteFile("C:/temp/log.txt", []byte(time.Now().String()), 0)
		}
	}
}

//SVCRun *.exe in Windows Service.
func SVCRun() {
	err := svc.Run("SCM", &scm{})
	//err := debug.Run("DummyService", &dummyService{}) //콘솔출력 디버깅시
	if err != nil {
		fmt.Println("here!!")
		panic(err)
	}
}

func main() {
	cmd := exec.Command("sc", "create", "SCM", "binPath= O:/go_project/src/golang_lib_Collection/SCM.exe")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Println(fmt.Sprint(err) + ": " + stderr.String())
		return
	}
	log.Println("cmdStdout:", cmd.Stdout)
	SVCRun()
}
