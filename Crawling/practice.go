package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"./google"
	"./naver"
)

func main() {
	cpuNumber := 1

	runtime.GOMAXPROCS(cpuNumber)
	var wait sync.WaitGroup
	wait.Add(cpuNumber)

	startTime := time.Now()

	go func() {
		for i := 0; i < 15; i++ {
			naver.Crawler()
		}
		defer wait.Done()
	}()

	go func() {
		for i := 0; i < 15; i++ {
			google.Crawler()
		}
		defer wait.Done()
	}()

	wait.Wait()
	elapseTime := time.Since(startTime)
	fmt.Printf("실행시간: %s\n", elapseTime)

}
