package checkos

import (
	"fmt"
	"runtime"
)

//ShowOS is for checking OSversion.
func ShowOS() {
	fmt.Println(runtime.GOOS)
}
