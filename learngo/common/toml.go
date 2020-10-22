package common

import (
	"fmt"
	"os"
	"strings"

	"learngo/structcomp"

	"github.com/BurntSushi/toml"
)

func Getmovieinfo() []structcomp.Movieinfo {
	var Res *structcomp.Response

	_, err := toml.DecodeFile("./common/movie.toml", &Res)
	if err != nil {
		fmt.Println("[ERR] toml DecodeFile", err)
	}

	return Res.Movie

}
func Writemovieinfo(moviearr []structcomp.Movieinfo) error {

	var movielistlogfile string
	var movieinfotext string
	var CRLF = "\n"

	fd, err := os.Create("./common/movie.toml")
	if err != nil {
		fmt.Println("[ERR] os.Create in Writemovieinfo : ", err)
		return err
	}
	defer fd.Close()

	for _, movie := range moviearr {
		movielistlogfile = "[[movie]]" + CRLF
		movielistlogfile += "Href = \"<HREF>\"" + CRLF
		movielistlogfile += "Name = \"<NAME>\"" + CRLF
		movielistlogfile += "Movie_id = \"<MOVIEID>\"" + CRLF
		movielistlogfile += CRLF

		movielistlogfile = strings.Replace(movielistlogfile, "<HREF>", movie.Href, -1)
		movielistlogfile = strings.Replace(movielistlogfile, "<NAME>", movie.Name, -1)
		movielistlogfile = strings.Replace(movielistlogfile, "<MOVIEID>", movie.Movie_id, -1)

		movieinfotext += movielistlogfile
	}
	fmt.Println("[LOG] movieinfotext : ", movieinfotext)

	_, err = fd.Write([]byte(movieinfotext))
	if err != nil {
		fmt.Println("[ERR] fd.Write : in Writemovieinfo func : ", err)
		return err
	}
	return nil
}

func Getjobstatementinfo() []structcomp.Jobstatementinfo {
	var Res *structcomp.Response

	_, err := toml.DecodeFile("./common/jobstatement.toml", &Res)
	if err != nil {
		fmt.Println("[ERR] toml DecodeFile", err)
	}

	fmt.Println("[LOG] Res :", Res)
	return Res.Jobstatement

}
func Writejobstatementinfo(moviearr []structcomp.Movieinfo) error {

	var jobstatementlistlogfile string
	var jobstatementinfotext string
	var CRLF = "\n"

	fd, err := os.Create("./common/jobstatement.toml")
	if err != nil {
		fmt.Println("[ERR] os.Create in Writejobstatementinfo : ", err)
		return err
	}
	defer fd.Close()

	for _, movie := range moviearr {
		jobstatementlistlogfile = "[[jobstatement]]" + CRLF
		jobstatementlistlogfile += "Href = \"<HREF>\"" + CRLF
		jobstatementlistlogfile += "Movie_id = \"<MOVIEID>\"" + CRLF
		jobstatementlistlogfile += CRLF

		jobstatementlistlogfile = strings.Replace(jobstatementlistlogfile, "<HREF>", movie.Href, -1)
		jobstatementlistlogfile = strings.Replace(jobstatementlistlogfile, "<MOVIEID>", movie.Movie_id, -1)

		jobstatementinfotext += jobstatementlistlogfile
	}
	fmt.Println("[LOG] jobstatementinfotext : ", jobstatementinfotext)

	_, err = fd.Write([]byte(jobstatementinfotext))
	if err != nil {
		fmt.Println("[ERR] fd.Write : in Writejobstatementinfo func : ", err)
		return err
	}
	return nil
}
func Cleanmovieinfo() error {
	configFile, err := os.OpenFile("./common/movie.toml", os.O_RDWR, 0666)
	if err != nil {
		fmt.Println("[ERR] os.OpenFile : in Cleanmovieinfo func : ", err)
		return err
	}
	defer configFile.Close()
	configFile.Truncate(0)
	configFile.Seek(0, 0)
	return nil
}
