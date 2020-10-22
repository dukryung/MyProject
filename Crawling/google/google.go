package google

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/antchfx/htmlquery"
)

func getHtml() (string, error) {
	url := "http://www.google.com"
	res, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return string(body), nil
}

func Crawler() (string, error) {
	html, err := getHtml()

	if err != nil {
		return html, err
	}

	doc, err := htmlquery.Parse(strings.NewReader(html))

	list := htmlquery.Find(doc, "//a")
	for _, val := range list {
		fmt.Println("-------google-----------", htmlquery.InnerText(val))
		time.Sleep(time.Second * 1)
	}

	return html, err
}
