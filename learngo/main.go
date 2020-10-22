package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"learngo/common"
	"learngo/structcomp"
	"log"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"
)

const (
	SUCCESS          = "200"
	NOTFOUND         = "404"
	TEAPOT           = "418"
	CREATED          = "201"
	BADREQUEST       = "400"
	CONFLICT         = "409"
	ACCEPTED         = "202"
	NOTACCEPTABLE    = "406"
	METHODNOTALLOWED = "405"
)

type Resource interface {
	Uri() string
	Get(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response
	Post(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response
	Put(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response
	Delete(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response
}

type (
	GetNotSupported    struct{}
	PostNotSupported   struct{}
	PutNotSupported    struct{}
	DeleteNotSupported struct{}
)

func (GetNotSupported) Get(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response {
	var res = new(structcomp.Response)
	res.Code = METHODNOTALLOWED
	res.Message = "MethodNotAllowed"
	res.Detail = "invalid Method(Get)"
	res.Path = r.RequestURI
	return res

}
func (PostNotSupported) Post(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response {
	var res = new(structcomp.Response)
	res.Code = METHODNOTALLOWED
	res.Message = "MethodNotAllowed"
	res.Detail = "invalid Method(Post)"
	res.Path = r.RequestURI

	return res
}
func (PutNotSupported) Put(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response {
	var res = new(structcomp.Response)
	res.Code = METHODNOTALLOWED
	res.Message = "MethodNotAllowed"
	res.Detail = "invalid Method(Put)"
	res.Path = r.RequestURI

	return res
}
func (DeleteNotSupported) Delete(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response {
	var res = new(structcomp.Response)
	res.Code = METHODNOTALLOWED
	res.Message = "MethodNotAllowed"
	res.Detail = "invalid Method(Delete)"
	res.Path = r.RequestURI
	return res
}

func abort(rw http.ResponseWriter, statusCode int) {
	rw.WriteHeader(statusCode)
}

func HttpResponse(rw http.ResponseWriter, req *http.Request, res *structcomp.Response) {
	content, err := json.Marshal(res)

	if err != nil {
		abort(rw, 500)
	}
	Code, err := strconv.Atoi(res.Code)
	if err != nil {
		log.Println("[ERR] fail Code Atoi")
	}

	rw.WriteHeader(Code)
	rw.Write(content)
}

func RegisterResource(router *httprouter.Router, resource Resource) {

	router.GET(resource.Uri(), func(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		res := resource.Get(rw, r, ps)
		HttpResponse(rw, r, res)
	})

	router.POST(resource.Uri(), func(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		res := resource.Post(rw, r, ps)
		HttpResponse(rw, r, res)
	})

	router.PUT(resource.Uri(), func(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		res := resource.Put(rw, r, ps)
		HttpResponse(rw, r, res)
	})

	router.DELETE(resource.Uri(), func(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		res := resource.Delete(rw, r, ps)
		HttpResponse(rw, r, res)
	})
}

type MovieResource struct {
	//DeleteNotSupported
}

func (MovieResource) Uri() string {
	return "/movie"
}

func (MovieResource) Get(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response {
	var res = new(structcomp.Response)
	movie := common.Getmovieinfo()

	if r.Header.Get("Content-Type") != "application/json" {
		res.Code = TEAPOT
		res.Message = "I'm a teapot"
		res.Detail = "I'm a teapot"
		res.Path = r.RequestURI
		return res
	}

	if len(movie) != 0 {
		res.Code = SUCCESS
		res.Message = "Success"
		res.Detail = "Get Moive Information"
		res.Path = r.RequestURI
		res.Movie = movie
	} else {
		res.Code = NOTFOUND
		res.Message = "Not Found"
		res.Detail = "empty Movie Information"
		res.Path = r.RequestURI
		res.Movie = nil
	}

	return res
}

func (MovieResource) Post(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response {
	var res = new(structcomp.Response)
	var moviearr []structcomp.Movieinfo
	var postmovieinfo structcomp.Postmovieinfo
	rbody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("[ERR] request body ioutil.ReadAll : ", err)
		res := BadRequest(r)
		return res
	}

	err = json.Unmarshal(rbody, &postmovieinfo)
	if err != nil {
		log.Println("[ERR] json movie list Unmarshal : ", err)
		res := BadRequest(r)
		return res
	}
	log.Println("[LOG] rbody : ", string(rbody))
	//문자 일치 여부 확인
	for _, moviename := range postmovieinfo.Name {
		savedmoviearr := common.Getmovieinfo()
		for _, savedmovie := range savedmoviearr {
			if moviename == savedmovie.Name {
				res.Code = CONFLICT
				res.Movie = append(moviearr, savedmovie)
				break
			}
		}
	}

	savedmoviearr := common.Getmovieinfo()
	var savingmoviearr structcomp.Movieinfo
	//var lengthsavedmoviearr = len(savedmoviearr)
	var ressavingmoviearr []structcomp.Movieinfo

	for _, moviename := range postmovieinfo.Name {

		savingmoviearr.Name = moviename
		savingmoviearr.Movie_id = strconv.Itoa(len(savedmoviearr) + 1)
		savingmoviearr.Href = "www.example.com" + r.RequestURI + "/" + savingmoviearr.Movie_id
		savedmoviearr = append(savedmoviearr, savingmoviearr)
		ressavingmoviearr = append(ressavingmoviearr, savingmoviearr)

	}
	log.Println("[LOG] savedmoviearr : ", savedmoviearr)
	common.Writemovieinfo(savedmoviearr)

	if res.Code == CONFLICT {
		res.Message = "Conflicted"
		res.Detail = "Already exist movie information"
		res.Path = r.RequestURI

	} else {
		res.Code = CREATED
		res.Message = "Created"
		res.Detail = "Created movie information"
		res.Path = r.RequestURI
		res.Movie = ressavingmoviearr

	}
	log.Println("[LOG] Post response : ", res)
	return res
}
func (MovieResource) Put(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response {

	var res = new(structcomp.Response)

	var putmovieinfo = new(structcomp.Putmovieinfo)
	rbody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("[ERR] request body ioutil.ReadAll : ", err)
		res := BadRequest(r)
		return res
	}

	contenttype := r.Header.Get("Content-type")
	if contenttype != "application/json" {
		res.Code = NOTACCEPTABLE
		res.Message = "Not  Acceptable"
		res.Detail = "invalid Content-type"
		res.Path = r.RequestURI
		return res
	}

	err = json.Unmarshal(rbody, &putmovieinfo)
	if err != nil {
		log.Println("[ERR] json movie list Unmarshal : ", err)
		res := BadRequest(r)
		return res
	}
	log.Println("[LOG] rbody : ", string(rbody))
	savedmoviearr := common.Getmovieinfo()

	for i, movieid := range putmovieinfo.Movie_id {
		var mid int
		mid, err = strconv.Atoi(movieid)
		if err != nil {
			log.Println("[ERR] json movie list Unmarshal : ", err)
			res := BadRequest(r)
			return res
		}

		if len(savedmoviearr) >= mid && mid > 0 {
			savedmoviearr[mid-1].Name = putmovieinfo.Name[i]
		} else {
			log.Println("[ERR] not exist movie id ")
			res := BadRequest(r)
			return res
		}
	}
	err = common.Writemovieinfo(savedmoviearr)
	if err != nil {
		log.Println("[ERR] common.Writemovieinfo in Put function : ", err)
		res = BadRequest(r)
		return res
	}

	savedjobstatementinfo := common.Getjobstatementinfo()

	var resputmovieinfoarr []structcomp.Movieinfo
	var resputmovieinfo structcomp.Movieinfo
	for i, moviename := range putmovieinfo.Name {
		resputmovieinfo.Href = "www.example.com/movie/" + putmovieinfo.Movie_id[i]
		resputmovieinfo.Name = moviename
		resputmovieinfo.Movie_id = putmovieinfo.Movie_id[i]
		resputmovieinfoarr = append(resputmovieinfoarr, resputmovieinfo)
	}
	res.Code = ACCEPTED
	res.Message = "Accepted"
	res.Detail = "“valid request but it has not been updated yet"
	res.Path = r.RequestURI
	res.Movie = resputmovieinfoarr
	res.Jobstatement = savedjobstatementinfo

	log.Println("[LOG] put response : ", res)
	return res

}

//{------------------------Delete function--------------------------------------
func (MovieResource) Delete(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response {

	var res = new(structcomp.Response)
	err := common.Cleanmovieinfo()
	if err != nil {
		fmt.Println("[ERR] os.OpenFile : in Cleanmovieinfo func : ", err)
		res := BadRequest(r)
		return res
	}
	savedjobstatementinfo := common.Getjobstatementinfo()

	res.Code = ACCEPTED
	res.Message = "Accepted"
	res.Detail = "“valid request but it has not been updated yet"
	res.Path = r.RequestURI
	res.Jobstatement = savedjobstatementinfo

	log.Println("[LOG] put response : ", res)
	return res

}

//------------------------Delete function--------------------------------------}

type MovieEachResource struct {
	PostNotSupported
	PutNotSupported
	DeleteNotSupported
}

func (MovieEachResource) Uri() string {
	return "/movie/:movie_id"
}
func BadRequest(r *http.Request) *structcomp.Response {
	var res = new(structcomp.Response)
	res.Code = BADREQUEST
	res.Message = "Bad Request"
	res.Detail = "Invalid Client Request"
	res.Path = r.RequestURI
	log.Println("[LOG] res struct in BadRequest function : ", res)
	return res
}

func (MovieEachResource) Get(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) *structcomp.Response {

	movieid, err := strconv.Atoi(ps.ByName("movie_id"))
	if err != nil {
		log.Println("[ERR] strconv.Atoi movie_id", err)
		res := BadRequest(r)
		return res
	}
	var res = new(structcomp.Response)
	movieinfoarr := common.Getmovieinfo()

	if len(movieinfoarr) >= movieid && movieid > 0 {
		for _, movie := range movieinfoarr {
			if movie.Movie_id == strconv.Itoa(movieid) {
				res.Movie = append(res.Movie, movie)
				break
			}
		}
		res.Code = SUCCESS
		res.Message = "Success"
		res.Detail = fmt.Sprintf("found Movie_%d information", movieid)
		res.Path = r.RequestURI
	} else {
		res.Code = NOTFOUND
		res.Message = "Not Found"
		res.Detail = fmt.Sprintf("Not found Movie_%d information", movieid)
		res.Path = r.RequestURI
	}
	return res
}

func main() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	router := httprouter.New()

	RegisterResource(router, new(MovieResource))
	RegisterResource(router, new(MovieEachResource))

	log.Fatal(http.ListenAndServe(":8080", router))

}
