package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type Resource interface {
	Uri() string
	Get(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response
	Post(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response
	Put(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response
	Delete(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response
}

type (
	GetNotSupported    struct{}
	PostNotSupported   struct{}
	PutNotSupported    struct{}
	DeleteNotSupported struct{}
)

func (GetNotSupported) Get(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response {
	return Response{405, "", nil}
}

func (PostNotSupported) Post(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response {
	return Response{405, "", nil}
}

func (PutNotSupported) Put(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response {
	return Response{405, "", nil}
}

func (DeleteNotSupported) Delete(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response {
	return Response{405, "", nil}
}

func abort(rw http.ResponseWriter, statusCode int) {
	rw.WriteHeader(statusCode)
}

func HttpResponse(rw http.ResponseWriter, req *http.Request, res Response) {
	content, err := json.Marshal(res)

	if err != nil {
		abort(rw, 500)
	}

	rw.WriteHeader(res.Code)
	rw.Write(content)
}

func AddResource(router *httprouter.Router, resource Resource) {
	fmt.Println("\"" + resource.Uri() + "\" api is registerd")

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

// user string array
var users = []string{
	"user1", "user2", "user3",
}

// /user
type UserResource struct {
	PutNotSupported
	DeleteNotSupported
}

func (UserResource) Uri() string {
	return "/user"
}

func (UserResource) Get(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response {
	return Response{200, "", users}
}

func (UserResource) Post(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response {
	user := r.FormValue("user")
	if len(user) > 0 {
		users = append(users, r.FormValue("user"))
		return Response{200, "", nil}
	} else {
		return Response{400, "", nil}
	}
}

// /user/:index
type UserEachResource struct {
	PostNotSupported
}

func (UserEachResource) Uri() string {
	return "/user/:index"
}

func (UserEachResource) Get(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response {
	if index, err := strconv.Atoi(ps.ByName("index")); err == nil {
		if len(users) > index && index > 0 {
			return Response{200, "", users[index]}
		}
	}
	return Response{400, "", nil}
}

func (UserEachResource) Put(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response {
	user := r.FormValue("user")
	if len(user) > 0 {
		if index, err := strconv.Atoi(ps.ByName("index")); err == nil {
			if len(users) > index && index > 0 {
				users[index] = user
				return Response{200, "", nil}
			}
		}
		return Response{400, "", nil}
	} else {
		return Response{400, "", nil}
	}
}

func (UserEachResource) Delete(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) Response {
	if index, err := strconv.Atoi(ps.ByName("index")); err == nil {
		if len(users) > index && index > 0 {
			users = append(users[:index], users[index+1:]...)
			return Response{200, "", nil}
		}
	}
	return Response{400, "", nil}
}

func main() {
	router := httprouter.New()

	AddResource(router, new(UserResource))
	AddResource(router, new(UserEachResource))

	log.Fatal(http.ListenAndServe(":8080", router))
}
