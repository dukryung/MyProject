package structcomp

type Response struct {
	Code         string             `json:"code"`
	Message      string             `json:"message"`
	Detail       string             `json:"detail"`
	Seq          string             `json:"sequence"`
	Path         string             `json:"path"`
	Movie        []Movieinfo        `json:"movie"`
	Jobstatement []Jobstatementinfo `json:"jobstatement"`
}

type Movieinfo struct {
	Href     string `json:"href"`
	Name     string `json:"name"`
	Movie_id string `json:"movie_id"`
}
type Jobstatementinfo struct {
	Href     string `json:"href"`
	Movie_id string `json:"movie_id"`
}
type Postmovieinfo struct {
	Name []string `json:"name`
}
type Putmovieinfo struct {
	Name     []string `json:"name`
	Movie_id []string `json:"movie_id"`
}
