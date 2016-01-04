package webpush

import (
	"html/template"
	"net/http"
)

var tpl = template.Must(template.ParseGlob("templates/*.html"))

func init() {
	http.HandleFunc("/", hello)
}

func hello(w http.ResponseWriter, r *http.Request) {
	tpl.ExecuteTemplate(w, "index.html", nil)
}
