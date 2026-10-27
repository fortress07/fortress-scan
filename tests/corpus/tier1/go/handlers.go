package main

import (
	"database/sql"
	"html/template"
	"net/http"
	"os/exec"
	"strconv"
)

var db *sql.DB

func userHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'") // fsb-expect: FSB-SQL-001
	defer rows.Close()
}

func userHandlerSafe(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT * FROM users WHERE name = $1", r.URL.Query().Get("name"))
	defer rows.Close()
}

func userByID(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		return
	}
	rows, _ := db.Query("SELECT * FROM users WHERE id = " + strconv.Itoa(id))
	defer rows.Close()
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output() // fsb-expect: FSB-CMD-001
	w.Write(out)
}

func pingHandlerSafe(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("ping", "-c", "1", r.FormValue("host")).Output()
	w.Write(out)
}

func bannerHandler(w http.ResponseWriter, r *http.Request) {
	msg := r.Header.Get("X-Banner")
	page := template.Must(template.New("p").Parse("<div>{{.}}</div>"))
	page.Execute(w, template.HTML(msg)) // fsb-expect: FSB-XSS-001
}

func bannerHandlerSafe(w http.ResponseWriter, r *http.Request) {
	page := template.Must(template.New("p").Parse("<div>{{.}}</div>"))
	page.Execute(w, r.Header.Get("X-Banner"))
}

func main() {
	http.HandleFunc("/user", userHandler)
	http.ListenAndServe(":8080", nil)
}
