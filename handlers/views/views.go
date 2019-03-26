package views

import (
	"database/sql"
	"html/template"
	"log"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"fmt"
	"time"
	"net/http"
	"strconv"
	"github.com/connelevalsam/GoWebDev/golang_crud/handlers/db"
)

// variables
var (
	err     error
	conn    *sql.DB
	templ   *template.Template
	adtempl *template.Template
	uName   string
	des     string
	IsLoggedin bool
)

// Page struct
type PageData struct {
	Title       string
	IsAuth      int
	Id          int
	Username    string
	Password    string
	Description string
	CreatedAt   mysql.NullTime
	UpdatedAt   mysql.NullTime
	AdminD      int
}


//init func: runs only the first time the app loads, so we get to set our templates
func InitFunc() {
	//login is false at start
	IsLoggedin = false

	//handles the default pages, you don't need to login to access
	templ, err = templ.ParseGlob("public/*.html")
	if err != nil {
		log.Fatalln(err.Error())
	}

	//handles the admin templates
	adtempl, err = adtempl.ParseGlob("public/admin/*.html")
	if err != nil {
		log.Fatalln(err.Error())
	}
}


// this func handles the index
func IndexHandler(res http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("logged-in")
	title := "Home || cb_net sessions"
	var isAuth int
	if err == http.ErrNoCookie {
		cookie = &http.Cookie{
			Name:  "logged-in",
			Value: "0",
		}
	}

	if cookie.Value == strconv.Itoa(1) {
		isAuth = 1
		var pd = PageData{Title: title, Username: uName}
		err = adtempl.ExecuteTemplate(res, "index.html", pd)
		if err != nil {
			log.Fatalln(err.Error(), "no admin index")
		}
		fmt.Println("success")
	} else if cookie.Value == strconv.Itoa(2) {
		isAuth = 2
		describeUser(uName)
		if req.Method == "POST" {
			describe := req.FormValue("description")
			updateDescription(describe)
			http.Redirect(res, req, "/", 302)
			return
		}
		fmt.Println("success")
	} else {
		isAuth = 0

	}
	var pd = PageData{Title: title, Username: uName, Description: des, IsAuth: isAuth}
	err = templ.ExecuteTemplate(res, "index.html", pd)
	if err != nil {
		log.Fatalln(err.Error())
	}

}

func LoginHandler(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		err = templ.ExecuteTemplate(res, "login.html", nil)
		if err != nil {
			fmt.Sprint("error", err)
		}
		return
	}
	var username = req.FormValue("username")
	password := req.FormValue("password")
	var pword string
	var isAdmin int
	// query
	conn = db.Conn
	rows, err := conn.Query("SELECT password,is_admin FROM Crud_tb WHERE username = ?", username)
	if err != nil {
		log.Println(err.Error())
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	for rows.Next() {
		err = rows.Scan(&pword, &isAdmin)
		if err != nil {
			log.Println(err)
			http.Error(res, "there was an error", http.StatusInternalServerError)
			return
		}
		if isAdmin == 1 {
			// Validate the password
			err = bcrypt.CompareHashAndPassword([]byte(pword), []byte(password))
			// If wrong password redirect to the login
			if err != nil {
				fmt.Println("invalid")
				http.Redirect(res, req, "/login", 301)
				return
			}
			uName = username
			cookie := &http.Cookie{
				Name:  "logged-in",
				Value: "1",
			}
			http.SetCookie(res, cookie)
			http.Redirect(res, req, "/", 302)
			return
		} else {
			// Validate the password
			err = bcrypt.CompareHashAndPassword([]byte(pword), []byte(password))
			// If wrong password redirect to the login
			if err != nil {
				fmt.Println("invalid")
				http.Redirect(res, req, "/login", 301)
				return
			}
			uName = username
			cookie := &http.Cookie{
				Name:  "logged-in",
				Value: "2",
			}
			http.SetCookie(res, cookie)
			http.Redirect(res, req, "/", 302)
			return
		}
	}

}

func Logout(w http.ResponseWriter, r *http.Request) {
	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	http.SetCookie(w, &http.Cookie{
		Name:   "logged-in",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

//admin hendlers
func CreateUserHandler(res http.ResponseWriter, req *http.Request) {
	//insert into db
	conn = db.Conn
	stmt, err := conn.Prepare("INSERT Crud_tb SET username=?, password=?, description=?, created_at=?, updated_at=?, is_admin=?")
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	if req.Method != "POST" {
		adtempl.ExecuteTemplate(res, "create.html", nil)
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")
	describe := req.FormValue("description")
	isAdmin := req.FormValue("admin")
	createdAt := time.Now()
	updatedAt := time.Now()

	var admin_chk int
	if isAdmin == "on" {
		admin_chk = 1
	} else {
		admin_chk = 0
	}

	var user string
	err = conn.QueryRow("SELECT username FROM Crud_tb WHERE username=?", username).Scan(&user)

	switch {
	//username is available
	case err == sql.ErrNoRows:
		securedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
			http.Error(res, "there was an error", http.StatusInternalServerError)
			return
		}
		rs, err := stmt.Exec(username, securedPassword, describe, createdAt, updatedAt, admin_chk)
		if err != nil {
			log.Println(err)
			http.Error(res, "there was an error", http.StatusInternalServerError)
			return
		}
		id, err := rs.LastInsertId()
		if err != nil {
			log.Println(err)
			http.Error(res, "there was an error", http.StatusInternalServerError)
			return
		}

		res.Write([]byte("user successfully created!"))
		fmt.Println("user: ", username, " with ID: ", id, " successfully created!")
		return
	case err != nil:
		http.Error(res, err.Error(), 500)
		return
	default:
		http.Redirect(res, req, "/create", 301)
	}
}

func ReadUserHandler(res http.ResponseWriter, req *http.Request) {
	// query
	conn = db.Conn
	rows, err := conn.Query("SELECT * FROM Crud_tb")
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	var id int
	var username string
	var password string
	var describe string
	var created_at mysql.NullTime
	var updated_at mysql.NullTime
	var isAdmin int

	var ps []PageData

	for rows.Next() {
		err = rows.Scan(&id, &username, &password, &describe, &created_at, &updated_at, &isAdmin)
		if err != nil {
			log.Println(err)
			http.Error(res, "there was an error", http.StatusInternalServerError)
			return
		}
		ps = append(ps, PageData{Id: id, Username: username, Password: password, Description: describe, CreatedAt: created_at, UpdatedAt: updated_at, AdminD: isAdmin})
		//return
	}

	adtempl.ExecuteTemplate(res, "read.html", ps)
}

func UpdateUserHandler(res http.ResponseWriter, req *http.Request) {
	//select id's
	conn = db.Conn
	rows, err := conn.Query("SELECT id FROM Crud_tb")
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	var user = req.FormValue("ids")
	var newUsername = req.FormValue("username")
	var ps []PageData
	id, err := strconv.Atoi(user)

	for rows.Next() {
		err = rows.Scan(&id)
		if err != nil {
			log.Println(err)
			http.Error(res, "there was an error", http.StatusInternalServerError)
			return
		}
		ps = append(ps, PageData{Id: id})
	}

	stmt, err := conn.Prepare("UPDATE Crud_tb SET username=?, updated_at=? WHERE id=?")
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	rs, err := stmt.Exec(newUsername, time.Now(), id)
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	affect, err := rs.RowsAffected()
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	if req.Method != "POST" {
		adtempl.ExecuteTemplate(res, "update.html", ps)
		return
	}

	fmt.Println("row :", affect, " affected")
}

func DeleteUserHandler(res http.ResponseWriter, req *http.Request) {
	//select id's
	conn = db.Conn
	rows, err := conn.Query("SELECT id FROM Crud_tb")
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusNoContent)
		return
	}

	var user = req.FormValue("ids")
	var ps []PageData
	id, err := strconv.Atoi(user)

	for rows.Next() {
		err = rows.Scan(&id)
		if err != nil {
			log.Println(err)
			http.Error(res, "there was an error", http.StatusInternalServerError)
			return
		}
		ps = append(ps, PageData{Id: id})
	}
	//
	if req.Method != "POST" {
		adtempl.ExecuteTemplate(res, "delete.html", ps)
		return
	}
	// delete
	stmt, err := conn.Prepare("delete from Crud_tb where id=?")
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	rs, err := stmt.Exec(id)
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	affect, err := rs.RowsAffected()
	if err != nil {
		log.Println(err)
		http.Error(res, "there was an error", http.StatusInternalServerError)
		return
	}

	fmt.Println("row :", affect, " affected")
}

//users handlers
func describeUser(username string) {
	// query
	conn = db.Conn
	rows, err := conn.Query("SELECT description FROM Crud_tb WHERE username=?", username)
	if err != nil {
		log.Println(err)
	}

	var describe string

	for rows.Next() {
		err = rows.Scan(&describe)
		if err != nil {
			log.Println(err)
		}
		des = describe
		//return
	}
}

func updateDescription(describe string) {
	//update user description
	stmt, err := db.Conn.Prepare("UPDATE Crud_tb SET description=?, updated_at=? WHERE username=?")
	if err != nil {
		log.Println(err)
	}

	rs, err := stmt.Exec(describe, time.Now(), uName)
	if err != nil {
		log.Println(err)
	}

	affect, err := rs.RowsAffected()
	if err != nil {
		log.Println(err)
	}

	fmt.Println("row :", affect, " affected")
}


