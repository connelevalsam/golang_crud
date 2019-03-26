package main

import (
	"fmt"
	"net/http"

	"github.com/connelevalsam/GoWebDev/golang_crud/handlers/db"
	"github.com/connelevalsam/GoWebDev/golang_crud/handlers/views"
)





func init() {
	views.InitFunc()

	db.DBConnect()
}

func main() {

	http.HandleFunc("/", views.IndexHandler)
	http.HandleFunc("/login", views.LoginHandler)
	http.HandleFunc("/logout", views.Logout)
	http.HandleFunc("/create", views.CreateUserHandler)
	http.HandleFunc("/read", views.ReadUserHandler)
	http.HandleFunc("/update", views.UpdateUserHandler)
	http.HandleFunc("/delete", views.DeleteUserHandler)
	http.Handle("/assets/", http.FileServer(http.Dir("./public"))) //serve other files in assets dir
	http.Handle("/favicon.ico", http.NotFoundHandler())
	fmt.Println("server running on port :8080")
	http.ListenAndServe(":8080", nil)
}


