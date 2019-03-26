package db

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
)

var (
	Conn *sql.DB
	err  error
)

const (
	user     = "root:"
	password = "GopherVsT-Rex@/"
	dbname   = "CRUD?parseTime=true"
)

//run database connection
func handleDbConnection(val string) {
	// Create an sql.DB and check for errors
	Conn, err = sql.Open("mysql", val)
	if err != nil {
		panic(err.Error())
	}

	// Test the connection to the database
	err = Conn.Ping()
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Successfully connected!")
}

//initialize database connection
func DBConnect() {
	psqlInfo := user + password + dbname
	handleDbConnection(psqlInfo)
}
