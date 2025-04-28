package utils

import (
	"database/sql"
	_ "github.com/lib/pq"
	"log"
	"os"
)

func DbOpenConnection() (*sql.DB, error) {
	dbConnStr := os.Getenv("DB_CONN_STR")

	db, err := sql.Open("postgres", dbConnStr)
	if err != nil {
		return nil, err
	}

	log.Println("POSTGRES connection opened")

	return db, nil
}

func DbCloseConnection(db *sql.DB) error {
	err := db.Close()
	if err != nil {
		return err
	}

	log.Println("POSTGRES connection closed")

	return nil
}
