package env_impl

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func Test_SQLiteEnv(t *testing.T) {
	db, err := sql.Open("sqlite3", "../../../build/env.db")
	if err != nil {
		t.Fatal(err)
	}

	_, err = LoadSQLiteEnv(db)
	if err != nil {
		t.Fatal(err)
	}
}
