package env_impl

import (
	"database/sql"
	"log"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// const roleTable = `
// CREATE TABLE IF NOT EXISTS role(
// 	id UNSIGNED BIG INT PRIMARY KEY AUTOINCREMENT,
// 	name VARCHAR(255) UNIQUE COLLATE BINARY,
// )
// `

// CREATE TABLE IF NOT EXISTS secret(
// 	id UNSIGNED BIG INT PRIMARY KEY AUTOINCREMENT,
// 	raw_secret BLOB
// );

// CREATE TABLE IF NOT EXISTS access(
// 	role_id UNSIGNED BIG INT,
// 	secret_id UNSIGNED BIG INT,
// 	FOREIGN KEY (role_id) REFERENCES role(id),
// 	FOREIGN KEY (secret_id) REFERENCES secret(id)
// );

func CreateTable(db *sql.DB) {
	const roleSql = `
		CREATE TABLE IF NOT EXISTS role (
			id INTEGER
				PRIMARY KEY
				NOT NULL,
			name VARCHAR(255)
				UNIQUE
				NOT NULL
				COLLATE BINARY
		)
	`
	if _, err := db.Exec(roleSql); err != nil {
		log.Fatal(err)
	}

	const secretSql = `
		CREATE TABLE IF NOT EXISTS secret (
			id INTEGER
				PRIMARY KEY
				NOT NULL,
			raw_secret BLOB
				NOT NULL
		)
	`
	if _, err := db.Exec(secretSql); err != nil {
		log.Fatal(err)
	}

	const accessSql = `
		CREATE TABLE IF NOT EXISTS access (
			role_id INTEGER
				NOT NULL,
			secret_id INTEGER
				NOT NULL,
			FOREIGN KEY (role_id)
				REFERENCES role(id)
				ON DELETE CASCADE
				ON UPDATE CASCADE,
			FOREIGN KEY (secret_id)
				REFERENCES secret(id)
				ON DELETE CASCADE
				ON UPDATE CASCADE
		)
	`
	if _, err := db.Exec(accessSql); err != nil {
		log.Fatal(err)
	}

	txn, _ := db.Begin()
	txn.Exec("INSERT INTO secret(raw_secret) VALUES (?)", []byte{0xff, 0xff})
	txn.Commit()
}

func Test_SQLiteEnv(t *testing.T) {
	db, err := sql.Open("sqlite3", "../../../build/env.db")
	if err != nil {
		t.Fatal(err)
	}
	CreateTable(db)
}
