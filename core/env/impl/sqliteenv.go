package env_impl

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteEnv struct {
	db *sql.DB
}

func LoadSQLiteEnv(db *sql.DB) (*SQLiteEnv, error) {
	const roleTable = `
		CREATE TABLE IF NOT EXISTS role (
			id INTEGER PRIMARY KEY NOT NULL,
			name VARCHAR(255) UNIQUE NOT NULL
		)`
	if _, err := db.Exec(roleTable); err != nil {
		return nil, err
	}
	const secretTable = `
		CREATE TABLE IF NOT EXISTS secret (
			id INTEGER PRIMARY KEY NOT NULL,
			raw BLOB NOT NULL
		)`
	if _, err := db.Exec(secretTable); err != nil {
		return nil, err
	}
	const accessTable = `
		CREATE TABLE IF NOT EXISTS access (
			role_id INTEGER NOT NULL,
			secret_id INTEGER NOT NULL,
			FOREIGN KEY (role_id) REFERENCES role(id)
				ON DELETE CASCADE ON UPDATE CASCADE,
			FOREIGN KEY (secret_id) REFERENCES secret(id)
				ON DELETE CASCADE ON UPDATE CASCADE
		)`
	if _, err := db.Exec(accessTable); err != nil {
		return nil, err
	}
	const accessIndex = `
		CREATE INDEX IF NOT EXISTS access_index
			ON access (role_id, secret_id)`
	if _, err := db.Exec(accessIndex); err != nil {
		return nil, err
	}
	env := &SQLiteEnv{db: db}
	return env, nil
}
