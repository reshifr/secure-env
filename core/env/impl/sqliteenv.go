package env_impl

import (
	"database/sql"
)

type SQLiteEnv struct {
	db *sql.DB
}

func LoadSQLiteEnv(db *sql.DB) (*SQLiteEnv, error) {
	const role = `
		CREATE TABLE IF NOT EXISTS role(
			id INTEGER PRIMARY KEY NOT NULL,
			name VARCHAR(255) UNIQUE NOT NULL
		)`
	if _, err := db.Exec(role); err != nil {
		return nil, err
	}
	const secret = `
		CREATE TABLE IF NOT EXISTS secret(
			id INTEGER PRIMARY KEY NOT NULL,
			raw BLOB NOT NULL
		)`
	if _, err := db.Exec(secret); err != nil {
		return nil, err
	}
	const access = `
		CREATE TABLE IF NOT EXISTS access (
			role_id INTEGER NOT NULL,
			secret_id INTEGER NOT NULL,
			FOREIGN KEY(role_id) REFERENCES role(id)
				ON DELETE CASCADE ON UPDATE CASCADE,
			FOREIGN KEY (secret_id) REFERENCES secret(id)
				ON DELETE CASCADE ON UPDATE CASCADE
		)`
	if _, err := db.Exec(access); err != nil {
		return nil, err
	}
	env := &SQLiteEnv{db: db}
	return env, nil
}
