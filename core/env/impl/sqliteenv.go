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
			name VARCHAR(127) UNIQUE NOT NULL
		)`
	if _, err := db.Exec(roleTable); err != nil {
		return nil, err
	}

	const envTable = `
		CREATE TABLE IF NOT EXISTS env (
			id INTEGER PRIMARY KEY NOT NULL,
			namespace VARCHAR(127) UNIQUE NOT NULL,
			description TEXT
		)`
	if _, err := db.Exec(envTable); err != nil {
		return nil, err
	}

	const varTable = `
		CREATE TABLE IF NOT EXISTS var (
			env_id INTEGER NOT NULL,
			name VARCHAR(127) NOT NULL,
			value BLOB NOT NULL,
			PRIMARY KEY (env_id, name),
			FOREIGN KEY (env_id) REFERENCES env(id)
				ON DELETE CASCADE ON UPDATE CASCADE
		)`
	if _, err := db.Exec(varTable); err != nil {
		return nil, err
	}

	const envAccessTable = `
		CREATE TABLE IF NOT EXISTS env_access (
			role_id INTEGER NOT NULL,
			env_id INTEGER NOT NULL,
			secret BLOB NOT NULL,
			FOREIGN KEY (role_id) REFERENCES role(id)
				ON DELETE CASCADE ON UPDATE CASCADE,
			FOREIGN KEY (env_id) REFERENCES env(id)
				ON DELETE CASCADE ON UPDATE CASCADE
		)`
	if _, err := db.Exec(envAccessTable); err != nil {
		return nil, err
	}

	const objectTable = `
		CREATE TABLE IF NOT EXISTS object (
			id INTEGER PRIMARY KEY NOT NULL,
			name VARCHAR(127) UNIQUE NOT NULL,
			description TEXT,
			data BLOB NOT NULL
		)`
	if _, err := db.Exec(objectTable); err != nil {
		return nil, err
	}

	const objectAccessTable = `
		CREATE TABLE IF NOT EXISTS object_access (
			role_id INTEGER NOT NULL,
			object_id INTEGER NOT NULL,
			secret BLOB NOT NULL,
			FOREIGN KEY (role_id) REFERENCES role(id)
				ON DELETE CASCADE ON UPDATE CASCADE,
			FOREIGN KEY (object_id) REFERENCES object(id)
				ON DELETE CASCADE ON UPDATE CASCADE
		)`
	if _, err := db.Exec(objectAccessTable); err != nil {
		return nil, err
	}

	const envAccessIndex = `
		CREATE INDEX IF NOT EXISTS env_access_index
			ON env_access (role_id, env_id)`
	if _, err := db.Exec(envAccessIndex); err != nil {
		return nil, err
	}

	const objectAccessIndex = `
		CREATE INDEX IF NOT EXISTS object_access_index
			ON object_access (role_id, object_id)`
	if _, err := db.Exec(objectAccessIndex); err != nil {
		return nil, err
	}

	env := &SQLiteEnv{db: db}
	return env, nil
}
