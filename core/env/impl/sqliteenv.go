package env_impl

import (
	"github.com/reshifr/secure-env/core/env"
)

type SQLiteEnv[DB env.SQLDB] struct {
	db DB
}

func LoadSQLiteEnv[DB env.SQLDB](db DB) *SQLiteEnv[DB] {
	env := &SQLiteEnv[DB]{db: db}
	return env
}

func (env *SQLiteEnv[DB]) CreateRole() {}
