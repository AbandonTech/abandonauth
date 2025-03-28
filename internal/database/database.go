package database

import (
	"context"
	"embed"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog/log"
)

var Engine *Queries

//go:embed migrations/*.sql
var embedMigrations embed.FS

func createConnString(host string, port uint, user, password, dbName string) string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s",
		host, port, user, password, dbName,
	)
}

func InitializeDatabase(host string, port uint, user, password, dbName string) {
	log.Info().
		Str("host", host).
		Uint("port", port).
		Str("user", user).
		Str("dbname", dbName).
		Msg("Opening database connection")

	ctx := context.Background()

	pool, err := pgxpool.New(ctx, createConnString(host, port, user, password, dbName))
	if err != nil {
		log.Fatal().
			Err(err).
			Msg("Failed to open database")
	}

	log.Info().
		Msg("Migrating database")
	goose.SetLogger(LoggerAdapter{Logger: log.Logger})

	goose.SetBaseFS(embedMigrations)
	if err := goose.SetDialect("postgres"); err != nil {
		panic(err)
	}

	db := stdlib.OpenDBFromPool(pool)
	if err := goose.Up(db, "migrations"); err != nil {
		panic(err)
	}

	Engine = New(pool)
}
