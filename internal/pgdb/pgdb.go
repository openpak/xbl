// SPDX-License-Identifier: AGPL-3.0-only

// Package pgdb opens a service's Postgres schema through pgx and database/sql.
// Every OpenPak Xbox service owns one schema inside the shared "xbox"
// database; Open creates it and pins search_path to it, so queries use bare
// table names. Statements are written with ? placeholders and rebound to $n.
package pgdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

var ident = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// MaxConns is the pool size of one service (the box allows 300 in total).
const MaxConns = 3

// DB is a *sql.DB whose statements use ? placeholders.
type DB struct{ *sql.DB }

// Tx is a *sql.Tx whose statements use ? placeholders.
type Tx struct{ *sql.Tx }

// Open connects to dsn, creates schema when missing and pins search_path to it.
// A search_path set in the DSN overrides defaultSchema (tests use that).
// script runs once at open and must be idempotent (CREATE ... IF NOT EXISTS).
func Open(dsn, defaultSchema, script string) (*DB, error) {
	if dsn == "" {
		return nil, errors.New("pgdb: empty DSN")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("pgdb: invalid DSN")
	}
	schema := defaultSchema
	if v := cfg.RuntimeParams["search_path"]; v != "" {
		schema = v
	}
	if !ident.MatchString(schema) {
		return nil, fmt.Errorf("pgdb: bad schema name %q", schema)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgdb: connect: %w", sanitize(err))
	}
	_, err = c.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema)
	c.Close(ctx)
	if err != nil {
		return nil, fmt.Errorf("pgdb: create schema: %w", sanitize(err))
	}
	cfg.RuntimeParams["search_path"] = schema
	db := sql.OpenDB(stdlib.GetConnector(*cfg))
	db.SetMaxOpenConns(MaxConns)
	db.SetMaxIdleConns(MaxConns)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("pgdb: ping: %w", sanitize(err))
	}
	d := &DB{db}
	if script != "" {
		if _, err := db.ExecContext(ctx, script); err != nil {
			db.Close()
			return nil, fmt.Errorf("pgdb: schema: %w", sanitize(err))
		}
	}
	return d, nil
}

// sanitize drops everything but the server's message so a DSN never reaches a log.
func sanitize(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return errors.New(pe.Message)
	}
	return errors.New("connection failed")
}

// Rebind turns ? placeholders into $1, $2, ...
func Rebind(q string) string {
	if !strings.Contains(q, "?") {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

func (d *DB) Exec(q string, a ...any) (sql.Result, error) { return d.DB.Exec(Rebind(q), a...) }
func (d *DB) ExecContext(ctx context.Context, q string, a ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, Rebind(q), a...)
}
func (d *DB) Query(q string, a ...any) (*sql.Rows, error) { return d.DB.Query(Rebind(q), a...) }
func (d *DB) QueryContext(ctx context.Context, q string, a ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, Rebind(q), a...)
}
func (d *DB) QueryRow(q string, a ...any) *sql.Row { return d.DB.QueryRow(Rebind(q), a...) }
func (d *DB) QueryRowContext(ctx context.Context, q string, a ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, Rebind(q), a...)
}
func (d *DB) Begin() (*Tx, error) {
	t, err := d.DB.Begin()
	return &Tx{t}, err
}
func (d *DB) BeginTx(ctx context.Context, o *sql.TxOptions) (*Tx, error) {
	t, err := d.DB.BeginTx(ctx, o)
	return &Tx{t}, err
}

func (t *Tx) Exec(q string, a ...any) (sql.Result, error) { return t.Tx.Exec(Rebind(q), a...) }
func (t *Tx) ExecContext(ctx context.Context, q string, a ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, Rebind(q), a...)
}
func (t *Tx) Query(q string, a ...any) (*sql.Rows, error) { return t.Tx.Query(Rebind(q), a...) }
func (t *Tx) QueryContext(ctx context.Context, q string, a ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, Rebind(q), a...)
}
func (t *Tx) QueryRow(q string, a ...any) *sql.Row { return t.Tx.QueryRow(Rebind(q), a...) }
func (t *Tx) QueryRowContext(ctx context.Context, q string, a ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, Rebind(q), a...)
}

// IsUnique reports a unique-constraint violation.
func IsUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}
