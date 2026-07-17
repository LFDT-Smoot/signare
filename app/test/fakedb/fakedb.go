// Package fakedb provides a configurable in-memory database/sql driver for tests that need
// to exercise driver-level failure paths which a real SQLite or Postgres driver cannot be
// made to produce deterministically: row-iteration errors (sql.Rows.Err after the loop),
// exec failures, and sql.Result.RowsAffected failures.
//
// It is test-only infrastructure and is not referenced by production code.
package fakedb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing/fstest"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/reflectx"

	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence"
	persistencesql "github.com/lfdt-smoot/signare/app/pkg/commons/persistence/sql"
)

const driverName = "signarefakedb"

func init() {
	sql.Register(driverName, &fakeDriver{})
	sqlx.BindDriver(driverName, sqlx.QUESTION)
}

// Behavior configures the responses of a single fake connection.
type Behavior struct {
	// QueryColumns and QueryValues define the rows returned by every query (SELECT) on the connection.
	QueryColumns []string
	QueryValues  [][]driver.Value
	// QueryIterErr, when set, is returned by the row iterator and surfaces through sql.Rows.Err()
	// after the loop. This is the failure QueryAll must report instead of a truncated success.
	QueryIterErr error
	// ExecErr, when set, makes every exec (INSERT/UPDATE/DELETE) fail.
	ExecErr error
	// RowsAffectedErr, when set, lets the exec succeed but makes the resulting
	// sql.Result.RowsAffected() fail.
	RowsAffectedErr error
}

var (
	registryMu sync.Mutex
	registry   = map[string]*Behavior{}
	counter    int
)

// NewConnection registers the given behavior and returns a persistence sql.Connection backed by it.
func NewConnection(behavior Behavior) (persistencesql.Connection, error) {
	b := behavior

	registryMu.Lock()
	counter++
	dsn := fmt.Sprintf("fakedb-%d", counter)
	registry[dsn] = &b
	registryMu.Unlock()

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	sqlxDB := sqlx.NewDb(db, driverName)
	sqlxDB.Mapper = reflectx.NewMapperFunc("storage", func(s string) string { return s })
	return &connection{db: sqlxDB}, nil
}

// MapperStatements builds a persistence.StorageConfig from a single mapper's statements. Each
// resulting lookup key is "<mapperID>.<statementID>", matching the production statement identifiers.
func MapperStatements(mapperID string, statements map[string]string) (persistence.StorageConfig, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "<mapper id=%q>", mapperID)
	for id, content := range statements {
		fmt.Fprintf(&sb, "<statement id=%q>%s</statement>", id, content)
	}
	sb.WriteString("</mapper>")

	const driver = "fake"
	fsys := fstest.MapFS{
		"include/config/mappers/" + driver + "/mappers.xml": &fstest.MapFile{Data: []byte(sb.String())},
	}
	cfg, err := persistence.NewStorageConfig(persistence.StorageConfigOptions{
		ReadDirAndFileFS: fsys,
		Driver:           driver,
	})
	if err != nil {
		return persistence.StorageConfig{}, err
	}
	return *cfg, nil
}

// connection implements persistencesql.Connection over the fake driver.
type connection struct {
	db *sqlx.DB
}

func (c *connection) GetDB() *sqlx.DB { return c.db }
func (c *connection) GetErrorTranslator() persistencesql.ErrorTranslator {
	return passthroughTranslator{}
}
func (c *connection) GetMigrator() persistencesql.Migrator { return nil }
func (c *connection) GetDialectName() string               { return driverName }
func (c *connection) Close() error {
	if c.db == nil {
		return nil
	}
	return c.db.Close()
}

// passthroughTranslator returns the framework's default error unchanged.
type passthroughTranslator struct{}

func (passthroughTranslator) TranslateError(_ context.Context, _ error, defaultError error) error {
	return defaultError
}

type fakeDriver struct{}

func (d *fakeDriver) Open(name string) (driver.Conn, error) {
	registryMu.Lock()
	b := registry[name]
	registryMu.Unlock()
	if b == nil {
		b = &Behavior{}
	}
	return &fakeConn{behavior: b}, nil
}

type fakeConn struct {
	behavior *Behavior
}

func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return &fakeStmt{behavior: c.behavior}, nil }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)           { return fakeTx{}, nil }

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeStmt struct {
	behavior *Behavior
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }

func (s *fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	if s.behavior.ExecErr != nil {
		return nil, s.behavior.ExecErr
	}
	return &fakeResult{rowsAffectedErr: s.behavior.RowsAffectedErr}, nil
}

func (s *fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	return &fakeRows{
		columns: s.behavior.QueryColumns,
		values:  s.behavior.QueryValues,
		iterErr: s.behavior.QueryIterErr,
	}, nil
}

type fakeResult struct {
	rowsAffectedErr error
}

func (r *fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r *fakeResult) RowsAffected() (int64, error) {
	if r.rowsAffectedErr != nil {
		return 0, r.rowsAffectedErr
	}
	return 1, nil
}

type fakeRows struct {
	columns []string
	values  [][]driver.Value
	iterErr error
	index   int
}

func (r *fakeRows) Columns() []string { return r.columns }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.iterErr != nil {
		return r.iterErr
	}
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}
