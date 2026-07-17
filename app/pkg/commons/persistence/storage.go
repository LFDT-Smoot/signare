package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
)

type Storage interface {
	// QueryAll obtains all element from statement with arguments provided. It returns an error if it fails
	QueryAll(ctx context.Context, stmtID string, args interface{}, dst interface{}) error
	// ExecuteStmt executes statement with arguments provided. It returns an error if it fails
	ExecuteStmt(ctx context.Context, stmtID string, args interface{}) error
	// ExecuteStmtWithStorageResult executes statement with arguments provided. It returns information on stmt or an error if it fails
	ExecuteStmtWithStorageResult(ctx context.Context, stmtID string, args interface{}) (*ExecuteStmtWithStorageResultOutput, error)
	// BeginTransaction starts a Storage operation that is transactional. It returns an error if it fails
	BeginTransaction(ctx context.Context) (context.Context, error)
	// RollbackTransaction rollbacks to previous state a Storage operation that is transactional. It returns an error if it fails
	RollbackTransaction(ctx context.Context) error
	// CommitTransaction confirms a Storage operation that is transactional. It returns an error if it fails
	CommitTransaction(ctx context.Context) error
	// GetTransaction returns the transaction from context (in case of success).
	GetTransaction(ctx context.Context) (any, error)
	// AddConfig registers SQL statements
	AddConfig(config StorageConfig) error
}

// OrderByOption defines the field to apply order
type OrderByOption string

// OrderDirection defines the order direction
type OrderDirection string

const (
	// Asc ascendant direction order
	Asc OrderDirection = "asc"
	// Desc descendant direction order
	Desc OrderDirection = "desc"
	// CreationDate creation date order
	CreationDate OrderByOption = "creation_date"
	// LastUpdate update date order
	LastUpdate OrderByOption = "last_update"
)

// Order defines order on Storage data
type Order struct {
	By        OrderByOption  `valid:"required"`
	Direction OrderDirection `valid:"required"`
}

// validOrderByOptions is the allow-list of columns permitted in an ORDER BY clause.
var validOrderByOptions = map[OrderByOption]bool{
	CreationDate: true,
	LastUpdate:   true,
}

// ToSQLStmt renders the ORDER BY clause for the order. It validates that By is an
// allow-listed OrderByOption and that Direction is a known OrderDirection, returning
// an error otherwise so that no unvalidated identifier reaches the statement.
func (o Order) ToSQLStmt() (string, error) {
	if !validOrderByOptions[o.By] {
		return "", fmt.Errorf("invalid order by option %q", o.By)
	}
	var direction string
	switch o.Direction {
	case Asc:
		direction = "ASC"
	case Desc:
		direction = "DESC"
	default:
		return "", fmt.Errorf("invalid order direction %q", o.Direction)
	}
	return fmt.Sprintf("%s %s", o.By, direction), nil
}

// FilterGroup defines the group of filters Storage data
type FilterGroup struct {
	Filters []Filter
}

// Filter defines the functionality to convert filters into statements
type Filter interface {
	// ToSQLStmt returns the SQL statement for the filter, or an error if its
	// column is not a valid SQL identifier.
	ToSQLStmt() (string, error)
}

// identifierPattern matches a safe SQL identifier: a leading letter or underscore
// followed by letters, digits or underscores. It excludes quotes, whitespace and
// statement separators so a column name can never carry SQL into a statement.
var identifierPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// validateIdentifier returns an error if by is not a safe SQL identifier.
func validateIdentifier(by string) error {
	if !identifierPattern.MatchString(by) {
		return fmt.Errorf("invalid SQL identifier %q", by)
	}
	return nil
}

// formatComparison validates the column identifier and renders a "<col><op>:<col>"
// comparison that binds the value as a named parameter.
func formatComparison(by, op string) (string, error) {
	if err := validateIdentifier(by); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s:%s", by, op, by), nil
}

// EqualFilter to filter by the specified field with equal value
type EqualFilter struct {
	By string
}

// ToSQLStmt SQL statement for the filter
func (f EqualFilter) ToSQLStmt() (string, error) {
	return formatComparison(f.By, "=")
}

// LessFilter to filter by the specified field with less value
type LessFilter struct {
	By string
}

// ToSQLStmt SQL statement for the filter
func (f LessFilter) ToSQLStmt() (string, error) {
	return formatComparison(f.By, "<")
}

// LessOrEqualFilter to filter by the specified field with less or equal value
type LessOrEqualFilter struct {
	By string
}

// ToSQLStmt SQL statement for the filter
func (f LessOrEqualFilter) ToSQLStmt() (string, error) {
	return formatComparison(f.By, "<=")
}

// GreaterFilter to filter by the specified field with greater value
type GreaterFilter struct {
	By string
}

// ToSQLStmt SQL statement for the filter
func (f GreaterFilter) ToSQLStmt() (string, error) {
	return formatComparison(f.By, ">")
}

// GreaterOrEqualFilter to filter by the specified field with greater or equal value
type GreaterOrEqualFilter struct {
	By string
}

// ToSQLStmt SQL statement for the filter
func (f GreaterOrEqualFilter) ToSQLStmt() (string, error) {
	return formatComparison(f.By, ">=")
}

// FilterOption defines a filter option
type FilterOption string

// Pagination from the Storage data with limit/offset navigation
type Pagination struct {
	// Limit maximum number of entries to return
	Limit int `valid:"required"`
	// Offset zero-based offset of the first item in the collection to return
	Offset int `valid:"required"`
}

const (
	// DefaultPageLimit is the page size applied to a list query when the caller supplies no positive limit.
	DefaultPageLimit = 30
	// MaxPageLimit is the largest page size a list query may request; larger values are capped to it.
	MaxPageLimit = 100
)

// ClampPageLimit normalizes a requested page limit so every list query is bounded: a non-positive
// limit falls back to DefaultPageLimit and a limit above MaxPageLimit is capped to MaxPageLimit.
func ClampPageLimit(limit int) int {
	if limit <= 0 {
		return DefaultPageLimit
	}
	if limit > MaxPageLimit {
		return MaxPageLimit
	}
	return limit
}

// ExecuteStmtWithStorageResultOutput wraps the result of an statement
type ExecuteStmtWithStorageResultOutput struct {
	Result sql.Result
}
