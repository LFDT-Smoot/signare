package transactionalmanager

import (
	"context"
	"sync"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
)

// FuncToExecuteAfterCommitType callback function to execute after a database transaction commit
type FuncToExecuteAfterCommitType func(context.Context) error

// afterCommitCallbacksContextKeyType is the unexported type for the after-commit callbacks context key.
type afterCommitCallbacksContextKeyType struct{}

// afterCommitCallbacksContextKey is the context key under which the per-transaction callback registry is stored.
var afterCommitCallbacksContextKey = afterCommitCallbacksContextKeyType{}

// afterCommitCallbacks holds the callbacks registered during a single transaction. It is carried in the
// request context for the lifetime of the transaction, so it is released together with the context on every
// exit path (commit, rollback, commit failure or recovered panic) and therefore cannot leak.
type afterCommitCallbacks struct {
	mu        sync.Mutex
	callbacks []FuncToExecuteAfterCommitType
}

// add appends a callback to the registry.
func (c *afterCommitCallbacks) add(funcToExecuteAfterCommit FuncToExecuteAfterCommitType) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.callbacks = append(c.callbacks, funcToExecuteAfterCommit)
}

// snapshot returns a copy of the registered callbacks in registration order.
func (c *afterCommitCallbacks) snapshot() []FuncToExecuteAfterCommitType {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]FuncToExecuteAfterCommitType, len(c.callbacks))
	copy(out, c.callbacks)
	return out
}

// callbacksFromContext returns the per-transaction callback registry from the context, or nil if no
// manager-managed transaction is in progress.
func callbacksFromContext(ctx context.Context) *afterCommitCallbacks {
	holder, _ := ctx.Value(afterCommitCallbacksContextKey).(*afterCommitCallbacks)
	return holder
}

// TransactionalManagerUseCase defines the functionality to execute a transaction in a transactional manner.
type TransactionalManagerUseCase interface {
	// ExecuteInTransaction executes a database transaction.
	ExecuteInTransaction(ctx context.Context, transactionalFunc func(context.Context) (interface{}, error)) (interface{}, error)
	// RegisterAfterCommitIfTransactionInProgress callback to execute after committing a database transaction.
	RegisterAfterCommitIfTransactionInProgress(ctx context.Context, funcToExecuteAfterCommit FuncToExecuteAfterCommitType) bool
}

// ExecuteInTransaction begins the execution of a transaction and rollbacks (reverts) any persistent changes if the transaction fails.
// ctx determines the context to execute transaction within and transactionalFunc the transaction to perform.
// It returns transaction result as interface{} and it returns an usecase failure if fails.
func (t *TransactionalManager) ExecuteInTransaction(ctx context.Context, transactionalFunc func(context.Context) (interface{}, error)) (response interface{}, failure error) {
	txCtx := ctx
	_, err := t.transactionalStorage.GetTransaction(ctx)
	ongoingTransaction := true // if there are nested transactions, the first one is responsible for executing the final commit or rollback. We handle that with this variable
	if err != nil {            // tx is nil
		ongoingTransaction = false
		beginTransactionCtx, errBeginTransaction := t.transactionalStorage.BeginTransaction(ctx)
		if errBeginTransaction != nil {
			return nil, errBeginTransaction
		}
		// The outermost transaction owns the after-commit callback registry for its entire lifetime.
		// Carrying it in the context means it is released on every exit path, so it cannot leak.
		txCtx = context.WithValue(beginTransactionCtx, afterCommitCallbacksContextKey, &afterCommitCallbacks{})
		// Sanity-check that the transaction we just began is retrievable from the context. On the
		// ongoing/nested path the transaction was already confirmed above, so no re-check is needed.
		if _, err = t.transactionalStorage.GetTransaction(txCtx); err != nil {
			return nil, errors.InternalFromErr(err)
		}
	}
	defer func() {
		if x := recover(); x != nil {
			if !ongoingTransaction {
				// if a panic occurs, we try to roll the transaction back
				rollbackTransactionErr := t.transactionalStorage.RollbackTransaction(txCtx)
				failure = errors.Internal().WithMessage("Database transaction was rolled back")
				if rollbackTransactionErr != nil {
					// If the transaction has already been committed, we will get an error when trying to roll it back.
					// In this situation the panic occurred when executing the function after the commit.
					failure = rollbackTransactionErr
				}
			}
		}
	}()

	response, failure = transactionalFunc(txCtx)
	if failure != nil {
		if ongoingTransaction {
			return response, failure
		}
		err2 := t.transactionalStorage.RollbackTransaction(txCtx)
		if err2 != nil {
			logger.LogEntry(ctx).Error(err2.Error())
		}
		return nil, failure
	}

	if !ongoingTransaction {
		commitTransactionErr := t.transactionalStorage.CommitTransaction(txCtx)
		if commitTransactionErr != nil {
			return nil, commitTransactionErr
		}

		if holder := callbacksFromContext(txCtx); holder != nil {
			for _, funcToExecute := range holder.snapshot() {
				failureFunc := funcToExecute(txCtx)
				if failureFunc != nil {
					return nil, failureFunc
				}
			}
		}
	}

	return response, nil
}

// RegisterAfterCommitIfTransactionInProgress registers a callback function to execute after the database transaction in the provided context is committed
func (t *TransactionalManager) RegisterAfterCommitIfTransactionInProgress(ctx context.Context, funcToExecuteAfterCommit FuncToExecuteAfterCommitType) bool {
	holder := callbacksFromContext(ctx)
	if holder == nil {
		// no transaction in progress: no callback can be registered
		return false
	}
	holder.add(funcToExecuteAfterCommit)
	return true
}

var _ TransactionalManagerUseCase = new(TransactionalManager)

// TransactionalManager handles transactional functionality.
type TransactionalManager struct {
	transactionalStorage TransactionalStorage
}

// TransactionalManagerOptions configures a TransactionalManager.
type TransactionalManagerOptions struct {
	// TransactionalStorage transactional manager storage
	TransactionalStorage TransactionalStorage
}

// ProvideTransactionalManager creates a TransactionalManager object with given options.
func ProvideTransactionalManager(options TransactionalManagerOptions) *TransactionalManager {
	return &TransactionalManager{
		transactionalStorage: options.TransactionalStorage,
	}
}
