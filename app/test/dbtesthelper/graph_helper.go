package dbtesthelper

import (
	"context"

	embedded "github.com/lfdt-smoot/signare/app"
	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence/dbmigrator"
	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence/sql"
	_ "github.com/lfdt-smoot/signare/app/pkg/commons/persistence/sql/init" // Used to register sql dialects
	"github.com/lfdt-smoot/signare/app/pkg/graph"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"
)

// connection is the persistence connection of the app InitializeApp last built, exposed so a test can
// write a row the API cannot produce. The only use today is a slot naming no pin source, which both
// creation and EditPinSource refuse.
var connection sql.Connection

// Connection returns the persistence connection of the app built by InitializeApp.
func Connection() sql.Connection {
	return connection
}

func InitializeApp() (*graph.GraphShared, error) {
	pinSourceDirectory, err := signaturemanagertesthelper.NewPinSourceDirectory()
	if err != nil {
		return nil, err
	}

	graphConfig := graph.Config{
		BuildConfig: nil,
		Libraries: graph.LibrariesConfig{
			PersistenceFw: graph.PersistenceFwConfig{
				SQLite: &graph.SQLiteConfig{},
			},
			HSMModules: &graph.HSMModules{
				SoftHSM: &graph.SoftHSMConfig{
					Library:            signaturemanagertesthelper.SoftHSMLib,
					PinSourceDirectory: pinSourceDirectory,
				},
			},
		},
	}

	g, err := graph.New(graphConfig)
	if err != nil {
		return nil, err
	}
	g.Build()

	connection = g.PersistenceFwConnection()

	dbMigrator, err := dbmigrator.NewDbMigrator(dbmigrator.DbMigratorOptions{Connection: g.PersistenceFwConnection()})
	if err != nil {
		panic(err)
	}
	err = dbMigrator.MigrateFromFiles(context.Background(), dbmigrator.MigrateFromFilesInput{FS: embedded.DatabaseMigrations})
	if err != nil {
		panic(err)
	}

	return g.UseCases(), nil
}
