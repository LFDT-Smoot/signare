package dbtesthelper

import (
	"context"

	embedded "github.com/lfdt-smoot/signare/app"
	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence/dbmigrator"
	_ "github.com/lfdt-smoot/signare/app/pkg/commons/persistence/sql/init" // Used to register sql dialects
	"github.com/lfdt-smoot/signare/app/pkg/graph"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"
)

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
