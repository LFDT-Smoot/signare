package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/graph"
	"github.com/lfdt-smoot/signare/app/pkg/infra/httpinfra"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/deployment/cmd/signare/config"
	"github.com/lfdt-smoot/signare/deployment/cmd/signare/flags"
	"github.com/lfdt-smoot/signare/deployment/cmd/signare/upgrader"
	"github.com/lfdt-smoot/signare/deployment/cmd/signare/version"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	name = "signare"

	// defaultListenAddress binds loopback only. Signare authenticates no one: it trusts the caller
	// identity a fronting proxy puts in the request headers, so a listener anything else can reach is
	// an unauthenticated one. Widening this is a deployment decision, made explicitly.
	defaultListenAddress  = "127.0.0.1"
	defaultPrometheusPort = 9785
	defaultHTTPPort       = 32325
	defaultRPCPort        = 4545

	serverWriteTimeout      = 15 * time.Second
	serverReadTimeout       = 15 * time.Second
	serverIdleTimeout       = 60 * time.Second
	serverReadHeaderTimeout = 15 * time.Second

	// shutdownGracePeriod bounds how long the servers are given to drain in-flight requests during
	// graceful shutdown. It matches the per-request read/write timeouts so a request the server
	// would have allowed to run still has a full window to finish before the process exits.
	shutdownGracePeriod = 15 * time.Second
)

var (
	commitHash string
	buildTime  string
	branch     string
	tag        string
)

var coreCmd = &cobra.Command{
	Use:     "signare",
	Long:    "Daemon for " + name,
	PreRunE: checkRequiredFlags,
	Run:     startServer,
}

func main() {
	configureCmd(coreCmd)

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetEnvPrefix("SIGNARE")

	coreCmd.AddCommand(upgrader.Command())
	coreCmd.AddCommand(version.Command(version.BuildInfo{CommitHash: commitHash, BuildTime: buildTime, Tag: tag, Branch: branch}))

	if err := coreCmd.Execute(); err != nil {
		logger.LogEntry(context.Background()).Errorf("not able to bootstrap: error executing %s cmd", name)
		os.Exit(1)
	}
}

func configureCmd(srcCmd *cobra.Command) {
	srcCmd.Flags().String(flags.ListenAddressFlag, defaultListenAddress, "Listening address, shared by the REST, JSON-RPC and metrics listeners")
	err := viper.BindPFlag(flags.ListenAddressFlag, srcCmd.Flags().Lookup(flags.ListenAddressFlag))
	if err != nil {
		panic(err)
	}

	srcCmd.Flags().Int(flags.HTTPPortFlag, defaultHTTPPort, "Listening HTTP port")
	err = viper.BindPFlag(flags.HTTPPortFlag, srcCmd.Flags().Lookup(flags.HTTPPortFlag))
	if err != nil {
		panic(err)
	}

	srcCmd.Flags().Int(flags.RPCPortFlag, defaultRPCPort, "Listening RPC port")
	err = viper.BindPFlag(flags.RPCPortFlag, srcCmd.Flags().Lookup(flags.RPCPortFlag))
	if err != nil {
		panic(err)
	}

	srcCmd.PersistentFlags().String(flags.SignareConfigPathFlag, ".", "Path to configuration file")
	err = viper.BindPFlag(flags.SignareConfigPathFlag, srcCmd.PersistentFlags().Lookup(flags.SignareConfigPathFlag))
	if err != nil {
		panic(err)
	}

	srcCmd.PersistentFlags().String(flags.SignareAdministratorFlag, "", "The ID of the initial signer administrator")
	err = viper.BindPFlag(flags.SignareAdministratorFlag, srcCmd.PersistentFlags().Lookup(flags.SignareAdministratorFlag))
	if err != nil {
		panic(err)
	}
}

func checkRequiredFlags(cmd *cobra.Command, _ []string) error {
	var requiredFlagsNotFound []string
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		required := len(flag.Annotations[cobra.BashCompOneRequiredFlag]) > 0 && flag.Annotations[cobra.BashCompOneRequiredFlag][0] == "true"
		if required && !envVarIsSet(flag.Name) {
			requiredFlagsNotFound = append(requiredFlagsNotFound, flag.Name)
		}
	})
	if len(requiredFlagsNotFound) > 0 {
		return fmt.Errorf("the following flags are required and were not present: %s ", strings.Join(requiredFlagsNotFound, ", "))
	}
	return nil
}

func startServer(_ *cobra.Command, _ []string) {
	ctxMainWithCancellation, mainCancel := context.WithCancel(context.Background())

	// Normalised once, here, so the safety check and all three listeners judge the same string. An
	// untrimmed value reaches net.Listen as a hostname and fails the lookup, and a bracketed IPv6
	// literal would be bracketed a second time by listenerAddress.
	listenAddress := config.ListenAddressHost(viper.GetString(flags.ListenAddressFlag))

	staticConfigPath := viper.GetString(flags.SignareConfigPathFlag)
	if staticConfigPath == "" {
		panic(fmt.Errorf("static config file folder to be provided with flag --%s", flags.SignareConfigPathFlag))
	}

	staticConfig, err := config.GetStaticConfiguration(staticConfigPath)
	if err != nil {
		panic(fmt.Sprintf("error reading static configuration: [%v]", err))
	}

	for _, warning := range staticConfig.InsecureSettingsWarnings() {
		logger.LogEntry(ctxMainWithCancellation).Warn(warning)
	}
	for _, warning := range config.InsecureListenAddressWarnings(listenAddress) {
		logger.LogEntry(ctxMainWithCancellation).Warn(warning)
	}

	appConfig := toGraphConfiguration(staticConfig)
	appGraph, err := graph.New(appConfig)
	if err != nil {
		panic(fmt.Sprintf("error initializing appGraph: [%v]", err))
	}

	appGraph.Build()
	initialSignerAdministrator := viper.GetString(flags.SignareAdministratorFlag)
	responseMessage, setInitialASignerAdministratorErr := appGraph.SetInitialSignerAdministrator(initialSignerAdministrator)
	if setInitialASignerAdministratorErr != nil {
		logger.LogEntry(ctxMainWithCancellation).Error(setInitialASignerAdministratorErr.Error())
		panic(setInitialASignerAdministratorErr)
	}
	logger.LogEntry(ctxMainWithCancellation).Info(responseMessage)

	maxBodyBytes, maxHeaderBytes := staticConfig.ServerLimits()

	httpServer := startMainServer(listenerAddress(listenAddress, viper.GetInt(flags.HTTPPortFlag)), *appGraph, maxBodyBytes, maxHeaderBytes)
	rpcServer := startRPCServer(listenerAddress(listenAddress, viper.GetInt(flags.RPCPortFlag)), *appGraph, maxBodyBytes, maxHeaderBytes)

	var metricsServer *http.Server
	if staticConfig.MetricsConfig != nil {
		metricsServer, err = startMetricsServers(listenAddress, staticConfig, *appGraph, maxHeaderBytes)
		if err != nil {
			panic(err)
		}
	}

	// Shutdown server
	terminationChannel := make(chan os.Signal, 1)
	signal.Notify(terminationChannel, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-terminationChannel:
			mainCancel() // the mainCancel is triggered from terminationChannel
		case <-ctxMainWithCancellation.Done():
			logger.LogEntry(ctxMainWithCancellation).Info("shutting down signare")
			// ctxMainWithCancellation is already cancelled here, so a fresh, time-bounded context is
			// used to give the servers a window to drain in-flight requests before the process exits.
			shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownGracePeriod)
			if err = shutDownServer(shutdownCtx, httpServer); err != nil {
				logger.LogEntry(ctxMainWithCancellation).Errorf("error shutting down main HTTP signare server: %v", err)
			}
			if err = shutDownServer(shutdownCtx, rpcServer); err != nil {
				logger.LogEntry(ctxMainWithCancellation).Errorf("error shutting down main JSON-RPC signare server: %v", err)
			}
			if metricsServer != nil {
				if err = shutDownServer(shutdownCtx, metricsServer); err != nil {
					logger.LogEntry(ctxMainWithCancellation).Errorf("error shutting down metrics server: %v", err)
				}
			}
			cancelShutdown()
			_, err = appGraph.UseCases().HSMConnector.CloseAll(context.Background(), hsmconnector.CloseAllInput{})
			if err != nil {
				logger.LogEntry(ctxMainWithCancellation).Errorf("error closing HSM resources: %v", err)
			}
			if connection := appGraph.PersistenceFwConnection(); connection != nil {
				if err = connection.Close(); err != nil {
					logger.LogEntry(ctxMainWithCancellation).Errorf("error closing database connection pool: %v", err)
				}
			}
			logger.LogEntry(ctxMainWithCancellation).Info("shutdown signare SUCCESS")
			os.Exit(0)
		}
	}
}

// listenerAddress builds the bind address for a listener from the --listen-address flag and a port.
// Every listener (main, RPC and metrics) goes through it, so the flag governs all three and cannot be
// honoured by two of them and not the third.
//
// net.JoinHostPort, not a "%s:%d", because an IPv6 host has to be bracketed: "::1" would otherwise
// yield "::1:32325", which net.Listen rejects as having too many colons. JoinHostPort brackets any
// host containing a colon without checking for brackets already there, so host must have come through
// config.ListenAddressHost, which is where a bracketed literal is unwrapped.
func listenerAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// metricsListenerAddress builds the metrics bind address, from --listen-address and the configured
// Prometheus port. The metrics listener shares the bind address of the REST and JSON-RPC listeners;
// only its port is configured separately.
func metricsListenerAddress(host string, prometheusConfig *config.PrometheusMetricsConfig) string {
	port := defaultPrometheusPort
	if prometheusConfig.Port != nil {
		port = *prometheusConfig.Port
	}
	return listenerAddress(host, port)
}

// newHTTPServer builds an *http.Server with the shared slow-client and idle-connection timeouts and the
// configured maximum header size, applied to every listener (main, RPC, and metrics).
func newHTTPServer(addr string, handler http.Handler, maxHeaderBytes int) *http.Server {
	return &http.Server{
		Addr:              addr,
		WriteTimeout:      serverWriteTimeout,
		ReadTimeout:       serverReadTimeout,
		IdleTimeout:       serverIdleTimeout,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		Handler:           handler,
	}
}

func startMainServer(addr string, appGraph graph.ApplicationGraph, maxBodyBytes int64, maxHeaderBytes int) *http.Server {
	router := appGraph.MainServer()
	srv := newHTTPServer(addr, httpinfra.MaxBytesMiddleware(maxBodyBytes)(handlers.LoggingHandler(os.Stdout, router.MainRouter())), maxHeaderBytes)
	logger.LogEntry(context.Background()).Infof("starting HTTP server on %s", addr)
	printRoutes(context.Background(), router.MainRouter())
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("error starting HTTP server: %v", err))
		}
	}()
	return srv
}

func startRPCServer(addr string, appGraph graph.ApplicationGraph, maxBodyBytes int64, maxHeaderBytes int) *http.Server {
	rpcRouter := appGraph.RPCServer()
	srv := newHTTPServer(addr, httpinfra.MaxBytesMiddleware(maxBodyBytes)(handlers.LoggingHandler(os.Stdout, rpcRouter.Router())), maxHeaderBytes)
	logger.LogEntry(context.Background()).Infof("starting JSON-RPC server on %s", addr)
	printRPCMethods(context.Background(), appGraph.RPCMethods())
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("error starting JSON-RPC server: %v", err))
		}
	}()
	return srv
}

func startMetricsServers(host string, staticConfig *config.StaticConfiguration, appGraph graph.ApplicationGraph, maxHeaderBytes int) (*http.Server, error) {
	if staticConfig.MetricsConfig.PrometheusMetricsConfig == nil {
		return nil, errors.New("unknown metric option to start server listener")
	}
	router := appGraph.MetricServer()
	addr := metricsListenerAddress(host, staticConfig.MetricsConfig.PrometheusMetricsConfig)
	// No request-body cap here: the metrics endpoint serves bodyless Prometheus scrape GETs. Only the
	// header limit applies; the body cap is reserved for the REST and JSON-RPC entrypoints.
	prometheusMetricsSrv := newHTTPServer(addr, handlers.LoggingHandler(os.Stdout, router.MainRouter()), maxHeaderBytes)
	logger.LogEntry(context.Background()).Infof("starting prometheus metrics server on %s", addr)
	printRoutes(context.Background(), router.MainRouter())
	go func() {
		if err := prometheusMetricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("error starting prometheus metrics server: %v", err))
		}
	}()
	return prometheusMetricsSrv, nil

}

func envVarIsSet(name string) bool {
	return os.Getenv(strings.ToUpper(name)) != ""
}

func toGraphConfiguration(staticConfig *config.StaticConfiguration) graph.Config {
	graphConfig := graph.Config{
		BuildConfig: &graph.BuildConfig{
			BuildTime:  &buildTime,
			Tag:        &tag,
			Branch:     &branch,
			CommitHash: &commitHash,
		},
		Libraries: graph.LibrariesConfig{
			PersistenceFw: graph.PersistenceFwConfig{
				PostgreSQL: &graph.PostgresSQLConfig{
					Host:     staticConfig.DatabaseInfo.PostgreSQL.Host,
					Port:     &staticConfig.DatabaseInfo.PostgreSQL.Port,
					Scheme:   &staticConfig.DatabaseInfo.PostgreSQL.Scheme,
					Username: staticConfig.DatabaseInfo.PostgreSQL.Username,
					Password: staticConfig.DatabaseInfo.PostgreSQL.Password,
					SSLMode:  staticConfig.DatabaseInfo.PostgreSQL.SSLMode,
					Database: staticConfig.DatabaseInfo.PostgreSQL.Database,
				},
			},
		},
	}

	if staticConfig.HSMModules != nil {
		graphConfig.Libraries.HSMModules = new(graph.HSMModules)

		if staticConfig.HSMModules.SoftHSM != nil {
			graphConfig.Libraries.HSMModules.SoftHSM = &graph.SoftHSMConfig{
				Library: staticConfig.HSMModules.SoftHSM.Library,
			}
		}

		if staticConfig.HSMModules.AKV != nil {
			graphConfig.Libraries.HSMModules.AKV = &graph.AKVConfig{
				URL: staticConfig.HSMModules.AKV.URL,
			}
		}
	}

	if staticConfig.DatabaseInfo.PostgreSQL.SQLClient != nil {
		graphConfig.Libraries.PersistenceFw.PostgreSQL.SQLClient = &graph.PostgresSQLClientConfig{
			MaxIdleConnections:    staticConfig.DatabaseInfo.PostgreSQL.SQLClient.MaxIdleConnections,
			MaxOpenConnections:    staticConfig.DatabaseInfo.PostgreSQL.SQLClient.MaxOpenConnections,
			MaxConnectionLifetime: staticConfig.DatabaseInfo.PostgreSQL.SQLClient.MaxConnectionLifetime,
		}
	}

	if staticConfig.Logger != nil {
		graphConfig.Libraries.Logger = &graph.LoggerConfig{
			LogLevel: &staticConfig.Logger.LogLevel,
		}
	}

	if staticConfig.RequestContext != nil {
		graphConfig.RequestContextConfig = &graph.RequestContextConfig{
			UserHeaderKey:        staticConfig.RequestContext.UserRequestHeader,
			ApplicationHeaderKey: staticConfig.RequestContext.ApplicationRequestHeader,
		}
	}

	if staticConfig.MetricsConfig != nil && staticConfig.MetricsConfig.PrometheusMetricsConfig != nil {
		graphConfig.Libraries.Metrics = &graph.MetricsConfig{
			Prometheus: graph.PrometheusConfig{
				Port:                staticConfig.MetricsConfig.PrometheusMetricsConfig.Port,
				Path:                staticConfig.MetricsConfig.PrometheusMetricsConfig.Path,
				MaxRequestsInFlight: staticConfig.MetricsConfig.PrometheusMetricsConfig.MaxRequestsInFlight,
				TimeoutInMillis:     staticConfig.MetricsConfig.PrometheusMetricsConfig.TimeoutInMillis,
				Namespace:           staticConfig.MetricsConfig.PrometheusMetricsConfig.Namespace,
			},
		}
	}
	return graphConfig
}

func shutDownServer(ctx context.Context, srv *http.Server) error {
	srv.SetKeepAlivesEnabled(false)
	return srv.Shutdown(ctx)
}

func printRoutes(ctx context.Context, router *mux.Router) {
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		var err error
		var methods []string
		var path string

		if path, err = route.GetPathTemplate(); err != nil {
			return err
		}
		if methods, err = route.GetMethods(); err != nil {
			return err
		}
		logger.LogEntry(ctx).Infof("%s: %s %s", route.GetName(), methods, path)
		return nil
	})
	if err != nil {
		logger.LogEntry(ctx).Errorf("error printing routes: %v", err)
	}
}

func printRPCMethods(ctx context.Context, methods []string) {
	for i := 0; i < len(methods); i++ {
		logger.LogEntry(ctx).Infof("[POST]: %s", methods[i])
	}
}
