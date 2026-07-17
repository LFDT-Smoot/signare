// Package config defines configuration parameters of Signare.
package config

import (
	"fmt"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/spf13/viper"
)

const (
	staticConfigurationFileName      = "signare-config.yml"
	staticConfigurationFileExtension = "yaml"

	// envPrefix namespaces every environment-variable override of the static configuration, so any key
	// is overridable via SIGNARE_<PATH> (e.g. database.postgresql.host -> SIGNARE_DATABASE_POSTGRESQL_HOST).
	envPrefix = "SIGNARE"
	// databasePasswordConfigKey is the only key bound explicitly to the environment (see GetStaticConfiguration),
	// so the database password can be supplied via SIGNARE_DATABASE_POSTGRESQL_PASSWORD even when it is
	// omitted from the YAML file. The env-var name is derived from envPrefix and this key.
	databasePasswordConfigKey = "database.postgresql.password"
)

// secureSSLModes are the PostgreSQL sslmode values that guarantee an encrypted database connection. Any
// other value can transmit database traffic in cleartext: 'disable' never encrypts, 'allow' tries
// plaintext first, and 'prefer' (libpq's own default) silently falls back to plaintext when the server
// does not offer TLS. An unrecognised or misspelled mode is treated as insecure as well.
var secureSSLModes = map[string]bool{
	"require":     true,
	"verify-ca":   true,
	"verify-full": true,
}

// StaticConfiguration configures the Signare system
type StaticConfiguration struct {
	// Logger configuration for server logging.
	Logger *Logger `mapstructure:"logger" valid:"optional"`
	// DatabaseInfo database information.
	DatabaseInfo DatabaseInfo `mapstructure:"database" valid:"required"`
	// RequestContext defines the context of a request
	RequestContext *RequestContext `mapstructure:"requestContext" valid:"optional"`
	// MetricsConfig provides configuration to expose numeric metrics.
	MetricsConfig *MetricsConfig `mapstructure:"metrics" valid:"optional"`
	// HSMModules provides the configuration of the hardware security modules.
	HSMModules *HSMModules `mapstructure:"hsmmodules" valid:"optional"`
	// Server configures HTTP/RPC server request limits.
	Server *Server `mapstructure:"server" valid:"optional"`
}

// Server configures request size limits applied to the HTTP and JSON-RPC entrypoints. A non-positive
// value for either field is treated as unset and falls back to the default.
type Server struct {
	// MaxRequestBodyBytes is the maximum accepted request body size in bytes. Oversized bodies are
	// rejected before unbounded allocation. Applies to both the REST and JSON-RPC entrypoints.
	MaxRequestBodyBytes *int64 `mapstructure:"maxRequestBodyBytes" valid:"optional"`
	// MaxHeaderBytes is the maximum accepted size of request headers in bytes, set on every server.
	MaxHeaderBytes *int `mapstructure:"maxHeaderBytes" valid:"optional"`
}

const (
	// defaultMaxRequestBodyBytes bounds an incoming request body when the limit is not set in config.
	// 1 MiB comfortably fits a full batch of typical signing requests (a value-transfer
	// eth_signTransaction is a few hundred bytes, so a 100-element batch is ~50 KB) while still
	// bounding allocation. The body size scales with the JSON-RPC batch element cap, so workloads that
	// submit large-calldata batches may need a higher value; the limit is configurable for that reason.
	defaultMaxRequestBodyBytes int64 = 1 << 20
	// defaultMaxHeaderBytes bounds incoming request headers when the limit is not set in config; 1 MiB
	// matches Go's http.DefaultMaxHeaderBytes.
	defaultMaxHeaderBytes = 1 << 20
)

// ServerLimits returns the effective request body and header byte limits, applying the defaults when
// the optional server configuration or an individual field is absent. A non-positive configured value
// is treated as "use the default" so the size protections cannot be silently disabled by a
// misconfiguration.
func (c *StaticConfiguration) ServerLimits() (maxBodyBytes int64, maxHeaderBytes int) {
	maxBodyBytes = defaultMaxRequestBodyBytes
	maxHeaderBytes = defaultMaxHeaderBytes
	if c == nil || c.Server == nil {
		return maxBodyBytes, maxHeaderBytes
	}
	if v := c.Server.MaxRequestBodyBytes; v != nil && *v > 0 {
		maxBodyBytes = *v
	}
	if v := c.Server.MaxHeaderBytes; v != nil && *v > 0 {
		maxHeaderBytes = *v
	}
	return maxBodyBytes, maxHeaderBytes
}

// InsecureSettingsWarnings returns human-readable warnings for configured values that are unsafe for a
// production deployment. It performs no logging so the caller controls how the warnings are surfaced.
// Currently it flags any sslmode that does not guarantee an encrypted connection (see secureSSLModes),
// which would send all database traffic (including the HSM slot credentials stored in the database) in
// cleartext.
func (c *StaticConfiguration) InsecureSettingsWarnings() []string {
	if c == nil || c.DatabaseInfo.PostgreSQL == nil {
		return nil
	}
	var warnings []string
	sslMode := strings.ToLower(strings.TrimSpace(c.DatabaseInfo.PostgreSQL.SSLMode))
	if !secureSSLModes[sslMode] {
		warnings = append(warnings, fmt.Sprintf("database.postgresql.sslmode is set to %q: database traffic, including the HSM slot credentials stored in the database, may be sent unencrypted. Set sslmode to 'require' or stronger ('verify-ca', 'verify-full') for production.", c.DatabaseInfo.PostgreSQL.SSLMode))
	}
	return warnings
}

// Logger specification
type Logger struct {
	// LogLevel as level of logs to display
	LogLevel string `mapstructure:"logLevel" valid:"required"`
}

// DatabaseInfo configures Signare database access
type DatabaseInfo struct {
	// PostgreSQL database configuration
	PostgreSQL *PostgreSQLInfo `mapstructure:"postgresql"`
}

// RequestContext
type RequestContext struct {
	// UserRequestHeader user in request header
	UserRequestHeader string `mapstructure:"userRequestHeader"`
	// ApplicationRequestHeader application in request header
	ApplicationRequestHeader string `mapstructure:"applicationRequestHeader"`
}

// PostgreSQLInfo defines the access to a SQL-compatible database system
type PostgreSQLInfo struct {
	// Host of database system
	Host string `mapstructure:"host" valid:"required~hosts is mandatory in SQL DB config"`
	// Port of database system
	Port int `mapstructure:"port" valid:"required~port is mandatory in SQL DB config"`
	// Scheme of database system
	Scheme string `mapstructure:"scheme" valid:"required~scheme is mandatory in SQL DB config"`
	// Username to use in database system
	Username string `mapstructure:"username" json:"-"`
	// Password to use with username in database system
	Password string `mapstructure:"password" json:"-"`
	// SSLMode to use in database system
	SSLMode string `mapstructure:"sslmode" valid:"required~sslmode is mandatory in SQL DB config"`
	// Database to access to in database system
	Database string `mapstructure:"database" valid:"required~database is mandatory in SQL DB config"`
	// SQLClient database client configuration
	SQLClient *PostgreSQLClient `mapstructure:"sqlClient"`
}

// PostgreSQLClient configures the database client
type PostgreSQLClient struct {
	// MaxIdleConnections max idle connections for the database/sql handle
	MaxIdleConnections *int `mapstructure:"maxIdleConnections"`
	// MaxOpenConnections max open connections for the database/sql handle
	MaxOpenConnections *int `mapstructure:"maxOpenConnections"`
	// MaxConnectionLifetime max connection lifetime for the database/sql handle
	MaxConnectionLifetime *int `mapstructure:"maxConnectionLifetime"`
}

// MetricsConfig configures Signare to export metrics
type MetricsConfig struct {
	// Prometheus Metric Record configuration
	PrometheusMetricsConfig *PrometheusMetricsConfig `mapstructure:"prometheus"  valid:"required"`
}

// PrometheusMetricsConfig provides configuration to expose prometheus metrics
type PrometheusMetricsConfig struct {
	// Port where prometheus metrics will be exposed. Default 9780 aligned with not used port from https://github.com/prometheus/prometheus/wiki/Default-port-allocations
	Port *int `mapstructure:"port" valid:"optional"`
	// Path where prometheus
	Path *string `mapstructure:"path" valid:"optional"`
	// The number of concurrent HTTP requests is limited to MaxRequestsInFlight. See golang prometheus client for deeper documentation
	MaxRequestsInFlight *int `mapstructure:"maxRequestsInFlight" valid:"optional"`
	// If handling a request takes longer than Timeout, it is responded to
	// with 503 ServiceUnavailable and a suitable Message. See golang prometheus client for deeper documentation
	TimeoutInMillis *int `mapstructure:"timeoutInMillis" valid:"optional"`
	// Namespace to prefix metric names
	Namespace *string `mapstructure:"namespace" valid:"optional"`
}

// HSMModules configures the hardware security modules.
type HSMModules struct {
	// SoftHSM configuration for SoftHSM.
	SoftHSM *SoftHSMConfig `mapstructure:"softhsm" valid:"optional"`
	// AKV configuration for AKV.
	AKV *AKVConfig `mapstructure:"akv" valid:"optional"`
}

// SoftHSMConfig configures a SoftHSM in Signare.
type SoftHSMConfig struct {
	Library string `mapstructure:"lib" valid:"required"`
}

// AKVConfig configures AKV in Signare.
type AKVConfig struct {
	URL string `mapstructure:"url" valid:"required"`
}

func GetStaticConfiguration(path string) (*StaticConfiguration, error) {
	v := viper.New()
	v.SetConfigName(staticConfigurationFileName)
	v.SetConfigType(staticConfigurationFileExtension)
	v.AddConfigPath(path)
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	// AutomaticEnv lets any configuration key present in the file be overridden by its SIGNARE_-prefixed
	// environment variable (dots become underscores), e.g. SIGNARE_DATABASE_POSTGRESQL_HOST or
	// SIGNARE_LOGGER_LOGLEVEL. This mirrors the behaviour of the CLI-flag viper configured in main() and
	// supports 12-factor style deployments; the database password override is documented in the
	// configuration reference.
	v.AutomaticEnv()
	// Bind the database password explicitly so it can be supplied via the environment even when the key
	// is omitted from the YAML file entirely. AutomaticEnv only surfaces a key that is present in the
	// file, so without this binding an env-only password would be ignored. The prefix and replacer above
	// derive the variable name, SIGNARE_DATABASE_POSTGRESQL_PASSWORD.
	if err := v.BindEnv(databasePasswordConfigKey); err != nil {
		return nil, fmt.Errorf("error binding environment variable for [%s] [error:%w]", databasePasswordConfigKey, err)
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading static config file placed in path [%s] [error:%w]", path, err)
	}

	var staticConfiguration StaticConfiguration
	if err := v.Unmarshal(&staticConfiguration); err != nil {
		return nil, fmt.Errorf("error unmarshalling static config file placed in path [%s] [error:%w]", path, err)
	}
	valid, err := govalidator.ValidateStruct(staticConfiguration)
	if !valid || err != nil {
		return nil, fmt.Errorf("error validating static config file placed in path[%s] [error:%w]", path, err)
	}

	return &staticConfiguration, nil
}
