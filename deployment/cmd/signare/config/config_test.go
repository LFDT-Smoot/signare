package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// databasePasswordEnv is the concrete environment variable the database password config key must resolve to.
// It is duplicated from the documented name on purpose, to pin config.go's prefix+replacer derivation.
const databasePasswordEnv = "SIGNARE_DATABASE_POSTGRESQL_PASSWORD"

func TestStaticConfigurationParsesServerLimits(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	const cfgYAML = `
server:
  maxRequestBodyBytes: 2097152
  maxHeaderBytes: 65536
`
	if err := v.ReadConfig(strings.NewReader(cfgYAML)); err != nil {
		t.Fatalf("reading config: %v", err)
	}

	var cfg StaticConfiguration
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatalf("unmarshalling config: %v", err)
	}

	if cfg.Server == nil {
		t.Fatalf("expected server config to be parsed, got nil")
	}
	if cfg.Server.MaxRequestBodyBytes == nil {
		t.Fatalf("expected maxRequestBodyBytes to be parsed, got nil")
	}
	if *cfg.Server.MaxRequestBodyBytes != 2097152 {
		t.Fatalf("maxRequestBodyBytes = %d, want 2097152", *cfg.Server.MaxRequestBodyBytes)
	}
	if cfg.Server.MaxHeaderBytes == nil {
		t.Fatalf("expected maxHeaderBytes to be parsed, got nil")
	}
	if *cfg.Server.MaxHeaderBytes != 65536 {
		t.Fatalf("maxHeaderBytes = %d, want 65536", *cfg.Server.MaxHeaderBytes)
	}
}

func TestStaticConfigurationServerLimitsOptional(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	const cfgYAML = `
logger:
  logLevel: 'debug'
`
	if err := v.ReadConfig(strings.NewReader(cfgYAML)); err != nil {
		t.Fatalf("reading config: %v", err)
	}

	var cfg StaticConfiguration
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatalf("unmarshalling config: %v", err)
	}

	if cfg.Server != nil {
		t.Fatalf("expected server config to be nil when omitted, got %+v", cfg.Server)
	}
}

func int64Ptr(v int64) *int64 { return &v }
func intPtr(v int) *int       { return &v }

func TestServerLimits(t *testing.T) {
	tests := []struct {
		name            string
		cfg             *StaticConfiguration
		wantBodyBytes   int64
		wantHeaderBytes int
	}{
		{
			name:            "nil config uses defaults",
			cfg:             nil,
			wantBodyBytes:   defaultMaxRequestBodyBytes,
			wantHeaderBytes: defaultMaxHeaderBytes,
		},
		{
			name:            "nil server section uses defaults",
			cfg:             &StaticConfiguration{},
			wantBodyBytes:   defaultMaxRequestBodyBytes,
			wantHeaderBytes: defaultMaxHeaderBytes,
		},
		{
			name:            "positive values are applied",
			cfg:             &StaticConfiguration{Server: &Server{MaxRequestBodyBytes: int64Ptr(2048), MaxHeaderBytes: intPtr(512)}},
			wantBodyBytes:   2048,
			wantHeaderBytes: 512,
		},
		{
			name:            "zero values fall back to defaults",
			cfg:             &StaticConfiguration{Server: &Server{MaxRequestBodyBytes: int64Ptr(0), MaxHeaderBytes: intPtr(0)}},
			wantBodyBytes:   defaultMaxRequestBodyBytes,
			wantHeaderBytes: defaultMaxHeaderBytes,
		},
		{
			name:            "negative values fall back to defaults",
			cfg:             &StaticConfiguration{Server: &Server{MaxRequestBodyBytes: int64Ptr(-1), MaxHeaderBytes: intPtr(-1)}},
			wantBodyBytes:   defaultMaxRequestBodyBytes,
			wantHeaderBytes: defaultMaxHeaderBytes,
		},
		{
			name:            "omitted field keeps its default",
			cfg:             &StaticConfiguration{Server: &Server{MaxRequestBodyBytes: int64Ptr(4096)}},
			wantBodyBytes:   4096,
			wantHeaderBytes: defaultMaxHeaderBytes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBody, gotHeader := tt.cfg.ServerLimits()
			if gotBody != tt.wantBodyBytes {
				t.Errorf("maxBodyBytes = %d, want %d", gotBody, tt.wantBodyBytes)
			}
			if gotHeader != tt.wantHeaderBytes {
				t.Errorf("maxHeaderBytes = %d, want %d", gotHeader, tt.wantHeaderBytes)
			}
		})
	}
}

func pgConfig(sslmode string) *StaticConfiguration {
	return &StaticConfiguration{DatabaseInfo: DatabaseInfo{PostgreSQL: &PostgreSQLInfo{SSLMode: sslmode}}}
}

func TestInsecureSettingsWarnings(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *StaticConfiguration
		wantWarn bool
	}{
		{name: "nil config", cfg: nil, wantWarn: false},
		{name: "nil postgres section", cfg: &StaticConfiguration{}, wantWarn: false},
		// A shape assertion, not a regression guard: with one check in the function there is nothing
		// for a missing database section to short-circuit, so this case passes against the early
		// return it replaced too. It pins the contract a second check will rely on.
		{name: "nil postgres section with other sections present", cfg: &StaticConfiguration{Logger: &Logger{LogLevel: "info"}, Server: &Server{}}, wantWarn: false},
		{name: "sslmode disable warns", cfg: pgConfig("disable"), wantWarn: true},
		{name: "sslmode disable is case-insensitive", cfg: pgConfig("DISABLE"), wantWarn: true},
		{name: "sslmode allow warns", cfg: pgConfig("allow"), wantWarn: true},
		{name: "sslmode prefer warns", cfg: pgConfig("prefer"), wantWarn: true},
		{name: "unrecognised sslmode warns", cfg: pgConfig("bogus"), wantWarn: true},
		{name: "empty sslmode warns", cfg: pgConfig(""), wantWarn: true},
		{name: "sslmode require does not warn", cfg: pgConfig("require"), wantWarn: false},
		{name: "sslmode verify-ca does not warn", cfg: pgConfig("verify-ca"), wantWarn: false},
		{name: "sslmode verify-full does not warn", cfg: pgConfig("verify-full"), wantWarn: false},
		{name: "sslmode is trimmed and lowercased", cfg: pgConfig("  Require  "), wantWarn: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := tt.cfg.InsecureSettingsWarnings()
			if got := len(warnings) > 0; got != tt.wantWarn {
				t.Fatalf("InsecureSettingsWarnings() = %v, wantWarn = %v", warnings, tt.wantWarn)
			}
		})
	}
}

// TestInsecureListenAddressWarningsNonLiteralAddresses covers the inputs that are not IP literals.
// There is no oracle for these: whether a name binds loopback is a question about a resolver, not
// about the string, and the check deliberately answers it without resolving. They are enumerated, and
// enumeration is all the coverage they have. The IP literals are covered differentially below.
func TestInsecureListenAddressWarningsNonLiteralAddresses(t *testing.T) {
	tests := []struct {
		name          string
		listenAddress string
		wantWarn      bool
	}{
		{name: "localhost does not warn", listenAddress: "localhost", wantWarn: false},
		{name: "localhost is case-insensitive", listenAddress: "LocalHost", wantWarn: false},
		{name: "localhost is trimmed", listenAddress: "  localhost  ", wantWarn: false},
		{name: "a loopback literal is trimmed", listenAddress: " 127.0.0.1 ", wantWarn: false},
		{name: "the empty address warns, it binds every interface", listenAddress: "", wantWarn: true},
		{name: "whitespace only warns, it is the empty address", listenAddress: "   ", wantWarn: true},
		{name: "another name warns, it is not resolved", listenAddress: "signare.internal", wantWarn: true},
		{name: "a loopback name that is not localhost warns", listenAddress: "localhost.localdomain", wantWarn: true},
		{name: "a zoned link-local literal warns, it is routable", listenAddress: "fe80::1%eth0", wantWarn: true},
		{name: "an octal-looking literal warns, it is not a valid address", listenAddress: "0177.0.0.1", wantWarn: true},
		{name: "a host:port value warns, it is not an address", listenAddress: "127.0.0.1:32325", wantWarn: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := InsecureListenAddressWarnings(tt.listenAddress)
			if got := len(warnings) > 0; got != tt.wantWarn {
				t.Fatalf("InsecureListenAddressWarnings(%q) = %v, wantWarn = %v", tt.listenAddress, warnings, tt.wantWarn)
			}
		})
	}
}

func TestListenAddressHost(t *testing.T) {
	tests := []struct {
		name          string
		listenAddress string
		want          string
	}{
		{name: "a bare IPv4 literal is unchanged", listenAddress: "127.0.0.1", want: "127.0.0.1"},
		{name: "a bare IPv6 literal is unchanged", listenAddress: "::1", want: "::1"},
		{name: "a bracketed IPv6 literal is unwrapped", listenAddress: "[::1]", want: "::1"},
		{name: "bracketed unspecified is unwrapped", listenAddress: "[::]", want: "::"},
		{name: "a bracketed zoned literal is unwrapped", listenAddress: "[fe80::1%eth0]", want: "fe80::1%eth0"},
		{name: "whitespace is trimmed", listenAddress: "  127.0.0.1  ", want: "127.0.0.1"},
		{name: "whitespace around brackets is trimmed", listenAddress: "  [::1]  ", want: "::1"},
		{name: "a name is unchanged", listenAddress: "localhost", want: "localhost"},
		{name: "the empty address is unchanged", listenAddress: "", want: ""},
		// Brackets come off only when what is inside them is an address. These are left alone, so the
		// warning check and the listener both reject them instead of one of them guessing.
		{name: "a doubled bracket is not unwrapped", listenAddress: "[[::1]]", want: "[[::1]]"},
		{name: "brackets round a name are not unwrapped", listenAddress: "[signare.internal]", want: "[signare.internal]"},
		{name: "an unmatched leading bracket is untouched", listenAddress: "[::1", want: "[::1"},
		{name: "an unmatched trailing bracket is untouched", listenAddress: "::1]", want: "::1]"},
		{name: "a lone bracket is untouched", listenAddress: "[", want: "["},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ListenAddressHost(tt.listenAddress)
			if got != tt.want {
				t.Fatalf("ListenAddressHost(%q) = %q, want %q", tt.listenAddress, got, tt.want)
			}
			// Both the listener and the warning check call this, the second of them on a value the
			// first already normalised, so a second pass must not change the answer again.
			if again := ListenAddressHost(got); again != got {
				t.Errorf("ListenAddressHost is not idempotent: %q then %q", got, again)
			}
		})
	}
}

// TestInsecureListenAddressWarningsBracketedLoopback guards the regression this check had: a
// bracketed IPv6 loopback binds loopback, and has to be recognised as such rather than warned about.
func TestInsecureListenAddressWarningsBracketedLoopback(t *testing.T) {
	silent := []string{"::1", "[::1]", "  [::1]  ", "[::ffff:127.0.0.1]", "[::1%lo0]"}
	for _, listenAddress := range silent {
		if warnings := InsecureListenAddressWarnings(listenAddress); len(warnings) > 0 {
			t.Errorf("InsecureListenAddressWarnings(%q) = %v, want no warning: it binds loopback", listenAddress, warnings)
		}
	}

	warned := []string{"[::]", "[2001:db8::1]", "[fe80::1%eth0]"}
	for _, listenAddress := range warned {
		if warnings := InsecureListenAddressWarnings(listenAddress); len(warnings) == 0 {
			t.Errorf("InsecureListenAddressWarnings(%q) = no warning, want one: it is not loopback", listenAddress)
		}
	}
}

// TestInsecureListenAddressWarningsNameTheExposure checks that the three exposure branches say three
// different things. The message is the whole product of this function, and a warning that fires but
// misdescribes why is barely better than none: asserting only that some warning appeared would pass
// with all three branches collapsed into one string, or with two of them swapped.
func TestInsecureListenAddressWarningsNameTheExposure(t *testing.T) {
	tests := []struct {
		name          string
		listenAddress string
		wantExposure  string
	}{
		{name: "unspecified IPv4", listenAddress: "0.0.0.0", wantExposure: "binds every network interface"},
		{name: "unspecified IPv6", listenAddress: "::", wantExposure: "binds every network interface"},
		{name: "the empty address", listenAddress: "", wantExposure: "binds every network interface"},
		{name: "a private literal", listenAddress: "10.0.0.5", wantExposure: "is reachable from every host that can route to it"},
		{name: "a documentation-range IPv6 literal", listenAddress: "2001:db8::1", wantExposure: "is reachable from every host that can route to it"},
		{name: "a name", listenAddress: "signare.internal", wantExposure: "cannot be confirmed to be loopback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := InsecureListenAddressWarnings(tt.listenAddress)
			if len(warnings) != 1 {
				t.Fatalf("InsecureListenAddressWarnings(%q) = %v, want exactly one warning", tt.listenAddress, warnings)
			}
			if !strings.Contains(warnings[0], tt.wantExposure) {
				t.Errorf("InsecureListenAddressWarnings(%q) = %q, want it to say %q", tt.listenAddress, warnings[0], tt.wantExposure)
			}
			// The address as it was configured has to appear, or the operator cannot act on it.
			if !strings.Contains(warnings[0], strconv.Quote(tt.listenAddress)) {
				t.Errorf("InsecureListenAddressWarnings(%q) = %q, want it to quote the address", tt.listenAddress, warnings[0])
			}
		})
	}
}

// TestInsecureListenAddressWarningsMatchLoopback checks the warn decision for every IP literal against
// a second implementation. The check classifies with net/netip; the expectation here comes from net.IP
// over addresses constructed from their bytes and rendered with String(), so neither the parser nor
// the loopback predicate is shared with the code under test. A wrong idea of what loopback means has
// to be wrong in both packages to pass.
func TestInsecureListenAddressWarningsMatchLoopback(t *testing.T) {
	var corpus []net.IP
	// Sweep the first octet across the 127/8 boundary, then the rest of 127/8, which is loopback in
	// full and not just 127.0.0.1.
	for octet := 0; octet < 256; octet++ {
		corpus = append(corpus, net.IP{byte(octet), 0, 0, 1}, net.IP{byte(octet), 255, 255, 254})
		corpus = append(corpus, net.IP{127, byte(octet), 0, 1}, net.IP{127, 0, 0, byte(octet)})
	}
	// Sweep the low byte of the IPv6 zero prefix, which covers "::" and "::1" and their neighbours.
	for low := 0; low < 256; low++ {
		v6 := make(net.IP, net.IPv6len)
		v6[net.IPv6len-1] = byte(low)
		corpus = append(corpus, v6)
		v6Global := make(net.IP, net.IPv6len)
		v6Global[0] = 0x20
		v6Global[net.IPv6len-1] = byte(low)
		corpus = append(corpus, v6Global)
	}
	corpus = append(corpus, net.IPv6loopback, net.IPv6zero, net.IPv4zero, net.IPv4(127, 0, 0, 1), net.IPv4(10, 0, 0, 5))

	var loopbacks, exposed int
	for _, ip := range corpus {
		listenAddress := ip.String()
		wantWarn := !ip.IsLoopback()
		if wantWarn {
			exposed++
		} else {
			loopbacks++
		}
		warnings := InsecureListenAddressWarnings(listenAddress)
		if got := len(warnings) > 0; got != wantWarn {
			t.Errorf("InsecureListenAddressWarnings(%q) = %v, wantWarn = %v", listenAddress, warnings, wantWarn)
		}
	}

	// Guard against a corpus that agrees with the check because it only holds one kind of address.
	if loopbacks == 0 || exposed == 0 {
		t.Fatalf("degenerate corpus: %d loopback, %d exposed", loopbacks, exposed)
	}
}

func writeStaticConfig(t *testing.T, dir, password string) {
	t.Helper()
	contents := "database:\n" +
		"  postgresql:\n" +
		"    host: 'localhost'\n" +
		"    port: 5432\n" +
		"    scheme: 'postgres'\n" +
		"    database: 'db_signare'\n" +
		"    username: 'signare'\n" +
		"    password: '" + password + "'\n" +
		"    sslmode: 'require'\n"
	if err := os.WriteFile(filepath.Join(dir, staticConfigurationFileName), []byte(contents), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
}

func TestGetStaticConfigurationPasswordFromEnv(t *testing.T) {
	dir := t.TempDir()
	writeStaticConfig(t, dir, "__CHANGE_ME__")
	t.Setenv(databasePasswordEnv, "secret-from-env")

	cfg, err := GetStaticConfiguration(dir)
	if err != nil {
		t.Fatalf("GetStaticConfiguration: %v", err)
	}
	if got := cfg.DatabaseInfo.PostgreSQL.Password; got != "secret-from-env" {
		t.Fatalf("password = %q, want it overridden by %s", got, databasePasswordEnv)
	}
}

func TestGetStaticConfigurationPasswordFromFileWhenEnvUnset(t *testing.T) {
	dir := t.TempDir()
	writeStaticConfig(t, dir, "file-password")
	// An empty value is treated as unset by viper, so the file value must win.
	t.Setenv(databasePasswordEnv, "")

	cfg, err := GetStaticConfiguration(dir)
	if err != nil {
		t.Fatalf("GetStaticConfiguration: %v", err)
	}
	if got := cfg.DatabaseInfo.PostgreSQL.Password; got != "file-password" {
		t.Fatalf("password = %q, want the file value when %s is unset", got, databasePasswordEnv)
	}
}

// TestGetStaticConfigurationEnvOverridesNonPasswordKey guards the documented AutomaticEnv behaviour: any
// key present in the YAML file can be overridden by its SIGNARE_-prefixed environment variable, not just
// the password.
func TestGetStaticConfigurationEnvOverridesNonPasswordKey(t *testing.T) {
	dir := t.TempDir()
	writeStaticConfig(t, dir, "file-password")
	t.Setenv("SIGNARE_DATABASE_POSTGRESQL_HOST", "db.example.internal")

	cfg, err := GetStaticConfiguration(dir)
	if err != nil {
		t.Fatalf("GetStaticConfiguration: %v", err)
	}
	if got := cfg.DatabaseInfo.PostgreSQL.Host; got != "db.example.internal" {
		t.Fatalf("host = %q, want it overridden by SIGNARE_DATABASE_POSTGRESQL_HOST", got)
	}
}

// TestGetStaticConfigurationPasswordEnvOnlyWhenAbsentFromFile guards the explicit BindEnv: the password
// can be supplied purely via the environment even when the YAML file omits the key entirely. AutomaticEnv
// alone does not surface a key that is absent from the file, so this exercises the binding specifically.
func TestGetStaticConfigurationPasswordEnvOnlyWhenAbsentFromFile(t *testing.T) {
	dir := t.TempDir()
	contents := "database:\n" +
		"  postgresql:\n" +
		"    host: 'localhost'\n" +
		"    port: 5432\n" +
		"    scheme: 'postgres'\n" +
		"    database: 'db_signare'\n" +
		"    username: 'signare'\n" +
		"    sslmode: 'require'\n"
	if err := os.WriteFile(filepath.Join(dir, staticConfigurationFileName), []byte(contents), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv(databasePasswordEnv, "secret-from-env")

	cfg, err := GetStaticConfiguration(dir)
	if err != nil {
		t.Fatalf("GetStaticConfiguration: %v", err)
	}
	if got := cfg.DatabaseInfo.PostgreSQL.Password; got != "secret-from-env" {
		t.Fatalf("password = %q, want it supplied via %s when omitted from the file", got, databasePasswordEnv)
	}
}
