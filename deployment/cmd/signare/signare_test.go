package main

import (
	"net"
	"strconv"
	"testing"

	"github.com/lfdt-smoot/signare/deployment/cmd/signare/config"
	"github.com/lfdt-smoot/signare/deployment/cmd/signare/flags"

	"github.com/spf13/cobra"
)

// Known gaps. Both call sites need a live database and a built graph, so only the helpers behind them
// are covered here:
//   - nothing asserts that startServer logs the bind warning, only that the warning exists;
//   - nothing asserts that startMetricsServers forwards the host it is handed to the listener.

func TestListenAddressFlagDefaultsToLoopback(t *testing.T) {
	cmd := &cobra.Command{Use: "signare-test"}
	configureCmd(cmd)

	listenAddress := cmd.Flags().Lookup(flags.ListenAddressFlag)
	if listenAddress == nil {
		t.Fatalf("flag --%s is not registered", flags.ListenAddressFlag)
	}
	if listenAddress.DefValue != "127.0.0.1" {
		t.Errorf("--%s default = %q, want %q", flags.ListenAddressFlag, listenAddress.DefValue, "127.0.0.1")
	}
	// The literal above pins the documented value; this pins the property that matters, so the default
	// cannot drift to an address the startup check would warn about.
	if warnings := config.InsecureListenAddressWarnings(listenAddress.DefValue); len(warnings) > 0 {
		t.Errorf("the default --%s is not loopback: %v", flags.ListenAddressFlag, warnings)
	}
}

func TestListenerAddress(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "loopback keeps the host", host: "127.0.0.1", port: defaultHTTPPort, want: "127.0.0.1:32325"},
		{name: "bind-all keeps the host", host: "0.0.0.0", port: defaultRPCPort, want: "0.0.0.0:4545"},
		{name: "a name keeps the host", host: "localhost", port: defaultPrometheusPort, want: "localhost:9785"},
		{name: "any other address keeps the host", host: "10.0.0.5", port: defaultHTTPPort, want: "10.0.0.5:32325"},
		{name: "IPv6 loopback is bracketed", host: "::1", port: defaultHTTPPort, want: "[::1]:32325"},
		{name: "a zoned literal is bracketed", host: "fe80::1%eth0", port: defaultHTTPPort, want: "[fe80::1%eth0]:32325"},
		{name: "IPv6 bind-all is bracketed", host: "::", port: defaultRPCPort, want: "[::]:4545"},
		{name: "an IPv4-mapped IPv6 literal is bracketed", host: "::ffff:127.0.0.1", port: defaultHTTPPort, want: "[::ffff:127.0.0.1]:32325"},
		{name: "an empty host binds every interface", host: "", port: defaultHTTPPort, want: ":32325"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := listenerAddress(tt.host, tt.port)
			if got != tt.want {
				t.Fatalf("listenerAddress(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
			}
			// The expected strings above are only as good as the model that wrote them, so the
			// address is also put back through the parser net.Listen itself uses. "%s:%d" formatting
			// satisfied a table like this one for every IPv4 case while producing "::1:32325" for the
			// IPv6 ones, which fails here with "too many colons in address", as it does at bind time.
			gotHost, gotPort, err := net.SplitHostPort(got)
			if err != nil {
				t.Fatalf("net.SplitHostPort(%q): %v", got, err)
			}
			if gotHost != tt.host {
				t.Errorf("host round trip: net.SplitHostPort(%q) host = %q, want %q", got, gotHost, tt.host)
			}
			if gotPort != strconv.Itoa(tt.port) {
				t.Errorf("port round trip: net.SplitHostPort(%q) port = %q, want %d", got, gotPort, tt.port)
			}
		})
	}
}

// TestConfiguredListenAddressReachesTheListener runs the spellings an operator might plausibly write
// through the path startServer uses, config.ListenAddressHost then listenerAddress, and requires that
// each one both parses as a bind address and is vetted as the address it actually binds.
//
// These two were separated before: the listener bracketed whatever it was handed, so "[::1]" arrived
// double-bracketed and unbindable, while the check could not parse the brackets either and warned that
// a loopback bind could not be confirmed. Neither was visible from a test of either half alone.
func TestConfiguredListenAddressReachesTheListener(t *testing.T) {
	tests := []struct {
		configured string
		wantWarn   bool
	}{
		{configured: "127.0.0.1", wantWarn: false},
		{configured: "  127.0.0.1  ", wantWarn: false},
		{configured: "localhost", wantWarn: false},
		{configured: "::1", wantWarn: false},
		{configured: "[::1]", wantWarn: false},
		{configured: "[::ffff:127.0.0.1]", wantWarn: false},
		{configured: "0.0.0.0", wantWarn: true},
		{configured: "::", wantWarn: true},
		{configured: "[::]", wantWarn: true},
		{configured: "", wantWarn: true},
		// Both of these bind every interface, which is why they must warn. Neither reads as
		// unspecified without help: netip does not unmap before testing, and "[]" is not a literal.
		{configured: "::ffff:0.0.0.0", wantWarn: true},
		{configured: "[]", wantWarn: true},
		{configured: "10.0.0.5", wantWarn: true},
		{configured: "[2001:db8::1]", wantWarn: true},
	}

	for _, tt := range tests {
		t.Run(tt.configured, func(t *testing.T) {
			host := config.ListenAddressHost(tt.configured)

			addr := listenerAddress(host, defaultHTTPPort)
			if _, _, err := net.SplitHostPort(addr); err != nil {
				t.Errorf("--listen-address %q builds %q, which net.Listen rejects: %v", tt.configured, addr, err)
			}

			if gotWarn := len(config.InsecureListenAddressWarnings(host)) > 0; gotWarn != tt.wantWarn {
				t.Errorf("--listen-address %q: warned = %v, want %v", tt.configured, gotWarn, tt.wantWarn)
			}
		})
	}
}

func TestMetricsListenerAddressHonoursListenAddress(t *testing.T) {
	configuredPort := 9092
	tests := []struct {
		name             string
		host             string
		prometheusConfig *config.PrometheusMetricsConfig
		want             string
	}{
		{
			name:             "configured port binds the listen address, not every interface",
			host:             "127.0.0.1",
			prometheusConfig: &config.PrometheusMetricsConfig{Port: &configuredPort},
			want:             "127.0.0.1:9092",
		},
		{
			name:             "default port binds the listen address",
			host:             "127.0.0.1",
			prometheusConfig: &config.PrometheusMetricsConfig{},
			want:             "127.0.0.1:9785",
		},
		{
			name:             "bind-all is still available",
			host:             "0.0.0.0",
			prometheusConfig: &config.PrometheusMetricsConfig{Port: &configuredPort},
			want:             "0.0.0.0:9092",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := metricsListenerAddress(tt.host, tt.prometheusConfig); got != tt.want {
				t.Errorf("metricsListenerAddress(%q, %+v) = %q, want %q", tt.host, tt.prometheusConfig, got, tt.want)
			}
		})
	}
}
