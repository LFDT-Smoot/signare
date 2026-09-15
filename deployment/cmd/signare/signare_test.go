package main

import (
	"testing"

	"github.com/lfdt-smoot/signare/deployment/cmd/signare/config"
	"github.com/lfdt-smoot/signare/deployment/cmd/signare/flags"

	"github.com/spf13/cobra"
)

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
		{name: "bind-all collapses to a bare port", host: defaultAllAddresses, port: defaultRPCPort, want: ":4545"},
		{name: "a name keeps the host", host: "localhost", port: defaultPrometheusPort, want: "localhost:9785"},
		{name: "any other address keeps the host", host: "10.0.0.5", port: defaultHTTPPort, want: "10.0.0.5:32325"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := listenerAddress(tt.host, tt.port); got != tt.want {
				t.Errorf("listenerAddress(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
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
			host:             defaultAllAddresses,
			prometheusConfig: &config.PrometheusMetricsConfig{Port: &configuredPort},
			want:             ":9092",
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
