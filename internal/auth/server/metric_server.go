package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func createPrometheusMetricServer(promServer string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	gatewayServer := &http.Server{
		Addr:    promServer,
		Handler: mux,
	}

	return gatewayServer
}
