package api

import (
	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/service"
	"github.com/Dmitriy-M1319/crystal-auth/opentelemetry"
	desc "github.com/Dmitriy-M1319/crystal-auth/pkg/crystal-auth/v1"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

type AuthApiImplementation struct {
	desc.UnimplementedAuthServiceServer
	service        *service.AuthService
	tracer         trace.Tracer
	metricProvider *opentelemetry.ApiMetricsProvider
}

func NewAuthApiImplementation(srv *service.AuthService, t trace.Tracer, m metric.Meter) *AuthApiImplementation {
	prov, err := opentelemetry.NewApiMetricsProvider(m)
	if err != nil {
		log.Err(err).Msg("Failed to create metrics")
	}
	return &AuthApiImplementation{service: srv, tracer: t, metricProvider: prov}
}
