package api

import (
	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/service"
	desc "github.com/Dmitriy-M1319/crystal-auth/pkg/crystal-auth/v1"
	"go.opentelemetry.io/otel/trace"
)

type AuthApiImplementation struct {
	desc.UnimplementedAuthServiceServer
	service *service.AuthService
	tracer  trace.Tracer
}

func NewAuthApiImplementation(srv *service.AuthService, t trace.Tracer) *AuthApiImplementation {
	return &AuthApiImplementation{service: srv, tracer: t}
}
