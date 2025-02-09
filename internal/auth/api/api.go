package api

import (
	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/service"
	desc "github.com/Dmitriy-M1319/crystal-auth/pkg/crystal-auth/v1"
)

type AuthApiImplementation struct {
	desc.UnimplementedAuthServiceServer
	service *service.AuthService
}

func NewAuthApiImplementation(srv *service.AuthService) *AuthApiImplementation {
	return &AuthApiImplementation{service: srv}
}
