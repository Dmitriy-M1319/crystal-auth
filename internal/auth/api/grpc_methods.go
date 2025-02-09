package api

import (
	"context"
	pb "github.com/Dmitriy-M1319/crystal-auth/pkg/crystal-auth/v1"
	"github.com/rs/zerolog"
	"os"
)

var logger = zerolog.New(os.Stdout)

func (impl *AuthApiImplementation) Register(ctx context.Context, r *pb.UserInfo) (*pb.JwtToken, error) {
	logger.Info().Msg("Register")
	return &pb.JwtToken{Token: "token"}, nil
}

func (impl *AuthApiImplementation) Login(ctx context.Context, r *pb.UserCredentials) (*pb.JwtToken, error) {
	logger.Info().Msg("Login")
	return &pb.JwtToken{Token: "token"}, nil
}

func (impl *AuthApiImplementation) Authorize(ctx context.Context, r *pb.JwtToken) (*pb.Access, error) {
	logger.Info().Msg("Authorize")
	return &pb.Access{Accessed: true}, nil
}

func (impl *AuthApiImplementation) Logout(ctx context.Context, r *pb.JwtToken) (*pb.Empty, error) {
	logger.Info().Msg("Logout")
	return &pb.Empty{}, nil
}
