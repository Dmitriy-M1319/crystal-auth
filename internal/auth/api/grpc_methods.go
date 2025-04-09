package api

import (
	"context"

	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"
	pb "github.com/Dmitriy-M1319/crystal-auth/pkg/crystal-auth/v1"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/crypto/bcrypt"
)

func (impl *AuthApiImplementation) Register(ctx context.Context, r *pb.UserInfo) (*pb.JwtToken, error) {
	ctx, span := impl.tracer.Start(ctx, "grpc register")
	defer span.End()

	log.Info().Msg("Register")

	hashFunc := func(s string) (string, error) {
		passwordBytes, err := bcrypt.GenerateFromPassword([]byte(s), 14)
		return string(passwordBytes), err
	}

	token, err := impl.service.Register(ctx, models.UserRegisterInfo{
		Email:       r.Email,
		FirstName:   r.FirstName,
		LastName:    r.LastName,
		Password:    r.Password,
		Role:        r.Role,
		PhoneNumber: r.PhoneNumber,
	}, hashFunc)
	if err != nil {
		span.SetStatus(codes.Error, "failed to register user")
		return nil, err
	}
	return &pb.JwtToken{Token: token.Token}, nil
}

func (impl *AuthApiImplementation) Login(ctx context.Context, r *pb.UserCredentials) (*pb.JwtToken, error) {
	ctx, span := impl.tracer.Start(ctx, "grpc login")
	defer span.End()

	log.Info().Msg("Login")

	hashFunc := func(s string) (string, error) {
		passwordBytes, err := bcrypt.GenerateFromPassword([]byte(s), 14)
		return string(passwordBytes), err
	}

	compareFunc := func(s1, s2 string) error {
		return bcrypt.CompareHashAndPassword([]byte(s1), []byte(s2))
	}

	token, err := impl.service.Login(ctx, models.UserCredentials{
		Email:    r.Email,
		Password: r.Password,
	}, hashFunc, compareFunc)
	if err != nil {
		span.SetStatus(codes.Error, "failed to login user")
		return nil, err
	}
	return &pb.JwtToken{Token: token.Token}, nil
}

func (impl *AuthApiImplementation) Authorize(ctx context.Context, r *pb.AuthorizeInfo) (*pb.Access, error) {
	ctx, span := impl.tracer.Start(ctx, "grpc authorize")
	defer span.End()

	log.Info().Msg("Authorize")
	access, err := impl.service.Authorize(ctx, models.JwtToken{Token: r.Token.Token}, r.ExpectedRole)
	if err != nil {
		span.SetStatus(codes.Error, "failed to authorize user")
		return nil, err
	}
	return &pb.Access{Accessed: access}, nil
}

func (impl *AuthApiImplementation) Logout(ctx context.Context, r *pb.JwtToken) (*pb.Empty, error) {
	ctx, span := impl.tracer.Start(ctx, "logout")
	defer span.End()

	log.Info().Msg("Logout")
	err := impl.service.Logout(ctx, models.JwtToken{Token: r.Token})
	if err != nil {
		span.SetStatus(codes.Error, "failed to logout user")
	}
	return &pb.Empty{}, err
}
