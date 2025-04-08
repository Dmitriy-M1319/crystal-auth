package api

import (
	"context"
	"go.opentelemetry.io/otel"

	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"
	pb "github.com/Dmitriy-M1319/crystal-auth/pkg/crystal-auth/v1"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

var (
	tracer = otel.Tracer("github.com/Dmitriy-M1319/crystal-auth")
)

func (impl *AuthApiImplementation) Register(ctx context.Context, r *pb.UserInfo) (*pb.JwtToken, error) {
	ctx, span := tracer.Start(ctx, "register")
	defer span.End()

	log.Info().Msg("Register")

	hashFunc := func(s string) (string, error) {
		passwordBytes, err := bcrypt.GenerateFromPassword([]byte(s), 14)
		return string(passwordBytes), err
	}

	token, err := impl.service.Register(models.UserRegisterInfo{
		Email:       r.Email,
		FirstName:   r.FirstName,
		LastName:    r.LastName,
		Password:    r.Password,
		Role:        r.Role,
		PhoneNumber: r.PhoneNumber,
	}, hashFunc)
	if err != nil {
		return nil, err
	}
	return &pb.JwtToken{Token: token.Token}, nil
}

func (impl *AuthApiImplementation) Login(ctx context.Context, r *pb.UserCredentials) (*pb.JwtToken, error) {
	ctx, span := tracer.Start(ctx, "login")
	defer span.End()

	log.Info().Msg("Login")

	hashFunc := func(s string) (string, error) {
		passwordBytes, err := bcrypt.GenerateFromPassword([]byte(s), 14)
		return string(passwordBytes), err
	}

	compareFunc := func(s1, s2 string) error {
		return bcrypt.CompareHashAndPassword([]byte(s1), []byte(s2))
	}

	token, err := impl.service.Login(models.UserCredentials{
		Email:    r.Email,
		Password: r.Password,
	}, hashFunc, compareFunc)
	if err != nil {
		return nil, err
	}
	return &pb.JwtToken{Token: token.Token}, nil
}

func (impl *AuthApiImplementation) Authorize(ctx context.Context, r *pb.AuthorizeInfo) (*pb.Access, error) {
	ctx, span := tracer.Start(ctx, "authorize")
	defer span.End()

	log.Info().Msg("Authorize")
	access, err := impl.service.Authorize(models.JwtToken{Token: r.Token.Token}, r.ExpectedRole)
	if err != nil {
		return nil, err
	}
	return &pb.Access{Accessed: access}, nil
}

func (impl *AuthApiImplementation) Logout(ctx context.Context, r *pb.JwtToken) (*pb.Empty, error) {
	ctx, span := tracer.Start(ctx, "logout")
	defer span.End()

	log.Info().Msg("Logout")
	err := impl.service.Logout(models.JwtToken{Token: r.Token})
	return &pb.Empty{}, err
}
