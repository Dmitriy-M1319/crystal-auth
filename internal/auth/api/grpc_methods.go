package api

import (
	"context"
	"os"

	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"
	pb "github.com/Dmitriy-M1319/crystal-auth/pkg/crystal-auth/v1"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

var logger = zerolog.New(os.Stdout)

func (impl *AuthApiImplementation) Register(ctx context.Context, r *pb.UserInfo) (*pb.JwtToken, error) {
	logger.Info().Msg("Register")

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
	logger.Info().Msg("Login")

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

func (impl *AuthApiImplementation) Authorize(ctx context.Context, r *pb.JwtToken) (*pb.Access, error) {
	logger.Info().Msg("Authorize")
	access, err := impl.service.Authorize(models.JwtToken{Token: r.Token})
	if err != nil {
		return nil, err
	}
	return &pb.Access{Accessed: access}, nil
}

func (impl *AuthApiImplementation) Logout(ctx context.Context, r *pb.JwtToken) (*pb.Empty, error) {
	logger.Info().Msg("Logout")
	err := impl.service.Logout(models.JwtToken{Token: r.Token})
	return &pb.Empty{}, err
}
