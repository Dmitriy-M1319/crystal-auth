package service

import (
	"fmt"
	"os"
	"time"

	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"
	"github.com/Dmitriy-M1319/crystal-auth/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

var logger = zerolog.New(os.Stdout)

type AuthRepository interface {
	GetUserByID(id int64) (models.UserInfoDB, error)
	GetUserByEmail(email string) (models.UserInfoDB, error)
	InsertNewUser(user models.UserRegisterInfo) (models.UserInfoDB, error)
}

type AuthService struct {
	repository AuthRepository
	config     *config.Config
}

func NewAuthService(repo AuthRepository, conf *config.Config) *AuthService {
	return &AuthService{repository: repo, config: conf}
}

func (service *AuthService) generateNewToken(model models.UserInfoDB) (models.JwtToken, error) {
	payloadInfo := jwt.MapClaims{
		"sub": model.Email,
		"exp": time.Now().Add(time.Hour * time.Duration(service.config.Grpc.JwtTimeLive)).Unix(),
	}
	newJwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payloadInfo)

	token, err := newJwtToken.SignedString(service.config.Grpc.JwtSecretKey)
	if err != nil {
		logger.Err(err).Msg("Failed to register new user")
		return models.JwtToken{}, nil
	}

	return models.JwtToken{Token: token}, nil
}

func (service *AuthService) Register(info models.UserRegisterInfo) (models.JwtToken, error) {
	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(info.Password), 14)
	if err != nil {
		logger.Err(err).Msg("Failed to secure password")
		return models.JwtToken{}, err
	}

	info.Password = string(passwordBytes)
	model, err := service.repository.InsertNewUser(info)
	if err != nil {
		logger.Err(err).Msg("Failed to register new user")
		return models.JwtToken{}, err
	}

	return service.generateNewToken(model)

}

func (service *AuthService) Login(creds models.UserCredentials) (models.JwtToken, error) {
	user, err := service.repository.GetUserByEmail(creds.Email)
	if err != nil {
		logger.Err(err).Msg("Failed to login user")
		return models.JwtToken{}, nil
	}

	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 14)
	if err != nil {
		logger.Err(err).Msg("Failed to secure password")
		return models.JwtToken{}, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), passwordBytes)
	if err == nil {
		service.generateNewToken(user)
	}

	return models.JwtToken{}, errors.Errorf("Token expired")
}

func (service *AuthService) Authorize(token models.JwtToken) (bool, error) {

	t, err := jwt.Parse(token.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return service.config.Grpc.JwtSecretKey, nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return false, fmt.Errorf("token expired")
		}

		email := claims["sub"].(string)

		_, err := service.repository.GetUserByEmail(email)
		if err != nil {
			logger.Err(err).Msg("Failed to authorize user")
			return false, err
		}
	} else {
		return false, fmt.Errorf("invalid token")
	}

	return true, nil
}

func (service *AuthService) Logout(token models.JwtToken) error {
	// TODO: Add Redis implementation
	return nil
}
