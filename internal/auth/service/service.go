package service

import (
	"fmt"
	"os"
	"time"

	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"
	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/service/errs"
	"github.com/Dmitriy-M1319/crystal-auth/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

// TODO: Более информативные логи
var logger = zerolog.New(os.Stdout)

type AuthRepository interface {
	GetUserByID(id int64) (models.UserInfoDB, error)
	GetUserByEmail(email string) (models.UserInfoDB, error)
	InsertNewUser(user models.UserRegisterInfo) (models.UserInfoDB, error)
}

type AuthKeyValueRepository interface {
	IsUserLogged(email string) (bool, error)
	LoginUser(email string) error
	LogoutUser(email string) error
}

type AuthService struct {
	repository      AuthRepository
	loginRepository AuthKeyValueRepository
	config          *config.Config
}

func NewAuthService(repo AuthRepository, conf *config.Config, lgRepo AuthKeyValueRepository) *AuthService {
	return &AuthService{repository: repo, config: conf, loginRepository: lgRepo}
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
		return models.JwtToken{}, errs.NewHashPasswordError(err.Error())
	}

	info.Password = string(passwordBytes)
	model, err := service.repository.InsertNewUser(info)
	if err != nil {
		logger.Err(err).Msg("Failed to register new user")
		return models.JwtToken{}, errs.NewDBoperationError(err.Error())
	}

	err = service.loginRepository.LoginUser(model.Email)
	if err != nil {
		logger.Err(err).Msg("Failed to register new user")
		return models.JwtToken{}, errs.NewDBoperationError(err.Error())
	}

	return service.generateNewToken(model)

}

func (service *AuthService) Login(creds models.UserCredentials) (models.JwtToken, error) {
	user, err := service.repository.GetUserByEmail(creds.Email)
	if err != nil {
		logger.Err(err).Msg("Failed to login user")
		return models.JwtToken{}, errs.NewDBoperationError(err.Error())
	}

	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 14)
	if err != nil {
		logger.Err(err).Msg("Failed to secure password")
		return models.JwtToken{}, errs.NewHashPasswordError(err.Error())
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), passwordBytes)
	if err == nil {
		err = service.loginRepository.LoginUser(creds.Email)
		if err == nil {
			return service.generateNewToken(user)
		} else {
			logger.Err(err).Msg("Failed to login user")
			return models.JwtToken{}, errs.NewDBoperationError(err.Error())
		}

	}

	return models.JwtToken{}, errors.Errorf("Invalid credentials")
}

func (service *AuthService) Authorize(token models.JwtToken) (bool, error) {

	// TODO: Проверка роли
	t, err := jwt.Parse(token.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errs.NewInvalidTokenError(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return service.config.Grpc.JwtSecretKey, nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return false, errs.NewTokenExpiredError("token expired")
		}

		email := claims["sub"].(string)

		_, err := service.repository.GetUserByEmail(email)
		if err != nil {
			logger.Err(err).Msg("Failed to authorize user")
			return false, errs.NewDBoperationError(err.Error())
		}

		logged, err := service.loginRepository.IsUserLogged(email)
		if err != nil {
			logger.Err(err).Msg("Failed to authorize user")
			return false, errs.NewDBoperationError(err.Error())
		}

		if !logged {
			return false, nil
		}

	} else {
		return false, errs.NewInvalidTokenError("invalid token")
	}

	return true, nil
}

func (service *AuthService) Logout(token models.JwtToken) error {
	t, err := jwt.Parse(token.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errs.NewInvalidTokenError(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return service.config.Grpc.JwtSecretKey, nil
	})

	if err != nil {
		return err
	}

	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return errs.NewTokenExpiredError("token expired")
		}

		email := claims["sub"].(string)

		err = service.loginRepository.LogoutUser(email)
		if err != nil {
			logger.Err(err).Msg("Failed to logout user")
			return errs.NewDBoperationError(err.Error())
		}
	} else {
		return errs.NewInvalidTokenError("invalid token")
	}

	return nil
}
