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

	token, err := newJwtToken.SignedString([]byte(service.config.Grpc.JwtSecretKey))
	if err != nil {
		logger.Err(err).Msg("Failed to sign new token")
		return models.JwtToken{}, err
	}

	return models.JwtToken{Token: token}, nil
}

func (service *AuthService) Register(info models.UserRegisterInfo, hashFunc func(s string) (string, error)) (models.JwtToken, error) {
	password, err := hashFunc(info.Password)
	if err != nil {
		logger.Err(err).Msg("Failed to secure password")
		return models.JwtToken{}, errs.NewHashPasswordError(err.Error())
	}
	info.Password = password
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

func (service *AuthService) Login(creds models.UserCredentials,
	hashFunc func(s string) (string, error),
	compareFunc func(s1, s2 string) error) (models.JwtToken, error) {
	user, err := service.repository.GetUserByEmail(creds.Email)
	if err != nil {
		logger.Err(err).Msg("Failed to login user")
		return models.JwtToken{}, errs.NewDBoperationError(err.Error())
	}

	genPassword, err := hashFunc(creds.Password)
	if err != nil {
		logger.Err(err).Msg("Failed to secure password")
		return models.JwtToken{}, errs.NewHashPasswordError(err.Error())
	}

	err = compareFunc(user.Password, genPassword)
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

func (service *AuthService) Authorize(token models.JwtToken, role int64) (bool, error) {

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

		authorizedUser, err := service.repository.GetUserByEmail(email)
		if err != nil {
			logger.Err(err).Msg("Failed to authorize user")
			return false, errs.NewDBoperationError(err.Error())
		}

		// Роли возрастают от 1 до 3 (чем выше, тем больше привилегий)
		if role < authorizedUser.Role {
			return false, nil
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
