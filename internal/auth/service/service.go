package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"
	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/service/errs"
	"github.com/Dmitriy-M1319/crystal-auth/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type AuthRepository interface {
	GetUserByID(id int64) (models.UserInfoDB, error)
	GetUserByEmail(email string) (models.UserInfoDB, error)
	InsertNewUser(ctx context.Context, user models.UserRegisterInfo) (models.UserInfoDB, error)
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
	tracer          trace.Tracer
}

func NewAuthService(repo AuthRepository, conf *config.Config, lgRepo AuthKeyValueRepository, t trace.Tracer) *AuthService {
	return &AuthService{repository: repo, config: conf, loginRepository: lgRepo, tracer: t}
}

func (service *AuthService) GenerateNewToken(ctx context.Context, model models.UserInfoDB) (models.JwtToken, error) {
	_, span := service.tracer.Start(ctx, "service generateToken")
	defer span.End()

	payloadInfo := jwt.MapClaims{
		"sub": model.Email,
		"exp": time.Now().Add(time.Hour * time.Duration(service.config.Grpc.JwtTimeLive)).Unix(),
	}
	newJwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payloadInfo)

	token, err := newJwtToken.SignedString([]byte(service.config.Grpc.JwtSecretKey))
	if err != nil {
		log.Err(err).Msg("Failed to sign new token")
		return models.JwtToken{}, err
	}

	return models.JwtToken{Token: token}, nil
}

func (service *AuthService) Register(ctx context.Context, info models.UserRegisterInfo,
	hashFunc func(s string) (string, error)) (models.JwtToken, error) {
	ctx, span := service.tracer.Start(ctx, "service register")
	defer span.End()

	if info.Role < 1 || info.Role > 3 {
		return models.JwtToken{}, fmt.Errorf("invalid role value")
	}

	password, err := hashFunc(info.Password)
	if err != nil {
		span.SetStatus(codes.Error, "register user error")
		log.Err(err).Msg("Failed to secure password")
		return models.JwtToken{}, errs.NewHashPasswordError(err.Error())
	}
	info.Password = password
	model, err := service.repository.InsertNewUser(ctx, info)
	if err != nil {
		span.SetStatus(codes.Error, "register user error")
		log.Err(err).Msg("Failed to register new user")
		return models.JwtToken{}, errs.NewDBoperationError(err.Error())
	}

	err = service.loginRepository.LoginUser(model.Email)
	if err != nil {
		span.SetStatus(codes.Error, "register user error")
		log.Err(err).Msg("Failed to register new user")
		return models.JwtToken{}, errs.NewDBoperationError(err.Error())
	}

	return service.GenerateNewToken(ctx, model)
}

func (service *AuthService) Login(ctx context.Context, creds models.UserCredentials,
	hashFunc func(s string) (string, error), compareFunc func(s1, s2 string) error) (models.JwtToken, error) {
	ctx, span := service.tracer.Start(ctx, "service login")
	defer span.End()

	user, err := service.repository.GetUserByEmail(creds.Email)
	if err != nil {
		span.SetStatus(codes.Error, "login user error")
		log.Err(err).Msg("Failed to login user")
		return models.JwtToken{}, errs.NewDBoperationError(err.Error())
	}

	err = compareFunc(user.Password, creds.Password)
	if err == nil {
		err = service.loginRepository.LoginUser(creds.Email)
		if err == nil {
			return service.GenerateNewToken(ctx, user)
		} else {
			log.Err(err).Msg("Failed to login user")
			span.SetStatus(codes.Error, "login user error")
			return models.JwtToken{}, errs.NewDBoperationError(err.Error())
		}

	}

	return models.JwtToken{}, errors.Errorf("Invalid credentials")
}

func (service *AuthService) Authorize(ctx context.Context, token models.JwtToken, role int64) (bool, error) {
	_, span := service.tracer.Start(ctx, "service authorize")
	defer span.End()

	if role < 1 || role > 3 {
		return false, nil
	}

	t, err := jwt.Parse(token.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			span.SetStatus(codes.Error, "authorize user error")
			return nil, errs.NewInvalidTokenError(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return []byte(service.config.Grpc.JwtSecretKey), nil
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
			log.Err(err).Msg("Failed to authorize user")
			return false, errs.NewDBoperationError(err.Error())
		}

		// Роли возрастают от 1 до 3
		if role > authorizedUser.Role {
			return false, nil
		}

		logged, err := service.loginRepository.IsUserLogged(email)
		if err != nil {
			log.Err(err).Msg("Failed to authorize user")
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

func (service *AuthService) Logout(ctx context.Context, token models.JwtToken) error {
	_, span := service.tracer.Start(ctx, "service logout")
	defer span.End()

	t, err := jwt.Parse(token.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errs.NewInvalidTokenError(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return []byte(service.config.Grpc.JwtSecretKey), nil
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
			span.SetStatus(codes.Error, "logout user error")
			log.Err(err).Msg("Failed to logout user")
			return errs.NewDBoperationError(err.Error())
		}
	} else {
		return errs.NewInvalidTokenError("invalid token")
	}

	return nil
}
