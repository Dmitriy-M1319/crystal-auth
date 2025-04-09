package service_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"
	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/service"
	"github.com/Dmitriy-M1319/crystal-auth/internal/config"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/mock/gomock"
)

func Test_Register(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	registerUser := models.UserRegisterInfo{
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	expected := models.UserInfoDB{
		ID:          1,
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	dbRepository := service.NewMockAuthRepository(ctrl)
	keyValue := service.NewMockAuthKeyValueRepository(ctrl)
	configMock := config.Config{
		Grpc: config.Grpc{
			JwtSecretKey: "secret",
			JwtTimeLive:  1,
		},
	}

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	tracer := otel.Tracer("example-tracer")

	dbRepository.EXPECT().InsertNewUser(context.Background(), registerUser).Return(expected, nil)
	keyValue.EXPECT().LoginUser(registerUser.Email).Return(nil)
	serv := service.NewAuthService(dbRepository, &configMock, keyValue, tracer)

	hashFunc := func(s string) (string, error) {
		return s, nil
	}

	_, err := serv.Register(context.Background(), registerUser, hashFunc)
	assert.NoError(t, err)
}

func Test_RegisterSampleEmail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	registerUser := models.UserRegisterInfo{
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	expected := models.UserInfoDB{
		ID:          1,
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	dbRepository := service.NewMockAuthRepository(ctrl)
	keyValue := service.NewMockAuthKeyValueRepository(ctrl)
	configMock := config.Config{
		Grpc: config.Grpc{
			JwtSecretKey: "secret",
			JwtTimeLive:  1,
		},
	}
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	tracer := otel.Tracer("example-tracer")

	dbRepository.EXPECT().InsertNewUser(context.Background(), registerUser).Return(expected, fmt.Errorf("non unique primary key"))
	keyValue.EXPECT().LoginUser(registerUser.Email).Return(nil)
	serv := service.NewAuthService(dbRepository, &configMock, keyValue, tracer)

	hashFunc := func(s string) (string, error) {
		return s, nil
	}

	_, err := serv.Register(context.Background(), registerUser, hashFunc)
	assert.True(t, assert.Error(t, err))

}

func Test_LoginExistingUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	hashFunc := func(s string) (string, error) {
		return s, nil
	}

	compareFunc := func(s1, s2 string) error {
		return nil
	}

	loginUser := models.UserCredentials{
		Email:    "email@mail.com",
		Password: "simple_password",
	}

	expectedUser := models.UserInfoDB{
		ID:          1,
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	dbRepository := service.NewMockAuthRepository(ctrl)
	keyValue := service.NewMockAuthKeyValueRepository(ctrl)
	configMock := config.Config{
		Grpc: config.Grpc{
			JwtSecretKey: "secret",
			JwtTimeLive:  1,
		},
	}

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	tracer := otel.Tracer("example-tracer")

	dbRepository.EXPECT().GetUserByEmail(loginUser.Email).Return(expectedUser, nil)
	keyValue.EXPECT().LoginUser(expectedUser.Email).Return(nil)
	serv := service.NewAuthService(dbRepository, &configMock, keyValue, tracer)

	_, err := serv.Login(context.Background(), loginUser, hashFunc, compareFunc)
	assert.NoError(t, err)
}

func Test_LoginNonExistingUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	hashFunc := func(s string) (string, error) {
		return s, nil
	}

	compareFunc := func(s1, s2 string) error {
		return nil
	}

	loginUser := models.UserCredentials{
		Email:    "email@mail.com",
		Password: "simple_password",
	}

	dbRepository := service.NewMockAuthRepository(ctrl)
	keyValue := service.NewMockAuthKeyValueRepository(ctrl)
	configMock := config.Config{
		Grpc: config.Grpc{
			JwtSecretKey: "secret",
			JwtTimeLive:  1,
		},
	}
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	tracer := otel.Tracer("example-tracer")

	dbRepository.EXPECT().GetUserByEmail(loginUser.Email).Return(models.UserInfoDB{}, fmt.Errorf("non existing user"))
	serv := service.NewAuthService(dbRepository, &configMock, keyValue, tracer)

	_, err := serv.Login(context.Background(), loginUser, hashFunc, compareFunc)
	assert.True(t, assert.Error(t, err))
}
func Test_LoginInvalidCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	hashFunc := func(s string) (string, error) {
		return s, nil
	}

	compareFunc := func(s1, s2 string) error {
		return fmt.Errorf("invalid credentials")
	}

	loginUser := models.UserCredentials{
		Email:    "email@mail.com",
		Password: "simple_password",
	}
	expectedUser := models.UserInfoDB{
		ID:          1,
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}
	dbRepository := service.NewMockAuthRepository(ctrl)
	keyValue := service.NewMockAuthKeyValueRepository(ctrl)
	configMock := config.Config{
		Grpc: config.Grpc{
			JwtSecretKey: "secret",
			JwtTimeLive:  1,
		},
	}
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	tracer := otel.Tracer("example-tracer")

	dbRepository.EXPECT().GetUserByEmail(loginUser.Email).Return(expectedUser, nil)
	serv := service.NewAuthService(dbRepository, &configMock, keyValue, tracer)

	_, err := serv.Login(context.Background(), loginUser, hashFunc, compareFunc)
	assert.True(t, assert.Error(t, err))
}

func Test_Authorize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	registerUser := models.UserRegisterInfo{
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	expectedUser := models.UserInfoDB{
		ID:          1,
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	dbRepository := service.NewMockAuthRepository(ctrl)
	keyValue := service.NewMockAuthKeyValueRepository(ctrl)
	configMock := config.Config{
		Grpc: config.Grpc{
			JwtSecretKey: "secret",
			JwtTimeLive:  1,
		},
	}
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	tracer := otel.Tracer("example-tracer")

	dbRepository.EXPECT().GetUserByEmail(registerUser.Email).Return(expectedUser, nil)
	keyValue.EXPECT().IsUserLogged(registerUser.Email).Return(true, nil)
	serv := service.NewAuthService(dbRepository, &configMock, keyValue, tracer)
	token, _ := serv.GenerateNewToken(context.Background(), expectedUser)

	access, err := serv.Authorize(context.Background(), token, 1)

	assert.NoError(t, err)
	assert.True(t, access)
}

func Test_AuthorizeNonExistingUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	registerUser := models.UserRegisterInfo{
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	expectedUser := models.UserInfoDB{
		ID:          1,
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	dbRepository := service.NewMockAuthRepository(ctrl)
	keyValue := service.NewMockAuthKeyValueRepository(ctrl)
	configMock := config.Config{
		Grpc: config.Grpc{
			JwtSecretKey: "secret",
			JwtTimeLive:  1,
		},
	}
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	tracer := otel.Tracer("example-tracer")

	dbRepository.EXPECT().GetUserByEmail(registerUser.Email).Return(models.UserInfoDB{}, fmt.Errorf(""))
	serv := service.NewAuthService(dbRepository, &configMock, keyValue, tracer)
	token, _ := serv.GenerateNewToken(context.Background(), expectedUser)

	access, err := serv.Authorize(context.Background(), token, 1)

	assert.True(t, assert.Error(t, err))
	assert.False(t, access)
}
