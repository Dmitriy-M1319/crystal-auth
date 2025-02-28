package service_test

import (
	"fmt"
	"testing"

	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"
	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/service"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

func Test_Register(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	//TODO: Добавить проверку роли в Authorize
	// TODO: замокать конфиг

	registerUser := models.UserRegisterInfo{
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    "simple_password",
		Role:        1,
	}

	passwordBytes, _ := bcrypt.GenerateFromPassword([]byte(registerUser.Password), 14)

	hashedUser := models.UserRegisterInfo{
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    string(passwordBytes),
		Role:        1,
	}

	expected := models.UserInfoDB{
		ID:          1,
		Email:       "email@mail.com",
		FirstName:   "User",
		LastName:    "Malkov",
		PhoneNumber: "81219032354",
		Password:    string(passwordBytes),
		Role:        1,
	}

	fmt.Println(registerUser)

	dbRepository := service.NewMockAuthRepository(ctrl)
	keyValue := service.NewMockAuthKeyValueRepository(ctrl)

	dbRepository.EXPECT().InsertNewUser(hashedUser).Return(expected, nil)

	keyValue.EXPECT().LoginUser(hashedUser.Email).Return(nil)

	serv := service.NewAuthService(dbRepository, nil, keyValue)

	_, err := serv.Register(hashedUser)
	assert.NoError(t, err)
}

func Test_RegisterSampleEmail(t *testing.T) {
	t.Fatal()
}

func Test_LoginExistingUser(t *testing.T) {
	t.Fatal()
}

func Test_LoginNonExistingUser(t *testing.T) {
	t.Fatal()
}
func Test_LoginInvalidCredentials(t *testing.T) {
	t.Fatal()
}

func Test_AuthorizeSuccess(t *testing.T) {
	t.Fatal()
}

func Test_AuthorizeNonExistingUser(t *testing.T) {
	t.Fatal()
}

func Test_AuthorizeTokenExpired(t *testing.T) {
	t.Fatal()
}

func Test_LogoutSuccess(t *testing.T) {
	t.Fatal()
}

func Test_LogoutNonExistingUser(t *testing.T) {
	t.Fatal()
}

func Test_LogoutTokenExpired(t *testing.T) {
	t.Fatal()
}
