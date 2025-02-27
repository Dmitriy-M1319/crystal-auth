package service

import "github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"

type AuthRepository interface {
	GetUserByID(id int64) (models.UserInfoDB, error)
	GetUserByEmail(email string) (models.UserInfoDB, error)
	InsertNewUser(user models.UserRegisterInfo) (models.UserInfoDB, error)
}

type AuthService struct {
	repository AuthRepository
}

func NewAuthService(repo AuthRepository) *AuthService {
	return &AuthService{repository: repo}
}

func (service *AuthService) Register(info models.UserRegisterInfo) (models.JwtToken, error) {
	return models.JwtToken{}, nil
}

func (service *AuthService) Login(creds models.UserCredentials) (models.JwtToken, error) {
	return models.JwtToken{}, nil
}

func (service *AuthService) Authorize(token models.JwtToken) (bool, error) {
	return false, nil
}

func (service *AuthService) Logout(token models.JwtToken) error {
	return nil
}
