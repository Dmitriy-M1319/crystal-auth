package repository

import (
	"github.com/Dmitriy-M1319/crystal-auth/internal/auth/models"
	"github.com/jmoiron/sqlx"
)

type AuthRepositoryImpl struct {
	database *sqlx.DB
}

func NewAuthRepositoryImpl(db *sqlx.DB) AuthRepositoryImpl {
	return AuthRepositoryImpl{database: db}
}

func (repo *AuthRepositoryImpl) GetUserByID(id int64) (models.UserInfoDB, error) {
	var user models.UserInfoDB
	err := repo.database.Get(&user, "SELECT * FROM users WHERE id=$1", id)
	if err != nil {
		return models.UserInfoDB{}, err
	}
	return models.UserInfoDB{}, nil
}

func (repo *AuthRepositoryImpl) GetUserByEmail(email string) (models.UserInfoDB, error) {
	var user models.UserInfoDB
	err := repo.database.Get(&user, "SELECT * FROM users WHERE email=$1", email)
	if err != nil {
		return models.UserInfoDB{}, err
	}
	return models.UserInfoDB{}, nil
}

func (repo *AuthRepositoryImpl) InsertNewUser(user models.UserRegisterInfo) (models.UserInfoDB, error) {
	insertQuery := "INSERT INTO users (email, first_name, last_name, phone_number, password, role)" +
		"VALUES($1, $2, $3, $4, $5, $6)"

	tx := repo.database.MustBegin()
	tx.MustExec(insertQuery, user.Email, user.FirstName, user.LastName, user.PhoneNumber, user.Password, user.Role)
	tx.Commit()

	return repo.GetUserByEmail(user.Email)
}
