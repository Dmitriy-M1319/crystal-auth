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
	return user, nil
}

func (repo *AuthRepositoryImpl) InsertNewUser(user models.UserRegisterInfo) (models.UserInfoDB, error) {
	insertQuery := "INSERT INTO users (email, first_name, last_name, phone_number, password, role)" +
		"VALUES(:email, :first_name, :last_name, :phone_number, :password, :role)"

	tx, err := repo.database.Beginx()
	if err != nil {
		return models.UserInfoDB{}, err
	}
	_, err = tx.NamedExec(insertQuery, &user)
	if err != nil {
		tx.Rollback()
		return models.UserInfoDB{}, err
	}

	err = tx.Commit()
	if err != nil {
		return models.UserInfoDB{}, err
	}

	return repo.GetUserByEmail(user.Email)
}
