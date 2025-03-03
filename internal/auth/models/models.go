package models

type UserRegisterInfo struct {
	Email       string `db:"email"`
	FirstName   string `db:"first_name"`
	LastName    string `db:"last_name"`
	Password    string `db:"password"`
	PhoneNumber string `db:"phone_number"`
	Role        int64  `db:"role"`
}

type UserInfoDB struct {
	ID          int64  `db:"id"`
	Email       string `db:"email"`
	FirstName   string `db:"first_name"`
	LastName    string `db:"last_name"`
	Password    string `db:"password"`
	PhoneNumber string `db:"phone_number"`
	Role        int64  `db:"role"`
}

type UserCredentials struct {
	Email    string
	Password string
}

type JwtToken struct {
	Token string
}
