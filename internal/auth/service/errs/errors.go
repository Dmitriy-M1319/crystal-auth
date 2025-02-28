package errs

type TokenExpiredError struct {
	Msg string
}

func NewTokenExpiredError(msg string) TokenExpiredError {
	return TokenExpiredError{Msg: msg}
}

func (e TokenExpiredError) Error() string {
	return e.Msg
}

type InvalidTokenError struct {
	Msg string
}

func NewInvalidTokenError(msg string) InvalidTokenError {
	return InvalidTokenError{Msg: msg}
}

func (e InvalidTokenError) Error() string {
	return e.Msg
}

type HashPasswordError struct {
	Msg string
}

func NewHashPasswordError(msg string) HashPasswordError {
	return HashPasswordError{Msg: msg}
}

func (e HashPasswordError) Error() string {
	return e.Msg
}

type DBoperationError struct {
	Msg string
}

func NewDBoperationError(msg string) DBoperationError {
	return DBoperationError{Msg: msg}
}

func (e DBoperationError) Error() string {
	return e.Msg
}
