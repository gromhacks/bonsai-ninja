package micro

import "database/sql"

type UserInfo struct {
	ID    string
	Token string
}

func GetUser(db *sql.DB, token string) (*UserInfo, error) {
	userID, err := VerifyToken(db, token)
	if err != nil {
		return nil, err
	}
	return &UserInfo{ID: userID, Token: token}, nil
}

func UpdateUser(db *sql.DB, token string, action string) (string, error) {
	userID, err := VerifyToken(db, token)
	if err != nil {
		return "", err
	}
	if userID != "" {
		err = RunAdminCommand(userID, action)
	}
	return userID, err
}
