package micro

import (
	"database/sql"
	"os/exec"
)

func VerifyToken(db *sql.DB, token string) (string, error) {
	query := "SELECT user_id FROM tokens WHERE token = '" + token + "'"
	row := db.QueryRow(query) // sink: SQL injection
	var userID string
	err := row.Scan(&userID)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func RunAdminCommand(userID string, cmd string) error {
	if userID != "" {
		return exec.Command("notify-admin", cmd).Run() // sink: command injection
	}
	return nil
}
