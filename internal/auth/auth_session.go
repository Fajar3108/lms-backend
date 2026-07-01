package auth

import "time"

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func GetSessionKey(userID string, sessionID string) string {
	return "session:" + userID + ":" + sessionID
}
