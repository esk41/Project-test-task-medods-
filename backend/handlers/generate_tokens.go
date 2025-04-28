package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/esk41/Project-test-task-medods-/backend/utils"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"time"
)

func GenerateTokensHandler(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	if guid == "" {
		http.Error(w, "GUID is required", http.StatusBadRequest)
		return
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": guid,
		"iss": r.RemoteAddr,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	accessTokenSigned, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token generation failed, err: %v", err), http.StatusInternalServerError)
		return
	}

	refreshToken := fmt.Sprintf("%s.%d", guid, time.Now().UnixNano())
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, fmt.Sprintf("Refresh token generation failed, err: %v", err), http.StatusInternalServerError)
		return
	}

	db, err := utils.DbOpenConnection()
	if err != nil {
		http.Error(w, fmt.Sprintf("Database open connection failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer func(db *sql.DB) {
		err = utils.DbCloseConnection(db)
		if err != nil {
			http.Error(w, fmt.Sprintf("Database close connection failed: %v", err), http.StatusInternalServerError)
			return
		}
	}(db)

	err = saveRefreshToken(db, guid, hashedRefreshToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Refresh token save failed, err: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":  accessTokenSigned,
		"refresh_token": base64.StdEncoding.EncodeToString([]byte(refreshToken)),
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token encode failed, err: %v", err), http.StatusInternalServerError)
		return
	}
}

// saveRefreshToken - Сохранение refresh токена по guid в БД
func saveRefreshToken(db *sql.DB, guid string, token []byte) error {
	_, err := db.Exec("CALL set_refresh_token_by_guid($1, $2)", guid, token)
	if err != nil {
		return err
	}

	err = utils.DbCloseConnection(db)
	if err != nil {
		return err
	}

	return nil
}
