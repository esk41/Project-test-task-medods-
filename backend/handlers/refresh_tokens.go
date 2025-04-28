package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/esk41/Project-test-task-medods-/backend/utils"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"strings"
	"time"
)

func RefreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	requestAccessToken := r.Header.Get("Authorization")
	requestRefreshToken := r.Header.Get("Refresh-Token")

	requestAccessTokenTrimmed := strings.TrimPrefix(requestAccessToken, "Bearer ")

	requestVerifiedAccessToken, err := utils.VerifyToken(requestAccessTokenTrimmed)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token. Cannot verify token, err: %v", err), http.StatusUnauthorized)
		return
	}

	requestAccessTokenExpirationTime, err := requestVerifiedAccessToken.Claims.GetExpirationTime()
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token. Cannot get expiration time, err: %v", err), http.StatusUnauthorized)
		return
	}

	if requestAccessTokenExpirationTime.Before(time.Now()) {
		http.Error(w, "Access token expired. Get new token", http.StatusUnauthorized)
		return
	}

	requestAccessTokenGUID, err := requestVerifiedAccessToken.Claims.GetSubject()
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token. Cannot get guid, err: %v", err), http.StatusUnauthorized)
		return
	}

	requestAccessTokenIP, err := requestVerifiedAccessToken.Claims.GetIssuer()
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token. Cannot get IP, err: %v", err), http.StatusUnauthorized)
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

	// Отсылаем письмо пользователю, если IP-адреса из запроса и токена различаются
	if requestAccessTokenIP != r.RemoteAddr {
		var emailTo sql.NullString

		emailTo, err = getEmailByGUID(db, requestAccessTokenGUID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Can't get email by guid: %v", err), http.StatusInternalServerError)
			return
		}

		err = utils.SendEmail(emailTo.String, "IP ADDRESSES MISMATCH", fmt.Sprintf("Просьба проверить GUID: %v", requestAccessTokenGUID))
		if err != nil {
			fmt.Printf("Can't send email, err: %v", err)
		}

		fmt.Printf("Email has been sent to mail: %v", emailTo.String)
	}

	requestDecodedRefreshToken, err := base64.StdEncoding.DecodeString(requestRefreshToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token format, err: %v", err), http.StatusUnauthorized)
		return
	}

	dbRefreshToken, err := getRefreshToken(db, requestAccessTokenGUID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token not found, err: %v", err), http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbRefreshToken.String), requestDecodedRefreshToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token, err: %v", err), http.StatusUnauthorized)
		return
	}

	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": requestAccessTokenGUID,
		"iss": r.RemoteAddr,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	newAccessTokenSigned, err := newAccessToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token generation failed, err: %v", err), http.StatusInternalServerError)
		return
	}

	newRefreshToken := fmt.Sprintf("%s.%d", requestAccessTokenGUID, time.Now().UnixNano())
	newHashedRefresh, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, fmt.Sprintf("Refresh token generation failed, err: %v", err), http.StatusInternalServerError)
		return
	}

	err = updateRefreshToken(db, requestAccessTokenGUID, newHashedRefresh)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to update refresh token: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":  newAccessTokenSigned,
		"refresh_token": base64.StdEncoding.EncodeToString([]byte(newRefreshToken)),
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token encode failed, err: %v", err), http.StatusInternalServerError)
		return
	}
}

// getRefreshToken - Получение refresh токена по guid в БД
func getRefreshToken(db *sql.DB, guid string) (sql.NullString, error) {
	var refreshtoken sql.NullString

	query := "SELECT get_refresh_token_by_guid($1)"

	err := db.QueryRow(query, guid).Scan(&refreshtoken)
	if err != nil {
		return sql.NullString{}, err
	}

	if refreshtoken.String == "" {
		return sql.NullString{}, errors.New("user's refresh token is empty")
	}

	return refreshtoken, nil
}

// updateRefreshToken - Обновление refresh токена по guid в БД
func updateRefreshToken(db *sql.DB, guid string, token []byte) error {
	_, err := db.Exec("CALL set_refresh_token_by_guid($1, $2)", guid, token)
	if err != nil {
		return err
	}

	return nil
}

// getEmailByGUID - Получение Email пользователя по guid в БД
func getEmailByGUID(db *sql.DB, guid string) (sql.NullString, error) {
	var email sql.NullString

	query := "SELECT get_email_by_guid($1)"

	err := db.QueryRow(query, guid).Scan(&email)
	if err != nil {
		return sql.NullString{}, err
	}

	if email.String == "" {
		return sql.NullString{}, errors.New("user's email is empty")
	}

	return email, nil
}
