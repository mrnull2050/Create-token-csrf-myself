package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type User struct {
	Password     string
	SessionToken string
	csrfToken    string
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/login", login)

	NewServer := &http.Server{
		Addr:    ":8085",
		Handler: mux,
	}
	NewServer.ListenAndServe()
}

var users = make(map[string]User)

func HashPassword(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]), nil
}

func CheckPassword(password, hashed string) bool {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]) == hashed
}

func GenerateToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	UserName := r.FormValue("username")
	Password := r.FormValue("password")

	if len(UserName) < 8 || len(Password) < 8 {
		http.Error(w, "user and password must be at least 8 characters long", http.StatusBadRequest)
		return
	}

	if _, ok := users[UserName]; ok {
		http.Error(w, "username already exists", http.StatusConflict)
		return
	}

	hashpass, _ := HashPassword(Password)
	users[UserName] = User{Password: hashpass}
	fmt.Fprintf(w, "User %v registered", UserName)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "invalid method", err)
		return
	}
	Username := r.FormValue("username")
	Password := r.FormValue("password")

	user, ok := users[Username]
	if !ok || !CheckPassword(Password, user.Password) {
		err := http.StatusNotFound
		http.Error(w, "user not found", err)
		return
	}

	sessionToken := GenerateToken(32)
	csrfToken := GenerateToken(32)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
	})
	user.SessionToken = sessionToken
	user.csrfToken = csrfToken
	users[Username] = user

	fmt.Fprintf(w, "user login successfuly")

}

var authErr = errors.New("Unauthorize")

func Authotize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		return authErr
	}
	st , err  := r.Cookie("Sesstion_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken{
		return authErr
	}
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf != user.csrfToken || csrf == ""{
		return authErr
	}
	return  nil 
}
