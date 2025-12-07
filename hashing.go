package hash

import (
	"crypto/rand"
	"encoding/base64"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(Password string) (string, error) {
	byte, err := bcrypt.GenerateFromPassword([]byte(Password), 10)
	return string(byte), err
}

func ChechPassWord(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateToken(length int)string{
	byte := make([]byte , length)
	if _, err := rand.Read(byte); err != nil {
		log.Fatal("faild to gen token\n" , err)
	}
	return base64.URLEncoding.EncodeToString(byte)

}
