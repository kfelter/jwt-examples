package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var (
	rsaFile = flag.String("rsa", "app.rsa", "Path to RSA private key")
)

/*
Example usage and output:
$ go run cmd/create-jwt/main.go
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDY3NjA0OTYsInBsYW4iOiJwcmVtaXVtIiwidXNlcl9pZCI6InBlcnNvbi0xMjMifQ.hQ1_5c7XhyWxlo8jtYnLBDdCXkg7Un4ipCkKaySPYVpjvTAw03T7quDiCBFuiePdv0QvaAng7ZPoDML00uxDJGqnIKThMTIcr7_oDFIUDvqk6-1g6dN85ZYWTUlgqYIBTMOgQAbrntwvXXW4HaZGEFHo0MrJdJXCMCdhR5k7vsIk1pGoGotQ6p-xO3UDRchoy7eI1DldHk77NpaLxoCnArcqOQ0C0Clnb4FNDq3eoB3DkR-Ds1E82YTeyDTpomfnV9iCIyra5aWhIe17XF6Qv_AWsEDcHJMi3-bRlBMLeYWvja7HvYM7WNAMje3KvuK54trNXojqvkk-vApp7i1wkw
*/
func main() {
	flag.Parse()

	// Generate RSA keys
	// openssl genrsa -out app.rsa 2048
	// openssl rsa -in app.rsa -pubout > app.rsa.pub

	rsaBytes, err := os.ReadFile(*rsaFile)
	if err != nil {
		panic(err)
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(rsaBytes)
	if err != nil {
		panic(err)
	}

	// Create the token
	token := jwt.New(jwt.SigningMethodRS256)

	// Set some claims
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = "person-123"
	claims["plan"] = "premium"
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		fmt.Println("Error creating token string")
	}

	fmt.Println(tokenString)
}
