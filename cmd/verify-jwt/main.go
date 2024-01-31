package main

import (
	"encoding/json"
	"flag"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

var (
	rsaFile = flag.String("rsa", "app.rsa.pub", "Path to RSA public key")
)

/*
Example usage and output:
$ go run cmd/verify-jwt/main.go 5cCI6IkpXVCJ9.eyJleHAiOjE3MDY3NTk3NzQsInBsYW4iOiJwcmVtaXVtIiwidXNlcl9pZCI6InBlcnNvbi0xMjMifQ.C7vu1FHlrSS-LlI8knIZm83K0Q5iUds8LZ360SWWK6oHnj3JzR7tvMt3U3nPvWX2FeGxCUtAaoRvs5s8eU_BqQknSt3bYxACZR0laWyTPPW0mWL-HnU8KdAZo0Het6WVVaygIpA8iLwSaYEtXuj6fjOhhyMaB2ANSEVJgJiaMHfrdmh2QGJghchoDlUtJVBdRnBOo4ymditGCBZBaDo_8ER3SUOGxoh41mmoo-fdI_CvKZtzFnxlB9mTSEFjaZ62FXpyZZiuUoucUgf5CTQkER2mLJOYSnh5niriGiBUuIrTrqrZTkBFVIN-ye_xQoeQMeMmNFhV9DnXl2dultfgSw
Valid token
{"alg":"RS256","typ":"JWT"}
{"exp":1706759774,"plan":"premium","user_id":"person-123"}
*/

func main() {
	flag.Parse()

	token := flag.Arg(0)
	rsaPubBytes, err := os.ReadFile(*rsaFile)
	if err != nil {
		panic(err)
	}

	// Generate RSA keys
	// openssl genrsa -out app.rsa 2048
	// openssl rsa -in app.rsa -pubout > app.rsa.pub

	// Verify the token
	claims, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(rsaPubBytes)
	})
	if err != nil {
		panic(err)
	}

	if claims.Valid {
		println("Valid token")
	} else {
		println("Invalid token")
	}

	// print the header and payload as valid json objects
	v, err := json.Marshal(claims.Header)
	if err != nil {
		panic(err)
	}
	println(string(v))

	v, err = json.Marshal(claims.Claims)
	if err != nil {
		panic(err)
	}
	println(string(v))

}
