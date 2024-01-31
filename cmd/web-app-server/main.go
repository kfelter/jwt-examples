package main

import (
	"encoding/json"
	"flag"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type User struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Passwd string `json:"passwd"`
	Plan   string `json:"plan"`
}

type LoginRequest struct {
	Email  string `json:"email"`
	Passwd string `json:"passwd"`
}

var (
	rsaPubkey  = flag.String("pub", "app.rsa.pub", "Path to RSA public key")
	rsaPrivkey = flag.String("priv", "app.rsa", "Path to RSA private key")

	usersDB = map[string]User{
		"test@example.com": {
			UserID: "person-123",
			Email:  "test@example.com",
			Passwd: "password",
			Plan:   "premium",
		},
	}
)

func main() {
	flag.Parse()

	// Generate RSA keys
	// openssl genrsa -out app.rsa 2048
	// openssl rsa -in app.rsa -pubout > app.rsa.pub

	println("Starting server on port 8080")
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/", homeHandler)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// read the post form body

	login := LoginRequest{}

	login.Email = r.PostFormValue("email")
	login.Passwd = r.PostFormValue("passwd")

	user, ok := usersDB[login.Email]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if user.Passwd != login.Passwd {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := createJWT(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// redirect to home page
	http.Redirect(w, r, "/?t="+token, http.StatusFound)
}

func createJWT(user User) (string, error) {
	// Generate RSA keys
	// openssl genrsa -out app.rsa 2048
	// openssl rsa -in app.rsa -pubout > app.rsa.pub

	rsaBytes, err := os.ReadFile(*rsaPrivkey)
	if err != nil {
		return "", err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(rsaBytes)
	if err != nil {
		return "", err
	}

	// Create the token
	token := jwt.New(jwt.SigningMethodRS256)

	// Set some claims
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.UserID
	claims["plan"] = user.Plan
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// this should be an html page that shows a login form or a welcome message
	// check if the user sent a valid token
	// if not, show the login form
	// if yes, show the welcome message

	token := r.URL.Query().Get("t")
	if token == "" {
		// show the login page with js
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
		<html>
			<head>
				<title>Login</title>
			</head>
			<body>
				<form action="/login" method="POST">
					<input type="text" name="email" placeholder="email" value="test@example.com">
					<input type="password" name="passwd" placeholder="password" value="password">
					<input type="submit" value="Login">
				</form>
			</body>
		</html>
		`))
		return
	}

	rsaPubBytes, err := os.ReadFile(*rsaPubkey)
	if err != nil {
		panic(err)
	}

	// Verify the token
	claims, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(rsaPubBytes)
	})
	if err != nil {
		panic(err)
	}

	if claims.Valid {
		println("Valid token")
		// display a welcom page in html
		w.Header().Set("Content-Type", "text/html")
		tmpl, err := template.New("welcome").Parse(`
		<html>
			<head>
				<title>Welcome</title>
			</head>
			<body>
				<h1>Welcome {{.UserID}}</h1>
				<p>Your plan is {{.Plan}}</p>
				<p>Token header:</p>
				<pre>{{.TokenHeader}}</pre>
				<p>Token claims:</p>
				<pre>{{.TokenClaims}}</pre>
				<p>Raw JWT token:</p>
				<pre>{{.Token}}</pre>
			</body>
		</html>
		`)
		if err != nil {
			panic(err)
		}
		tokenHeader, err := json.MarshalIndent(claims.Header, "", "  ")
		if err != nil {
			panic(err)
		}

		tokenClaims, err := json.MarshalIndent(claims.Claims, "", "  ")
		if err != nil {
			panic(err)
		}

		v := struct {
			UserID      string
			Token       string
			Plan        string
			TokenHeader string
			TokenClaims string
		}{
			Token:       token,
			UserID:      claims.Claims.(jwt.MapClaims)["user_id"].(string),
			Plan:        claims.Claims.(jwt.MapClaims)["plan"].(string),
			TokenHeader: string(tokenHeader),
			TokenClaims: string(tokenClaims),
		}
		err = tmpl.Execute(w, v)
		if err != nil {
			panic(err)
		}
		return
	} else {
		println("Invalid token")
		// unauthorized, show a red message
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("<h1>Unauthorized</h1>"))
		return
	}

}
