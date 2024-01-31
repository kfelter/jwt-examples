## Create a JWT signing key and public key

```bash
openssl genrsa -out app.rsa 2048
openssl rsa -in app.rsa -pubout > app.rsa.pub
```

## Create a JWT token

Run the following command to create a JWT token and print it to the console:
```bash
JWT_TOKEN=$(go run cmd/create-jwt/main.go)
echo $JWT_TOKEN
```

## Verify a JWT token

Run the following command to verify a JWT token:
```bash
go run cmd/verify-jwt/main.go $JWT_TOKEN
```

## Use JWT tokens in a web server

Run the following command to start a web server that uses JWT tokens:
```bash
go run cmd/web-app-server/main.go
```
View the web server at http://localhost:8080 and login with the preset username and password.

After logging in, you will see a welcome message with your parsed JWT token.



