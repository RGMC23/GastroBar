package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte("clave_secreta_super_segura") // Cambia esto por una clave segura

// Generar un token JWT
func GenerateToken(role string) (string, error) {
	claims := &jwt.MapClaims{
		"role": role,
		"exp":  time.Now().Add(60 * time.Hour).Unix(), // Expira en 24 horas
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// Middleware para validar el token
func ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Token no proporcionado", http.StatusUnauthorized)
			return
		}

		claims := &jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Token inválido", http.StatusUnauthorized)
			return
		}

		// Extraer el rol del token y agregarlo al encabezado
		role, ok := (*claims)["role"].(string)
		if !ok {
			http.Error(w, "Rol no encontrado en el token", http.StatusUnauthorized)
			return
		}
		fmt.Println("Rol extraído del token:", role) // Log para depuración
		fmt.Println("Contenido del token:", claims)
		r.Header.Set("Role", role)

		next.ServeHTTP(w, r)
	})
}

func GenerateTokenHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Role string `json:"role"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil || (requestBody.Role != "Dueño" && requestBody.Role != "Admin" && requestBody.Role != "Employee") {
		http.Error(w, "Rol inválido", http.StatusBadRequest)
		return
	}

	token, err := GenerateToken(requestBody.Role)
	if err != nil {
		http.Error(w, "Error al generar el token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})


}


