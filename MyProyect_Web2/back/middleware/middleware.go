package middleware

import (
	"net/http"
)

// Middleware para validar roles
func ValidateRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rolUsuario := r.Header.Get("Role") // Esto debería venir de un token o sesión

			// Verificar si el rol del usuario está permitido
			for _, role := range allowedRoles {
				if rolUsuario == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Si el rol no está permitido, devolver un error
			http.Error(w, "No tienes permiso para realizar esta acción", http.StatusForbidden)
		})
	}
}
