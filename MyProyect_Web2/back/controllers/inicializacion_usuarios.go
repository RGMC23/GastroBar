package controllers

import (
	"back/config"
	"back/models"
	"fmt"
)

// Crear usuarios iniciales (Dueño y Admin)
func InitializeUsers() {
	users := []struct {
		Name     string
		Email    string
		Username string
		Password string
		Role     string
	}{
		{
			Name:     "Dueño Principal",
			Email:    "dueno@example.com",
			Username: "Juan",
			Password: "contraseña$fija_Dueño", // Contraseña fija
			Role:     "Dueño",
		},
		{
			Name:     "Administrador",
			Email:    "admin@example.com",
			Username: "Ana",
			Password: "contraseña$fija_Admin", // Contraseña fija
			Role:     "Admin",
		},
	}

	for _, user := range users {
		// Encriptar la contraseña
		hashedPassword, err := models.EncryptPassword(user.Password)
		if err != nil {
			fmt.Printf("Error al encriptar la contraseña para %s: %v\n", user.Username, err)
			continue
		}

		// Guardar el usuario en la base de datos
		query := `INSERT INTO users (name, email, username, password, role) VALUES ($1, $2, $3, $4, $5)`
		_, err = config.DB.Exec(query, user.Name, user.Email, user.Username, hashedPassword, user.Role)
		if err != nil {
			fmt.Printf("Error al guardar el usuario %s en la base de datos: %v\n", user.Username, err)
			continue
		}

		fmt.Printf("Usuario %s creado exitosamente\n", user.Username)
	}
}
