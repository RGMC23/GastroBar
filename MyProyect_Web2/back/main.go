package main

import (
	"back/config"
	"back/routes"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	// Cargar variables de entorno
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Conectar a la base de datos
	config.ConnectDB()

	// Crear el router
	r := mux.NewRouter()

	// Registrar las rutas
	routes.RegisterRoutes(r)

	// Iniciar el servidor
	log.Println("Servidor iniciado en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
