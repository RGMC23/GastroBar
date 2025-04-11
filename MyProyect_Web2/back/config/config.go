package config

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

var DB *sql.DB

func ConnectDB() {
	var err error
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error al conectar a la base de datos:", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatal("Error al hacer ping a la base de datos:", err)
	}

	log.Println("Conexión exitosa a la base de datos")
}

func SetupRoutes(r *mux.Router) {
	r.HandleFunc("/ping-db", func(w http.ResponseWriter, r *http.Request) {
		if err := DB.Ping(); err != nil {
			http.Error(w, "No se pudo conectar a la base de datos", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Conexión exitosa a la base de datos"))
	}).Methods("GET")
}
