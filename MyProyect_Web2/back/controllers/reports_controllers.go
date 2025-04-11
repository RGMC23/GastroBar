package controllers

import (
	"back/config"
	"back/models"
	"encoding/json"
	"net/http"
)

// CreateReport maneja la creación de un nuevo reporte
func CreateReport(w http.ResponseWriter, r *http.Request) {
	var report models.Report
	err := json.NewDecoder(r.Body).Decode(&report)
	if err != nil {
		http.Error(w, "Solicitud inválida", http.StatusBadRequest)
		return
	}

	// Insertar el reporte en la base de datos
	query := `INSERT INTO reports (titulo, descripcion, fecha) VALUES ($1, $2, $3) RETURNING id`
	err = config.DB.QueryRow(query, report.Titulo, report.Descripcion, report.Fecha).Scan(&report.ID)
	if err != nil {
		http.Error(w, "Error al crear el reporte", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(report)
}

// GetReports maneja la obtención de todos los reportes
func GetReports(w http.ResponseWriter, r *http.Request) {
	rows, err := config.DB.Query("SELECT id, titulo, descripcion, fecha FROM reports")
	if err != nil {
		http.Error(w, "Error al obtener los reportes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var reports []models.Report
	for rows.Next() {
		var report models.Report
		err := rows.Scan(&report.ID, &report.Titulo, &report.Descripcion, &report.Fecha)
		if err != nil {
			http.Error(w, "Error al procesar los datos", http.StatusInternalServerError)
			return
		}
		reports = append(reports, report)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reports)
}
