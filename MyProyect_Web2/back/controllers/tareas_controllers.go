package controllers

import (
	"back/config"
	"back/models"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// Asignar una tarea a un empleado (solo Admin)
func AsignarTarea(w http.ResponseWriter, r *http.Request) {
	// Validar el rol del usuario
	rolUsuario := r.Header.Get("Role")
	if rolUsuario != "Admin" {
		http.Error(w, "No tienes permiso para asignar tareas", http.StatusForbidden)
		return
	}

	// Estructura para recibir los datos de la tarea
	var tarea models.Tarea
	err := json.NewDecoder(r.Body).Decode(&tarea)
	if err != nil {
		http.Error(w, "Solicitud inválida", http.StatusBadRequest)
		return
	}

	// Validar que los campos requeridos no estén vacíos
	if tarea.EmpleadoID == 0 || tarea.Titulo == "" || tarea.Descripcion == "" || tarea.FechaLimite == "" {
		http.Error(w, "Todos los campos son obligatorios", http.StatusBadRequest)
		return
	}

	// Insertar la tarea en la base de datos
	query := `INSERT INTO tareas (empleado_id, titulo, descripcion, fecha_limite, estado) VALUES ($1, $2, $3, $4, 'Pendiente')`
	_, err = config.DB.Exec(query, tarea.EmpleadoID, tarea.Titulo, tarea.Descripcion, tarea.FechaLimite)
	if err != nil {
		fmt.Println("Error al asignar la tarea:", err)
		http.Error(w, "Error al asignar la tarea", http.StatusInternalServerError)
		return
	}

	// Responder con éxito
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Tarea asignada exitosamente"))
}

// Ver las tareas asignadas a un empleado
func VerTareas(w http.ResponseWriter, r *http.Request) {
	// Validar el rol del usuario
	rolUsuario := r.Header.Get("Role")
	if rolUsuario != "Dueño" && rolUsuario != "Admin" && rolUsuario != "Empleado" {
		http.Error(w, "No tienes permiso para ver las tareas", http.StatusForbidden)
		return
	}

	// Construir la consulta SQL para obtener todas las tareas
	query := `SELECT id, empleado_id, titulo, descripcion, fecha_limite, estado FROM tareas`

	// Ejecutar la consulta
	rows, err := config.DB.Query(query)
	if err != nil {
		fmt.Println("Error al obtener las tareas:", err)
		http.Error(w, "Error al obtener las tareas", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Crear una lista para almacenar las tareas
	var tareas []models.Tarea

	// Iterar sobre los resultados y agregarlos a la lista
	for rows.Next() {
		var tarea models.Tarea
		err := rows.Scan(&tarea.ID, &tarea.EmpleadoID, &tarea.Titulo, &tarea.Descripcion, &tarea.FechaLimite, &tarea.Estado)
		if err != nil {
			fmt.Println("Error al procesar las tareas:", err)
			http.Error(w, "Error al procesar las tareas", http.StatusInternalServerError)
			return
		}
		tareas = append(tareas, tarea)
	}

	// Responder con las tareas en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tareas)
}

// Actualizar el estado de una tarea
func ActualizarEstadoTarea(w http.ResponseWriter, r *http.Request) {
	// Validar el rol del usuario
	rolUsuario := r.Header.Get("Role")
	if rolUsuario != "Empleado" {
		http.Error(w, "No tienes permiso para actualizar el estado de las tareas", http.StatusForbidden)
		return
	}

	// Obtener el ID de la tarea desde los parámetros de la URL
	vars := mux.Vars(r)
	tareaID := vars["tarea_id"]

	// Estructura para recibir el nuevo estado
	var requestBody struct {
		Estado string `json:"estado"` // "Completada" o "No Completada"
	}
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Solicitud inválida", http.StatusBadRequest)
		return
	}

	// Validar que el estado sea válido
	if requestBody.Estado != "Completada" && requestBody.Estado != "No Completada" {
		http.Error(w, "Estado inválido", http.StatusBadRequest)
		return
	}

	// Actualizar el estado de la tarea en la base de datos
	query := `UPDATE tareas SET estado = $1 WHERE id = $2`
	_, err = config.DB.Exec(query, requestBody.Estado, tareaID)
	if err != nil {
		fmt.Println("Error al actualizar el estado de la tarea:", err)
		http.Error(w, "Error al actualizar el estado de la tarea", http.StatusInternalServerError)
		return
	}

	// Responder con éxito
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Estado de la tarea actualizado exitosamente"))
}
