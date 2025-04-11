package controllers

import (
	"back/config"
	"back/middleware"
	"back/models"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

//
// ==================== Funciones Auxiliares ====================
//

// Función genérica para verificar permisos y ejecutar lógica
func HandleWithPermission(w http.ResponseWriter, r *http.Request, userRole string, permission string, action func()) {
	if !models.CheckPermission(userRole, permission) {
		http.Error(w, "No tienes permiso para realizar esta acción", http.StatusForbidden)
		return
	}
	action()
}

//
// ==================== Operaciones CRUD ====================
//

// Obtener todos los usuarios
func GetUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := config.DB.Query("SELECT id, name, email, username, role FROM users")
	if err != nil {
		http.Error(w, "Error al obtener los usuarios", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Username, &user.Role); err != nil {
			http.Error(w, "Error al procesar los datos del usuario", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// Crear un nuevo usuario con contraseña aleatoria
func CreateUserWithRandomPassword(w http.ResponseWriter, r *http.Request) {
	rolUsuario := r.Header.Get("Role")
	if rolUsuario != "Dueño" && rolUsuario != "Admin" {
		http.Error(w, "No tienes permiso para crear usuarios", http.StatusForbidden)
		return
	}

	var user struct {
		Name     string
		Email    string
		Username string
		Role     string
	}

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Solicitud inválida", http.StatusBadRequest)
		return
	}

	if user.Name == "" || user.Email == "" || user.Username == "" || user.Role == "" {
		http.Error(w, "Todos los campos son obligatorios", http.StatusBadRequest)
		return
	}

	randomPassword := models.GenerateRandomPassword(12)
	hashedPassword, err := models.EncryptPassword(randomPassword)
	if err != nil {
		http.Error(w, "Error al encriptar la contraseña", http.StatusInternalServerError)
		return
	}

	query := `INSERT INTO users (name, email, username, password, role) VALUES ($1, $2, $3, $4, $5)`
	result, err := config.DB.Exec(query, user.Name, user.Email, user.Username, hashedPassword, user.Role)
	if err != nil {
		http.Error(w, "Error al guardar el usuario en la base de datos", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		http.Error(w, "No se pudo crear el usuario", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message":  "Usuario creado exitosamente",
		"username": user.Username,
		"password": randomPassword,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Actualizar la contraseña de un usuario
func UpdatePassword(w http.ResponseWriter, r *http.Request) {
	rolUsuario := r.Header.Get("Role")
	if rolUsuario != "Dueño" && rolUsuario != "Admin" {
		http.Error(w, "No tienes permiso para actualizar contraseñas", http.StatusForbidden)
		return
	}

	var requestBody struct {
		UserID      int    `json:"user_id"`
		NewPassword string `json:"new_password"`
	}
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Solicitud inválida", http.StatusBadRequest)
		return
	}

	if requestBody.UserID == 0 || requestBody.NewPassword == "" {
		http.Error(w, "Todos los campos son obligatorios", http.StatusBadRequest)
		return
	}

	hashedPassword, err := models.EncryptPassword(requestBody.NewPassword)
	if err != nil {
		http.Error(w, "Error al encriptar la nueva contraseña", http.StatusInternalServerError)
		return
	}

	query := `UPDATE users SET password = $1 WHERE id = $2`
	result, err := config.DB.Exec(query, hashedPassword, requestBody.UserID)
	if err != nil {
		http.Error(w, "Error al actualizar la contraseña en la base de datos", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		http.Error(w, "Usuario no encontrado", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Contraseña actualizada exitosamente"))
}

// Eliminar un usuario por ID
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	rolUsuario := r.Header.Get("Role")
	if rolUsuario != "Dueño" && rolUsuario != "Admin" {
		http.Error(w, "No tienes permiso para eliminar usuarios", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]
	if userID == "" {
		http.Error(w, "El ID del usuario es requerido", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM users WHERE id = $1`
	result, err := config.DB.Exec(query, userID)
	if err != nil {
		http.Error(w, "Error al eliminar el usuario", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		http.Error(w, "Usuario no encontrado", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Usuario eliminado exitosamente"))
}

//
// ==================== Funciones Específicas ====================
//

// Función para gestionar el negocio
func ManageBusiness(w http.ResponseWriter, r *http.Request) {
	// Validar el rol del usuario
	userRole := r.Header.Get("Role")
	if userRole != "Dueño" {
		http.Error(w, "No tienes permiso para gestionar el negocio", http.StatusForbidden)
		return
	}

	// Estructura para recibir los datos del negocio
	var businessData struct {
		Name                string `json:"name"`
		NIT                 string `json:"nit"`
		LegalRepresentative string `json:"legal_representative"`
		BusinessReason      string `json:"business_reason"`
		UserID              int    `json:"user_id"`
	}

	// Decodificar el cuerpo de la solicitud
	err := json.NewDecoder(r.Body).Decode(&businessData)
	if err != nil {
		http.Error(w, "Solicitud inválida", http.StatusBadRequest)
		return
	}

	// Validar que los campos requeridos no estén vacíos
	if businessData.Name == "" || businessData.NIT == "" || businessData.LegalRepresentative == "" || businessData.BusinessReason == "" {
		http.Error(w, "Todos los campos son obligatorios", http.StatusBadRequest)
		return
	}

	// Actualizar la información del negocio en la base de datos
	query := `UPDATE business SET name = $1, nit = $2, legal_representative = $3, business_reason = $4 WHERE id = 1`
	_, err = config.DB.Exec(query, businessData.Name, businessData.NIT, businessData.LegalRepresentative, businessData.BusinessReason)
	if err != nil {
		fmt.Println("Error en consulta UPDATE:", err)
		http.Error(w, "Error al actualizar la información del negocio", http.StatusInternalServerError)
		return
	}

	// Registrar la gestión en la tabla business_logs
	logQuery := `INSERT INTO business_logs (user_id, action) VALUES ($1, $2)`
	_, err = config.DB.Exec(logQuery, businessData.UserID, "Actualización de información del negocio")
	if err != nil {
		fmt.Println("Error en consulta INSERT:", err)
		http.Error(w, "Error al registrar la gestión en el historial", http.StatusInternalServerError)
		return
	}

	// Responder con éxito
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Información del negocio actualizada exitosamente"))
}
func GetBusiness(w http.ResponseWriter, r *http.Request) {
    // Validar el rol del usuario
    userRole := r.Header.Get("Role")
    fmt.Println("Rol del usuario:", userRole) // Log para depuración
    if userRole != "Dueño" {
        http.Error(w, "No tienes permiso para ver la información del negocio", http.StatusForbidden)
        return
    }

    fmt.Println("Ejecutando consulta SELECT para obtener la información del negocio...")

    // Consultar la información del negocio
    query := `SELECT name, nit, legal_representative, business_reason FROM business WHERE id = 1`
    var businessData struct {
        Name                string `json:"name"`
        NIT                 string `json:"nit"`
        LegalRepresentative string `json:"legal_representative"`
        BusinessReason      string `json:"business_reason"`
    }

    err := config.DB.QueryRow(query).Scan(&businessData.Name, &businessData.NIT, &businessData.LegalRepresentative, &businessData.BusinessReason)
    if err != nil {
        fmt.Println("Error al obtener la información del negocio:", err) // Log para depuración
        http.Error(w, "Error al obtener la información del negocio", http.StatusInternalServerError)
        return
    }
    fmt.Println("Consulta SELECT ejecutada con éxito. Datos obtenidos:", businessData)

    // Responder con la información del negocio
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(businessData)
}

// Función para ver reportes (compartida entre Dueño y Admin)
func ViewReports(w http.ResponseWriter, r *http.Request) {
	userRole := "Admin" // Esto debería obtenerse del usuario autenticado
	if userRole != "Dueño" && userRole != "Admin" {
		http.Error(w, "No tienes permiso para ver reportes", http.StatusForbidden)
		return
	}
	HandleWithPermission(w, r, userRole, "ver_reportes", func() {
		w.Write([]byte("Reportes mostrados"))
	})
}

// Función para gestionar empleados (compartida entre Dueño y Admin)
func ManageEmployees(w http.ResponseWriter, r *http.Request) {
	userRole := "Admin" // Esto debería obtenerse del usuario autenticado
	if userRole != "Dueño" && userRole != "Admin" {
		http.Error(w, "No tienes permiso para gestionar empleados", http.StatusForbidden)
		return
	}
	HandleWithPermission(w, r, userRole, "gestionar_empleados", func() {
		w.Write([]byte("Empleados gestionados"))
	})
}

// Función para ver el historial de ventas (compartida entre Dueño, Admin y Employee)
func ViewSalesHistory(w http.ResponseWriter, r *http.Request) {
	userRole := "Admin" // Esto debería obtenerse del usuario autenticado
	if userRole != "Dueño" && userRole != "Admin" && userRole != "Employee" {
		http.Error(w, "No tienes permiso para ver el historial de ventas", http.StatusForbidden)
		return
	}
	HandleWithPermission(w, r, userRole, "ver_historial_ventas", func() {
		w.Write([]byte("Historial de ventas mostrado"))
	})
}

// Función para gestionar usuarios (compartida entre Dueño y Admin)
func ManageUsers(w http.ResponseWriter, r *http.Request) {
	userRole := "Admin" // Esto debería obtenerse del usuario autenticado
	if userRole != "Dueño" && userRole != "Admin" {
		http.Error(w, "No tienes permiso para gestionar usuarios", http.StatusForbidden)
		return
	}
	HandleWithPermission(w, r, userRole, "gestionar_usuarios", func() {
		w.Write([]byte("Usuarios gestionados"))
	})
}

// Función para autorizar descuentos
func AuthorizeDiscounts(w http.ResponseWriter, r *http.Request) {
	userRole := r.Header.Get("Role")
	HandleWithPermission(w, r, userRole, "autorizar_descuentos", func() {
		var requestBody struct {
			DiscountID int    `json:"discount_id"`
			Status     string `json:"status"`
		}
		err := json.NewDecoder(r.Body).Decode(&requestBody)
		if err != nil {
			http.Error(w, "Solicitud inválida", http.StatusBadRequest)
			return
		}

		query := `INSERT INTO permissions_logs (user_id, action, status) VALUES ($1, $2, $3)`
		_, dbErr := config.DB.Exec(query, 1, "autorizar_descuentos", requestBody.Status)
		if dbErr != nil {
			http.Error(w, "Error al registrar la acción", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"message":    "Descuento autorizado exitosamente",
			"discountID": requestBody.DiscountID,
			"status":     requestBody.Status,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
}

// Función para autorizar cambios de contraseña
func AuthorizePasswordChange(w http.ResponseWriter, r *http.Request) {
	userRole := "Dueño" // Esto debería obtenerse del usuario autenticado
	userID := 1         // ID del usuario autenticado (esto debería venir de un token o sesión)

	HandleWithPermission(w, r, userRole, "autorizar_cambio_contraseña", func() {
		var requestBody struct {
			UserID int    `json:"user_id"`
			Status string `json:"status"` // "aprobado" o "rechazado"
		}
		err := json.NewDecoder(r.Body).Decode(&requestBody)
		if err != nil {
			http.Error(w, "Solicitud inválida", http.StatusBadRequest)
			return
		}

		// Registrar la acción en la base de datos
		query := `INSERT INTO permissions_logs (user_id, action, status) VALUES ($1, $2, $3)`
		_, dbErr := config.DB.Exec(query, userID, "autorizar_cambio_contraseña", requestBody.Status)
		if dbErr != nil {
			http.Error(w, "Error al registrar la acción", http.StatusInternalServerError)
			return
		}

		// Responder con éxito
		response := map[string]interface{}{
			"message": "Cambio de contraseña autorizado exitosamente",
			"userID":  requestBody.UserID,
			"status":  requestBody.Status,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
}

// Función para gestionar el inventario (compartida entre Dueño y Admin)
func ManageInventory(w http.ResponseWriter, r *http.Request) {
	userRole := r.Header.Get("Role")
	HandleWithPermission(w, r, userRole, "gestionar_inventario", func() {
		w.Write([]byte("Inventario gestionado"))
	})
}

// Función para ver tareas (solo para Employee)
func ViewTasks(w http.ResponseWriter, r *http.Request) {
	userRole := "Employee" // Esto debería obtenerse del usuario autenticado
	HandleWithPermission(w, r, userRole, "ver_tareas", func() {
		w.Write([]byte("Tareas mostradas"))
	})
}

// Función para registrar ventas (solo para Employee)
func RegisterSales(w http.ResponseWriter, r *http.Request) {
	userRole := "Employee" // Esto debería obtenerse del usuario autenticado
	HandleWithPermission(w, r, userRole, "realizar_ventas", func() {
		w.Write([]byte("Venta registrada con éxito"))
	})
}

// Función para actualizar tareas (solo para Employee)
func UpdateTasks(w http.ResponseWriter, r *http.Request) {
	userRole := "Employee" // Esto debería obtenerse del usuario autenticado
	HandleWithPermission(w, r, userRole, "actualizar_tareas", func() {
		// Lógica para actualizar tareas
		w.Write([]byte("Tarea actualizada con éxito"))
	})
}

// GetPermissionsLogs obtiene los registros de permisos desde la base de datos
func GetPermissionsLogs(w http.ResponseWriter, r *http.Request) {
	// Consulta para obtener los registros de la tabla permissions_logs
	query := `SELECT id, user_id, action, status, created_at FROM permissions_logs`
	rows, err := config.DB.Query(query)
	if err != nil {
		http.Error(w, "Error al obtener los registros de permisos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Estructura para almacenar los registros
	var logs []struct {
		ID        int    `json:"id"`
		UserID    int    `json:"user_id"`
		Action    string `json:"action"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}

	// Iterar sobre los resultados y agregarlos a la lista
	for rows.Next() {
		var log struct {
			ID        int    `json:"id"`
			UserID    int    `json:"user_id"`
			Action    string `json:"action"`
			Status    string `json:"status"`
			CreatedAt string `json:"created_at"`
		}
		err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.Status, &log.CreatedAt)
		if err != nil {
			http.Error(w, "Error al procesar los registros", http.StatusInternalServerError)
			return
		}
		logs = append(logs, log)
	}

	// Responder con los registros en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// GetAuthorizedDiscounts obtiene los descuentos autorizados desde la base de datos
func GetAuthorizedDiscounts(w http.ResponseWriter, r *http.Request) {
	// Consulta para obtener los descuentos autorizados
	query := `SELECT id, user_id, action, status, created_at FROM permissions_logs WHERE action = 'autorizar_descuentos'`
	rows, err := config.DB.Query(query)
	if err != nil {
		http.Error(w, "Error al obtener los descuentos autorizados", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Estructura para almacenar los registros
	var discounts []struct {
		ID        int    `json:"id"`
		UserID    int    `json:"user_id"`
		Action    string `json:"action"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}

	// Iterar sobre los resultados y agregarlos a la lista
	for rows.Next() {
		var discount struct {
			ID        int    `json:"id"`
			UserID    int    `json:"user_id"`
			Action    string `json:"action"`
			Status    string `json:"status"`
			CreatedAt string `json:"created_at"`
		}
		err := rows.Scan(&discount.ID, &discount.UserID, &discount.Action, &discount.Status, &discount.CreatedAt)
		if err != nil {
			http.Error(w, "Error al procesar los registros", http.StatusInternalServerError)
			return
		}
		discounts = append(discounts, discount)
	}

	// Responder con los registros en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discounts)
}

// Función para generar un token
func GenerateToken(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Role string `json:"role"`
	}

	// Decodificar el cuerpo de la solicitud
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Error al decodificar la solicitud: formato inválido", http.StatusBadRequest)
		return
	}

	// Validar que el campo Role no esté vacío
	if requestBody.Role == "" {
		http.Error(w, "El campo 'role' es obligatorio", http.StatusBadRequest)
		return
	}

	// Validar que el rol sea válido
	validRoles := map[string]bool{
		"Dueño":    true,
		"Admin":    true,
		"Employee": true,
	}
	if !validRoles[requestBody.Role] {
		http.Error(w, "Rol inválido. Los roles permitidos son: Dueño, Admin, Employee", http.StatusBadRequest)
		return
	}

	// Generar el token
	token, err := middleware.GenerateToken(requestBody.Role)
	if err != nil {
		fmt.Println("Error al generar el token:", err) // Log para depuración
		http.Error(w, "Error interno al generar el token", http.StatusInternalServerError)
		return
	}

	// Responder con el token generado
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// (Duplicate definition removed)

func GetBusinessLogs(w http.ResponseWriter, r *http.Request) {
	// Obtener el rol del usuario autenticado desde el encabezado
	userRole := r.Header.Get("Role")
	if userRole != "Dueño" {
		http.Error(w, "No tienes permiso para ver las gestiones del negocio", http.StatusForbidden)
		return
	}

	// Consultar las gestiones realizadas en la tabla business_logs
	query := `SELECT id, user_id, action, timestamp FROM business_logs ORDER BY timestamp DESC`
	rows, err := config.DB.Query(query)
	if err != nil {
		http.Error(w, "Error al obtener las gestiones del negocio", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Estructura para almacenar las gestiones
	var logs []struct {
		ID        int    `json:"id"`
		UserID    int    `json:"user_id"`
		Action    string `json:"action"`
		Timestamp string `json:"timestamp"`
	}

	// Iterar sobre los resultados y agregarlos a la lista
	for rows.Next() {
		var log struct {
			ID        int    `json:"id"`
			UserID    int    `json:"user_id"`
			Action    string `json:"action"`
			Timestamp string `json:"timestamp"`
		}
		err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.Timestamp)
		if err != nil {
			http.Error(w, "Error al procesar los registros", http.StatusInternalServerError)
			return
		}
		logs = append(logs, log)
	}

	// Responder con los registros en formato JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}
