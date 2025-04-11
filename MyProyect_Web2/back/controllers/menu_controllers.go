package controllers

import (
	"back/config"
	"back/models"
	"encoding/json"
	"net/http"
)

// Obtener el menú (comida y bebidas)
func GetMenu(w http.ResponseWriter, r *http.Request) {
	rows, err := config.DB.Query("SELECT id, nombre, categoria, precio, stock FROM menu_items")
	if err != nil {
		http.Error(w, "Error al obtener el menú", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var menu []models.MenuItem
	for rows.Next() {
		var item models.MenuItem
		if err := rows.Scan(&item.ID, &item.Nombre, &item.Categoria, &item.Precio, &item.Stock); err != nil {
			http.Error(w, "Error al procesar un ítem del menú", http.StatusInternalServerError)
			return
		}
		menu = append(menu, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(menu)
}

// Crear un pedido
func CreateOrder(w http.ResponseWriter, r *http.Request) {
	var pedido models.Pedido
	err := json.NewDecoder(r.Body).Decode(&pedido)
	if err != nil {
		http.Error(w, "Entrada inválida", http.StatusBadRequest)
		return
	}

	// Verificar que se haya especificado el número de la mesa
	if pedido.MesaID == 0 {
		http.Error(w, "Debe especificar el número de la mesa", http.StatusBadRequest)
		return
	}
	// Validar que el número de la mesa esté dentro del rango permitido (1 a 4)
    if pedido.MesaID < 1 || pedido.MesaID > 4 {
        http.Error(w, "El número de la mesa debe estar entre 1 y 4", http.StatusBadRequest)
        return
    }

	// Verificar stock y calcular el total
	var total float64
	for _, elemento := range pedido.Elementos {
		var itemMenu models.MenuItem
		// Obtener el ítem del menú desde la base de datos
		err := config.DB.QueryRow("SELECT id, nombre, precio, stock FROM menu_items WHERE id = $1", elemento.ItemMenuID).Scan(&itemMenu.ID, &itemMenu.Nombre, &itemMenu.Precio, &itemMenu.Stock)
		if err != nil {
			http.Error(w, "Ítem no encontrado", http.StatusNotFound)
			return
		}

		// Verificar si hay suficiente stock
		if itemMenu.Stock < elemento.Cantidad {
			http.Error(w, "Stock insuficiente para "+itemMenu.Nombre, http.StatusBadRequest)
			return
		}

		// Calcular el costo total del pedido
		total += itemMenu.Precio * float64(elemento.Cantidad)

		// Descontar del inventario
		_, err = config.DB.Exec("UPDATE menu_items SET stock = stock - $1 WHERE id = $2", elemento.Cantidad, elemento.ItemMenuID)
		if err != nil {
			http.Error(w, "Error al actualizar el stock", http.StatusInternalServerError)
			return
		}
	}

	// Guardar el pedido en la base de datos
	query := `INSERT INTO orders (table_id, total, paid) VALUES ($1, $2, $3) RETURNING id`
	err = config.DB.QueryRow(query, pedido.MesaID, total, false).Scan(&pedido.ID)
	if err != nil {
		http.Error(w, "Error al guardar el pedido", http.StatusInternalServerError)
		return
	}

	// Responder con el pedido creado
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(pedido)
}

// Ver historial de ventas
func GetSalesHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := config.DB.Query("SELECT id, table_id, total, paid FROM orders")
	if err != nil {
		http.Error(w, "Error al obtener el historial de ventas", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var pedidos []models.Pedido
	for rows.Next() {
		var pedido models.Pedido
		if err := rows.Scan(&pedido.ID, &pedido.MesaID, &pedido.Total, &pedido.Pagado); err != nil {
			http.Error(w, "Error al procesar un pedido", http.StatusInternalServerError)
			return
		}
		pedidos = append(pedidos, pedido)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pedidos)
}
