package models

// Estructura para un ítem del menú
type MenuItem struct {
	ID        int     `json:"id"`
	Nombre    string  `json:"nombre"`    // Nombre del ítem
	Categoria string  `json:"categoria"` // "comida" o "bebida"
	Precio    float64 `json:"precio"`    // Precio del ítem
	Stock     int     `json:"stock"`     // Cantidad disponible en el inventario
}

// Estructura para un pedido
type Pedido struct {
	ID        int              `json:"id"`
	MesaID    int              `json:"mesa_id"`   // Número de la mesa
	Elementos []ElementoPedido `json:"elementos"` // Lista de ítems pedidos
	Total     float64          `json:"total"`     // Total del pedido
	Pagado    bool             `json:"pagado"`    // Estado del pago
}

// Estructura para un ítem dentro de un pedido
type ElementoPedido struct {
	ItemMenuID int `json:"item_menu_id"` // ID del ítem del menú
	Cantidad   int `json:"cantidad"`     // Cantidad pedida
}

// Estructura para una mesa
type Mesa struct {
	ID     int    `json:"id"`
	Estado string `json:"estado"` // "ocupada" o "libre"
}
