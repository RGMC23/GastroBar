package models

var RolePermissions = map[string][]string{
	"Dueño": {
		"gestionar_negocio",    // Permiso para gestionar el negocio
		"ver_reportes",         // Permiso para ver reportes
		"gestionar_empleados",  // Permiso para gestionar empleados
		"ver_historial_ventas", // Permiso para ver el historial de ventas
		"gestionar_usuarios",   // Permiso para gestionar usuarios
	    "autorizar_descuentos", // Permiso para autorizar descuentos
	    "autorizar_cambio_contraseña", // Permiso para autorizar cambios de contraseña
	    "gestionar_inventario", // Permiso para gestionar el inventario
	},
	"Admin": {
		"ver_reportes",         // Permiso para ver reportes
		"gestionar_usuarios",   // Permiso para gestionar usuarios
		"ver_historial_ventas", // Permiso para ver el historial de ventas
	    "gestionar_empleados", // Permiso para gestionar empleados
	    "gestionar_inventario", // Permiso para gestionar el inventario
	},
	"Empleado": {
		"ver_tareas",           // Permiso para ver tareas
		"actualizar_tareas",    // Permiso para actualizar tareas
		"realizar_ventas",      // Permiso para registrar ventas
		"ver_historial_ventas", // Permiso para ver el historial de ventas realizadas
	},
}
