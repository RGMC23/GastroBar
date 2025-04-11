package models

type Tarea struct {
    ID          int    `json:"id"`
    EmpleadoID  int    `json:"empleado_id"`
    Titulo      string `json:"titulo"`
    Descripcion string `json:"descripcion"`
    FechaLimite string `json:"fecha_limite"`
    Estado      string `json:"estado"` // "Pendiente", "Completada", "No Completada"
}