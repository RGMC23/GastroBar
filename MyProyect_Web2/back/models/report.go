package models

type Report struct {
    ID          int    `json:"id"`
    Titulo      string `json:"titulo"`
    Descripcion string `json:"descripcion"`
    Fecha       string `json:"fecha"`
}