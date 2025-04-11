package controllers

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestGetMenu(t *testing.T) {
    req, err := http.NewRequest("GET", "/menu", nil)
    if err != nil {
        t.Fatal(err)
    }

    rr := httptest.NewRecorder()
    handler := http.HandlerFunc(GetMenu)

    handler.ServeHTTP(rr, req)

    // Verificar el código de estado
    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler devolvió un código de estado incorrecto: obtuvo %v, esperaba %v", status, http.StatusOK)
    }

    // Verificar el contenido de la respuesta
    expected := `[{"id":1,"nombre":"Hamburguesa","categoria":"comida","precio":8.50,"stock":50}]`
    if rr.Body.String() != expected {
        t.Errorf("handler devolvió un cuerpo inesperado: obtuvo %v, esperaba %v", rr.Body.String(), expected)
    }
}