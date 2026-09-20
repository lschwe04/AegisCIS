package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"aegis/internal/audit"
	"aegis/internal/handlers"
	aegisMiddleware "aegis/internal/middleware" // Alias, um Konflikte zu vermeiden

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:secret@localhost:5432/aegis" // Standard-Dev-String
	}

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer pool.Close()

	// Starte den asynchronen WORM Worker[cite: 8]
	wormBuilder := audit.NewWORMBuilder(pool)
	go wormBuilder.StartWORMWorker(context.Background(), 2*time.Second)

	// Routing & Middleware-Kette
	mux := http.NewServeMux()

	// API Endpoint für Agenten
	mux.Handle("/api/v1/hardening/report",
		aegisMiddleware.AuthMiddleware(pool)(
			aegisMiddleware.AuditLogMiddleware(pool)(
				handlers.HandleHardeningReport(pool),
			),
		),
	)

	// Dashboard Endpoint für den Browser
	mux.Handle("/dashboard",
		aegisMiddleware.AuthMiddleware(pool)(
			handlers.HandleDashboard(pool),
		),
	)

	log.Println("🚀 AegisCIS Server gestartet auf Port 8080")
	log.Println("Öffne http://localhost:8080/dashboard (Setze X-API-Key: DEMO-ADMIN-KEY-456)")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
