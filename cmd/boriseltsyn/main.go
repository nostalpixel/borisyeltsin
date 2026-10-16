package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "time/tzdata"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nostalpixel/boriseltsyn/internal/config"
	"github.com/nostalpixel/boriseltsyn/internal/db"
	"github.com/nostalpixel/boriseltsyn/internal/httpserver"
	"github.com/nostalpixel/boriseltsyn/internal/migrate"
	"github.com/nostalpixel/boriseltsyn/internal/scheduler"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err := migrate.Up(ctx, pool); err != nil {
		slog.Error("migrate", "error", err)
		os.Exit(1)
	}
	token, created, err := httpserver.Bootstrap(ctx, db.New(pool), cfg)
	if err != nil {
		slog.Error("bootstrap", "error", err)
		os.Exit(1)
	}
	if created {
		fmt.Println("BOOTSTRAP_INVITE_TOKEN=" + token)
	}
	server := httpserver.New(pool, cfg)
	if err := server.UseOIDC(ctx); err != nil {
		slog.Error("oidc", "error", err)
		os.Exit(1)
	}
	scheduler.Start(ctx, pool, server.Loc)
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	slog.Info("listening", "addr", cfg.HTTPAddr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("http", "error", err)
		os.Exit(1)
	}
}
