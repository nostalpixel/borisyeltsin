// Package testpg starts one PostgreSQL container for integration tests.
package testpg

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nostalpixel/borisyeltsin/internal/migrate"
)

var (
	once       sync.Once
	migrateMu  sync.Once
	dsn        string
	name       string
	startErr   error
	migrateErr error
)

// Pool returns a connection pool. The test is skipped when Docker is
// unavailable, unless TESTPG_REQUIRED=1, which CI sets so a green run always
// means the database tests ran.
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	once.Do(start)
	if startErr != nil {
		if os.Getenv("TESTPG_REQUIRED") == "1" {
			t.Fatal(startErr.Error())
		}
		t.Skip(startErr.Error())
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrateMu.Do(func() {
		migrateErr = migrate.Up(context.Background(), pool)
	})
	if migrateErr != nil {
		t.Fatal(migrateErr)
	}
	return pool
}

// EmptyDatabase creates a separate database with no tables and returns a pool
// for it. Tests that need an empty users table or a specific migration state
// use it instead of the shared database.
func EmptyDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	admin := Pool(t)
	dbName := "t_" + strings.ReplaceAll(strconv.FormatInt(time.Now().UnixNano(), 36), "-", "")
	if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), strings.Replace(dsn, "/boriseltsyn?", "/"+dbName+"?", 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Stop removes the test container.
func Stop() {
	if name == "" {
		return
	}
	_ = exec.Command("docker", "rm", "-f", name).Run()
}

func start() {
	if _, err := exec.LookPath("docker"); err != nil {
		startErr = fmt.Errorf("docker not available: %w", err)
		return
	}
	name = "boris-pg-" + strconv.Itoa(os.Getpid())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_PASSWORD=test",
		"-e", "POSTGRES_USER=boris",
		"-e", "POSTGRES_DB=boriseltsyn",
		"-p", "127.0.0.1::5432",
		"postgres:16-alpine").CombinedOutput()
	if err != nil {
		startErr = fmt.Errorf("docker run: %w %s", err, out)
		return
	}
	deadline := time.Now().Add(2 * time.Minute)
	var mapped string
	for time.Now().Before(deadline) {
		portOut, err := exec.Command("docker", "port", name, "5432/tcp").Output()
		if err == nil && strings.Contains(string(portOut), ":") {
			mapped = strings.TrimSpace(string(portOut))
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if mapped == "" {
		startErr = fmt.Errorf("no published port")
		return
	}
	port := mapped[strings.LastIndex(mapped, ":")+1:]
	dsn = "postgres://boris:test@127.0.0.1:" + port + "/boriseltsyn?sslmode=disable"
	for time.Now().Before(deadline) {
		pool, err := pgxpool.New(context.Background(), dsn)
		if err == nil {
			err = pool.Ping(context.Background())
			pool.Close()
			if err == nil {
				return
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	startErr = fmt.Errorf("postgres not ready")
}
