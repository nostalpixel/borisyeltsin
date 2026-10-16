.PHONY: test web ui compose sqlc

# Integration tests start Postgres with Docker and skip when Docker is unavailable.
test:
	go test ./...

web:
	cd web && npm test && npm run build

# Local go run only. Docker copies the UI inside the image. Do not commit this output.
ui: web
	rm -rf internal/httpserver/dist
	mkdir -p internal/httpserver/dist
	cp -R web/dist/. internal/httpserver/dist/

compose:
	docker compose config

sqlc:
	sqlc generate
