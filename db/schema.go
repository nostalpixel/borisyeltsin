// Package dbschema embeds the SQL migrations applied at startup.
package dbschema

import "embed"

//go:embed migrations/*.sql
var Migrations embed.FS
