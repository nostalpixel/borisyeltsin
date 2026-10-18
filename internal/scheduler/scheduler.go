// Package scheduler advances auto-renewing subscriptions and records renewal
// alerts inside the application process.
package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"github.com/nostalpixel/borisyeltsin/internal/spend"
)

// Start checks renewal dates once a minute until ctx is cancelled.
func Start(ctx context.Context, pool *pgxpool.Pool, loc *time.Location) {
	if loc == nil {
		loc = time.UTC
	}
	go func() {
		run(ctx, pool, loc)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run(ctx, pool, loc)
			}
		}
	}()
}

func run(ctx context.Context, pool *pgxpool.Pool, loc *time.Location) {
	q := db.New(pool)
	rows, err := q.ListRenewalCandidates(ctx)
	if err != nil {
		slog.Error("renewal scan failed", "error", err)
		return
	}
	now := time.Now()
	today := spend.Today(now, loc)
	for _, row := range rows {
		if row.AutoRenew {
			advance(ctx, q, &row, today)
		}
		for _, horizon := range spend.AlertHorizons(spend.DaysUntil(row.RenewalDate, now, loc), true) {
			if err := q.InsertRenewalAlert(ctx, db.InsertRenewalAlertParams{
				OrganizationID: row.OrganizationID,
				SubscriptionID: row.ID,
				DaysBefore:     int32(horizon),
				DueOn:          row.RenewalDate,
			}); err != nil {
				slog.Error("renewal alert failed", "error", err)
			}
		}
	}
}

// advance moves a past-due auto-renewing subscription to its next renewal.
func advance(ctx context.Context, q *db.Queries, row *db.ListRenewalCandidatesRow, today time.Time) {
	var customDays int32
	if row.CustomIntervalDays != nil {
		customDays = *row.CustomIntervalDays
	}
	next, moved := spend.NextRenewal(row.RenewalDate, row.BillingCycle, customDays, today)
	if !moved {
		return
	}
	n, err := q.AdvanceRenewalDate(ctx, db.AdvanceRenewalDateParams{NextDate: next, ID: row.ID, PreviousDate: row.RenewalDate})
	if err != nil {
		slog.Error("renewal advance failed", "error", err)
		return
	}
	if n == 1 {
		row.RenewalDate = next
	}
}
