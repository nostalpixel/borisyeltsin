package scheduler

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nostalpixel/boriseltsyn/internal/db"
	"github.com/nostalpixel/boriseltsyn/internal/testpg"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testpg.Stop()
	os.Exit(code)
}

func TestRunInsertsExactHorizonAlert(t *testing.T) {
	pool := testpg.Pool(t)
	q := db.New(pool)
	ctx := context.Background()
	org, err := q.CreateOrganization(ctx, "Alerts")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := q.CreateService(ctx, db.CreateServiceParams{
		OrganizationID: org.ID,
		Name:           "Zomro",
		Category:       "infra",
		Logo:           "ZO",
		LogoBg:         "#eeeafc",
		LogoFg:         "#7663c6",
		Tags:           []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	due := time.Now().UTC().AddDate(0, 0, 3)
	due = time.Date(due.Year(), due.Month(), due.Day(), 0, 0, 0, 0, time.UTC)
	sub, err := q.CreateSubscription(ctx, db.CreateSubscriptionParams{
		ServiceID: svc.ID, Name: "VPN", BillingCycle: "monthly",
		RenewalDate: due, CostMinor: 1250, Currency: "USDT", AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	run(ctx, pool, time.UTC)
	run(ctx, pool, time.UTC)
	alerts, err := q.ListRenewalAlerts(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].DaysBefore != 3 || alerts[0].SubscriptionID != sub.ID {
		t.Fatalf("alerts %+v", alerts)
	}
}
