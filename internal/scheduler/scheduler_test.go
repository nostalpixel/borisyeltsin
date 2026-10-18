package scheduler

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nostalpixel/borisyeltsin/internal/db"
	"github.com/nostalpixel/borisyeltsin/internal/testpg"
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

func TestRunAdvancesPastAutoRenewals(t *testing.T) {
	pool := testpg.Pool(t)
	q := db.New(pool)
	ctx := context.Background()
	org, err := q.CreateOrganization(ctx, "Renewals")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := q.CreateService(ctx, db.CreateServiceParams{
		OrganizationID: org.ID, Name: "Linode", Category: "infra",
		Logo: "LI", LogoBg: "#eeeafc", LogoFg: "#7663c6", Tags: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC()
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	past := today.AddDate(0, 0, -45)
	custom := int32(30)
	create := func(name, cycle string, days *int32, auto bool) db.Subscription {
		sub, err := q.CreateSubscription(ctx, db.CreateSubscriptionParams{
			ServiceID: svc.ID, Name: name, BillingCycle: cycle, CustomIntervalDays: days,
			RenewalDate: past, CostMinor: 500, Currency: "USD", AutoRenew: auto,
		})
		if err != nil {
			t.Fatal(err)
		}
		return sub
	}
	custSub := create("custom", "custom", &custom, true)
	manual := create("manual", "monthly", nil, false)

	run(ctx, pool, time.UTC)
	run(ctx, pool, time.UTC)

	got, err := q.GetSubscription(ctx, db.GetSubscriptionParams{ID: custSub.ID, OrganizationID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	if want := past.AddDate(0, 0, 60); !got.RenewalDate.Equal(want) {
		t.Fatalf("custom renewal %s, want %s", got.RenewalDate.Format("2006-01-02"), want.Format("2006-01-02"))
	}
	kept, err := q.GetSubscription(ctx, db.GetSubscriptionParams{ID: manual.ID, OrganizationID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !kept.RenewalDate.Equal(past) {
		t.Fatalf("manual renewal moved to %s", kept.RenewalDate.Format("2006-01-02"))
	}
}
