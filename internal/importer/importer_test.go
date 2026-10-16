package importer

import "testing"

func TestParseBackup(t *testing.T) {
	raw := []byte(`{
	  "version": 1,
	  "services": [{
	    "name": "Zomro",
	    "url": "https://zomro.com/",
	    "category": "infra",
	    "description": "VPN",
	    "unclear": false,
	    "logo": "ZO",
	    "bg": "#eeeafc",
	    "fg": "#7663c6",
	    "accounts": [{
	      "label": "Аккаунт 1",
	      "login": "ops@example.com",
	      "password": "",
	      "cost": "12.50",
	      "currency": "USDT",
	      "date": "2026-11-01",
	      "card": "Visa 4242",
	      "notes": "prod"
	    }]
	  }]
	}`)
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Accounts[0].Currency != "USDT" || got[0].Accounts[0].Cost != "12.50" {
		t.Fatalf("%+v", got)
	}
}

func TestParseRejectsPassword(t *testing.T) {
	raw := []byte(`{"version":1,"services":[{"name":"A","accounts":[{"password":"secret"}]}]}`)
	if _, err := Parse(raw); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestParseRejectsPAN(t *testing.T) {
	raw := []byte(`{"version":1,"services":[{"name":"A","accounts":[{"card":"4111111111111111","password":""}]}]}`)
	if _, err := Parse(raw); err == nil {
		t.Fatal("expected card rejection")
	}
}
