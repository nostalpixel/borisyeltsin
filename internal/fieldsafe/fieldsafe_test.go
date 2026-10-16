package fieldsafe

import "testing"

func TestRejectSecrets(t *testing.T) {
	if err := RejectSecrets([]byte(`{"services":[{"name":"A","password":"hunter2"}]}`)); err != ErrSecret {
		t.Fatal(err)
	}
	if err := RejectSecrets([]byte(`{"services":[{"name":"A","password":""}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := RejectSecrets([]byte(`{"notes":"no secrets here"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestPAN(t *testing.T) {
	if !ContainsPAN("4111 1111 1111 1111") {
		t.Fatal("spaced")
	}
	if !ContainsPAN("4111-1111-1111-1111") {
		t.Fatal("dashed")
	}
	if ContainsPAN("Visa •4242") || ContainsPAN("2026-11-01") {
		t.Fatal("false positive")
	}
}
