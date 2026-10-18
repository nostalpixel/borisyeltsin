package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"github.com/nostalpixel/borisyeltsin/internal/token"
)

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

type mcpFixture struct {
	srv   *Server
	q     *db.Queries
	h     http.Handler
	http  *httptest.Server
	org   db.Organization
	admin actor
}

func newMCPFixture(t *testing.T) mcpFixture {
	t.Helper()
	srv, q := newServer(t)
	srv.Now = func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) }
	org, err := q.CreateOrganization(context.Background(), "Agents")
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return mcpFixture{srv: srv, q: q, h: h, http: ts, org: org, admin: srv.addUser(t, q, org.ID, "admin", "active")}
}

func (f mcpFixture) token(t *testing.T, a *actor, canWrite bool) string {
	t.Helper()
	rec := call(f.h, http.MethodPost, "/api/v1/tokens", map[string]any{"name": "claude", "can_write": canWrite}, a)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create token %d %s", rec.Code, rec.Body.String())
	}
	return decodeJSON(t, rec.Body.Bytes())["token"].(string)
}

func (f mcpFixture) connect(t *testing.T, plain string) (*mcp.ClientSession, error) {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	return client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             f.http.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: bearer{token: plain, base: http.DefaultTransport}},
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
}

func (f mcpFixture) session(t *testing.T, plain string) *mcp.ClientSession {
	t.Helper()
	cs, err := f.connect(t, plain)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		text := ""
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text += tc.Text
			}
		}
		return map[string]any{"error": text}, false
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	return decodeJSON(t, raw), true
}

func (f mcpFixture) service(t *testing.T, name string, owner uuid.UUID) db.Service {
	t.Helper()
	svc, err := f.q.CreateService(context.Background(), db.CreateServiceParams{
		OrganizationID: f.org.ID, Name: name, Category: "infra", Logo: "XX",
		LogoBg: "#000000", LogoFg: "#ffffff", OwnerID: &owner, Tags: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (f mcpFixture) subscription(t *testing.T, svc db.Service, cycle, renewal string, cost int64) {
	t.Helper()
	date, _ := time.Parse("2006-01-02", renewal)
	if _, err := f.q.CreateSubscription(context.Background(), db.CreateSubscriptionParams{
		ServiceID: svc.ID, BillingCycle: cycle, RenewalDate: date, CostMinor: cost, Currency: "USD", AutoRenew: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAgentTokenIsShownOnceStoredHashedAndRevocable(t *testing.T) {
	f := newMCPFixture(t)
	plain := f.token(t, &f.admin, false)
	if !strings.HasPrefix(plain, "bey_") {
		t.Fatalf("token %q", plain)
	}
	row, err := f.q.GetActiveAPIToken(context.Background(), token.Hash(plain))
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := f.srv.Pool.QueryRow(context.Background(), "SELECT token_hash FROM api_tokens WHERE id = $1", row.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), plain) || len(stored) != 32 {
		t.Fatal("token stored in the clear")
	}
	list := call(f.h, http.MethodGet, "/api/v1/tokens", nil, &f.admin)
	if strings.Contains(list.Body.String(), plain) {
		t.Fatal("list shows the token")
	}
	f.session(t, plain)

	if rec := call(f.h, http.MethodPost, "/api/v1/tokens/"+row.ID.String()+"/revoke", map[string]any{}, &f.admin); rec.Code != http.StatusOK {
		t.Fatalf("revoke %d", rec.Code)
	}
	if _, err := f.connect(t, plain); err == nil {
		t.Fatal("revoked token still connects")
	}
	if _, err := f.connect(t, "bey_"+strings.Repeat("A", 43)); err == nil {
		t.Fatal("unknown token connects")
	}
}

func TestAgentTokenRules(t *testing.T) {
	f := newMCPFixture(t)
	reader := f.srv.addUser(t, f.q, f.org.ID, "readonly", "active")
	if rec := call(f.h, http.MethodPost, "/api/v1/tokens", map[string]any{"name": "x", "can_write": true}, &reader); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only user got a write token: %d", rec.Code)
	}
	if rec := call(f.h, http.MethodPost, "/api/v1/tokens", map[string]any{"name": "x", "days": 91}, &f.admin); rec.Code != http.StatusBadRequest {
		t.Fatalf("91 days: %d", rec.Code)
	}
	// A member cannot revoke someone else's token; an admin can.
	member := f.srv.addUser(t, f.q, f.org.ID, "member", "active")
	plain := f.token(t, &f.admin, false)
	row, _ := f.q.GetActiveAPIToken(context.Background(), token.Hash(plain))
	if rec := call(f.h, http.MethodPost, "/api/v1/tokens/"+row.ID.String()+"/revoke", map[string]any{}, &member); rec.Code != http.StatusNotFound {
		t.Fatalf("member revoked admin token: %d", rec.Code)
	}
	// Revoking the person revokes their tokens.
	memberToken := f.token(t, &member, false)
	if rec := call(f.h, http.MethodPost, "/api/v1/users/"+member.user.ID.String()+"/revoke", map[string]any{}, &f.admin); rec.Code != http.StatusOK {
		t.Fatalf("revoke user %d %s", rec.Code, rec.Body.String())
	}
	if _, err := f.connect(t, memberToken); err == nil {
		t.Fatal("revoked user's token still connects")
	}
	// Expired tokens stop working.
	expired := f.token(t, &f.admin, false)
	if _, err := f.srv.Pool.Exec(context.Background(), "UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = $1", token.Hash(expired)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.connect(t, expired); err == nil {
		t.Fatal("expired token connects")
	}
}

func TestMCPReadsTheLedgerTheOwnerCanSee(t *testing.T) {
	f := newMCPFixture(t)
	member := f.srv.addUser(t, f.q, f.org.ID, "member", "active")
	linode := f.service(t, "Linode", member.user.ID)
	f.subscription(t, linode, "monthly", "2026-10-25", 40000)
	hidden := f.service(t, "Payroll", f.admin.user.ID)
	f.subscription(t, hidden, "annual", "2027-03-01", 120000)
	if _, err := f.q.CreateAccount(context.Background(), db.CreateAccountParams{
		ServiceID: linode.ID, Label: "root", LoginHint: "ops-root@example.com", CardLabel: "Visa 4242",
	}); err != nil {
		t.Fatal(err)
	}

	admin := f.session(t, f.token(t, &f.admin, false))
	bill, ok := callTool(t, admin, "monthly_bill", nil)
	if !ok || bill["monthly_total"].(map[string]any)["USD"] != "500.00" || bill["subscriptions"].(float64) != 2 {
		t.Fatalf("admin bill %+v", bill)
	}
	renewals, ok := callTool(t, admin, "upcoming_renewals", map[string]any{"days": 30})
	if !ok || len(renewals["subscriptions"].([]any)) != 1 {
		t.Fatalf("renewals %+v", renewals)
	}
	first := renewals["subscriptions"].([]any)[0].(map[string]any)
	if first["service"] != "Linode" || first["days_until_renewal"].(float64) != 6 || first["renewal_date"] != "2026-10-25" {
		t.Fatalf("renewal %+v", first)
	}

	mine := f.session(t, f.token(t, &member, false))
	memberBill, _ := callTool(t, mine, "monthly_bill", nil)
	if memberBill["monthly_total"].(map[string]any)["USD"] != "400.00" {
		t.Fatalf("member sees a service it cannot view: %+v", memberBill)
	}
	all, _ := callTool(t, mine, "list_subscriptions", nil)
	raw, _ := json.Marshal(all)
	for _, secret := range []string{"ops-root@example.com", "Visa 4242", "Payroll"} {
		if strings.Contains(string(raw)+mustJSON(t, memberBill), secret) {
			t.Fatalf("MCP output contains %q", secret)
		}
	}

	tools, err := mine.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if tool.Name == "add_subscription" {
			t.Fatal("read-only token lists the write tool")
		}
	}
	if _, err := mine.CallTool(context.Background(), &mcp.CallToolParams{Name: "add_subscription", Arguments: map[string]any{}}); err == nil {
		t.Fatal("read-only token called the write tool")
	}
}

func TestMCPAddsASubscriptionAndItsService(t *testing.T) {
	f := newMCPFixture(t)
	cs := f.session(t, f.token(t, &f.admin, true))
	args := map[string]any{"service": "Claude", "name": "Team, 2 users", "cost": "400", "renewal_date": "2026-11-15", "category": "tools"}
	out, ok := callTool(t, cs, "add_subscription", args)
	if !ok || out["service_created"] != true {
		t.Fatalf("add %+v", out)
	}
	sub := out["subscription"].(map[string]any)
	if sub["cost"] != "400.00" || sub["currency"] != "USD" || sub["billing_cycle"] != "monthly" || sub["renewal_date"] != "2026-11-15" || sub["auto_renew"] != true {
		t.Fatalf("subscription %+v", sub)
	}
	// The same name (any case) reuses the service.
	args["service"] = "claude"
	args["name"] = "API"
	if out, ok := callTool(t, cs, "add_subscription", args); !ok || out["service_created"] != false {
		t.Fatalf("second add %+v", out)
	}
	bill, _ := callTool(t, cs, "monthly_bill", map[string]any{"category": "tools"})
	if bill["monthly_total"].(map[string]any)["USD"] != "800.00" {
		t.Fatalf("bill %+v", bill)
	}
	var viaMCP int
	if err := f.srv.Pool.QueryRow(context.Background(),
		"SELECT count(*) FROM audit_events WHERE organization_id = $1 AND metadata->>'via' = 'mcp'", f.org.ID).Scan(&viaMCP); err != nil {
		t.Fatal(err)
	}
	if viaMCP != 3 {
		t.Fatalf("audit events via mcp: %d", viaMCP)
	}

	if out, ok := callTool(t, cs, "add_subscription", map[string]any{"service": "Claude", "cost": "abc", "renewal_date": "2026-11-15"}); ok {
		t.Fatalf("bad cost accepted %+v", out)
	}
	if out, ok := callTool(t, cs, "add_subscription", map[string]any{"service": "Claude", "name": "card 4111 1111 1111 1111", "cost": "1", "renewal_date": "2026-11-15"}); ok {
		t.Fatalf("card number accepted %+v", out)
	}

	// A member may not create services, and may only add to services they can edit.
	member := f.srv.addUser(t, f.q, f.org.ID, "member", "active")
	mine := f.session(t, f.token(t, &member, true))
	if out, ok := callTool(t, mine, "add_subscription", map[string]any{"service": "Zoom", "cost": "15", "renewal_date": "2026-11-01"}); ok {
		t.Fatalf("member created a service %+v", out)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAgentErrorsHideInternals(t *testing.T) {
	if got := agentErr(errors.New(`ERROR: violates check constraint "cost_chk" (SQLSTATE 23514)`)); got.Error() != "internal error" {
		t.Fatalf("leaked %q", got)
	}
	if got := agentErr(toolError("cost is required")); got.Error() != "cost is required" {
		t.Fatalf("lost message %q", got)
	}
	f := newMCPFixture(t)
	cs := f.session(t, f.token(t, &f.admin, true))
	out, ok := callTool(t, cs, "add_subscription", map[string]any{"service": "Big", "cost": "92233720368547759", "renewal_date": "2026-11-15"})
	if ok || strings.Contains(out["error"].(string), "SQLSTATE") {
		t.Fatalf("overflowing cost: %+v", out)
	}
}

func TestAgentTokensStayInTheirOrganization(t *testing.T) {
	f := newMCPFixture(t)
	plain := f.token(t, &f.admin, false)
	row, _ := f.q.GetActiveAPIToken(context.Background(), token.Hash(plain))
	other, err := f.q.CreateOrganization(context.Background(), "Other")
	if err != nil {
		t.Fatal(err)
	}
	stranger := f.srv.addUser(t, f.q, other.ID, "admin", "active")
	if rec := call(f.h, http.MethodGet, "/api/v1/tokens?all=1", nil, &stranger); strings.Contains(rec.Body.String(), row.ID.String()) {
		t.Fatal("another organization's admin lists the token")
	}
	if rec := call(f.h, http.MethodPost, "/api/v1/tokens/"+row.ID.String()+"/revoke", map[string]any{}, &stranger); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-org revoke %d", rec.Code)
	}
	f.session(t, plain)
}

func TestDemotedOwnerLosesTheWriteTool(t *testing.T) {
	f := newMCPFixture(t)
	manager := f.srv.addUser(t, f.q, f.org.ID, "manager", "active")
	plain := f.token(t, &manager, true)
	if _, err := f.srv.Pool.Exec(context.Background(), "UPDATE users SET role = 'readonly' WHERE id = $1", manager.user.ID); err != nil {
		t.Fatal(err)
	}
	tools, err := f.session(t, plain).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if tool.Name == "add_subscription" {
			t.Fatal("demoted owner still has the write tool")
		}
	}
}

func TestManagerCannotWriteToServicesItCannotSee(t *testing.T) {
	f := newMCPFixture(t)
	private := f.service(t, "Payroll", f.admin.user.ID)
	manager := f.srv.addUser(t, f.q, f.org.ID, "manager", "active")
	cs := f.session(t, f.token(t, &manager, true))
	callTool(t, cs, "add_subscription", map[string]any{"service": "Payroll", "cost": "10", "renewal_date": "2026-11-01"})
	var onPrivate int
	if err := f.srv.Pool.QueryRow(context.Background(), "SELECT count(*) FROM subscriptions WHERE service_id = $1", private.ID).Scan(&onPrivate); err != nil {
		t.Fatal(err)
	}
	if onPrivate != 0 {
		t.Fatal("manager wrote to a service it cannot see")
	}
}

func TestArchivedServiceIsNotDuplicated(t *testing.T) {
	f := newMCPFixture(t)
	svc := f.service(t, "Zoom", f.admin.user.ID)
	if _, err := f.srv.Pool.Exec(context.Background(), "UPDATE services SET archived_at = now() WHERE id = $1", svc.ID); err != nil {
		t.Fatal(err)
	}
	cs := f.session(t, f.token(t, &f.admin, true))
	if out, ok := callTool(t, cs, "add_subscription", map[string]any{"service": "zoom", "cost": "15", "renewal_date": "2026-11-01"}); ok || !strings.Contains(out["error"].(string), "archived") {
		t.Fatalf("archived duplicate: %+v", out)
	}
}

func TestMCPRejectsGetAndOversizedBodies(t *testing.T) {
	f := newMCPFixture(t)
	plain := f.token(t, &f.admin, false)
	req, _ := http.NewRequest(http.MethodGet, f.http.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	req.Header.Set("Accept", "text/event-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET %d", res.StatusCode)
	}
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("x", 2<<20) + `"}}`
	req, _ = http.NewRequest(http.MethodPost, f.http.URL+"/mcp", strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer "+plain)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode < 400 {
		t.Fatalf("2 MiB body accepted: %d", res.StatusCode)
	}
}
