package httpserver

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nostalpixel/borisyeltsin/internal/authz"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"github.com/nostalpixel/borisyeltsin/internal/fieldsafe"
	"github.com/nostalpixel/borisyeltsin/internal/spend"
)

// The MCP endpoint (docs/MCP.md) answers "what renews when, and what does it
// cost" for an agent holding a personal token. It reads the ledger only: no
// vault items, envelopes, login hints, card labels or payment methods.

type agentToken struct {
	ID       uuid.UUID
	CanWrite bool
}

const agentKey ctxKey = 2

type agentCtx struct {
	p     Principal
	token agentToken
}

func withAgent(ctx context.Context, p Principal, t agentToken) context.Context {
	return context.WithValue(ctx, agentKey, agentCtx{p: p, token: t})
}

func (s *Server) mcpHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		agent, ok := r.Context().Value(agentKey).(agentCtx)
		if !ok {
			return nil
		}
		return s.mcpServer(agent)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
}

// mcpServer builds the tool set for one request, bound to the token's owner.
// A read-only token does not see the write tool at all.
func (s *Server) mcpServer(agent agentCtx) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "borisyeltsin", Title: "BorisYeltsin subscription ledger"}, &mcp.ServerOptions{
		Instructions: "Subscription ledger for one organization. Amounts are decimal strings in the subscription's currency; " +
			"totals are per currency and never converted. Monthly figures spread quarterly, annual and custom cycles over a month. " +
			"Passwords and other credentials are not available here.",
	})
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "monthly_bill",
		Description: "Total monthly subscription cost per currency, with the services that make it up, largest first.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in billInput) (*mcp.CallToolResult, billOutput, error) {
		out, err := s.monthlyBill(ctx, agent.p, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "upcoming_renewals",
		Description: "Subscriptions renewing within the next N days (default 30), soonest first. Overdue ones come first with negative days.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in renewalsInput) (*mcp.CallToolResult, subscriptionsOutput, error) {
		out, err := s.upcomingRenewals(ctx, agent.p, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_subscriptions",
		Description: "All subscriptions, optionally filtered by service name (case-insensitive substring).",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listInput) (*mcp.CallToolResult, subscriptionsOutput, error) {
		out, err := s.listAgentSubscriptions(ctx, agent.p, in)
		return nil, out, err
	})
	if agent.token.CanWrite {
		mcp.AddTool(server, &mcp.Tool{
			Name: "add_subscription",
			Description: "Add a subscription to a service, creating the service if no service has that name. " +
				"Put the plan and seat count in name, for example \"Team, 2 users\". Confirm the details with the user first.",
			Annotations: &mcp.ToolAnnotations{IdempotentHint: false},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in addInput) (*mcp.CallToolResult, addOutput, error) {
			out, err := s.addAgentSubscription(ctx, agent, in)
			return nil, out, err
		})
	}
	return server
}

type billInput struct {
	Category string `json:"category,omitempty" jsonschema:"only services in this category: infra, domains, tools, comms, partners, payments or other"`
}

type billLine struct {
	Service  string `json:"service"`
	Name     string `json:"name,omitempty"`
	Cycle    string `json:"billing_cycle"`
	Cost     string `json:"cost"`
	Monthly  string `json:"monthly"`
	Currency string `json:"currency"`
}

type billOutput struct {
	MonthlyTotal  map[string]string `json:"monthly_total" jsonschema:"monthly total per currency"`
	Subscriptions int               `json:"subscriptions"`
	Lines         []billLine        `json:"lines"`
}

type renewalsInput struct {
	Days int `json:"days,omitempty" jsonschema:"look-ahead window in days, 1 to 366, default 30"`
}

type listInput struct {
	Service string `json:"service,omitempty" jsonschema:"filter by service name"`
}

type agentSubscription struct {
	ID          string `json:"id"`
	Service     string `json:"service"`
	Category    string `json:"category"`
	Name        string `json:"name,omitempty"`
	Cycle       string `json:"billing_cycle"`
	CustomDays  *int32 `json:"custom_interval_days,omitempty"`
	RenewalDate string `json:"renewal_date"`
	Days        int    `json:"days_until_renewal"`
	Cost        string `json:"cost"`
	Monthly     string `json:"monthly"`
	Currency    string `json:"currency"`
	AutoRenew   bool   `json:"auto_renew"`
}

type subscriptionsOutput struct {
	Today         string              `json:"today"`
	Subscriptions []agentSubscription `json:"subscriptions"`
}

type addInput struct {
	Service      string `json:"service" jsonschema:"service name, for example Claude"`
	Name         string `json:"name,omitempty" jsonschema:"plan and seats, for example Team, 2 users"`
	Cost         string `json:"cost" jsonschema:"price per billing cycle as a decimal string, for example 400 or 19.99"`
	Currency     string `json:"currency,omitempty" jsonschema:"3 to 5 capital letters, default USD"`
	BillingCycle string `json:"billing_cycle,omitempty" jsonschema:"monthly, quarterly, annual or custom; default monthly"`
	CustomDays   *int32 `json:"custom_interval_days,omitempty" jsonschema:"days per cycle, only for custom"`
	RenewalDate  string `json:"renewal_date" jsonschema:"next renewal date, YYYY-MM-DD"`
	AutoRenew    *bool  `json:"auto_renew,omitempty" jsonschema:"default true"`
	Category     string `json:"category,omitempty" jsonschema:"category for a new service: infra, domains, tools, comms, partners, payments or other"`
}

type addOutput struct {
	ServiceCreated bool              `json:"service_created"`
	Subscription   agentSubscription `json:"subscription"`
}

// agentLedger returns the services the principal may view, by id, and the
// subscriptions on those services. Archived services are left out.
func (s *Server) agentLedger(ctx context.Context, p Principal) (map[uuid.UUID]db.Service, []db.Subscription, error) {
	services, err := s.Q.ListServicesForOrg(ctx, p.OrgID)
	if err != nil {
		return nil, nil, err
	}
	grantSet, err := s.grants(ctx, p.OrgID)
	if err != nil {
		return nil, nil, err
	}
	visible := map[uuid.UUID]db.Service{}
	for _, svc := range services {
		if !svc.ArchivedAt.Valid && authz.CanViewService(p.Role, p.UserID, svc.OwnerID, grantSet[svc.ID][p.UserID]) {
			visible[svc.ID] = svc
		}
	}
	subs, err := s.Q.ListSubscriptionsForOrg(ctx, p.OrgID)
	if err != nil {
		return nil, nil, err
	}
	out := subs[:0]
	for _, sub := range subs {
		if _, ok := visible[sub.ServiceID]; ok {
			out = append(out, sub)
		}
	}
	return visible, out, nil
}

func monthlyOf(sub db.Subscription) int64 {
	custom := int32(0)
	if sub.CustomIntervalDays != nil {
		custom = *sub.CustomIntervalDays
	}
	return spend.MonthlyMinor(sub.CostMinor, sub.BillingCycle, custom)
}

func (s *Server) agentView(svc db.Service, sub db.Subscription) agentSubscription {
	return agentSubscription{
		ID: sub.ID.String(), Service: svc.Name, Category: svc.Category, Name: sub.Name,
		Cycle: sub.BillingCycle, CustomDays: sub.CustomIntervalDays,
		RenewalDate: sub.RenewalDate.Format("2006-01-02"),
		Days:        spend.DaysUntil(sub.RenewalDate, s.now(), s.Loc),
		Cost:        spend.FormatMinor(sub.CostMinor), Monthly: spend.FormatMinor(monthlyOf(sub)),
		Currency: sub.Currency, AutoRenew: sub.AutoRenew,
	}
}

func (s *Server) today() string {
	return spend.Today(s.now(), s.Loc).Format("2006-01-02")
}

func (s *Server) monthlyBill(ctx context.Context, p Principal, in billInput) (billOutput, error) {
	if in.Category != "" && !authz.ValidCategory(in.Category) {
		return billOutput{}, errors.New("unknown category")
	}
	services, subs, err := s.agentLedger(ctx, p)
	if err != nil {
		return billOutput{}, err
	}
	totals := map[string]int64{}
	type line struct {
		billLine
		minor int64
	}
	lines := []line{}
	for _, sub := range subs {
		svc := services[sub.ServiceID]
		if in.Category != "" && svc.Category != in.Category {
			continue
		}
		monthly := monthlyOf(sub)
		totals[sub.Currency] += monthly
		lines = append(lines, line{billLine{
			Service: svc.Name, Name: sub.Name, Cycle: sub.BillingCycle, Cost: spend.FormatMinor(sub.CostMinor),
			Monthly: spend.FormatMinor(monthly), Currency: sub.Currency,
		}, monthly})
	}
	sort.SliceStable(lines, func(i, j int) bool {
		if lines[i].Currency != lines[j].Currency {
			return lines[i].Currency < lines[j].Currency
		}
		return lines[i].minor > lines[j].minor
	})
	out := billOutput{MonthlyTotal: map[string]string{}, Subscriptions: len(lines), Lines: []billLine{}}
	for currency, amount := range totals {
		out.MonthlyTotal[currency] = spend.FormatMinor(amount)
	}
	for _, l := range lines {
		out.Lines = append(out.Lines, l.billLine)
	}
	return out, nil
}

func (s *Server) upcomingRenewals(ctx context.Context, p Principal, in renewalsInput) (subscriptionsOutput, error) {
	if in.Days == 0 {
		in.Days = 30
	}
	if in.Days < 1 || in.Days > 366 {
		return subscriptionsOutput{}, errors.New("days must be between 1 and 366")
	}
	services, subs, err := s.agentLedger(ctx, p)
	if err != nil {
		return subscriptionsOutput{}, err
	}
	out := subscriptionsOutput{Today: s.today(), Subscriptions: []agentSubscription{}}
	for _, sub := range subs {
		view := s.agentView(services[sub.ServiceID], sub)
		if view.Days <= in.Days {
			out.Subscriptions = append(out.Subscriptions, view)
		}
	}
	sort.SliceStable(out.Subscriptions, func(i, j int) bool { return out.Subscriptions[i].Days < out.Subscriptions[j].Days })
	return out, nil
}

func (s *Server) listAgentSubscriptions(ctx context.Context, p Principal, in listInput) (subscriptionsOutput, error) {
	services, subs, err := s.agentLedger(ctx, p)
	if err != nil {
		return subscriptionsOutput{}, err
	}
	filter := strings.ToLower(strings.TrimSpace(in.Service))
	out := subscriptionsOutput{Today: s.today(), Subscriptions: []agentSubscription{}}
	for _, sub := range subs {
		svc := services[sub.ServiceID]
		if filter != "" && !strings.Contains(strings.ToLower(svc.Name), filter) {
			continue
		}
		out.Subscriptions = append(out.Subscriptions, s.agentView(svc, sub))
	}
	return out, nil
}

// addAgentSubscription follows the same rules as the UI: the caller must be
// able to edit the service, and only admins and managers create services.
func (s *Server) addAgentSubscription(ctx context.Context, agent agentCtx, in addInput) (addOutput, error) {
	p := agent.p
	name := clip(in.Service, 160)
	if name == "" {
		return addOutput{}, errors.New("service is required")
	}
	if in.RenewalDate == "" {
		return addOutput{}, errors.New("renewal_date is required, as YYYY-MM-DD")
	}
	if strings.TrimSpace(in.Cost) == "" {
		return addOutput{}, errors.New("cost is required")
	}
	params, _, err := s.billing(ctx, p, accountBody{
		BillingCycle: in.BillingCycle, RenewalDate: in.RenewalDate, Cost: in.Cost,
		Currency: strings.ToUpper(strings.TrimSpace(in.Currency)), AutoRenew: in.AutoRenew, CustomIntervalDays: in.CustomDays,
	})
	if err != nil {
		return addOutput{}, errors.New("invalid subscription: check cost, currency, billing_cycle, custom_interval_days and renewal_date")
	}
	params.Name = clip(in.Name, 160)
	if err := screenAgentText(params.Name); err != nil {
		return addOutput{}, err
	}

	services, _, err := s.agentLedger(ctx, p)
	if err != nil {
		return addOutput{}, err
	}
	var matches []db.Service
	for _, svc := range services {
		if strings.EqualFold(svc.Name, name) {
			matches = append(matches, svc)
		}
	}
	if len(matches) > 1 {
		return addOutput{}, errors.New("several services have that name; rename one in the app first")
	}
	created := false
	var svc db.Service
	if len(matches) == 1 {
		svc = matches[0]
		ok, err := s.canEdit(ctx, p, svc)
		if err != nil {
			return addOutput{}, err
		}
		if !ok {
			return addOutput{}, errors.New("you cannot edit this service")
		}
	} else {
		if p.Role != "admin" && p.Role != "manager" {
			return addOutput{}, errors.New("no service has that name, and only admins and managers can create one")
		}
		body, err := validateService(serviceBody{Name: name, Category: in.Category, Tags: []string{}})
		if err != nil {
			return addOutput{}, errors.New("invalid service name or category")
		}
		owner := p.UserID
		svc, err = s.Q.CreateService(ctx, db.CreateServiceParams{
			OrganizationID: p.OrgID, Name: body.Name, Category: body.Category, Url: body.URL,
			Description: body.Description, Unclear: body.Unclear, Logo: body.Logo, LogoBg: body.LogoBg,
			LogoFg: body.LogoFg, OwnerID: &owner, Notes: body.Notes, Tags: body.Tags,
		})
		if err != nil {
			return addOutput{}, err
		}
		created = true
		s.audit(ctx, p.OrgID, &p.UserID, "service_created", "service", svc.ID.String(), map[string]string{"via": "mcp", "agent_token_id": agent.token.ID.String()})
	}
	params.ServiceID = svc.ID
	row, err := s.Q.CreateSubscription(ctx, params)
	if err != nil {
		return addOutput{}, err
	}
	s.audit(ctx, p.OrgID, &p.UserID, "subscription_created", "subscription", row.ID.String(), map[string]string{"via": "mcp", "agent_token_id": agent.token.ID.String()})
	return addOutput{ServiceCreated: created, Subscription: s.agentView(svc, row)}, nil
}

// screenAgentText applies the ledger's card-number screen to free text.
func screenAgentText(values ...string) error {
	if err := fieldsafe.ScreenText(values...); err != nil {
		return errors.New("this looks like a full card number; keep only a name and the last 4 digits")
	}
	return nil
}
