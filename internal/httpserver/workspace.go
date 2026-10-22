package httpserver

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nostalpixel/borisyeltsin/internal/authz"
	"github.com/nostalpixel/borisyeltsin/internal/db"
	"github.com/nostalpixel/borisyeltsin/internal/fieldsafe"
	"github.com/nostalpixel/borisyeltsin/internal/importer"
	"github.com/nostalpixel/borisyeltsin/internal/spend"
)

func (s *Server) grants(ctx context.Context, org uuid.UUID) (map[uuid.UUID]map[uuid.UUID]bool, error) {
	rows, err := s.Q.ListGrantsForOrg(ctx, org)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]map[uuid.UUID]bool{}
	for _, row := range rows {
		if out[row.ServiceID] == nil {
			out[row.ServiceID] = map[uuid.UUID]bool{}
		}
		out[row.ServiceID][row.UserID] = true
	}
	return out, nil
}

func (s *Server) canView(ctx context.Context, p Principal, svc db.Service) (bool, error) {
	grants, err := s.grants(ctx, p.OrgID)
	if err != nil {
		return false, err
	}
	return authz.CanViewService(p.Role, p.UserID, svc.OwnerID, grants[svc.ID][p.UserID]), nil
}

func (s *Server) canEdit(ctx context.Context, p Principal, svc db.Service) (bool, error) {
	grants, err := s.grants(ctx, p.OrgID)
	if err != nil {
		return false, err
	}
	return authz.CanEditService(p.Role, p.UserID, svc.OwnerID, grants[svc.ID][p.UserID]), nil
}

func (s *Server) serviceFor(ctx context.Context, p Principal, id uuid.UUID, edit bool) (db.Service, error) {
	svc, err := s.Q.GetService(ctx, db.GetServiceParams{ID: id, OrganizationID: p.OrgID})
	if err != nil {
		return db.Service{}, errStatus(http.StatusNotFound, "not_found")
	}
	var ok bool
	if edit {
		ok, err = s.canEdit(ctx, p, svc)
	} else {
		ok, err = s.canView(ctx, p, svc)
	}
	if err != nil {
		return db.Service{}, err
	}
	if !ok {
		return db.Service{}, errStatus(http.StatusNotFound, "not_found")
	}
	return svc, nil
}

func serviceView(row db.Service) map[string]any {
	return map[string]any{
		"id": row.ID, "name": row.Name, "category": row.Category, "url": row.Url,
		"description": row.Description, "unclear": row.Unclear, "logo": row.Logo,
		"logo_bg": row.LogoBg, "logo_fg": row.LogoFg, "owner_id": row.OwnerID,
		"notes": row.Notes, "tags": row.Tags, "archived": row.ArchivedAt.Valid,
		"created_at": row.CreatedAt,
	}
}

func accountView(row db.ServiceAccount) map[string]any {
	return map[string]any{
		"id": row.ID, "service_id": row.ServiceID, "label": row.Label,
		"login_hint": row.LoginHint, "card_label": row.CardLabel, "notes": row.Notes,
		"vault_id": row.VaultID, "vault_item_id": row.VaultItemID, "position": row.Position,
	}
}

func subscriptionView(row db.Subscription, loc *time.Location, today time.Time) map[string]any {
	days := spend.DaysUntil(row.RenewalDate, today, loc)
	custom := int32(0)
	if row.CustomIntervalDays != nil {
		custom = *row.CustomIntervalDays
	}
	return map[string]any{
		"id": row.ID, "service_id": row.ServiceID, "account_id": row.AccountID,
		"payment_method_id": row.PaymentMethodID, "name": row.Name,
		"billing_cycle": row.BillingCycle, "custom_interval_days": row.CustomIntervalDays,
		"renewal_date": row.RenewalDate.Format("2006-01-02"),
		"cost":         spend.FormatMinor(row.CostMinor), "currency": row.Currency,
		"auto_renew": row.AutoRenew, "days": days, "due_level": spend.DueLevel(days, true),
		"monthly": spend.FormatMinor(spend.MonthlyMinor(row.CostMinor, row.BillingCycle, custom)),
	}
}

func (s *Server) workspace(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	services, err := s.Q.ListServicesForOrg(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	grantSet, err := s.grants(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	visible := map[uuid.UUID]bool{}
	serviceOut := []map[string]any{}
	for _, svc := range services {
		if svc.ArchivedAt.Valid {
			continue
		}
		if !authz.CanViewService(p.Role, p.UserID, svc.OwnerID, grantSet[svc.ID][p.UserID]) {
			continue
		}
		visible[svc.ID] = true
		serviceOut = append(serviceOut, serviceView(svc))
	}
	accounts, err := s.Q.ListAccountsForOrg(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	accountOut := []map[string]any{}
	for _, row := range accounts {
		if visible[row.ServiceID] {
			accountOut = append(accountOut, accountView(row))
		}
	}
	subs, err := s.Q.ListSubscriptionsForOrg(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	subOut := []map[string]any{}
	monthly := map[string]int64{}
	overdue, dueSoon, unclear := 0, 0, 0
	for _, svc := range services {
		if visible[svc.ID] && (svc.Unclear || svc.Url == "") {
			unclear++
		}
	}
	for _, row := range subs {
		if !visible[row.ServiceID] {
			continue
		}
		view := subscriptionView(row, s.Loc, s.now())
		subOut = append(subOut, view)
		switch view["due_level"] {
		case "danger":
			if view["days"].(int) < 0 || view["days"].(int) <= 3 {
				if days, _ := view["days"].(int); days < 0 {
					overdue++
				} else {
					dueSoon++
				}
			}
		case "warning":
			dueSoon++
		}
		custom := int32(0)
		if row.CustomIntervalDays != nil {
			custom = *row.CustomIntervalDays
		}
		monthly[row.Currency] += spend.MonthlyMinor(row.CostMinor, row.BillingCycle, custom)
	}
	monthlyOut := map[string]string{}
	for currency, amount := range monthly {
		monthlyOut[currency] = spend.FormatMinor(amount)
	}
	methods, err := s.Q.ListPaymentMethods(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	alerts, err := s.Q.ListRenewalAlerts(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	alertOut := []map[string]any{}
	for _, row := range alerts {
		if visible[row.ServiceID] {
			alertOut = append(alertOut, map[string]any{
				"id": row.ID, "subscription_id": row.SubscriptionID, "service_id": row.ServiceID,
				"days_before": row.DaysBefore, "due_on": row.DueOn.Format("2006-01-02"),
				"name": row.Name, "currency": row.Currency, "cost": spend.FormatMinor(row.CostMinor),
			})
		}
	}
	org, err := s.Q.GetOrganization(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	ready, err := recoveryReady(r.Context(), s.Q, p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"organization":    map[string]any{"id": org.ID, "name": org.Name, "recovery_ready": ready != nil},
		"services":        serviceOut,
		"accounts":        accountOut,
		"subscriptions":   subOut,
		"payment_methods": methods,
		"alerts":          alertOut,
		"summary": map[string]any{
			"services": len(serviceOut), "accounts": len(accountOut), "unclear": unclear,
			"overdue": overdue, "due_soon": dueSoon, "monthly": monthlyOut,
		},
	})
}

type serviceBody struct {
	Name        string     `json:"name"`
	Category    string     `json:"category"`
	URL         string     `json:"url"`
	Description string     `json:"description"`
	Unclear     bool       `json:"unclear"`
	Logo        string     `json:"logo"`
	LogoBg      string     `json:"logo_bg"`
	LogoFg      string     `json:"logo_fg"`
	OwnerID     *uuid.UUID `json:"owner_id"`
	Notes       string     `json:"notes"`
	Tags        []string   `json:"tags"`
}

func validateService(body serviceBody) (serviceBody, error) {
	body.Name = clip(body.Name, 160)
	if body.Name == "" {
		return body, errStatus(http.StatusBadRequest, "bad_service")
	}
	if body.Category == "" {
		body.Category = "other"
	}
	if !authz.ValidCategory(body.Category) {
		return body, errStatus(http.StatusBadRequest, "bad_service")
	}
	body.URL = httpURL(body.URL)
	body.Description = clip(body.Description, 200)
	body.Notes = clip(body.Notes, 5000)
	body.Logo = logoFrom(body.Name, body.Logo)
	body.LogoBg = hexColor(body.LogoBg, "#1a2238")
	body.LogoFg = hexColor(body.LogoFg, "#f3e6cf")
	if len(body.Tags) > 20 {
		body.Tags = body.Tags[:20]
	}
	for i, tag := range body.Tags {
		body.Tags[i] = clip(tag, 32)
	}
	if err := fieldsafe.ScreenText(body.Name, body.Description, body.Notes, body.URL); err != nil {
		return body, errStatus(http.StatusBadRequest, "card_number")
	}
	if body.URL == "" {
		body.Unclear = true
	}
	return body, nil
}

func (s *Server) createService(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if p.Role != "admin" && p.Role != "manager" {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	var body serviceBody
	if !s.decode(w, r, &body) {
		return
	}
	body, err := validateService(body)
	if err != nil {
		s.sendError(w, err)
		return
	}
	owner := p.UserID
	if p.Role == "admin" && body.OwnerID != nil {
		if _, err := s.Q.GetUser(r.Context(), db.GetUserParams{ID: *body.OwnerID, OrganizationID: p.OrgID}); err != nil {
			s.fail(w, http.StatusBadRequest, "bad_owner")
			return
		}
		owner = *body.OwnerID
	}
	if body.Tags == nil {
		body.Tags = []string{}
	}
	row, err := s.Q.CreateService(r.Context(), db.CreateServiceParams{
		OrganizationID: p.OrgID, Name: body.Name, Category: body.Category, Url: body.URL,
		Description: body.Description, Unclear: body.Unclear, Logo: body.Logo, LogoBg: body.LogoBg,
		LogoFg: body.LogoFg, OwnerID: &owner, Notes: body.Notes, Tags: body.Tags,
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "service_created", "service", row.ID.String(), nil)
	s.writeJSON(w, http.StatusCreated, serviceView(row))
}

func (s *Server) updateService(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	id, err := pathID(r, "serviceID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	current, err := s.serviceFor(r.Context(), p, id, true)
	if err != nil {
		s.sendError(w, err)
		return
	}
	// Start from the stored row so fields the client omits keep their values.
	body := serviceBody{
		Name: current.Name, Category: current.Category, URL: current.Url, Description: current.Description,
		Unclear: current.Unclear, Logo: current.Logo, LogoBg: current.LogoBg, LogoFg: current.LogoFg,
		Notes: current.Notes, Tags: current.Tags,
	}
	if !s.decode(w, r, &body) {
		return
	}
	body, err = validateService(body)
	if err != nil {
		s.sendError(w, err)
		return
	}
	owner := current.OwnerID
	if p.Role == "admin" && body.OwnerID != nil {
		owner = body.OwnerID
	}
	if body.Tags == nil {
		body.Tags = []string{}
	}
	row, err := s.Q.UpdateService(r.Context(), db.UpdateServiceParams{
		ID: id, OrganizationID: p.OrgID, Name: body.Name, Category: body.Category, Url: body.URL,
		Description: body.Description, Unclear: body.Unclear, Logo: body.Logo, LogoBg: body.LogoBg,
		LogoFg: body.LogoFg, OwnerID: owner, Notes: body.Notes, Tags: body.Tags,
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "service_updated", "service", id.String(), nil)
	s.writeJSON(w, http.StatusOK, serviceView(row))
}

func (s *Server) archiveService(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	id, err := pathID(r, "serviceID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := s.serviceFor(r.Context(), p, id, true); err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := s.Q.ArchiveService(r.Context(), db.ArchiveServiceParams{ID: id, OrganizationID: p.OrgID}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "service_archived", "service", id.String(), nil)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) grantService(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	serviceID, err := pathID(r, "serviceID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := s.serviceFor(r.Context(), p, serviceID, true); err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		UserID uuid.UUID `json:"user_id"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	if _, err := s.Q.GetUser(r.Context(), db.GetUserParams{ID: body.UserID, OrganizationID: p.OrgID}); err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if err := s.Q.InsertGrant(r.Context(), db.InsertGrantParams{ServiceID: serviceID, UserID: body.UserID}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "service_granted", "service", serviceID.String(), map[string]string{"user_id": body.UserID.String()})
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	serviceID, err := pathID(r, "serviceID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	userID, err := pathID(r, "userID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := s.serviceFor(r.Context(), p, serviceID, true); err != nil {
		s.sendError(w, err)
		return
	}
	if err := s.Q.DeleteGrant(r.Context(), db.DeleteGrantParams{ServiceID: serviceID, UserID: userID}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "service_grant_revoked", "service", serviceID.String(), nil)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type accountBody struct {
	Label              string     `json:"label"`
	LoginHint          string     `json:"login_hint"`
	CardLabel          string     `json:"card_label"`
	Notes              string     `json:"notes"`
	Position           *int32     `json:"position"`
	BillingCycle       string     `json:"billing_cycle"`
	RenewalDate        string     `json:"renewal_date"`
	Cost               string     `json:"cost"`
	Currency           string     `json:"currency"`
	AutoRenew          *bool      `json:"auto_renew"`
	CustomIntervalDays *int32     `json:"custom_interval_days"`
	PaymentMethodID    *uuid.UUID `json:"payment_method_id"`
}

func cleanAccount(body accountBody) (accountBody, error) {
	body.Label = clip(body.Label, 80)
	if body.Label == "" {
		body.Label = "Account"
	}
	body.LoginHint = clip(body.LoginHint, 500)
	body.CardLabel = clip(body.CardLabel, 80)
	body.Notes = clip(body.Notes, 5000)
	if err := fieldsafe.ScreenText(body.Label, body.LoginHint, body.CardLabel, body.Notes); err != nil {
		return body, errStatus(http.StatusBadRequest, "card_number")
	}
	return body, nil
}

func (s *Server) billing(ctx context.Context, p Principal, body accountBody) (db.CreateSubscriptionParams, bool, error) {
	// The account form always sends a cycle, so cost and date decide: with
	// neither there is nothing to bill and no subscription is made or changed.
	if strings.TrimSpace(body.Cost) == "" && strings.TrimSpace(body.RenewalDate) == "" {
		return db.CreateSubscriptionParams{}, false, nil
	}
	if body.BillingCycle == "" {
		body.BillingCycle = "monthly"
	}
	if !authz.ValidCycle(body.BillingCycle) {
		return db.CreateSubscriptionParams{}, false, errStatus(http.StatusBadRequest, "bad_subscription")
	}
	currency := body.Currency
	if currency == "" {
		currency = "USD"
	}
	if !authz.ValidCurrency(currency) {
		return db.CreateSubscriptionParams{}, false, errStatus(http.StatusBadRequest, "bad_subscription")
	}
	cost := int64(0)
	if body.Cost != "" {
		parsed, err := spend.ParseMinor(body.Cost)
		if err != nil {
			return db.CreateSubscriptionParams{}, false, errStatus(http.StatusBadRequest, "bad_subscription")
		}
		cost = parsed
	}
	renewal := s.now()
	if body.RenewalDate != "" {
		parsed, err := time.Parse("2006-01-02", body.RenewalDate)
		if err != nil {
			return db.CreateSubscriptionParams{}, false, errStatus(http.StatusBadRequest, "bad_subscription")
		}
		renewal = parsed
	}
	var custom *int32
	if body.BillingCycle == "custom" {
		if body.CustomIntervalDays == nil || *body.CustomIntervalDays <= 0 {
			return db.CreateSubscriptionParams{}, false, errStatus(http.StatusBadRequest, "bad_subscription")
		}
		custom = body.CustomIntervalDays
	}
	auto := true
	if body.AutoRenew != nil {
		auto = *body.AutoRenew
	}
	if body.PaymentMethodID != nil {
		methods, err := s.Q.ListPaymentMethods(ctx, p.OrgID)
		if err != nil {
			return db.CreateSubscriptionParams{}, false, err
		}
		found := false
		for _, method := range methods {
			if method.ID == *body.PaymentMethodID {
				found = true
			}
		}
		if !found {
			return db.CreateSubscriptionParams{}, false, errStatus(http.StatusBadRequest, "bad_subscription")
		}
	}
	return db.CreateSubscriptionParams{
		PaymentMethodID: body.PaymentMethodID, BillingCycle: body.BillingCycle,
		CustomIntervalDays: custom, RenewalDate: renewal, CostMinor: cost, Currency: currency, AutoRenew: auto,
	}, true, nil
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	serviceID, err := pathID(r, "serviceID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := s.serviceFor(r.Context(), p, serviceID, true); err != nil {
		s.sendError(w, err)
		return
	}
	var body accountBody
	if !s.decode(w, r, &body) {
		return
	}
	body, err = cleanAccount(body)
	if err != nil {
		s.sendError(w, err)
		return
	}
	position := int32(0)
	if body.Position != nil {
		position = *body.Position
	}
	row, err := s.Q.CreateAccount(r.Context(), db.CreateAccountParams{
		ServiceID: serviceID, Label: body.Label, LoginHint: body.LoginHint,
		CardLabel: body.CardLabel, Notes: body.Notes, Position: position,
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	params, ok, err := s.billing(r.Context(), p, body)
	if err != nil {
		s.sendError(w, err)
		return
	}
	if ok {
		params.ServiceID = serviceID
		params.AccountID = &row.ID
		if _, err := s.Q.CreateSubscription(r.Context(), params); err != nil {
			s.sendError(w, err)
			return
		}
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "account_created", "account", row.ID.String(), nil)
	s.writeJSON(w, http.StatusCreated, accountView(row))
}

func (s *Server) updateAccount(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	accountID, err := pathID(r, "accountID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	current, err := s.Q.GetAccount(r.Context(), db.GetAccountParams{ID: accountID, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if _, err := s.serviceFor(r.Context(), p, current.ServiceID, true); err != nil {
		s.sendError(w, err)
		return
	}
	var body accountBody
	if !s.decode(w, r, &body) {
		return
	}
	body, err = cleanAccount(body)
	if err != nil {
		s.sendError(w, err)
		return
	}
	position := current.Position
	if body.Position != nil {
		position = *body.Position
	}
	row, err := s.Q.UpdateAccount(r.Context(), db.UpdateAccountParams{
		ID: accountID, Label: body.Label, LoginHint: body.LoginHint,
		CardLabel: body.CardLabel, Notes: body.Notes, Position: position,
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	params, ok, err := s.billing(r.Context(), p, body)
	if err != nil {
		s.sendError(w, err)
		return
	}
	if ok {
		if err := s.upsertAccountSubscription(r.Context(), current.ServiceID, accountID, params); err != nil {
			s.sendError(w, err)
			return
		}
	}
	s.writeJSON(w, http.StatusOK, accountView(row))
}

func (s *Server) upsertAccountSubscription(ctx context.Context, serviceID, accountID uuid.UUID, params db.CreateSubscriptionParams) error {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM subscriptions WHERE account_id = $1 ORDER BY created_at LIMIT 1`, accountID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var existing uuid.UUID
	found := rows.Next()
	if found {
		if err := rows.Scan(&existing); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !found {
		params.ServiceID = serviceID
		params.AccountID = &accountID
		_, err = s.Q.CreateSubscription(ctx, params)
		return err
	}
	_, err = s.Q.UpdateSubscription(ctx, db.UpdateSubscriptionParams{
		ID: existing, PaymentMethodID: params.PaymentMethodID, Name: params.Name,
		BillingCycle: params.BillingCycle, CustomIntervalDays: params.CustomIntervalDays,
		RenewalDate: params.RenewalDate, CostMinor: params.CostMinor, Currency: params.Currency,
		AutoRenew: params.AutoRenew,
	})
	return err
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	accountID, err := pathID(r, "accountID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	current, err := s.Q.GetAccount(r.Context(), db.GetAccountParams{ID: accountID, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if _, err := s.serviceFor(r.Context(), p, current.ServiceID, true); err != nil {
		s.sendError(w, err)
		return
	}
	if err := s.Q.DeleteAccount(r.Context(), db.DeleteAccountParams{ID: accountID, OrganizationID: p.OrgID}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "account_deleted", "account", accountID.String(), nil)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) linkVaultItem(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	accountID, err := pathID(r, "accountID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	current, err := s.Q.GetAccount(r.Context(), db.GetAccountParams{ID: accountID, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if _, err := s.serviceFor(r.Context(), p, current.ServiceID, true); err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		VaultID     uuid.UUID `json:"vault_id"`
		VaultItemID uuid.UUID `json:"vault_item_id"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	if _, _, err := s.memberVault(r.Context(), p, body.VaultID); err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := s.Q.GetVaultItem(r.Context(), db.GetVaultItemParams{ID: body.VaultItemID, VaultID: body.VaultID}); err != nil {
		s.fail(w, http.StatusBadRequest, "bad_vault_item")
		return
	}
	if err := s.Q.LinkAccountVaultItem(r.Context(), db.LinkAccountVaultItemParams{
		ID: accountID, OrganizationID: p.OrgID, VaultID: &body.VaultID, VaultItemID: &body.VaultItemID,
	}); err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type subscriptionBody struct {
	ServiceID          uuid.UUID  `json:"service_id"`
	AccountID          *uuid.UUID `json:"account_id"`
	PaymentMethodID    *uuid.UUID `json:"payment_method_id"`
	Name               string     `json:"name"`
	BillingCycle       string     `json:"billing_cycle"`
	RenewalDate        string     `json:"renewal_date"`
	Cost               string     `json:"cost"`
	Currency           string     `json:"currency"`
	AutoRenew          *bool      `json:"auto_renew"`
	CustomIntervalDays *int32     `json:"custom_interval_days"`
}

func (s *Server) createSubscription(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	var body subscriptionBody
	if !s.decode(w, r, &body) {
		return
	}
	if _, err := s.serviceFor(r.Context(), p, body.ServiceID, true); err != nil {
		s.sendError(w, err)
		return
	}
	params, ok, err := s.billing(r.Context(), p, accountBody{
		BillingCycle: body.BillingCycle, RenewalDate: body.RenewalDate, Cost: body.Cost,
		Currency: body.Currency, AutoRenew: body.AutoRenew, CustomIntervalDays: body.CustomIntervalDays,
		PaymentMethodID: body.PaymentMethodID,
	})
	if err != nil || !ok {
		if err == nil {
			err = errStatus(http.StatusBadRequest, "bad_subscription")
		}
		s.sendError(w, err)
		return
	}
	if body.AccountID != nil {
		account, err := s.Q.GetAccount(r.Context(), db.GetAccountParams{ID: *body.AccountID, OrganizationID: p.OrgID})
		if err != nil || account.ServiceID != body.ServiceID {
			s.fail(w, http.StatusBadRequest, "bad_account")
			return
		}
	}
	params.ServiceID = body.ServiceID
	params.AccountID = body.AccountID
	params.Name = clip(body.Name, 160)
	row, err := s.Q.CreateSubscription(r.Context(), params)
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "subscription_created", "subscription", row.ID.String(), nil)
	s.writeJSON(w, http.StatusCreated, subscriptionView(row, s.Loc, s.now()))
}

func (s *Server) updateSubscription(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	id, err := pathID(r, "subscriptionID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	current, err := s.Q.GetSubscription(r.Context(), db.GetSubscriptionParams{ID: id, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if _, err := s.serviceFor(r.Context(), p, current.ServiceID, true); err != nil {
		s.sendError(w, err)
		return
	}
	var body subscriptionBody
	if !s.decode(w, r, &body) {
		return
	}
	params, ok, err := s.billing(r.Context(), p, accountBody{
		BillingCycle: body.BillingCycle, RenewalDate: body.RenewalDate, Cost: body.Cost,
		Currency: body.Currency, AutoRenew: body.AutoRenew, CustomIntervalDays: body.CustomIntervalDays,
		PaymentMethodID: body.PaymentMethodID,
	})
	if err == nil && !ok {
		err = errStatus(http.StatusBadRequest, "bad_subscription")
	}
	if err != nil {
		s.sendError(w, err)
		return
	}
	row, err := s.Q.UpdateSubscription(r.Context(), db.UpdateSubscriptionParams{
		ID: id, PaymentMethodID: params.PaymentMethodID, Name: clip(body.Name, 160),
		BillingCycle: params.BillingCycle, CustomIntervalDays: params.CustomIntervalDays,
		RenewalDate: params.RenewalDate, CostMinor: params.CostMinor, Currency: params.Currency,
		AutoRenew: params.AutoRenew,
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, subscriptionView(row, s.Loc, s.now()))
}

func (s *Server) addPayment(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	id, err := pathID(r, "subscriptionID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	sub, err := s.Q.GetSubscription(r.Context(), db.GetSubscriptionParams{ID: id, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if _, err := s.serviceFor(r.Context(), p, sub.ServiceID, true); err != nil {
		s.sendError(w, err)
		return
	}
	var body struct {
		PaidOn   string `json:"paid_on"`
		Amount   string `json:"amount"`
		Currency string `json:"currency"`
		Note     string `json:"note"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	paid, err := time.Parse("2006-01-02", body.PaidOn)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_payment")
		return
	}
	amount, err := spend.ParseMinor(body.Amount)
	if err != nil || !authz.ValidCurrency(body.Currency) {
		s.fail(w, http.StatusBadRequest, "bad_payment")
		return
	}
	body.Note = clip(body.Note, 500)
	if err := fieldsafe.ScreenText(body.Note); err != nil {
		s.fail(w, http.StatusBadRequest, "card_number")
		return
	}
	row, err := s.Q.InsertPayment(r.Context(), db.InsertPaymentParams{
		SubscriptionID: id, PaidOn: paid, AmountMinor: amount, Currency: body.Currency, Note: body.Note,
	})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "payment_recorded", "subscription", id.String(), nil)
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id": row.ID, "paid_on": row.PaidOn.Format("2006-01-02"),
		"amount": spend.FormatMinor(row.AmountMinor), "currency": row.Currency, "note": row.Note,
	})
}

func (s *Server) listPayments(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	id, err := pathID(r, "subscriptionID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	sub, err := s.Q.GetSubscription(r.Context(), db.GetSubscriptionParams{ID: id, OrganizationID: p.OrgID})
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if _, err := s.serviceFor(r.Context(), p, sub.ServiceID, false); err != nil {
		s.sendError(w, err)
		return
	}
	rows, err := s.Q.ListPaymentsForSubscription(r.Context(), id)
	if err != nil {
		s.sendError(w, err)
		return
	}
	out := []map[string]any{}
	for _, row := range rows {
		out = append(out, map[string]any{
			"id": row.ID, "paid_on": row.PaidOn.Format("2006-01-02"),
			"amount": spend.FormatMinor(row.AmountMinor), "currency": row.Currency, "note": row.Note,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"payments": out})
}

func (s *Server) listPaymentMethods(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	rows, err := s.Q.ListPaymentMethods(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"payment_methods": rows})
}

func (s *Server) createPaymentMethod(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if p.Role == "readonly" || p.Role == "member" {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		Nickname string `json:"nickname"`
		Issuer   string `json:"issuer"`
		Last4    string `json:"last4"`
		ExpMonth int32  `json:"exp_month"`
		ExpYear  int32  `json:"exp_year"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	body.Nickname = clip(body.Nickname, 80)
	body.Issuer = clip(body.Issuer, 40)
	if body.Nickname == "" || len(body.Last4) != 4 {
		s.fail(w, http.StatusBadRequest, "bad_payment_method")
		return
	}
	for _, r := range body.Last4 {
		if r < '0' || r > '9' {
			s.fail(w, http.StatusBadRequest, "bad_payment_method")
			return
		}
	}
	if err := fieldsafe.ScreenText(body.Nickname, body.Issuer); err != nil {
		s.fail(w, http.StatusBadRequest, "card_number")
		return
	}
	row, err := s.Q.InsertPaymentMethod(r.Context(), db.InsertPaymentMethodParams{
		OrganizationID: p.OrgID, Nickname: body.Nickname, Issuer: body.Issuer,
		Last4: body.Last4, ExpMonth: body.ExpMonth, ExpYear: body.ExpYear,
	})
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_payment_method")
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "payment_method_created", "payment_method", row.ID.String(), nil)
	s.writeJSON(w, http.StatusCreated, row)
}

func (s *Server) deletePaymentMethod(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if p.Role != "admin" && p.Role != "manager" {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	id, err := pathID(r, "methodID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	if err := s.Q.DeletePaymentMethod(r.Context(), db.DeletePaymentMethodParams{ID: id, OrganizationID: p.OrgID}); err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) importServices(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if p.Role != "admin" && p.Role != "manager" {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	if r.Header.Get("X-Requested-With") != "fetch" {
		s.fail(w, http.StatusForbidden, "csrf")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_json")
		return
	}
	parsed, err := importer.Parse(raw)
	if err != nil {
		code := "invalid_backup"
		if err == fieldsafe.ErrSecret {
			code = "secret_field"
		}
		if err == fieldsafe.ErrCard {
			code = "card_number"
		}
		s.fail(w, http.StatusBadRequest, code)
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	defer tx.Rollback(r.Context())
	q := s.Q.WithTx(tx)
	created := 0
	for _, item := range parsed {
		tags := []string{}
		row, err := q.CreateService(r.Context(), db.CreateServiceParams{
			OrganizationID: p.OrgID, Name: item.Name, Category: item.Category, Url: item.URL,
			Description: item.Description, Unclear: item.Unclear || item.URL == "", Logo: item.Logo,
			LogoBg: item.Bg, LogoFg: item.Fg, OwnerID: &p.UserID, Tags: tags,
		})
		if err != nil {
			s.sendError(w, err)
			return
		}
		for i, acc := range item.Accounts {
			account, err := q.CreateAccount(r.Context(), db.CreateAccountParams{
				ServiceID: row.ID, Label: acc.Label, LoginHint: acc.Login, CardLabel: acc.Card,
				Notes: acc.Notes, Position: int32(i),
			})
			if err != nil {
				s.sendError(w, err)
				return
			}
			if acc.Cost == "" && acc.Date == "" {
				continue
			}
			cost := int64(0)
			if acc.Cost != "" {
				cost, err = spend.ParseMinor(acc.Cost)
				if err != nil {
					s.fail(w, http.StatusBadRequest, "invalid_cost")
					return
				}
			}
			renewal := s.now()
			if acc.Date != "" {
				renewal, err = time.Parse("2006-01-02", acc.Date)
				if err != nil {
					s.fail(w, http.StatusBadRequest, "invalid_date")
					return
				}
			}
			currency := acc.Currency
			if !authz.ValidCurrency(currency) {
				currency = "USD"
			}
			if _, err := q.CreateSubscription(r.Context(), db.CreateSubscriptionParams{
				ServiceID: row.ID, AccountID: &account.ID, BillingCycle: "monthly",
				RenewalDate: renewal, CostMinor: cost, Currency: currency, AutoRenew: true,
			}); err != nil {
				s.sendError(w, err)
				return
			}
		}
		created++
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "services_imported", "organization", p.OrgID.String(), nil)
	s.writeJSON(w, http.StatusCreated, map[string]int{"services": created})
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if err := s.requireAdmin(p); err != nil {
		s.sendError(w, err)
		return
	}
	rows, err := s.Q.ListAuditEvents(r.Context(), db.ListAuditEventsParams{OrganizationID: p.OrgID, Limit: 200})
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"events": rows})
}

func (s *Server) listFlags(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if p.Role != "admin" && p.Role != "manager" {
		s.fail(w, http.StatusForbidden, "forbidden")
		return
	}
	rows, err := s.Q.ListOpenCredentialFlags(r.Context(), p.OrgID)
	if err != nil {
		s.sendError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"flags": rows})
}

func (s *Server) resolveFlag(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	if err := s.requireAdmin(p); err != nil {
		s.sendError(w, err)
		return
	}
	id, err := pathID(r, "flagID")
	if err != nil {
		s.sendError(w, err)
		return
	}
	if _, err := s.Q.ResolveCredentialFlag(r.Context(), db.ResolveCredentialFlagParams{ID: id, OrganizationID: p.OrgID}); err != nil {
		s.sendError(w, err)
		return
	}
	s.audit(r.Context(), p.OrgID, &p.UserID, "credential_flag_resolved", "flag", id.String(), nil)
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Silence unused import if a refactor drops pgtype.
var _ = pgtype.Timestamptz{}
