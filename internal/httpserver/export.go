package httpserver

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"strconv"

	"github.com/nostalpixel/borisyeltsin/internal/authz"
	"github.com/nostalpixel/borisyeltsin/internal/spend"
	"github.com/nostalpixel/borisyeltsin/internal/xlsx"
)

func (s *Server) exportRows(r *http.Request) ([][]string, error) {
	p, _ := principalFrom(r)
	services, err := s.Q.ListServicesForOrg(r.Context(), p.OrgID)
	if err != nil {
		return nil, err
	}
	grants, err := s.grants(r.Context(), p.OrgID)
	if err != nil {
		return nil, err
	}
	accounts, err := s.Q.ListAccountsForOrg(r.Context(), p.OrgID)
	if err != nil {
		return nil, err
	}
	subs, err := s.Q.ListSubscriptionsForOrg(r.Context(), p.OrgID)
	if err != nil {
		return nil, err
	}
	byAccount := map[string]int{}
	for i, sub := range subs {
		if sub.AccountID != nil {
			byAccount[sub.AccountID.String()] = i
		}
	}
	header := []string{"Название", "Сайт", "Категория", "Аккаунт", "Логин", "Стоимость", "Валюта", "Цикл", "Дата оплаты", "Способ оплаты", "Заметки"}
	rows := [][]string{header}
	for _, svc := range services {
		if svc.ArchivedAt.Valid || !authz.CanViewService(p.Role, p.UserID, svc.OwnerID, grants[svc.ID][p.UserID]) {
			continue
		}
		matched := false
		for _, account := range accounts {
			if account.ServiceID != svc.ID {
				continue
			}
			matched = true
			cost, currency, cycle, date := "", "", "", ""
			if idx, ok := byAccount[account.ID.String()]; ok {
				sub := subs[idx]
				cost = spend.FormatMinor(sub.CostMinor)
				currency = sub.Currency
				cycle = sub.BillingCycle
				date = sub.RenewalDate.Format("2006-01-02")
			}
			rows = append(rows, []string{
				svc.Name, svc.Url, svc.Category, account.Label, account.LoginHint,
				cost, currency, cycle, date, account.CardLabel, account.Notes,
			})
		}
		if !matched {
			rows = append(rows, []string{svc.Name, svc.Url, svc.Category, "", "", "", "", "", "", "", svc.Notes})
		}
	}
	return rows, nil
}

func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request) {
	rows, err := s.exportRows(r)
	if err != nil {
		s.sendError(w, err)
		return
	}
	var buf bytes.Buffer
	buf.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(&buf)
	if err := writer.WriteAll(rows); err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"services.csv\"")
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) exportXLSX(w http.ResponseWriter, r *http.Request) {
	rows, err := s.exportRows(r)
	if err != nil {
		s.sendError(w, err)
		return
	}
	body, err := xlsx.Workbook(rows)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "server")
		return
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", "attachment; filename=\"services.xlsx\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}
