// Package authz is the authorization policy. Handlers call these functions
// with values taken from the server session, never from the request body.
package authz

import "github.com/google/uuid"

func ValidAppRole(role string) bool {
	switch role {
	case "admin", "manager", "member", "readonly":
		return true
	default:
		return false
	}
}

func ValidVaultRole(role string) bool {
	switch role {
	case "owner", "manager", "member":
		return true
	default:
		return false
	}
}

func ValidCategory(category string) bool {
	switch category {
	case "infra", "domains", "tools", "comms", "partners", "payments", "other":
		return true
	default:
		return false
	}
}

func ValidCycle(cycle string) bool {
	switch cycle {
	case "monthly", "quarterly", "annual", "custom":
		return true
	default:
		return false
	}
}

func ValidCurrency(code string) bool {
	if len(code) < 3 || len(code) > 5 {
		return false
	}
	for _, r := range code {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// CanViewService reports whether an app role may read a service.
// Admins see the whole organization. Everyone else needs ownership or a grant.
func CanViewService(role string, userID uuid.UUID, ownerID *uuid.UUID, granted bool) bool {
	if role == "admin" {
		return true
	}
	if granted {
		return true
	}
	return ownerID != nil && *ownerID == userID
}

// CanEditService reports whether an app role may change a service.
func CanEditService(role string, userID uuid.UUID, ownerID *uuid.UUID, granted bool) bool {
	switch role {
	case "admin":
		return true
	case "manager":
		if granted {
			return true
		}
		return ownerID != nil && *ownerID == userID
	default:
		return false
	}
}

func CanReadVault(vaultRole string) bool {
	return vaultRole == "owner" || vaultRole == "manager" || vaultRole == "member"
}

func CanWriteVault(vaultRole string) bool {
	return vaultRole == "owner" || vaultRole == "manager"
}

func CanAdminVault(vaultRole string) bool {
	return vaultRole == "owner"
}

// CanApproveKey allows a different active admin to approve a key.
// The sole bootstrap admin may approve only their own key, including while
// their own account is still waiting for that approval.
func CanApproveKey(actorID, subjectID uuid.UUID, actorRole, actorStatus string, userCount int) bool {
	if actorRole != "admin" || actorStatus == "revoked" || actorStatus == "pending_enrollment" {
		return false
	}
	if actorID == subjectID {
		return userCount == 1
	}
	return actorStatus == "active"
}

// MFASatisfied is fail-closed. An empty allow-list or an empty amr denies access.
func MFASatisfied(amr, allowed []string) bool {
	if len(allowed) == 0 || len(amr) == 0 {
		return false
	}
	ok := map[string]struct{}{}
	for _, value := range allowed {
		ok[value] = struct{}{}
	}
	for _, value := range amr {
		if _, found := ok[value]; found {
			return true
		}
	}
	return false
}
