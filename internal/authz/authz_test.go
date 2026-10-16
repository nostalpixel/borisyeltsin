package authz

import (
	"testing"

	"github.com/google/uuid"
)

func TestServiceAccess(t *testing.T) {
	user := uuid.New()
	other := uuid.New()
	cases := []struct {
		name    string
		role    string
		owner   *uuid.UUID
		granted bool
		view    bool
		edit    bool
	}{
		{"admin sees unassigned", "admin", &other, false, true, true},
		{"manager own", "manager", &user, false, true, true},
		{"manager grant", "manager", &other, true, true, true},
		{"manager stranger", "manager", &other, false, false, false},
		{"member grant views", "member", nil, true, true, false},
		{"readonly own views", "readonly", &user, false, true, false},
		{"member stranger", "member", &other, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanViewService(tc.role, user, tc.owner, tc.granted); got != tc.view {
				t.Fatalf("view %v", got)
			}
			if got := CanEditService(tc.role, user, tc.owner, tc.granted); got != tc.edit {
				t.Fatalf("edit %v", got)
			}
		})
	}
}

func TestVaultRoles(t *testing.T) {
	if CanAdminVault("manager") || !CanAdminVault("owner") {
		t.Fatal("admin vault")
	}
	if !CanWriteVault("manager") || CanWriteVault("member") {
		t.Fatal("write vault")
	}
	if !CanReadVault("member") || CanReadVault("") {
		t.Fatal("read vault")
	}
}

func TestApproveKey(t *testing.T) {
	admin := uuid.New()
	other := uuid.New()
	if !CanApproveKey(admin, admin, "admin", "pending_approval", 1) {
		t.Fatal("bootstrap self approval")
	}
	if CanApproveKey(admin, admin, "admin", "active", 2) {
		t.Fatal("self approval with a second user")
	}
	if !CanApproveKey(admin, other, "admin", "active", 2) {
		t.Fatal("admin approves another user")
	}
	if CanApproveKey(admin, other, "manager", "active", 2) {
		t.Fatal("manager approves")
	}
	if CanApproveKey(admin, other, "admin", "pending_approval", 2) {
		t.Fatal("pending admin approving someone else")
	}
}

func TestMFA(t *testing.T) {
	allowed := []string{"mfa", "otp", "totp", "webauthn"}
	if !MFASatisfied([]string{"pwd", "otp"}, allowed) {
		t.Fatal("otp should pass")
	}
	if MFASatisfied([]string{"pwd"}, allowed) {
		t.Fatal("password alone")
	}
	if MFASatisfied(nil, allowed) || MFASatisfied([]string{"mfa"}, nil) {
		t.Fatal("fail closed")
	}
}

func TestEnums(t *testing.T) {
	if !ValidCurrency("USDT") || ValidCurrency("us") || ValidCurrency("USD1") {
		t.Fatal("currency")
	}
	if !ValidCategory("infra") || ValidCategory("vpn") {
		t.Fatal("category")
	}
	if !ValidCycle("custom") || !ValidAppRole("readonly") || !ValidVaultRole("owner") {
		t.Fatal("enums")
	}
}
