package permissions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"azops-cli/internal/azure"
	"azops-cli/internal/config"
)

func TestExpandGroupName(t *testing.T) {
	got, err := ExpandGroupName("teamprojectname-team-role", "Project", "Dev", "Admins")
	if err != nil {
		t.Fatal(err)
	}
	if want := "Project-Dev-Admins"; got != want {
		t.Fatalf("expanded group name = %q, want %q", got, want)
	}
}

func TestPlanAccessSupportsDeclaredValues(t *testing.T) {
	principal := Principal{Alias: "11", Name: "Project Dev Admins", Descriptor: "d1"}
	principals := map[config.GroupSelector][]Principal{"11": {principal}}
	bits := map[config.PermissionName]AccessBit{"Read": 1}
	tests := []struct {
		name    string
		current config.AccessValue
		desired config.AccessValue
	}{
		{name: "allow", current: config.AccessNotSet, desired: config.AccessAllow},
		{name: "deny", current: config.AccessAllow, desired: config.AccessDeny},
		{name: "not set", current: config.AccessDeny, desired: config.AccessNotSet},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changes, err := PlanAccess(
				config.AccessAssignments{"Read": {test.desired: {"11"}}},
				bits,
				principals,
				map[string]map[AccessBit]config.AccessValue{"d1": {1: test.current}},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(changes) != 1 || changes[0].Current != test.current || changes[0].Desired != test.desired {
				t.Fatalf("access changes = %#v, want %q to %q", changes, test.current, test.desired)
			}
		})
	}
}

func TestResolverExpandsAliasesAllAndCachesDirectory(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/Project/_api/_identity/ReadScopedApplicationGroupsJson":
			if request.URL.Query().Get("__v") != "5" || request.URL.Query().Get("api-version") != "7.0" {
				t.Errorf("unexpected group query: %s", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`{"identities":[
				{"FriendlyDisplayName":"Project Dev Admins","TeamFoundationId":"id1"},
				{"FriendlyDisplayName":"Project Dev Readers","TeamFoundationId":"id2"},
				{"FriendlyDisplayName":"Project Extra","TeamFoundationId":"id3"},
				{"FriendlyDisplayName":"Other Project","TeamFoundationId":"id4"}
			]}`))
		case "/Project/_api/_identity/Display":
			id := request.URL.Query().Get("tfid")
			_, _ = writer.Write([]byte(`{"security":{"descriptorIdentityType":"type","descriptorIdentifier":"` + id + `"}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := azure.NewClient(server.URL, "test-pat")
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewResolver(config.GeneralConfig{
		TeamProjectName: "Project", GroupNameTemplate: "teamprojectname team role",
		GroupsAlias: map[string]map[string]string{"Dev": {"Admins": "11", "Readers": "12"}},
	}, NewAzureGroupDirectory(azure.NewAdapter(client, azure.ProjectIdentity)))
	if err != nil {
		t.Fatal(err)
	}

	principals, err := resolver.Resolve(context.Background(), []config.GroupSelector{"11", AllGroups})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(principals))
	for index, principal := range principals {
		got[index] = principal.Descriptor
	}
	if want := []string{"type;id1", "type;id2", "type;id3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("descriptors = %#v, want %#v", got, want)
	}
	if _, err := resolver.Resolve(context.Background(), []config.GroupSelector{"12"}); err != nil || requests != 5 {
		t.Fatalf("cached resolve: requests = %d, err = %v", requests, err)
	}
	if _, err := resolver.Resolve(context.Background(), []config.GroupSelector{"99"}); err == nil {
		t.Fatal("expected unresolved alias error")
	}
}

func TestPermissionPlanningDetectsChangesNoOpsAndInvalidAssignments(t *testing.T) {
	admin := Principal{Alias: "11", Name: "Project Dev Admins", Descriptor: "d1"}
	reader := Principal{Alias: "12", Name: "Project Dev Readers", Descriptor: "d2"}
	principals := map[config.GroupSelector][]Principal{"11": {admin}, "all": {admin, reader}}
	bits := map[config.PermissionName]AccessBit{"Read": 1}

	accessChanges, err := PlanAccess(config.AccessAssignments{
		"Read": {config.AccessAllow: {"all"}},
	}, bits, principals, map[string]map[AccessBit]config.AccessValue{
		"d1": {1: config.AccessAllow}, "d2": {1: config.AccessDeny},
	})
	if err != nil || len(accessChanges) != 1 || accessChanges[0].Principal.Descriptor != "d2" {
		t.Fatalf("access changes = %#v, err = %v", accessChanges, err)
	}
	if noOp, err := PlanAccess(config.AccessAssignments{"Read": {config.AccessAllow: {"11"}}}, bits, principals, map[string]map[AccessBit]config.AccessValue{"d1": {1: config.AccessAllow}}); err != nil || len(noOp) != 0 {
		t.Fatalf("access no-op = %#v, err = %v", noOp, err)
	}
	if _, err := PlanAccess(config.AccessAssignments{"Unknown": {config.AccessAllow: {"11"}}}, bits, principals, nil); err == nil {
		t.Fatal("expected unresolved permission error")
	}

	roles := config.RoleAssignments{config.RoleReader: {"all"}}
	roleChanges, err := PlanRoles(roles, principals, map[string]config.Role{"d1": config.RoleReader, "d2": config.RoleUser}, map[config.Role]struct{}{config.RoleReader: {}})
	if err != nil || len(roleChanges) != 1 || roleChanges[0].Principal.Descriptor != "d2" {
		t.Fatalf("role changes = %#v, err = %v", roleChanges, err)
	}
	if noOp, err := PlanRoles(config.RoleAssignments{config.RoleReader: {"11"}}, principals, map[string]config.Role{"d1": config.RoleReader}, map[config.Role]struct{}{config.RoleReader: {}}); err != nil || len(noOp) != 0 {
		t.Fatalf("role no-op = %#v, err = %v", noOp, err)
	}
	if _, err := PlanRoles(config.RoleAssignments{config.RoleAdmin: {"11"}}, principals, nil, map[config.Role]struct{}{config.RoleReader: {}}); err == nil {
		t.Fatal("expected unsupported role error")
	}
}
