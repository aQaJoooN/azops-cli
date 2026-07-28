package azure

import (
	"context"
	"fmt"
)

// Scope identifies where a service is rooted relative to a collection URL.
type Scope uint8

const (
	CollectionScope Scope = iota
	ProjectScope
)

// Service defines a Server 2022.2 REST area and compatible default API version.
type Service struct {
	Name       string
	Scope      Scope
	Prefix     []string
	APIVersion string
}

var (
	Projects         = Service{"projects", CollectionScope, []string{"_apis", "projects"}, "7.0"}
	Identity         = Service{"identity", CollectionScope, []string{"_apis", "identities"}, "7.0"}
	Graph            = Service{"graph", CollectionScope, []string{"_apis", "graph"}, "7.0-preview.1"}
	Security         = Service{"security", CollectionScope, []string{"_apis", "securitynamespaces"}, "7.0"}
	Build            = Service{"build", ProjectScope, []string{"_apis", "build"}, "7.0"}
	Release          = Service{"release", ProjectScope, []string{"_apis", "release"}, "7.0"}
	DistributedTask  = Service{"distributedtask", ProjectScope, []string{"_apis", "distributedtask"}, "7.0"}
	ServiceHooks     = Service{"hooks", CollectionScope, []string{"_apis", "hooks"}, "7.0"}
	Dashboards       = Service{"dashboard", ProjectScope, []string{"_apis", "dashboard"}, "7.0-preview.3"}
	ServiceEndpoints = Service{"serviceendpoint", ProjectScope, []string{"_apis", "serviceendpoint"}, "7.0"}
	Test             = Service{"test", ProjectScope, []string{"_apis", "test"}, "7.0"}
)

// Adapter binds requests to one Azure DevOps REST service.
type Adapter struct {
	client  *Client
	service Service
}

func NewAdapter(client *Client, service Service) *Adapter {
	return &Adapter{client: client, service: service}
}

func (adapter *Adapter) Do(ctx context.Context, request Request, output any) error {
	request.Service = adapter.service
	return adapter.client.Do(ctx, request, output)
}

// UnsupportedOperationError identifies a capability without a supported public Server 2022.2 API.
type UnsupportedOperationError struct {
	Service   string
	Operation string
}

func (e *UnsupportedOperationError) Error() string {
	return fmt.Sprintf("Azure DevOps Server 2022.2 does not expose a supported public %s operation for %s", e.Operation, e.Service)
}

func Unsupported(service Service, operation string) error {
	return &UnsupportedOperationError{Service: service.Name, Operation: operation}
}

// Services exposes adapters for all REST areas used by AzOps modules.
type Services struct {
	Projects         *Adapter
	Identity         *Adapter
	Graph            *Adapter
	Security         *Adapter
	Build            *Adapter
	Release          *Adapter
	DistributedTask  *Adapter
	ServiceHooks     *Adapter
	Dashboards       *Adapter
	ServiceEndpoints *Adapter
	Test             *Adapter
}

func NewServices(client *Client) Services {
	return Services{
		Projects: NewAdapter(client, Projects), Identity: NewAdapter(client, Identity),
		Graph: NewAdapter(client, Graph), Security: NewAdapter(client, Security),
		Build: NewAdapter(client, Build), Release: NewAdapter(client, Release),
		DistributedTask: NewAdapter(client, DistributedTask), ServiceHooks: NewAdapter(client, ServiceHooks),
		Dashboards: NewAdapter(client, Dashboards), ServiceEndpoints: NewAdapter(client, ServiceEndpoints),
		Test: NewAdapter(client, Test),
	}
}
