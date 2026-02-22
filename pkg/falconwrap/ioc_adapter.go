package falconwrap

import (
	"context"
	"errors"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/mattiazi/uccellino/pkg/uccellino/ioc"
)

// IOCAdapter implements the domain interface using gofalcon SDK
// N.B: All SDK-specific mapping must be inside this package.
type IOCAdapter struct {
	fc *client.CrowdStrikeAPISpecification
}

func NewIOCAdapter(fc *client.CrowdStrikeAPISpecification) *IOCAdapter {
	return &IOCAdapter{fc: fc}
}

func (a *IOCAdapter) List(ctx context.Context, filter string, limit int) ([]ioc.IOC, error) {
	_ = ctx
	_ = filter
	_ = limit

	// TODO: call the correct gofalcon IOC endpoint and map results:
	// - query/list endpoint (with filter + pagination)
	// - map SDK models -> ioc.IOC
	return nil, errors.New("falcon ioc list: not implemented yet")
}

func (a *IOCAdapter) Create(ctx context.Context, in ioc.IOC) (string, error) {
	_ = ctx
	_ = in

	// TODO: call create/upsert endpoint and return created IOC ID.
	// - map ioc.IOC -> SDK request model
	return "", errors.New("falcon ioc create: not implemented yet")
}

func (a *IOCAdapter) Delete(ctx context.Context, id string) error {
	_ = ctx
	_ = id

	// TODO: call delete endpoint.
	return errors.New("falcon ioc delete: not implemented yet")
}
