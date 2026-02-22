package ioc

import "context"

// Implementations are in the adapters folder (pkg/falconwrap)
type IOCsAPI interface {
	List(ctx context.Context, filter string, limit int) ([]IOC, error)
	Create(ctx context.Context, i IOC) (string, error)
	Delete(ctx context.Context, id string) error
}

type IOC struct {
	Type        string // ip, domain, url, md5, sha256, ...
	Value       string
	Action      string // no_action, detect, prevent, ...
	Severity    int
	Description string
	Tags        []string
	Platforms   []string
}
