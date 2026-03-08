package falconwrap

import (
	"context"
	"errors"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	falcon_ioc "github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/mattiazi/uccellino/internal/config"
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

func (a *IOCAdapter) List(ctx context.Context, filter string) ([]ioc.IOC, error) {
	iocs := []ioc.IOC{}
	var limit, offset, total int64
	limit = 2000
	offset = 0
	total = 0

	config, err := config.Load()
	if err != nil {
		return []ioc.IOC{}, err
	}

	client, err := NewClient(context.Background(), Config(config.Falcon))
	if err != nil {
		return []ioc.IOC{}, err
	}

	for offset <= total {
		params := falcon_ioc.NewIndicatorCombinedV1Params().WithDefaults()
		params.SetOffset(&offset)
		params.SetLimit(&limit)
		res, err := client.Ioc.IndicatorCombinedV1(params)
		if err != nil {
			return []ioc.IOC{}, err
		}
		if err = falcon.AssertNoError(res.GetPayload().Errors); err != nil {
			return []ioc.IOC{}, err
		}

		for _, f_ioc := range res.GetPayload().Resources {
			iocs = append(iocs, ioc.IOC{
				Type:        f_ioc.Type,
				Value:       f_ioc.Value,
				Action:      f_ioc.Action,
				Severity:    f_ioc.Severity,
				Description: f_ioc.Description,
				Tags:        f_ioc.Tags,
				Platforms:   f_ioc.Platforms,
			})
		}

		total = *res.GetPayload().Meta.Pagination.Total
		offset += limit
	}

	return iocs, nil
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
