package falconwrap

import (
	"context"
	"errors"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	falcon_ioc "github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/models"
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
	if a.fc == nil {
		return "", errors.New("falcon ioc create: client is nil")
	}
	if err := ioc.ValidateCreate(in); err != nil {
		return "", err
	}

	appliedGlobally := true
	params := falcon_ioc.NewIndicatorCreateV1Params().
		WithContext(ctx).
		WithDefaults().
		WithBody(&models.APIIndicatorCreateReqsV1{
			Indicators: []*models.APIIndicatorCreateReqV1{
				{
					AppliedGlobally: &appliedGlobally,
					Type:            in.Type,
					Value:           in.Value,
					Action:          in.Action,
					Severity:        in.Severity,
					Description:     in.Description,
					Tags:            append([]string(nil), in.Tags...),
					Platforms:       append([]string(nil), in.Platforms...),
				},
			},
		})

	res, err := a.fc.Ioc.IndicatorCreateV1(params)
	if err != nil {
		return "", err
	}

	payload := res.GetPayload()
	if payload == nil {
		return "", errors.New("falcon ioc create: empty response payload")
	}
	if err := falcon.AssertNoError(payload.Errors); err != nil {
		return "", err
	}
	if len(payload.Resources) == 0 || payload.Resources[0] == nil {
		return "", errors.New("falcon ioc create: no created IOC returned")
	}
	if payload.Resources[0].ID == "" {
		return "", errors.New("falcon ioc create: created IOC ID missing from response")
	}

	return payload.Resources[0].ID, nil
}

func (a *IOCAdapter) Delete(ctx context.Context, id string) error {
	if a.fc == nil {
		return errors.New("falcon ioc delete: client is nil")
	}

	params := falcon_ioc.NewIndicatorDeleteV1Params().
		WithContext(ctx).
		WithIds([]string{id})

	res, err := a.fc.Ioc.IndicatorDeleteV1(params)
	if err != nil {
		return err
	}

	payload := res.GetPayload()
	if payload == nil {
		return errors.New("falcon ioc delete: empty response payload")
	}

	return falcon.AssertNoError(payload.Errors)
}
