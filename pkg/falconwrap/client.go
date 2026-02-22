package falconwrap

import (
	"context"
	"errors"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
)

type Config struct {
	ClientId     string
	ClientSecret string
	Cloud        falcon.CloudType // Optional override for cloud env ("us-1", "eu-1", etc..). These are iota values from falcon.CloudType
}

func NewClient(ctx context.Context, config Config) (*client.CrowdStrikeAPISpecification, error) {
	// Validate credentials
	if config.ClientId == "" || config.ClientSecret == "" {
		return nil, errors.New("missing CrowdStrike credentials")
	}

	// Create new Falcon client with Config values
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     config.ClientId,
		ClientSecret: config.ClientSecret,
		Cloud:        config.Cloud,
		Context:      ctx,
	})
	if err != nil {
		return nil, err
	}

	return client, nil
}
