package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mattiazi/uccellino/pkg/falconwrap"
)

type Config struct {
	Falcon falconwrap.Config
}

func Load() (Config, error) {
	config := Config{
		Falcon: falconwrap.Config{
			ClientId:     strings.TrimSpace(os.Getenv("CROWDSTRIKE_CLIENT_ID")),
			ClientSecret: strings.TrimSpace(os.Getenv("CROWDSTRIKE_CLIENT_SECRET")),
			//TODO: Cloud:        os.Getenv("CROWDSTRIKE_CLOUD"), // optional. Use falcon.CloudType
		},
	}

	if err := validate(config); err != nil {
		return Config{}, err
	}

	return config, nil
}

func validate(config Config) error {
	var missing []string

	if config.Falcon.ClientId == "" {
		missing = append(missing, "CROWDSTRIKE_CLIENT_ID")
	}
	if config.Falcon.ClientSecret == "" {
		missing = append(missing, "CROWDSTRIKE_CLIENT_SECRET")
	}

	if len(missing) > 0 {
		return errors.New("missing required env vars: " + strings.Join(missing, ", "))
	}

	// TODO: validate cloud value if provided

	return nil
}

// Helper for "safe" print
func (c Config) RedactedString() string {
	cloud := c.Falcon.Cloud.String()
	if cloud == "" {
		cloud = "(default)"
	}
	return fmt.Sprintf("falcon: client_id=%s cloud=%s", redactID(c.Falcon.ClientId), cloud)
}

func redactID(s string) string {
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "***" + s[len(s)-3:]
}
