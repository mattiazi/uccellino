package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
)

type Config struct {
	Falcon FalconConfig
}

type FalconConfig struct {
	ClientId     string
	ClientSecret string
	Cloud        falcon.CloudType
}

func Load() (Config, error) {
	config, err := LoadRaw()
	if err != nil {
		return Config{}, err
	}

	if err := Validate(config); err != nil {
		return Config{}, err
	}

	return config, nil
}

func LoadRaw() (Config, error) {
	cloud := falcon.CloudType(falcon.CloudAutoDiscover)
	cloudEnv := strings.TrimSpace(os.Getenv("CROWDSTRIKE_CLOUD"))
	if cloudEnv != "" {
		parsedCloud, err := falcon.CloudValidate(cloudEnv)
		if err != nil {
			return Config{}, fmt.Errorf("invalid CROWDSTRIKE_CLOUD value: %w", err)
		}
		cloud = parsedCloud
	}

	config := Config{
		Falcon: FalconConfig{
			ClientId:     strings.TrimSpace(os.Getenv("CROWDSTRIKE_CLIENT_ID")),
			ClientSecret: strings.TrimSpace(os.Getenv("CROWDSTRIKE_CLIENT_SECRET")),
			Cloud:        cloud,
		},
	}

	return config, nil
}

func Validate(config Config) error {
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
