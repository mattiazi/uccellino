package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/spf13/cobra"

	"github.com/mattiazi/uccellino/internal/config"
	"github.com/mattiazi/uccellino/pkg/falconwrap"
	iocdomain "github.com/mattiazi/uccellino/pkg/uccellino/ioc"
)

const (
	outputText = "text"
	outputJSON = "json"
)

type iocProvider func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error)

type dependencies struct {
	out      io.Writer
	errOut   io.Writer
	provider iocProvider
}

type rootState struct {
	clientID     string
	clientSecret string
	cloud        string
	output       string

	provider iocProvider
	iocAPI   iocdomain.IOCsAPI
}

type statusResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func NewRootCmd() *cobra.Command {
	return newRootCmdWithDeps(dependencies{
		out:      os.Stdout,
		errOut:   os.Stderr,
		provider: defaultIOCProvider,
	})
}

func Execute() error {
	return NewRootCmd().Execute()
}

func defaultIOCProvider(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
	fc, err := falconwrap.NewClient(ctx, falconwrap.Config{
		ClientId:     cfg.Falcon.ClientId,
		ClientSecret: cfg.Falcon.ClientSecret,
		Cloud:        cfg.Falcon.Cloud,
	})
	if err != nil {
		return nil, err
	}
	return falconwrap.NewIOCAdapter(fc), nil
}

func newRootCmdWithDeps(deps dependencies) *cobra.Command {
	if deps.out == nil {
		deps.out = os.Stdout
	}
	if deps.errOut == nil {
		deps.errOut = os.Stderr
	}
	if deps.provider == nil {
		deps.provider = defaultIOCProvider
	}

	state := &rootState{
		output:   outputText,
		provider: deps.provider,
	}

	rootCmd := &cobra.Command{
		Use:           "uccellino",
		Short:         "Uccellino is an automation tool/CLI for CrowdStrike Falcon",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.SetOut(deps.out)
	rootCmd.SetErr(deps.errOut)

	rootFlags := rootCmd.PersistentFlags()
	rootFlags.StringVar(&state.clientID, "client-id", "", "CrowdStrike client ID (overrides CROWDSTRIKE_CLIENT_ID)")
	rootFlags.StringVar(&state.clientSecret, "client-secret", "", "CrowdStrike client secret (overrides CROWDSTRIKE_CLIENT_SECRET)")
	rootFlags.StringVar(&state.cloud, "cloud", "", "CrowdStrike cloud region (autodiscover, us-1, us-2, eu-1, us-gov-1, gov1, us-gov-2, gov2)")
	rootFlags.StringVar(&state.output, "output", outputText, "Output format: text|json")

	rootCmd.AddCommand(newIOCCmd(state))

	return rootCmd
}

func newIOCCmd(state *rootState) *cobra.Command {
	var (
		listFilter string
		listLimit  int

		createType        string
		createValue       string
		createAction      string
		createSeverity    string
		createDescription string
		createTags        []string
		createPlatforms   []string
	)

	iocCmd := &cobra.Command{
		Use:   "ioc",
		Short: "Manage indicators of compromise",
		Long: strings.TrimSpace(`
Manage CrowdStrike custom indicators of compromise.

Common options:
  type: domain, ipv4, ipv6, md5, sha256
  action: no_action, detect, prevent, allow, prevent_no_ui
  severity: informational, low, medium, high, critical
  platform: windows, mac, linux
`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	iocCmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if cmd == iocCmd || isHelpCommand(cmd) {
			return nil
		}
		return state.ensureIOCAPI(cmd)
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List indicators of compromise",
		Long: strings.TrimSpace(`
List CrowdStrike custom indicators of compromise.

Options:
  filter: Falcon Query Language (FQL) expression, for example value:'example.org'
`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// if listLimit <= 0 {
			// 	return errors.New("limit must be greater than 0")
			// }

			indicators, err := state.iocAPI.List(cmd.Context(), listFilter)
			if err != nil {
				return err
			}

			return writeIOCList(cmd.OutOrStdout(), state.output, indicators)
		},
	}
	listCmd.Flags().StringVar(&listFilter, "filter", "", "Filter expression")
	listCmd.Flags().IntVar(&listLimit, "limit", 100, "Maximum number of IOCs to return")

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create an indicator of compromise",
		Long: strings.TrimSpace(`
Create a CrowdStrike custom indicator of compromise.

Options:
  type: domain, ipv4, ipv6, md5, sha256
  action: no_action, detect, prevent, allow, prevent_no_ui
  severity: informational, low, medium, high, critical
  platform: windows, mac, linux

Notes:
  domain/ipv4/ipv6 usually support detect or no_action
  md5/sha256 can use prevent
`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			input := iocdomain.IOC{
				Type:        createType,
				Value:       createValue,
				Action:      createAction,
				Severity:    createSeverity,
				Description: createDescription,
				Tags:        createTags,
				Platforms:   createPlatforms,
			}
			if err := iocdomain.ValidateCreate(input); err != nil {
				return err
			}

			id, err := state.iocAPI.Create(cmd.Context(), input)
			if err != nil {
				return err
			}

			return writeStatus(cmd.OutOrStdout(), state.output, statusResponse{
				ID:     id,
				Status: "created",
			})
		},
	}
	createCmd.Flags().StringVar(&createType, "type", "", "IOC type. Options: domain, ipv4, ipv6, md5, sha256")
	createCmd.Flags().StringVar(&createValue, "value", "", "IOC value")
	createCmd.Flags().StringVar(&createAction, "action", "", "IOC action. Options: no_action, detect, prevent, allow, prevent_no_ui")
	createCmd.Flags().StringVar(&createSeverity, "severity", "", "IOC severity. Options: informational, low, medium, high, critical")
	createCmd.Flags().StringVar(&createDescription, "description", "", "IOC description")
	createCmd.Flags().StringSliceVar(&createTags, "tags", nil, "Comma-separated IOC tags")
	createCmd.Flags().StringSliceVar(&createPlatforms, "platform", nil, "Comma-separated IOC platforms. Options: windows, mac, linux")
	markFlagRequired(createCmd, "type", "value", "action")

	deleteCmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete an indicator of compromise",
		Long: strings.TrimSpace(`
Delete a CrowdStrike custom indicator of compromise.

Options:
  id: CrowdStrike IOC ID returned by create or visible via list/get APIs
`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.TrimSpace(args[0])
			if id == "" {
				return errors.New("ioc id must not be empty")
			}
			if err := state.iocAPI.Delete(cmd.Context(), id); err != nil {
				return err
			}

			return writeStatus(cmd.OutOrStdout(), state.output, statusResponse{
				ID:     id,
				Status: "deleted",
			})
		},
	}

	iocCmd.AddCommand(listCmd, createCmd, deleteCmd)

	return iocCmd
}

func (s *rootState) ensureIOCAPI(cmd *cobra.Command) error {
	if s.iocAPI != nil {
		return nil
	}

	mode, err := normalizeOutputMode(s.output)
	if err != nil {
		return err
	}
	s.output = mode

	cfg, err := config.LoadRaw()
	if err != nil {
		return err
	}

	if clientID := strings.TrimSpace(s.clientID); clientID != "" {
		cfg.Falcon.ClientId = clientID
	}
	if clientSecret := strings.TrimSpace(s.clientSecret); clientSecret != "" {
		cfg.Falcon.ClientSecret = clientSecret
	}
	if cloud := strings.TrimSpace(s.cloud); cloud != "" {
		cloudType, err := falcon.CloudValidate(cloud)
		if err != nil {
			return err
		}
		cfg.Falcon.Cloud = cloudType
	}

	if err := config.Validate(cfg); err != nil {
		return err
	}

	if s.provider == nil {
		return errors.New("ioc provider is not configured")
	}

	iocAPI, err := s.provider(cmd.Context(), cfg)
	if err != nil {
		return err
	}

	s.iocAPI = iocAPI
	return nil
}

func isHelpCommand(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	if cmd.Name() == "help" {
		return true
	}

	helpFlag := cmd.Flags().Lookup("help")
	return helpFlag != nil && helpFlag.Value.String() == "true"
}

func normalizeOutputMode(mode string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	switch normalized {
	case outputText, outputJSON:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid output format %q: expected text or json", mode)
	}
}

func writeIOCList(w io.Writer, mode string, indicators []iocdomain.IOC) error {
	normalizedMode, err := normalizeOutputMode(mode)
	if err != nil {
		return err
	}

	switch normalizedMode {
	case outputJSON:
		return writeJSON(w, indicators)
	case outputText:
		for _, indicator := range indicators {
			if _, err := fmt.Fprintf(
				w,
				"type=%s value=%s action=%s severity=%s description=%q tags=%s platforms=%s\n",
				indicator.Type,
				indicator.Value,
				indicator.Action,
				indicator.Severity,
				indicator.Description,
				strings.Join(indicator.Tags, ","),
				strings.Join(indicator.Platforms, ","),
			); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("invalid output format %q: expected text or json", mode)
	}
}

func writeStatus(w io.Writer, mode string, response statusResponse) error {
	normalizedMode, err := normalizeOutputMode(mode)
	if err != nil {
		return err
	}

	switch normalizedMode {
	case outputJSON:
		return writeJSON(w, response)
	case outputText:
		_, err := fmt.Fprintf(w, "%s ioc: %s\n", response.Status, response.ID)
		return err
	default:
		return fmt.Errorf("invalid output format %q: expected text or json", mode)
	}
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func markFlagRequired(cmd *cobra.Command, names ...string) {
	for _, name := range names {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}
