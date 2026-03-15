package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/mattiazi/uccellino/internal/config"
	iocdomain "github.com/mattiazi/uccellino/pkg/uccellino/ioc"
)

type fakeIOCAPI struct {
	listFn   func(ctx context.Context, filter string) ([]iocdomain.IOC, error)
	createFn func(ctx context.Context, in iocdomain.IOC) (string, error)
	deleteFn func(ctx context.Context, id string) error
}

func (f *fakeIOCAPI) List(ctx context.Context, filter string) ([]iocdomain.IOC, error) {
	if f.listFn == nil {
		return nil, nil
	}
	return f.listFn(ctx, filter)
}

func (f *fakeIOCAPI) Create(ctx context.Context, in iocdomain.IOC) (string, error) {
	if f.createFn == nil {
		return "", nil
	}
	return f.createFn(ctx, in)
}

func (f *fakeIOCAPI) Delete(ctx context.Context, id string) error {
	if f.deleteFn == nil {
		return nil
	}
	return f.deleteFn(ctx, id)
}

func TestRootHelpDoesNotRequireCredentials(t *testing.T) {
	clearFalconEnv(t)
	cmd, _, _ := newTestRootCmd(nil)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected help to succeed, got error: %v", err)
	}
}

func TestIOCHelpDoesNotRequireCredentials(t *testing.T) {
	clearFalconEnv(t)
	cmd, out, _ := newTestRootCmd(nil)
	cmd.SetArgs([]string{"ioc", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected ioc help to succeed, got error: %v", err)
	}
	help := out.String()
	for _, snippet := range []string{
		"type: domain, ipv4, ipv6, md5, sha256",
		"action: no_action, detect, prevent, allow, prevent_no_ui",
		"severity: informational, low, medium, high, critical",
		"platform: windows, mac, linux",
	} {
		if !strings.Contains(help, snippet) {
			t.Fatalf("expected ioc help to contain %q, got:\n%s", snippet, help)
		}
	}
}

func TestIOCActionsRequireCredentialsWhenMissing(t *testing.T) {
	clearFalconEnv(t)
	providerCalled := false
	cmd, _, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		providerCalled = true
		return &fakeIOCAPI{}, nil
	})
	cmd.SetArgs([]string{"ioc", "list"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "missing required env vars") {
		t.Fatalf("expected missing env vars error, got: %v", err)
	}
	if providerCalled {
		t.Fatal("expected provider not to be called when credentials are missing")
	}
}

func TestFlagsOverrideEnvCredentialsAndCloud(t *testing.T) {
	clearFalconEnv(t)
	t.Setenv("CROWDSTRIKE_CLIENT_ID", "env-client-id")
	t.Setenv("CROWDSTRIKE_CLIENT_SECRET", "env-client-secret")
	t.Setenv("CROWDSTRIKE_CLOUD", "us-1")

	var captured config.Config
	cmd, _, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		captured = cfg
		return &fakeIOCAPI{}, nil
	})
	cmd.SetArgs([]string{
		"--client-id", "flag-client-id",
		"--client-secret", "flag-client-secret",
		"--cloud", "eu-1",
		"ioc", "list",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if captured.Falcon.ClientId != "flag-client-id" {
		t.Fatalf("expected client id override, got: %q", captured.Falcon.ClientId)
	}
	if captured.Falcon.ClientSecret != "flag-client-secret" {
		t.Fatalf("expected client secret override, got: %q", captured.Falcon.ClientSecret)
	}
	if captured.Falcon.Cloud.String() != "eu-1" {
		t.Fatalf("expected cloud override eu-1, got: %q", captured.Falcon.Cloud.String())
	}
}

func TestInvalidCloudFailsWithClearError(t *testing.T) {
	clearFalconEnv(t)
	cmd, _, _ := newTestRootCmd(unexpectedProvider(t))
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"--cloud", "not-a-cloud",
		"ioc", "list",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "unrecognized CrowdStrike Falcon Cloud") {
		t.Fatalf("expected cloud parsing error, got: %v", err)
	}
}

func TestInvalidOutputFailsWithClearError(t *testing.T) {
	clearFalconEnv(t)
	cmd, _, _ := newTestRootCmd(unexpectedProvider(t))
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"--output", "yaml",
		"ioc", "list",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), `invalid output format "yaml": expected text or json`) {
		t.Fatalf("expected output validation error, got: %v", err)
	}
}

func TestCreateRequiresFlags(t *testing.T) {
	clearFalconEnv(t)
	cmd, _, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		return &fakeIOCAPI{}, nil
	})
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"ioc", "create",
		"--type", "ip",
		"--value", "1.2.3.4",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), `required flag(s) "action" not set`) {
		t.Fatalf("expected required flag error, got: %v", err)
	}
}

func TestCreateHelpListsSupportedOptions(t *testing.T) {
	clearFalconEnv(t)
	cmd, out, _ := newTestRootCmd(nil)
	cmd.SetArgs([]string{"ioc", "create", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected create help to succeed, got error: %v", err)
	}

	help := out.String()
	for _, snippet := range []string{
		"Options:",
		"type: domain, ipv4, ipv6, md5, sha256",
		"action: no_action, detect, prevent, allow, prevent_no_ui",
		"severity: informational, low, medium, high, critical",
		"platform: windows, mac, linux",
		"--type string",
		"--action string",
		"--severity string",
		"--platform strings",
	} {
		if !strings.Contains(help, snippet) {
			t.Fatalf("expected create help to contain %q, got:\n%s", snippet, help)
		}
	}
}

func TestCreateRejectsUnsupportedActionForDomain(t *testing.T) {
	clearFalconEnv(t)
	createCalled := false
	cmd, _, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		return &fakeIOCAPI{
			createFn: func(ctx context.Context, in iocdomain.IOC) (string, error) {
				createCalled = true
				return "ioc-123", nil
			},
		}, nil
	})
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"ioc", "create",
		"--type", "domain",
		"--value", "test.mattiazignale.it",
		"--action", "prevent",
		"--platform", "mac",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), `action "prevent" is not supported for IOC type "domain"`) {
		t.Fatalf("expected unsupported action error, got: %v", err)
	}
	if createCalled {
		t.Fatal("expected Create not to be called for an invalid type/action combination")
	}
}

func TestDeleteRequiresID(t *testing.T) {
	clearFalconEnv(t)
	cmd, _, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		return &fakeIOCAPI{}, nil
	})
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"ioc", "delete",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg(s), received 0") {
		t.Fatalf("expected delete args validation error, got: %v", err)
	}
}

func TestAdapterErrorsBubbleUp(t *testing.T) {
	clearFalconEnv(t)
	wantErr := errors.New("boom")
	cmd, _, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		return &fakeIOCAPI{
			listFn: func(ctx context.Context, filter string) ([]iocdomain.IOC, error) {
				return nil, wantErr
			},
		}, nil
	})
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"ioc", "list",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected adapter error to bubble up, got: %v", err)
	}
}

func TestListTextOutput(t *testing.T) {
	clearFalconEnv(t)
	cmd, out, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		return &fakeIOCAPI{
			listFn: func(ctx context.Context, filter string) ([]iocdomain.IOC, error) {
				if filter != "" {
					t.Fatalf("expected empty filter, got %q", filter)
				}
				return []iocdomain.IOC{
					{
						Type:        "ip",
						Value:       "1.2.3.4",
						Action:      "detect",
						Severity:    "medium",
						Description: "test indicator",
						Tags:        []string{"malware", "feed"},
						Platforms:   []string{"windows", "mac"},
					},
				}, nil
			},
		}, nil
	})
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"ioc", "list",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	got := out.String()
	want := "type=ip value=1.2.3.4 action=detect severity=medium description=\"test indicator\" tags=malware,feed platforms=windows,mac\n"
	if got != want {
		t.Fatalf("unexpected text output:\nwant: %q\ngot:  %q", want, got)
	}
}

func TestListJSONOutput(t *testing.T) {
	clearFalconEnv(t)
	cmd, out, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		return &fakeIOCAPI{
			listFn: func(ctx context.Context, filter string) ([]iocdomain.IOC, error) {
				return []iocdomain.IOC{
					{
						Type:     "domain",
						Value:    "example.org",
						Action:   "prevent",
						Severity: "high",
					},
				}, nil
			},
		}, nil
	})
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"--output", "json",
		"ioc", "list",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	var got []iocdomain.IOC
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode json output: %v", err)
	}

	if len(got) != 1 || got[0].Value != "example.org" || got[0].Action != "prevent" || got[0].Severity != "high" {
		t.Fatalf("unexpected list json output: %#v", got)
	}
}

func TestCreateCommandWiresFlagsToAPI(t *testing.T) {
	clearFalconEnv(t)
	var gotIOC iocdomain.IOC
	cmd, out, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		return &fakeIOCAPI{
			createFn: func(ctx context.Context, in iocdomain.IOC) (string, error) {
				gotIOC = in
				return "ioc-123", nil
			},
		}, nil
	})
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"ioc", "create",
		"--type", "ip",
		"--value", "1.2.3.4",
		"--action", "detect",
		"--severity", "medium",
		"--description", "test indicator",
		"--tags", "tag-a,tag-b",
		"--platform", "windows,linux",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	wantIOC := iocdomain.IOC{
		Type:        "ip",
		Value:       "1.2.3.4",
		Action:      "detect",
		Severity:    "medium",
		Description: "test indicator",
		Tags:        []string{"tag-a", "tag-b"},
		Platforms:   []string{"windows", "linux"},
	}
	if !reflect.DeepEqual(gotIOC, wantIOC) {
		t.Fatalf("unexpected IOC passed to Create:\nwant: %#v\ngot:  %#v", wantIOC, gotIOC)
	}
	if got, want := out.String(), "created ioc: ioc-123\n"; got != want {
		t.Fatalf("unexpected create output:\nwant: %q\ngot:  %q", want, got)
	}
}

func TestDeleteCommandWiresIDToAPI(t *testing.T) {
	clearFalconEnv(t)
	var gotID string
	cmd, out, _ := newTestRootCmd(func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		return &fakeIOCAPI{
			deleteFn: func(ctx context.Context, id string) error {
				gotID = id
				return nil
			},
		}, nil
	})
	cmd.SetArgs([]string{
		"--client-id", "id",
		"--client-secret", "secret",
		"--output", "json",
		"ioc", "delete", "ioc-999",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if gotID != "ioc-999" {
		t.Fatalf("unexpected ID passed to Delete: %q", gotID)
	}

	var got statusResponse
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode delete json output: %v", err)
	}

	if got.ID != "ioc-999" || got.Status != "deleted" {
		t.Fatalf("unexpected delete json output: %#v", got)
	}
}

func newTestRootCmd(provider iocProvider) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	cmd := newRootCmdWithDeps(dependencies{
		out:      out,
		errOut:   errOut,
		provider: provider,
	})

	return cmd, out, errOut
}

func unexpectedProvider(t *testing.T) iocProvider {
	t.Helper()
	return func(ctx context.Context, cfg config.Config) (iocdomain.IOCsAPI, error) {
		t.Fatal("provider should not have been called")
		return nil, nil
	}
}

func clearFalconEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CROWDSTRIKE_CLIENT_ID", "")
	t.Setenv("CROWDSTRIKE_CLIENT_SECRET", "")
	t.Setenv("CROWDSTRIKE_CLOUD", "")
}
