package ioc

import (
	"fmt"
	"strings"
)

// ValidateCreate performs minimal validation before calling Create endpoint.
func ValidateCreate(ioc IOC) error {
	typeValue := strings.ToLower(strings.TrimSpace(ioc.Type))
	actionValue := strings.ToLower(strings.TrimSpace(ioc.Action))

	if typeValue == "" {
		return fmt.Errorf("ioc type must not be empty")
	}
	if strings.TrimSpace(ioc.Value) == "" {
		return fmt.Errorf("ioc value must not be empty")
	}
	if actionValue == "" {
		return fmt.Errorf("ioc action must not be empty")
	}

	switch typeValue {
	case "domain", "ipv4", "ipv6":
		switch actionValue {
		case "prevent", "allow", "prevent_no_ui":
			return fmt.Errorf("action %q is not supported for IOC type %q; use %q or %q", ioc.Action, ioc.Type, "detect", "no_action")
		}
	}

	return nil
}
