package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Wearden/proto/wire"
)

// Ruleset is data, never executable code. Registry access is always HKLM, 64-bit view.
type Ruleset struct {
	Version        string `json:"version"`
	BenchmarkID    string `json:"benchmark_id"`
	RulesetVersion string `json:"ruleset_version"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Path     string `json:"path,omitempty"`
	Name     string `json:"name,omitempty"`
	Match    string `json:"match,omitempty"`
	Expected string `json:"expected,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

var idPattern = regexp.MustCompile(`^WIN-[A-Z]{2,4}-[0-9]{3}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type wmiCheck struct{ Namespace, Class, Property string }
type firewallCheck struct{ Profile, Property string }

var firewallChecks = map[string]firewallCheck{
	"Domain.Enabled":               {"Domain", "Enabled"},
	"Private.Enabled":              {"Private", "Enabled"},
	"Public.Enabled":               {"Public", "Enabled"},
	"Domain.DefaultInboundAction":  {"Domain", "DefaultInboundAction"},
	"Private.DefaultInboundAction": {"Private", "DefaultInboundAction"},
	"Public.DefaultInboundAction":  {"Public", "DefaultInboundAction"},
	"Domain.LogBlocked":            {"Domain", "LogBlocked"},
	"Public.LogBlocked":            {"Public", "LogBlocked"},
	"Public.LogMaxSizeKilobytes":   {"Public", "LogMaxSizeKilobytes"},
}

var wmiChecks = map[string]wmiCheck{
	"MSFT_MpPreference.DisableRealtimeMonitoring":          {`ROOT\Microsoft\Windows\Defender`, "MSFT_MpPreference", "DisableRealtimeMonitoring"},
	"MSFT_MpPreference.MAPSReporting":                      {`ROOT\Microsoft\Windows\Defender`, "MSFT_MpPreference", "MAPSReporting"},
	"MSFT_MpPreference.PUAProtection":                      {`ROOT\Microsoft\Windows\Defender`, "MSFT_MpPreference", "PUAProtection"},
	"MSFT_MpPreference.DisableScanningNetworkFiles":        {`ROOT\Microsoft\Windows\Defender`, "MSFT_MpPreference", "DisableScanningNetworkFiles"},
	"MSFT_MpPreference.EnableNetworkProtection":            {`ROOT\Microsoft\Windows\Defender`, "MSFT_MpPreference", "EnableNetworkProtection"},
	"MSFT_SmbServerConfiguration.EnableSMB1Protocol":       {`ROOT\Microsoft\Windows\Smb`, "MSFT_SmbServerConfiguration", "EnableSMB1Protocol"},
	"MSFT_SmbServerConfiguration.RequireSecuritySignature": {`ROOT\Microsoft\Windows\Smb`, "MSFT_SmbServerConfiguration", "RequireSecuritySignature"},
	"MSFT_SmbClientConfiguration.RequireSecuritySignature": {`ROOT\Microsoft\Windows\Smb`, "MSFT_SmbClientConfiguration", "RequireSecuritySignature"},
}

var policyNames = map[string]bool{"min_length": true, "max_age_seconds": true, "min_age_seconds": true, "history_length": true, "lockout_duration_seconds": true, "lockout_window_seconds": true, "lockout_threshold": true}
var serviceNames = map[string]bool{"Spooler": true, "RemoteRegistry": true, "TlntSvr": true, "SNMP": true, "Fax": true, "simptcp": true}
var rightNames = map[string]bool{"SeDenyNetworkLogonRight": true, "SeDenyRemoteInteractiveLogonRight": true, "SeDebugPrivilege": true, "SeRemoteShutdownPrivilege": true, "SeTakeOwnershipPrivilege": true, "SeTcbPrivilege": true, "SeImpersonatePrivilege": true, "SeLoadDriverPrivilege": true, "SeBackupPrivilege": true, "SeNetworkLogonRight": true, "SeDenyServiceLogonRight": true, "SeDenyBatchLogonRight": true}
var auditNames = map[string]uint32{"Credential Validation": 0x0cce923f, "Kerberos Authentication Service": 0x0cce9242, "Kerberos Service Ticket Operations": 0x0cce9240, "Account Lockout": 0x0cce9217, "Logoff": 0x0cce9216, "Logon": 0x0cce9215, "Special Logon": 0x0cce921b, "Other Logon/Logoff Events": 0x0cce921c, "Security Group Management": 0x0cce9237, "User Account Management": 0x0cce9235, "Process Creation": 0x0cce922b, "Directory Service Changes": 0x0cce923c, "Audit Policy Change": 0x0cce922f, "Authentication Policy Change": 0x0cce9230, "Sensitive Privilege Use": 0x0cce9228, "Security State Change": 0x0cce9210, "Security System Extension": 0x0cce9211, "System Integrity": 0x0cce9212}

func Decode(data []byte) (Ruleset, error) {
	var rs Ruleset
	if len(data) > 4<<20 {
		return rs, errors.New("ruleset exceeds 4 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&rs); err != nil {
		return rs, fmt.Errorf("invalid ruleset JSON: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return rs, errors.New("trailing ruleset data")
	}
	if rs.Version != wire.Version || !identifier.MatchString(rs.BenchmarkID) || !identifier.MatchString(rs.RulesetVersion) || len(rs.Rules) == 0 || len(rs.Rules) > 10000 {
		return rs, errors.New("invalid ruleset metadata")
	}
	seen := map[string]bool{}
	for _, r := range rs.Rules {
		if !idPattern.MatchString(r.ID) || seen[r.ID] {
			return rs, errors.New("invalid or duplicate rule ID")
		}
		seen[r.ID] = true
		target, known := approvedTargets[r.ID]
		if !known || target.Kind != r.Kind || !strings.EqualFold(target.Path, r.Path) || !strings.EqualFold(target.Name, r.Name) {
			return rs, errors.New("rule target is not in the reviewed native catalog")
		}
		if r.Severity != "low" && r.Severity != "medium" && r.Severity != "high" && r.Severity != "critical" {
			return rs, errors.New("invalid severity")
		}
		if len(r.Title) > 1024 || len(r.Reason) > 1024 {
			return rs, errors.New("rule text exceeds limit")
		}
		switch r.Kind {
		case "unsupported":
			if r.Reason == "" {
				return rs, errors.New("unsupported rule requires reason")
			}
		case "registry":
			if r.Path == "" || len(r.Path) > 1024 || len(r.Name) == 0 || len(r.Name) > 256 || strings.ContainsAny(r.Path+r.Name, "\x00\r\n") || strings.HasPrefix(r.Path, `\`) || strings.Contains(r.Path, ":") {
				return rs, errors.New("invalid HKLM registry target")
			}
			if r.Match != "equals" && r.Match != "numeric_gte" && r.Match != "numeric_lte" && r.Match != "nonempty" {
				return rs, errors.New("unsupported registry comparison")
			}
			if r.Match == "numeric_gte" || r.Match == "numeric_lte" {
				if _, err := strconv.ParseUint(r.Expected, 10, 64); err != nil {
					return rs, errors.New("invalid numeric expectation")
				}
			}
		case "password_flag":
			name, _, desired, known := passwordFlagPolicy(r.ID)
			if !known || r.Name != name || r.Path != "" || r.Match != "equals" || r.Expected != strconv.FormatUint(uint64(desired), 10) {
				return rs, errors.New("invalid compiled password policy flag")
			}
		case "password_policy":
			if !policyNames[r.Name] || (r.Match != "numeric_gte" && r.Match != "numeric_lte") {
				return rs, errors.New("unsupported password policy field or comparison")
			}
			if _, err := strconv.ParseUint(r.Expected, 10, 32); err != nil {
				return rs, errors.New("invalid password policy expectation")
			}
		case "user_right":
			if !rightNames[r.Name] || (r.Match != "set_equals" && r.Match != "set_contains") {
				return rs, errors.New("unsupported user right or comparison")
			}
			for _, sid := range strings.Split(r.Expected, ",") {
				if sid != "" && !regexp.MustCompile(`^S-[0-9]+(?:-[0-9]+)+$`).MatchString(sid) {
					return rs, errors.New("invalid user right SID")
				}
			}
		case "audit_policy":
			if auditNames[r.Name] == 0 || r.Match != "equals" || (r.Expected != "1" && r.Expected != "2" && r.Expected != "3") {
				return rs, errors.New("invalid audit policy check")
			}
		case "service":
			if !serviceNames[r.Name] || r.Match != "equals" || r.Expected != "Disabled" {
				return rs, errors.New("invalid service check")
			}
		case "guest_account":
			if r.ID != "WIN-PWD-010" || r.Name != "Guest" || r.Match != "equals" || r.Expected != "False" {
				return rs, errors.New("invalid guest account check")
			}
		case "installer_policy":
			if r.ID != "WIN-DEF-007" || r.Match != "equals" || r.Expected != "0" {
				return rs, errors.New("invalid installer policy check")
			}
		case "anonymous_pipes":
			if r.ID != "WIN-SMB-010" || r.Match != "equals" || r.Expected != "none" {
				return rs, errors.New("invalid anonymous pipe check")
			}
		case "wmi":
			if _, ok := wmiChecks[r.Name]; !ok || r.Match != "equals" || len(r.Expected) > 32 {
				return rs, errors.New("WMI check is not allowlisted")
			}
		case "firewall":
			check, ok := firewallChecks[r.Name]
			if !ok {
				return rs, errors.New("firewall profile/property is not allowlisted")
			}
			if check.Property == "LogMaxSizeKilobytes" {
				if r.Match != "numeric_gte" {
					return rs, errors.New("invalid firewall log size comparison")
				}
				if _, err := strconv.ParseUint(r.Expected, 10, 64); err != nil {
					return rs, errors.New("invalid firewall log size expectation")
				}
			} else if r.Match != "equals" || (r.Expected != "True" && r.Expected != "Block") {
				return rs, errors.New("invalid firewall enumeration expectation")
			}
		default:
			return rs, errors.New("unknown check kind")
		}
	}
	return rs, nil
}

func Scan(rs Ruleset) ([]wire.Finding, error) {
	if err := supportedOS(); err != nil {
		return nil, err
	}
	if err := supportedBenchmark(rs.BenchmarkID); err != nil {
		return nil, err
	}
	findings := make([]wire.Finding, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		f := wire.Finding{RuleID: r.ID, Severity: r.Severity, Status: wire.Error}
		if r.Kind == "unsupported" {
			f.Evidence = r.Reason
			findings = append(findings, f)
			continue
		}
		value, err := nativeValue(r)
		if err != nil {
			f.Evidence = "native " + r.Kind + " read failed: " + err.Error()
			findings = append(findings, f)
			continue
		}
		pass := false
		switch r.Match {
		case "equals":
			pass = value == r.Expected
		case "nonempty":
			pass = len(value) > 0
		case "set_equals":
			pass = normalizedSet(value) == normalizedSet(r.Expected)
		case "set_contains":
			for _, item := range strings.Split(value, ",") {
				if item == r.Expected {
					pass = true
					break
				}
			}
		case "numeric_lte", "numeric_gte":
			n, e := strconv.ParseUint(value, 10, 64)
			expected, _ := strconv.ParseUint(r.Expected, 10, 64)
			if e != nil {
				f.Evidence = "native policy value is not an unsigned integer"
				findings = append(findings, f)
				continue
			}
			// A zero inactivity/disconnection timer disables the limit and must not pass.
			pass = (r.Match == "numeric_lte" && n > 0 && n <= expected) || (r.Match == "numeric_gte" && n >= expected)
		}
		f.Status = wire.Fail
		if pass {
			f.Status = wire.Pass
		}
		// Do not include arbitrary registry string content in reports.
		f.Evidence = r.Kind + " " + r.Name + ": comparison " + r.Match + " evaluated"
		findings = append(findings, f)
	}
	return findings, nil
}

func normalizedSet(value string) string {
	if value == "" {
		return ""
	}
	entries := strings.Split(value, ",")
	sort.Strings(entries)
	return strings.Join(entries, ",")
}
