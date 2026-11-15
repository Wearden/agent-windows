package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Wearden/agent-windows/internal/actions"
	"github.com/Wearden/agent-windows/internal/client"
	"github.com/Wearden/agent-windows/internal/identity"
	"github.com/Wearden/agent-windows/internal/scanner"
	"github.com/Wearden/proto/wire"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if runtime.GOOS != "windows" {
		return errors.New("Windows agent requires Windows")
	}
	if len(args) == 0 {
		return errors.New("usage: agent scan|enroll|run|service [options]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "service":
		return serviceCLI(ctx, args[1:])
	case "__service":
		if len(args) != 1 {
			return errors.New("service host accepts no external parameters")
		}
		return hostService()
	case "__watchdog":
		root := f.String("root", "", "internal private task root")
		task := f.String("task", "", "internal task scope")
		nonce := f.String("nonce", "", "internal recovery nonce")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected recovery helper arguments")
		}
		return actions.Watchdog(*root, *task, *nonce)
	case "scan":
		path := f.String("ruleset", "", "native Windows JSON ruleset path")
		id := f.String("agent-id", "local-windows", "report agent ID")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 || *path == "" {
			return errors.New("scan requires --ruleset and no positional arguments")
		}
		data, err := readBounded(*path, 4<<20)
		if err != nil {
			return err
		}
		rs, err := scanner.Decode(data)
		if err != nil {
			return err
		}
		report, err := scan(rs, *id, "")
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case "enroll":
		server := f.String("server", "", "HTTPS core origin")
		path := f.String("identity", "identity.dpapi", "new DPAPI-protected identity file")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected enrollment arguments")
		}
		if _, err := os.Stat(*path); err == nil || !os.IsNotExist(err) {
			return errors.New("identity path already exists or cannot be inspected")
		}
		c, err := client.New(*server)
		if err != nil {
			return err
		}
		request, err := identity.PrepareEnrollment(*path+".pending.dpapi", *server)
		if err != nil {
			return err
		}
		enrolled, err := c.Enroll(ctx, os.Getenv("WEARDEN_ENROLLMENT_TOKEN"), request)
		if err != nil {
			return err
		}
		if err = identity.SaveNew(*path, identity.Identity{Server: *server, AgentID: enrolled.AgentID, Token: enrolled.AgentToken}); err != nil {
			return fmt.Errorf("enrollment accepted but identity persistence failed; preserve pending request and retry within 24 hours, or revoke if recovery is impossible: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Enrollment saved with current-user DPAPI protection.")
		return nil
	case "run":
		path := f.String("identity", "identity.dpapi", "DPAPI identity file")
		spool := f.String("spool", "spool", "directory for durable pending report")
		once := f.Bool("once", false, "submit one scan, then exit")
		allowRemediation := f.Bool("allow-remediation", false, "explicit local opt-in to known native mutation tasks")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected run arguments")
		}
		return daemonRun(ctx, *path, *spool, *once, *allowRemediation, func(err error) { fmt.Fprintln(os.Stderr, "agent cycle failed:", err) })
	default:
		return errors.New("unknown command; use scan, enroll, run, or service")
	}
}

func daemonRun(ctx context.Context, identityPath, spoolDir string, once, allowRemediation bool, logFailure func(error)) error {
	id, err := identity.Load(identityPath)
	if err != nil {
		return err
	}
	c, err := client.New(id.Server)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(spoolDir, 0700); err != nil {
		return errors.New("cannot create spool directory")
	}
	unlock, err := identity.Lock(filepath.Join(spoolDir, "agent.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if err = actions.Recover(filepath.Join(spoolDir, "tasks"), id.AgentID); err != nil {
		return fmt.Errorf("task recovery must complete before networking: %w", err)
	}
	pending := filepath.Join(spoolDir, "pending-report.json")
	var next time.Time
	for {
		interval, err := cycle(ctx, c, id, pending, next, once, allowRemediation)
		if err != nil {
			if once {
				return err
			}
			logFailure(err)
		} else if interval > 0 {
			next = time.Now().Add(time.Duration(interval) * time.Second)
		}
		if once {
			return nil
		}
		timer := time.NewTimer(60 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func scan(rs scanner.Ruleset, agentID, scanID string) (wire.Report, error) {
	r := wire.Report{Version: wire.Version, AgentID: agentID, BenchmarkID: rs.BenchmarkID, RulesetVersion: rs.RulesetVersion, ScanID: scanID, StartedAt: time.Now().UTC()}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return r, err
	}
	r.ReportID = hex.EncodeToString(random[:])
	findings, err := scanner.Scan(rs)
	if err != nil {
		return r, err
	}
	r.Findings = findings
	r.FinishedAt = time.Now().UTC()
	return r, r.Validate()
}

func cycle(ctx context.Context, c *client.Client, id identity.Identity, pending string, next time.Time, once, allowRemediation bool) (int, error) {
	if err := c.Heartbeat(ctx, id.Token, id.AgentID); err != nil {
		return 0, err
	}
	if handled, err := actions.Resume(ctx, c, id, filepath.Join(filepath.Dir(pending), "tasks")); err != nil {
		return 0, err
	} else if handled && !once {
		return 0, nil
	}
	data, err := readBounded(pending, 8<<20)
	if err == nil {
		var report wire.Report
		if json.Unmarshal(data, &report) != nil || report.AgentID != id.AgentID {
			return 0, errors.New("invalid pending report; preserve for operator review")
		}
		if err = c.Report(ctx, id.Token, report); err != nil {
			return 0, err
		}
		if err = os.Remove(pending); err != nil {
			return 0, errors.New("accepted report could not be removed from spool")
		}
		return 60, nil
	}
	if !os.IsNotExist(err) {
		return 0, err
	}
	cfg, rs, err := c.Assignment(ctx, id.Token)
	if err != nil {
		return 0, err
	}
	if !once && allowRemediation {
		handled, err := actions.Poll(ctx, c, id, filepath.Join(filepath.Dir(pending), "tasks"), cfg.BenchmarkID)
		if err != nil {
			return 0, err
		}
		if handled {
			return 0, nil
		}
	}
	if !once && cfg.ScanID == "" && time.Now().Before(next) {
		return 0, nil
	}
	report, err := scan(rs, id.AgentID, cfg.ScanID)
	if err != nil {
		return 0, err
	}
	data, err = json.Marshal(report)
	if err != nil {
		return 0, err
	}
	if len(data) > 8<<20 {
		return 0, errors.New("report exceeds 8 MiB")
	}
	// A crash before rename leaves only a recoverable temporary file, never a partial pending report.
	f, err := os.CreateTemp(filepath.Dir(pending), "report-*.tmp")
	if err != nil {
		return 0, err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return 0, err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return 0, errors.New("could not persist report; temporary file retained")
	}
	if err = os.Rename(f.Name(), pending); err != nil {
		return 0, errors.New("could not commit pending report; temporary file retained")
	}
	if err = c.Report(ctx, id.Token, report); err != nil {
		return 0, err
	}
	if err = os.Remove(pending); err != nil {
		return 0, errors.New("accepted report could not be removed from spool")
	}
	return cfg.IntervalSeconds, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("input must be a regular file within size limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("input exceeds size limit")
	}
	return data, nil
}
