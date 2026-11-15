//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Wearden/agent-windows/internal/actions"
	"github.com/Wearden/agent-windows/internal/client"
	"github.com/Wearden/agent-windows/internal/identity"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "WeardenAgent"

type serviceConfig struct {
	Version             string `json:"version"`
	Server              string `json:"server"`
	EnrollmentTokenFile string `json:"enrollment_token_file"`
	AllowRemediation    bool   `json:"allow_remediation"`
}
type servicePaths struct{ Root, Binary, Config, Bootstrap, Identity, Spool, Log string }

func localServicePaths() (servicePaths, error) {
	data, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return servicePaths{}, errors.New("cannot resolve protected ProgramData service location")
	}
	programs, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return servicePaths{}, errors.New("cannot resolve protected Program Files service location")
	}
	root := filepath.Join(data, "WeardenAgent")
	return servicePaths{Root: root, Binary: filepath.Join(programs, "WeardenAgent", "agent.exe"), Config: filepath.Join(root, "service.json"), Bootstrap: filepath.Join(root, "enrollment-token.txt"), Identity: filepath.Join(root, "identity.dpapi"), Spool: filepath.Join(root, "spool"), Log: filepath.Join(root, "agent.log")}, nil
}

func newPrivateDirectory(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return actions.TrustedServicePath(path)
	} else if !os.IsNotExist(err) {
		return errors.New("cannot inspect fixed service directory")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return errors.New("cannot create fixed service directory; run elevated")
	}
	return actions.ProtectServicePath(path)
}

func newPrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot exclusively create private service file")
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("cannot persist private service file; preserve it for operator review")
	}
	return actions.ProtectServicePath(path)
}

func binaryDigest(path string) ([32]byte, error) {
	var out [32]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return out, err
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

func installServiceBinary(path string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err = newPrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err = os.Lstat(path); err == nil {
		if err = actions.TrustedServicePath(path); err != nil {
			return err
		}
		left, e := binaryDigest(executable)
		if e != nil {
			return errors.New("cannot fingerprint reviewed source executable")
		}
		right, e := binaryDigest(path)
		if e != nil || left != right {
			return errors.New("installed binary differs; service upgrade requires separate operator review")
		}
		return actions.TrustedServiceExecutable(path)
	} else if !os.IsNotExist(err) {
		return errors.New("cannot inspect installed service executable")
	}
	source, err := os.Open(executable)
	if err != nil {
		return errors.New("cannot open reviewed agent executable")
	}
	defer source.Close()
	target, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return errors.New("cannot create protected installed agent executable")
	}
	_, copyErr := io.Copy(target, source)
	syncErr := target.Sync()
	closeErr := target.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("cannot persist installed executable; preserve partial artifact for operator review")
	}
	if err = actions.ProtectServicePath(path); err != nil {
		return err
	}
	return actions.TrustedServiceExecutable(path)
}

func readServiceConfig(paths servicePaths) (serviceConfig, error) {
	var cfg serviceConfig
	if err := actions.TrustedServicePath(paths.Root); err != nil {
		return cfg, err
	}
	if err := actions.TrustedServicePath(paths.Config); err != nil {
		return cfg, err
	}
	data, err := readBounded(paths.Config, 16384)
	if err != nil {
		return cfg, errors.New("cannot read fixed private service configuration")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || cfg.Version != "1" || cfg.EnrollmentTokenFile != paths.Bootstrap {
		return cfg, errors.New("invalid fixed service configuration or bootstrap scope")
	}
	if _, err = client.New(cfg.Server); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func serviceCLI(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agent service install|start|stop|uninstall [options]")
	}
	f := flag.NewFlagSet("service "+args[0], flag.ContinueOnError)
	confirmed := f.Bool("confirm", false, "explicitly authorize local SCM installation or removal")
	server := f.String("server", "", "HTTPS core origin for installation")
	allowRemediation := f.Bool("allow-remediation", false, "persist an explicit local opt-in to known native mutation tasks")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected service command arguments")
	}
	if args[0] != "install" && args[0] != "start" && args[0] != "stop" && args[0] != "uninstall" {
		return errors.New("unknown service action")
	}
	if args[0] != "install" && (*allowRemediation || *server != "") {
		return errors.New("server and remediation opt-in flags are installation-only settings")
	}
	if (args[0] == "install" || args[0] == "uninstall") && !*confirmed {
		return errors.New("install/uninstall require --confirm because they change local SCM state")
	}
	paths, err := localServicePaths()
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return errors.New("cannot connect to local SCM with administrator rights")
	}
	defer manager.Disconnect()
	if args[0] == "install" {
		if _, err = client.New(*server); err != nil {
			return err
		}
		if existing, e := manager.OpenService(serviceName); e == nil {
			existing.Close()
			return errors.New("WeardenAgent service already exists; existing SCM record was not changed")
		} else if !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return errors.New("cannot inspect existing WeardenAgent SCM record")
		}
		if err = installServiceBinary(paths.Binary); err != nil {
			return err
		}
		if err = newPrivateDirectory(paths.Root); err != nil {
			return err
		}
		cfg := serviceConfig{Version: "1", Server: *server, EnrollmentTokenFile: paths.Bootstrap, AllowRemediation: *allowRemediation}
		if _, err = os.Lstat(paths.Config); os.IsNotExist(err) {
			data, e := json.MarshalIndent(cfg, "", "  ")
			if e != nil {
				return e
			}
			if err = newPrivateFile(paths.Config, append(data, '\n')); err != nil {
				return err
			}
		} else if err != nil {
			return errors.New("cannot inspect service configuration")
		} else {
			old, e := readServiceConfig(paths)
			if e != nil || old != cfg {
				return errors.New("private service configuration already exists with different or invalid settings")
			}
		}
		if _, err = os.Lstat(paths.Bootstrap); os.IsNotExist(err) {
			if err = newPrivateFile(paths.Bootstrap, []byte{}); err != nil {
				return err
			}
		} else if err != nil {
			return errors.New("cannot inspect bootstrap file")
		} else if err = actions.TrustedServicePath(paths.Bootstrap); err != nil {
			return err
		}
		service, err := manager.CreateService(serviceName, paths.Binary, mgr.Config{DisplayName: "Wearden Agent", Description: "Wearden native compliance agent with independent recovery", ServiceStartName: "LocalSystem", StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal}, "__service")
		if err != nil {
			return errors.New("cannot create LocalSystem SCM service; private installation files were retained")
		}
		defer service.Close()
		if err = service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 30 * time.Second}}, 86400); err != nil {
			return errors.New("SCM service created but crash-restart configuration failed; service remains stopped for operator review")
		}
		fmt.Fprintln(os.Stdout, "LocalSystem service installed and left stopped. Provision its private enrollment token file before starting:", paths.Bootstrap)
		return nil
	}
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return errors.New("cannot open fixed WeardenAgent SCM service")
	}
	defer service.Close()
	cfg, err := service.Config()
	if err != nil {
		return errors.New("cannot verify existing SCM service configuration")
	}
	if !strings.EqualFold(cfg.ServiceStartName, "LocalSystem") || cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || cfg.BinaryPathName != syscall.EscapeArg(paths.Binary)+" __service" {
		return errors.New("SCM service does not match fixed LocalSystem executable configuration")
	}
	if err = actions.TrustedServiceExecutable(paths.Binary); err != nil {
		return err
	}
	status, err := service.Query()
	if err != nil {
		return errors.New("cannot query WeardenAgent status")
	}
	switch args[0] {
	case "start":
		if status.State == svc.Running {
			return nil
		}
		if status.State != svc.Stopped {
			return errors.New("service is transitioning; retry after its current transition")
		}
		if err = service.Start(); err != nil {
			return errors.New("cannot start WeardenAgent service")
		}
		return waitService(ctx, service, svc.Running)
	case "stop":
		if status.State == svc.Stopped {
			return nil
		}
		if _, err = service.Control(svc.Stop); err != nil {
			return errors.New("cannot request service stop")
		}
		return waitService(ctx, service, svc.Stopped)
	case "uninstall":
		if status.State != svc.Stopped {
			return errors.New("stop the service before uninstall; no process was terminated")
		}
		if err = service.Delete(); err != nil {
			return errors.New("cannot remove WeardenAgent SCM record")
		}
		fmt.Fprintln(os.Stdout, "SCM service removed. Installed binary, private identity, bootstrap, logs and backups were retained.")
		return nil
	}
	return nil
}

func waitService(ctx context.Context, service *mgr.Service, wanted svc.State) error {
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := service.Query()
		if err != nil {
			return errors.New("cannot query SCM transition")
		}
		if status.State == wanted {
			return nil
		}
		if wanted == svc.Running && status.State == svc.Stopped {
			return errors.New("service stopped during startup; inspect protected agent.log and SCM exit status")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("SCM transition remains pending; no forced termination performed")
		case <-ticker.C:
		}
	}
}

type serviceHandler struct{}

func hostService() error { return svc.Run(serviceName, serviceHandler{}) }

func (serviceHandler) Execute(args []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending, WaitHint: 30000, CheckPoint: 1}
	if len(args) != 1 {
		return true, 1
	}
	paths, err := localServicePaths()
	if err != nil {
		return true, 1
	}
	if actions.TrustedSystemState(paths.Root) != nil || actions.TrustedServicePath(paths.Root) != nil || actions.TrustedServiceExecutable(paths.Binary) != nil {
		return true, 1
	}
	executable, err := os.Executable()
	if err != nil || !strings.EqualFold(executable, paths.Binary) {
		return true, 1
	}
	cfg, err := readServiceConfig(paths)
	if err != nil {
		return true, 1
	}
	if _, err = os.Lstat(paths.Log); os.IsNotExist(err) {
		if err = newPrivateFile(paths.Log, []byte{}); err != nil {
			return true, 1
		}
	} else if err != nil || actions.TrustedServicePath(paths.Log) != nil {
		return true, 1
	}
	logFile, err := os.OpenFile(paths.Log, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return true, 1
	}
	defer logFile.Close()
	logger := log.New(logFile, "agent: ", log.LstdFlags|log.LUTC)
	var bootstrap string
	if _, err = os.Lstat(paths.Identity); os.IsNotExist(err) {
		if actions.TrustedServicePath(paths.Bootstrap) != nil {
			logger.Print("SYSTEM-private bootstrap token file is missing or unsafe")
			return true, 1
		}
		data, e := readBounded(paths.Bootstrap, 4096)
		if e != nil {
			logger.Print("Cannot read configured private bootstrap token file")
			return true, 1
		}
		bootstrap = strings.TrimSpace(string(data))
		if len(bootstrap) == 0 || len(bootstrap) > 512 || strings.ContainsAny(bootstrap, "\r\n") {
			logger.Print("Private bootstrap token file is empty or invalid")
			return true, 1
		}
	} else if err != nil || actions.TrustedServicePath(paths.Identity) != nil {
		logger.Print("SYSTEM DPAPI identity file is missing or unsafe")
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serviceWork(ctx, paths, cfg, bootstrap, func(err error) { logger.Print(err) }) }()
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- current
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	stopping := false
	for {
		select {
		case err := <-done:
			if err != nil {
				logger.Print(err)
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				if !stopping {
					stopping = true
					cancel()
					current = svc.Status{State: svc.StopPending, WaitHint: 10000, CheckPoint: 1}
					statuses <- current
				}
			case svc.Interrogate:
				statuses <- current
			}
		case <-ticker.C:
			if stopping {
				current.CheckPoint++
				statuses <- current
			}
		}
	}
}

func serviceWork(ctx context.Context, paths servicePaths, cfg serviceConfig, bootstrap string, logFailure func(error)) error {
	if _, err := os.Stat(paths.Identity); os.IsNotExist(err) {
		request, err := identity.PrepareEnrollment(paths.Identity+".pending.dpapi", cfg.Server)
		if err != nil {
			return err
		}
		if err = actions.TrustedServicePath(paths.Identity + ".pending.dpapi"); err != nil {
			return err
		}
		api, err := client.New(cfg.Server)
		if err != nil {
			return err
		}
		for {
			if ctx.Err() != nil {
				return nil
			}
			enrolled, e := api.Enroll(ctx, bootstrap, request)
			if e == nil {
				if err = identity.SaveNew(paths.Identity, identity.Identity{Server: cfg.Server, AgentID: enrolled.AgentID, Token: enrolled.AgentToken}); err != nil {
					return err
				}
				break
			}
			if ctx.Err() != nil {
				return nil
			}
			logFailure(e)
			timer := time.NewTimer(30 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	} else if err != nil {
		return errors.New("cannot inspect SYSTEM identity")
	}
	id, err := identity.Load(paths.Identity)
	if err != nil {
		return err
	}
	if id.Server != cfg.Server {
		return errors.New("SYSTEM identity core origin differs from private service configuration")
	}
	return daemonRun(ctx, paths.Identity, paths.Spool, false, cfg.AllowRemediation, logFailure)
}
