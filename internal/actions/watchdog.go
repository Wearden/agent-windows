package actions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Wearden/agent-windows/internal/scanner"
)

type watchdogLease struct {
	TaskID           string    `json:"task_id"`
	AgentID          string    `json:"agent_id"`
	Nonce            string    `json:"nonce"`
	Fingerprint      string    `json:"fingerprint"`
	ExecutableSHA256 string    `json:"executable_sha256"`
	Deadline         time.Time `json:"deadline"`
	StartTick        uint64    `json:"start_tick"`
	DeadlineTick     uint64    `json:"deadline_tick"`
}
type watchdogReady struct {
	TaskID, Nonce, Fingerprint string
	PID                        int
}

func leasePath(root, id string) string { return filepath.Join(root, "watchdogs", id+".lease.dpapi") }
func readyPath(root, id string) string { return filepath.Join(root, "watchdogs", id+".ready.dpapi") }
func taskFingerprint(j journal) string {
	data, _ := json.Marshal(j.Task)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func executableHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot read installed recovery executable")
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", errors.New("cannot fingerprint installed recovery executable")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readScoped(root, id string) (journal, error) {
	var j journal
	err := load(activePath(root), &j)
	if err == nil && j.Task.ID == id {
		return j, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return j, err
	}
	err = load(completedPath(root, id), &j)
	if err != nil {
		return j, err
	}
	if j.Task.ID != id {
		return j, errors.New("watchdog journal scope mismatch")
	}
	return j, nil
}

func validLease(root string, j journal) (watchdogLease, error) {
	var lease watchdogLease
	if err := load(leasePath(root, j.Task.ID), &lease); err != nil {
		return lease, err
	}
	if lease.TaskID != j.Task.ID || lease.AgentID != j.AgentID || lease.Fingerprint != taskFingerprint(j) || lease.Nonce == "" || lease.Deadline.IsZero() || !lease.Deadline.Equal(j.Deadline) || lease.Deadline.After(j.Task.ExpiresAt) || lease.StartTick != j.StartTick || lease.DeadlineTick != j.DeadlineTick || lease.DeadlineTick <= lease.StartTick || lease.DeadlineTick-lease.StartTick > 600000 {
		return lease, errors.New("independent recovery lease does not match authorized task")
	}
	return lease, nil
}

// armWatchdog persists a lease and verifies a detached same-executable helper's
// readiness before the parent may acquire the mutation lock and write a value.
func armWatchdog(ctx context.Context, root string, j *journal, deadline time.Time) error {
	executable, err := os.Executable()
	if err != nil {
		return errors.New("cannot locate installed recovery executable")
	}
	if err = trustedExecutable(executable); err != nil {
		return err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if err = trustedState(abs); err != nil {
		return err
	}
	hash, err := executableHash(executable)
	if err != nil {
		return err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > 10*time.Minute {
		return errors.New("invalid recovery safety budget")
	}
	start := uptimeMillis()
	end := start + uint64(remaining/time.Millisecond)
	lease := watchdogLease{TaskID: j.Task.ID, AgentID: j.AgentID, Nonce: hex.EncodeToString(nonce[:]), Fingerprint: taskFingerprint(*j), ExecutableSHA256: hash, Deadline: deadline, StartTick: start, DeadlineTick: end}
	unlock, err := lockTask(ctx, root, j.Task.ID)
	if err != nil {
		return err
	}
	j.Deadline = deadline
	j.StartTick = start
	j.DeadlineTick = end
	err = store(activePath(root), j, false)
	if err == nil {
		err = store(leasePath(root, j.Task.ID), lease, true)
	}
	unlock()
	if err != nil {
		return err
	}
	pid, err := startHelper(executable, abs, j.Task.ID, lease.Nonce)
	if err != nil {
		return err
	}
	readyDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(readyDeadline) && !recoveryExpired(*j) {
		var ready watchdogReady
		if load(readyPath(root, j.Task.ID), &ready) == nil && ready.TaskID == j.Task.ID && ready.Nonce == lease.Nonce && ready.Fingerprint == lease.Fingerprint && ready.PID == pid {
			if err = helperAlive(pid); err != nil {
				return err
			}
			j.HelperPID = pid
			return nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("independent recovery helper did not become ready; no mutations authorized")
}

func compensateExpired(root string, j *journal) error {
	if j.Acknowledged || j.Task.Action != "apply" || (j.Result != nil && j.Result.Revision == 1) {
		return nil
	}
	if j.Result != nil && len(j.PreviousResults) == 0 {
		j.PreviousResults = append(j.PreviousResults, *j.Result)
	}
	return failAndRestore(root, j, "Unacknowledged apply recovery required; original local state restored where possible", 1)
}

// Watchdog does not read credentials or contact core. Its only possible writes are
// restoration of the prepared approved native policy snapshots and scoped local state.
func Watchdog(root, id, nonce string) error {
	if !safeIdentifier(id) || !filepath.IsAbs(root) || len(nonce) != 64 {
		return errors.New("invalid independent recovery scope")
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return errors.New("invalid recovery nonce")
	}
	if err := trustedState(root); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err = trustedExecutable(executable); err != nil {
		return err
	}
	hash, err := executableHash(executable)
	if err != nil {
		return err
	}
	unlock, err := lockTask(context.Background(), root, id)
	if err != nil {
		return err
	}
	j, err := readScoped(root, id)
	if err != nil {
		unlock()
		return err
	}
	lease, err := validLease(root, j)
	if err != nil || nonce != lease.Nonce || hash != lease.ExecutableSHA256 || j.Task.Action != "apply" || !j.Task.Confirmed || j.Task.Version != "1" || validateJournal(j, lease.AgentID) != nil {
		unlock()
		return errors.New("independent helper has no matching authorized apply lease")
	}
	if len(j.Undo) != len(j.Task.RuleIDs) || len(j.Targets) != len(j.Task.RuleIDs) {
		unlock()
		return errors.New("independent helper backup set is incomplete")
	}
	for _, id := range j.Task.RuleIDs {
		plan, e := scanner.Plan(id)
		if e != nil || !scanner.ValidApplyTarget(plan, j.Targets[id], j.Undo[id]) {
			unlock()
			return errors.New("independent helper contains an unapproved restoration target")
		}
	}
	j.HelperPID = os.Getpid()
	if err = store(activePath(root), j, false); err == nil {
		err = store(readyPath(root, id), watchdogReady{TaskID: id, Nonce: nonce, Fingerprint: lease.Fingerprint, PID: os.Getpid()}, true)
	}
	unlock()
	if err != nil {
		return err
	}
	for {
		unlock, err = lockTask(context.Background(), root, id)
		if err != nil {
			return err
		}
		j, err = readScoped(root, id)
		if err != nil {
			unlock()
			return err
		}
		if validateJournal(j, lease.AgentID) != nil {
			unlock()
			return errors.New("independent helper journal changed identity")
		}
		if j.Acknowledged || (j.Result != nil && j.Result.Revision == 1) {
			unlock()
			return nil
		}
		if recoveryExpired(j) {
			err = compensateExpired(root, &j)
			unlock()
			return err
		}
		unlock()
		time.Sleep(250 * time.Millisecond)
	}
}

func recoveryExpired(j journal) bool {
	now := uptimeMillis()
	return j.DeadlineTick == 0 || now < j.StartTick || now >= j.DeadlineTick
}
func recoveryRemaining(j journal) time.Duration {
	now := uptimeMillis()
	if now < j.StartTick || now >= j.DeadlineTick {
		return 0
	}
	return time.Duration(j.DeadlineTick-now) * time.Millisecond
}
