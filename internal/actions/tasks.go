package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Wearden/agent-windows/internal/client"
	"github.com/Wearden/agent-windows/internal/identity"
	"github.com/Wearden/agent-windows/internal/scanner"
	"github.com/Wearden/proto/wire"
)

var taskIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type backup struct {
	AgentID  string                   `json:"agent_id"`
	RunID    string                   `json:"run_id"`
	TaskID   string                   `json:"task_id"`
	Snapshot scanner.RegistrySnapshot `json:"snapshot"`
}
type journal struct {
	AgentID         string                              `json:"agent_id"`
	Task            wire.Task                           `json:"task"`
	Phase           string                              `json:"phase"`
	Undo            map[string]scanner.RegistrySnapshot `json:"undo"`
	Targets         map[string]scanner.RegistrySnapshot `json:"targets"`
	Armed           []string                            `json:"armed"`
	Blocked         bool                                `json:"blocked"`
	Result          *wire.TaskResult                    `json:"result,omitempty"`
	Deadline        time.Time                           `json:"deadline,omitempty"`
	StartTick       uint64                              `json:"start_tick,omitempty"`
	DeadlineTick    uint64                              `json:"deadline_tick,omitempty"`
	HelperPID       int                                 `json:"helper_pid,omitempty"`
	Acknowledged    bool                                `json:"acknowledged"`
	ReceiptAt       time.Time                           `json:"receipt_at,omitempty"`
	PreviousResults []wire.TaskResult                   `json:"previous_results,omitempty"`
}

func activePath(root string) string        { return filepath.Join(root, "active-task.dpapi") }
func completedPath(root, id string) string { return filepath.Join(root, "completed", id+".dpapi") }
func backupPath(root, runID, ruleID string) string {
	return filepath.Join(root, "backups", runID, ruleID+".dpapi")
}

func validIdentity(task wire.Task) error {
	if !safeIdentifier(task.ID) || !safeIdentifier(task.RunID) {
		return errors.New("invalid task or backup group ID")
	}
	if task.Action != "apply" && task.Action != "rollback" {
		return errors.New("unsupported task action")
	}
	if len(task.RuleIDs) == 0 || len(task.RuleIDs) > 100 {
		return errors.New("task must contain 1..100 known rules")
	}
	seen := map[string]bool{}
	for _, id := range task.RuleIDs {
		if !scanner.KnownRule(id) || seen[id] {
			return errors.New("task contains unknown or duplicate rule IDs")
		}
		seen[id] = true
	}
	return nil
}

func safeIdentifier(value string) bool {
	if !taskIdentifier.MatchString(value) || strings.HasSuffix(value, ".") {
		return false
	}
	base := strings.ToUpper(strings.SplitN(value, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" {
		return false
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return false
	}
	return true
}

func authorization(task wire.Task) error {
	if task.Version != wire.Version || !task.Confirmed {
		return errors.New("task version or explicit confirmation is invalid")
	}
	now := time.Now()
	if task.ExpiresAt.IsZero() || !task.ExpiresAt.After(now) || task.ExpiresAt.After(now.Add(24*time.Hour)) {
		return errors.New("task has expired or exceeds the 24-hour authorization horizon")
	}
	if task.SafetyWindowSeconds < 30 || task.SafetyWindowSeconds > 600 {
		return errors.New("task safety window must be 30..600 seconds")
	}
	return nil
}

func taskEqual(a, b wire.Task) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

func validateJournal(j journal, agentID string) error {
	if j.AgentID != agentID || validIdentity(j.Task) != nil {
		return errors.New("local task journal identity is invalid")
	}
	known := map[string]bool{}
	for _, id := range j.Task.RuleIDs {
		known[id] = true
	}
	seen := map[string]bool{}
	for _, id := range j.Armed {
		plan, err := scanner.Plan(id)
		if err != nil || !known[id] || seen[id] || !scanner.ValidSnapshot(plan, j.Undo[id]) || !scanner.ValidSnapshot(plan, j.Targets[id]) {
			return errors.New("local mutation journal is inconsistent")
		}
		if j.Task.Action == "apply" && !scanner.ValidApplyTarget(plan, j.Targets[id], j.Undo[id]) {
			return errors.New("local mutation journal has an unapproved apply target")
		}
		seen[id] = true
	}
	if j.Result != nil {
		if j.Result.Revision < 0 || j.Result.Revision > 1 || (j.Result.Revision == 1 && (j.Task.Action != "apply" || j.Result.Status != "failed")) {
			return errors.New("invalid local task result revision")
		}
		if j.Result.Version != wire.Version || j.Result.AgentID != agentID || j.Result.TaskID != j.Task.ID || len(j.Result.Changes) != len(j.Task.RuleIDs) || (j.Result.Status != "completed" && j.Result.Status != "failed") {
			return errors.New("local task result is inconsistent")
		}
		seen = map[string]bool{}
		for _, change := range j.Result.Changes {
			if !known[change.RuleID] || seen[change.RuleID] {
				return errors.New("local task result coverage is inconsistent")
			}
			seen[change.RuleID] = true
		}
	}
	return nil
}

// Recover restores interrupted mutations before the daemon performs networking.
// A final durable result is never re-executed, even if its receipt was lost.
func Recover(root, agentID string) error {
	resolved, resolveErr := filepath.Abs(root)
	if resolveErr != nil {
		return resolveErr
	}
	root = resolved
	if err := prepareRoot(root); err != nil {
		return err
	}
	var j journal
	if err := load(activePath(root), &j); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := validateJournal(j, agentID); err != nil {
		return err
	}
	if len(j.Armed) > 0 {
		if err := trustedState(root); err != nil {
			return err
		}
	}
	unlock, err := lockTask(context.Background(), root, j.Task.ID)
	if err != nil {
		return err
	}
	defer unlock()
	j, err = readScoped(root, j.Task.ID)
	if err != nil {
		return err
	}
	if err = validateJournal(j, agentID); err != nil {
		return err
	}
	if j.Task.Action == "apply" && !j.Acknowledged && (len(j.Armed) > 0 || !j.Deadline.IsZero()) {
		return compensateExpired(root, &j)
	}
	return recoverLocked(root, &j)
}

// Resume retries an already durable result without fetching an assignment or new task.
// Recover must initialize the private state directory before entering the daemon loop.
func Resume(ctx context.Context, c *client.Client, id identity.Identity, root string) (bool, error) {
	var j journal
	err := load(activePath(root), &j)
	if err == nil {
		if err = validateJournal(j, id.AgentID); err != nil {
			return false, err
		}
		return true, acknowledge(ctx, c, id, root, &j)
	}
	if !os.IsNotExist(err) {
		return false, err
	}
	return false, nil
}

func Poll(ctx context.Context, c *client.Client, id identity.Identity, root, benchmark string) (bool, error) {
	if handled, err := Resume(ctx, c, id, root); handled || err != nil {
		return handled, err
	}
	task, err := c.Task(ctx, id.Token)
	if err != nil || task == nil {
		return false, err
	}
	if err = validIdentity(*task); err != nil {
		return false, err
	}
	var previous journal
	if err = load(completedPath(root, task.ID), &previous); err == nil {
		if validateJournal(previous, id.AgentID) != nil || !taskEqual(previous.Task, *task) || previous.Result == nil {
			return false, errors.New("server reused a completed task ID with different contents")
		}
		unlock, e := lockTask(ctx, root, task.ID)
		if e != nil {
			return false, e
		}
		defer unlock()
		if e = load(completedPath(root, task.ID), &previous); e != nil {
			return false, e
		}
		if validateJournal(previous, id.AgentID) != nil || !taskEqual(previous.Task, *task) || previous.Result == nil {
			return false, errors.New("completed task changed before retransmission")
		}
		return true, c.TaskResult(ctx, id.Token, *previous.Result)
	} else if !os.IsNotExist(err) {
		return false, err
	}
	j := journal{AgentID: id.AgentID, Task: *task, Phase: "received", Undo: map[string]scanner.RegistrySnapshot{}, Targets: map[string]scanner.RegistrySnapshot{}}
	if err = store(activePath(root), j, true); err != nil {
		return false, err
	}
	if err = authorization(j.Task); err != nil {
		if err = failAndRestore(root, &j, err.Error()); err != nil {
			return true, err
		}
		return true, acknowledge(ctx, c, id, root, &j)
	}
	if err = scanner.RemediationHost(benchmark); err != nil {
		if err = failAndRestore(root, &j, "Assigned benchmark does not match this native Windows host"); err != nil {
			return true, err
		}
		return true, acknowledge(ctx, c, id, root, &j)
	}
	if err = execute(ctx, root, &j); err != nil {
		return true, err
	}
	return true, acknowledge(ctx, c, id, root, &j)
}

func execute(ctx context.Context, root string, j *journal) error {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if err = trustedState(absolute); err != nil {
		return failAndRestore(root, j, "Native mutation requires LocalSystem-owned private task state; no mutations authorized")
	}
	deadline := time.Now().Add(time.Duration(j.Task.SafetyWindowSeconds) * time.Second)
	if j.Task.ExpiresAt.Before(deadline) {
		deadline = j.Task.ExpiresAt
	}
	execution, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// Reject the complete batch before writes when any requested provider is not writable.
	for _, id := range j.Task.RuleIDs {
		if _, err := scanner.Plan(id); err != nil {
			return failAndRestore(root, j, "Task includes a read-only or risky rule; no batch mutations performed")
		}
	}
	runPath := filepath.Join(root, "backups", j.Task.RunID)
	if err := os.MkdirAll(runPath, 0700); err != nil {
		return failAndRestore(root, j, "Cannot create local backup group")
	}
	if info, err := os.Lstat(runPath); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return failAndRestore(root, j, "Backup group directory must not be a link")
	}
	if err := privateDirectory(runPath); err != nil {
		return failAndRestore(root, j, "Cannot protect local backup group")
	}
	for _, id := range j.Task.RuleIDs {
		if err := execution.Err(); err != nil {
			return failAndRestore(root, j, "Task authorization or safety window expired before mutation")
		}
		plan, _ := scanner.Plan(id)
		before, err := scanner.Snapshot(plan)
		if err != nil {
			return failAndRestore(root, j, "Native policy backup failed; unavailable scope, missing key, unexpected type, or access error")
		}
		j.Undo[id] = before
		if j.Task.Action == "apply" {
			record := backup{AgentID: j.AgentID, RunID: j.Task.RunID, TaskID: j.Task.ID, Snapshot: before}
			if err = store(backupPath(root, j.Task.RunID, id), record, true); err != nil {
				return failAndRestore(root, j, "Backup already exists or cannot be persisted; original backup was not overwritten")
			}
			j.Targets[id] = scanner.DesiredSnapshot(plan)
			if scanner.SnapshotStatus(plan, before) == wire.Pass {
				j.Targets[id] = before
			}
		} else {
			var record backup
			if err = load(backupPath(root, j.Task.RunID, id), &record); err != nil || record.AgentID != j.AgentID || record.RunID != j.Task.RunID || !taskIdentifier.MatchString(record.TaskID) || !scanner.ValidSnapshot(plan, record.Snapshot) {
				return failAndRestore(root, j, "Rollback backup is missing, invalid, or belongs to another agent/group")
			}
			if !scanner.SameSnapshot(before, scanner.DesiredSnapshot(plan)) && !scanner.SameSnapshot(before, record.Snapshot) {
				return failAndRestore(root, j, "Native policy drift detected; refusing to overwrite unrelated changes")
			}
			j.Targets[id] = record.Snapshot
		}
	}
	j.Phase = "prepared"
	if err := store(activePath(root), j, false); err != nil {
		return err
	}
	if j.Task.Action == "apply" {
		if err := armWatchdog(execution, root, j, deadline); err != nil {
			unlock, e := lockTask(context.Background(), root, j.Task.ID)
			if e != nil {
				return e
			}
			defer unlock()
			fresh, e := readScoped(root, j.Task.ID)
			if e != nil {
				return e
			}
			*j = fresh
			if j.Result != nil && j.Result.Revision == 1 {
				return nil
			}
			j.Deadline = time.Time{}
			j.StartTick = 0
			j.DeadlineTick = 0
			j.HelperPID = 0
			return failAndRestore(root, j, "Independent recovery helper is not ready; no mutation authorized")
		}
	}
	unlock, err := lockTask(context.Background(), root, j.Task.ID)
	if err != nil {
		return err
	}
	defer unlock()
	fresh, err := readScoped(root, j.Task.ID)
	if err != nil {
		return err
	}
	if validateJournal(fresh, j.AgentID) != nil {
		return errors.New("mutation journal changed identity")
	}
	*j = fresh
	if j.Result != nil {
		return nil
	}
	if j.Task.Action == "apply" {
		if _, err = validLease(root, *j); err != nil {
			return failAndRestore(root, j, "Independent recovery lease is invalid")
		}
		if recoveryExpired(*j) || helperAlive(j.HelperPID) != nil {
			return failAndRestore(root, j, "Independent recovery helper unavailable or expired; batch not executed")
		}
	}
	changes := make([]wire.ChangeResult, 0, len(j.Task.RuleIDs))
	for _, id := range j.Task.RuleIDs {
		if execution.Err() != nil || (j.Task.Action == "apply" && recoveryExpired(*j)) {
			return failAndRestore(root, j, "Task authorization or safety window expired; batch restored")
		}
		if j.Task.Action == "apply" && helperAlive(j.HelperPID) != nil {
			return failAndRestore(root, j, "Independent recovery helper exited; batch restored")
		}
		plan, _ := scanner.Plan(id)
		before := j.Undo[id]
		target := j.Targets[id]
		status := "applied"
		if j.Task.Action == "rollback" {
			status = "reverted"
		}
		if scanner.SameSnapshot(before, target) {
			if j.Task.Action == "apply" {
				status = "skipped"
			}
		} else {
			j.Phase = "running"
			j.Armed = append(j.Armed, id)
			if err := store(activePath(root), j, false); err != nil {
				return failAndRestore(root, j, "Could not persist mutation intent; batch restored")
			}
			if err := scanner.Replace(plan, target, before); err != nil {
				return failAndRestore(root, j, "Native policy write or recheck failed; batch restored where possible")
			}
		}
		after, err := scanner.Snapshot(plan)
		if err != nil || !scanner.SameSnapshot(after, target) || execution.Err() != nil || (j.Task.Action == "apply" && recoveryExpired(*j)) {
			return failAndRestore(root, j, "Native verification or safety deadline failed; batch restored where possible")
		}
		message := "Native policy state persisted and rechecked; exact backup remains local"
		if status == "skipped" {
			message = "Already satisfies the reviewed native policy; no native write performed"
		} else if status == "reverted" {
			message = "Original native policy state restored and rechecked; compliance may intentionally differ"
		}
		changes = append(changes, wire.ChangeResult{RuleID: id, Status: status, BeforeStatus: scanner.SnapshotStatus(plan, before), AfterStatus: scanner.SnapshotStatus(plan, after), BeforeValue: scanner.SnapshotDescription(before), AfterValue: scanner.SnapshotDescription(after), Message: message, BackupID: j.Task.RunID + "/" + id})
	}
	j.Result = &wire.TaskResult{Version: wire.Version, TaskID: j.Task.ID, AgentID: j.AgentID, Status: "completed", Changes: changes}
	j.Phase = "done"
	if err := store(activePath(root), j, false); err != nil {
		j.Result = nil
		if recovery := failAndRestore(root, j, "Final result persistence failed; batch restored where possible"); recovery != nil {
			return recovery
		}
		return err
	}
	return nil
}

func failAndRestore(root string, j *journal, message string, revision ...int) error {
	if len(j.Armed) > 0 {
		absolute, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		if err = trustedState(absolute); err != nil {
			return errors.New("restoration requires trusted LocalSystem task state; local operator recovery is required")
		}
	}
	rev := 0
	if len(revision) > 0 {
		rev = revision[0]
	} else if j.Task.Action == "apply" && !j.Deadline.IsZero() && recoveryExpired(*j) {
		rev = 1
	}
	if rev == 1 && j.Result != nil && j.Result.Revision == 0 && len(j.PreviousResults) == 0 {
		j.PreviousResults = append(j.PreviousResults, *j.Result)
	}
	blocked := false
	for i := len(j.Armed) - 1; i >= 0; i-- {
		id := j.Armed[i]
		plan, err := scanner.Plan(id)
		if err != nil {
			blocked = true
			continue
		}
		before := j.Undo[id]
		wanted := j.Targets[id]
		current, err := scanner.Snapshot(plan)
		if err != nil {
			blocked = true
			continue
		}
		if scanner.SameSnapshot(current, before) {
			continue
		}
		if !scanner.SameSnapshot(current, wanted) {
			blocked = true
			continue
		}
		if err = scanner.Replace(plan, before, current); err != nil {
			blocked = true
		}
	}
	if blocked {
		message = "Automatic restoration incomplete; external policy drift or native failure requires local manual review. New task mutations are blocked."
	}
	changes := make([]wire.ChangeResult, 0, len(j.Task.RuleIDs))
	for _, id := range j.Task.RuleIDs {
		change := wire.ChangeResult{RuleID: id, Status: "failed", Message: message}
		if before, ok := j.Undo[id]; ok {
			plan, err := scanner.Plan(id)
			if err == nil {
				change.BeforeStatus = scanner.SnapshotStatus(plan, before)
				change.BeforeValue = scanner.SnapshotDescription(before)
				after, e := scanner.Snapshot(plan)
				if e == nil {
					change.AfterStatus = scanner.SnapshotStatus(plan, after)
					change.AfterValue = scanner.SnapshotDescription(after)
				} else {
					change.AfterStatus = wire.Error
				}
			}
		}
		changes = append(changes, change)
	}
	if blocked {
		for i := range changes {
			changes[i].AfterStatus = wire.Error
			changes[i].AfterValue = "Recovery state unverified; local operator review required"
		}
	}
	j.Blocked = blocked
	j.Phase = "done"
	j.Acknowledged = false
	j.ReceiptAt = time.Time{}
	j.Result = &wire.TaskResult{Revision: rev, Version: wire.Version, TaskID: j.Task.ID, AgentID: j.AgentID, Status: "failed", Changes: changes}
	return store(activePath(root), j, false)
}

func acknowledge(ctx context.Context, c *client.Client, id identity.Identity, root string, j *journal) error {
	unlock, err := lockTask(ctx, root, j.Task.ID)
	if err != nil {
		return err
	}
	defer unlock()
	fresh, err := readScoped(root, j.Task.ID)
	if err != nil {
		return err
	}
	if err = validateJournal(fresh, id.AgentID); err != nil {
		return err
	}
	*j = fresh
	if err = recoverLocked(root, j); err != nil {
		return err
	}
	if j.Result == nil {
		return errors.New("task has no durable result")
	}
	if !j.Acknowledged {
		requestCtx := ctx
		cancel := func() {}
		if j.Task.Action == "apply" && j.Result.Revision == 0 && !j.Deadline.IsZero() {
			requestCtx, cancel = context.WithTimeout(ctx, recoveryRemaining(*j))
		}
		err = c.TaskResult(requestCtx, id.Token, *j.Result)
		cancel()
		if err != nil {
			if j.Task.Action == "apply" && !j.Deadline.IsZero() && recoveryExpired(*j) {
				if e := compensateExpired(root, j); e != nil {
					return e
				}
			}
			return err
		}
		if j.Task.Action == "apply" && j.Result.Revision == 0 && !j.Deadline.IsZero() && recoveryExpired(*j) {
			return compensateExpired(root, j)
		}
		j.Acknowledged = true
		j.ReceiptAt = time.Now().UTC()
		if err = store(activePath(root), j, false); err != nil {
			return err
		}
		if j.Task.Action == "apply" && j.Result.Revision == 0 && !j.Deadline.IsZero() && recoveryExpired(*j) {
			j.Acknowledged = false
			return compensateExpired(root, j)
		}
	}
	if j.Blocked {
		return errors.New("task result accepted, but unresolved local recovery blocks new mutations")
	}
	path := completedPath(root, j.Task.ID)
	var previous journal
	if err := load(path, &previous); err == nil {
		left, _ := json.Marshal(previous)
		right, _ := json.Marshal(j)
		if !bytes.Equal(left, right) {
			return errors.New("completed task journal conflicts with pending result")
		}
	} else if os.IsNotExist(err) {
		if err = store(path, j, true); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := os.Remove(activePath(root)); err != nil {
		return errors.New("accepted task result retained because journal finalization failed")
	}
	return nil
}

func recoverLocked(root string, j *journal) error {
	if j.Acknowledged {
		return nil
	}
	if j.Result != nil && j.Result.Revision == 1 {
		return nil
	}
	if j.Task.Action == "apply" {
		if !j.Deadline.IsZero() {
			if _, err := validLease(root, *j); err != nil {
				return err
			}
			if recoveryExpired(*j) {
				return compensateExpired(root, j)
			}
			if j.Result == nil {
				if helperAlive(j.HelperPID) == nil {
					return errors.New("live independent helper owns unfinished task; retry after recovery deadline")
				}
				return failAndRestore(root, j, "Interrupted task restored before networking", 1)
			}
			return nil
		}
		if len(j.Armed) > 0 {
			return failAndRestore(root, j, "Legacy unacknowledged apply has no independent recovery lease; state restored", 1)
		}
	}
	if j.Result == nil {
		return failAndRestore(root, j, "Interrupted task restored before networking")
	}
	return nil
}
