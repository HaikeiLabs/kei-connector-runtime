package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/HaikeiLabs/kei-connector-contracts/policybundlehealth"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/crypto"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// runRuntime provides the startup contract used by a Bot Runtime image. The
// proxy remains a one-shot CLI for tool authorization; the runtime image calls
// `runtime bootstrap` before starting its bot process and may run `heartbeat`
// alongside that process for liveness updates.
func runRuntime(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "runtime requires a subcommand: bootstrap or heartbeat")
		return 1
	}
	switch args[0] {
	case "bootstrap":
		return runRuntimeBootstrap(args[1:], os.Stdout, os.Stderr, configFromEnv(), NewRuntimeClient)
	case "heartbeat":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runRuntimeHeartbeat(ctx, args[1:], os.Stdin, os.Stdout, os.Stderr, configFromEnv(), os.Getenv, NewRuntimeClient)
	default:
		fmt.Fprintf(os.Stderr, "unknown runtime command %q\n", args[0])
		return 1
	}
}

type runtimeClientFactory func(baseURL string, timeout time.Duration) RuntimeClient

// runtimeBootstrapOutput is what a harness reads to learn its own scope. OrgID
// and WorkspaceID come from the authenticating harness key, which is minted per
// (workspace, harness) and is the authority for its scope (ADR 014). A harness
// discovers them here rather than being configured with them, so there is no
// second source of truth to drift.
//
// WorkspaceID is omitted for a legacy key minted before the workspace boundary.
// A consumer that requires a workspace should treat its absence as an error and
// have the key re-minted, not fall back to an organization-wide scope.
type runtimeBootstrapOutput struct {
	InstallationID string  `json:"installation_id"`
	OrgID          string  `json:"org_id"`
	WorkspaceID    *string `json:"workspace_id,omitempty"`
	Platform       string  `json:"platform"`
	Status         string  `json:"status"`
	BindingStatus  string  `json:"binding_status"`
}

func runRuntimeBootstrap(args []string, stdout, stderr io.Writer, cfg Config, newClient runtimeClientFactory) int {
	flags := flag.NewFlagSet("runtime bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 15*time.Second, "control-plane request timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		fmt.Fprintln(stderr, "runtime bootstrap accepts no positional arguments and requires a positive --timeout")
		return 2
	}
	identity, err := bootstrapRuntimeWithClient(context.Background(), cfg, *timeout, newClient)
	if err != nil {
		if IsRuntimeRevocation(err) {
			RevokePolicyState(cfg)
		}
		fmt.Fprintf(stderr, "runtime bootstrap failed: %v\n", err)
		return 1
	}
	if cfg.ToolManifestPath != "" {
		syncToolManifest(context.Background(), cfg, *timeout, newClient, stderr)
	}
	if err := SyncPolicyBundle(context.Background(), cfg, identity, *timeout); err != nil {
		fmt.Fprintf(stderr, "runtime policy bundle bootstrap failed: %v\n", err)
		return 1
	}
	return writeRuntimeBootstrapOutput(stdout, identity, stderr)
}

// runRuntimeHeartbeat reports runtime -> catalog liveness until cancelled.
//
// The default text output is the legacy contract: one identity line on stdout,
// the v1 heartbeat body, and exit 1 on any failure a retry cannot clear.
// `--output jsonl` is the supervised contract used by Agentware RuntimeLink:
// identity, beat, and terminal events on stdout, the v2 heartbeat body, and
// classified exit codes. `--parent-stdin` exits 0 once stdin reaches EOF, so a
// child never outlives the harness that started it.
//
// In both modes a transient catalog failure is retried once within the tick,
// reported, and followed by the next tick; it never stops the loop.
func runRuntimeHeartbeat(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, cfg Config, getenv func(string) string, newClient runtimeClientFactory) int {
	flags := flag.NewFlagSet("runtime heartbeat", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 15*time.Second, "control-plane request timeout")
	interval := flags.Duration("interval", time.Minute, "heartbeat interval")
	output := flags.String("output", "text", "stdout format: text (one identity line) or jsonl (identity, beat, and terminal events)")
	parentStdin := flags.Bool("parent-stdin", false, "exit when stdin reaches EOF; a supervisor holds stdin open for its lifetime")
	if err := flags.Parse(args); err != nil {
		return heartbeatExitContract
	}
	if flags.NArg() != 0 || *timeout <= 0 || *interval < time.Second {
		fmt.Fprintln(stderr, "runtime heartbeat accepts no positional arguments; --timeout must be positive and --interval must be at least one second")
		return heartbeatExitContract
	}
	if *output != "text" && *output != "jsonl" {
		fmt.Fprintln(stderr, "runtime heartbeat --output must be text or jsonl")
		return heartbeatExitContract
	}
	if *parentStdin {
		var cancel context.CancelFunc
		ctx, cancel = keiruntime.WatchParentStdin(ctx, stdin)
		defer cancel()
	}
	if *output == "jsonl" {
		return runRuntimeHeartbeatJSONL(ctx, cfg, getenv, stdout, stderr, *timeout, *interval, *parentStdin, newClient)
	}
	identity, err := bootstrapRuntimeWithClient(ctx, cfg, *timeout, newClient)
	if err != nil {
		if IsRuntimeRevocation(err) {
			RevokePolicyState(cfg)
		}
		if ctx.Err() != nil {
			return heartbeatExitOK
		}
		fmt.Fprintf(stderr, "runtime heartbeat failed: %v\n", err)
		return heartbeatExitTransient
	}
	if code := writeRuntimeBootstrapOutput(stdout, identity, stderr); code != 0 {
		return code
	}
	auditPath, auditMax := cfg.AuditPath, cfg.AuditMaxBytes
	loop := &keiruntime.HeartbeatLoop{
		Client:   newClient(cfg.RuntimeControlPlaneURL, *timeout),
		Token:    cfg.RuntimeToken,
		Report:   HeartbeatReport{RuntimeVersion: version},
		Interval: *interval,
		Warn:     stderr,
		Now:      time.Now,
		Jitter:   keiruntime.JitterInterval,
		AppendLifecycle: func(e keiruntime.LifecycleEvent) error {
			return appendLifecycleEvent(auditPath, auditMax, e)
		},
		PolicyBundle: func() *policybundlehealth.Health { return currentPolicyBundleHealth(cfg, identity) },
	}
	stopCollector := keiruntime.StartCollector(ctx, cfg, keiruntime.ResolveAuditPath(cfg.AuditPath, cfg.RuntimeStateDir), collectorPollInterval, shutdownFlushTimeout)
	defer stopCollector()
	whoami := func() (*keiruntime.Identity, error) {
		return identityFromRoot(identity), nil
	}
	syncBundle := func(id *keiruntime.Identity) error {
		return SyncPolicyBundle(ctx, cfg, &RuntimeIdentity{
			ID: id.ID, OrgID: id.OrgID, WorkspaceID: id.WorkspaceID,
		}, *timeout)
	}
	stopRefresher := keiruntime.StartPolicyRefresher(ctx, cfg, whoami, syncBundle, IsRuntimeRevocation, func() { RevokePolicyState(cfg) }, nil, nil,
		keiruntime.WithHarnessResync(keiruntime.NewHarnessResync(cfg, getenv)))
	defer stopRefresher()
	if err := loop.Run(ctx, false); err != nil {
		if IsRuntimeRevocation(err) {
			RevokePolicyState(cfg)
		}
		fmt.Fprintf(stderr, "runtime heartbeat failed: %v\n", err)
		return heartbeatExitTransient
	}
	return heartbeatExitOK
}

func runRuntimeHeartbeatJSONL(ctx context.Context, cfg Config, getenv func(string) string, stdout, stderr io.Writer, timeout, interval time.Duration, attached bool, newClient runtimeClientFactory) int {
	started := time.Now()
	runID, runIDErr := keiruntime.HeartbeatRunID(getenv)
	if runIDErr != nil {
		runID = uuid.NewString()
	}
	events := keiruntime.NewHeartbeatEmitter(stdout, runID)
	envelope, envErr := keiruntime.HarnessEnvelopeFromEnv(getenv)
	if envErr == nil {
		envErr = runIDErr
	}
	if envErr == nil && !cfg.IsRuntime() {
		envErr = errors.New("KEI_RUNTIME_TOKEN is required for runtime heartbeat")
	}
	if envErr == nil {
		envErr = cfg.Validate()
	}
	if envErr != nil {
		events.Terminal(keiruntime.ReasonConfigInvalid)
		fmt.Fprintf(stderr, "runtime heartbeat failed: %v\n", envErr)
		return heartbeatExitConfig
	}
	if attached {
		if envelope == nil {
			envelope = &keiruntime.HarnessEnvelope{}
		}
		envelope.Link = "attached"
	}
	client := newClient(cfg.RuntimeControlPlaneURL, timeout)
	auditPath, auditMax := cfg.AuditPath, cfg.AuditMaxBytes
	loop := &keiruntime.HeartbeatLoop{
		Client: client,
		Token:  cfg.RuntimeToken,
		Report: keiruntime.HeartbeatReport{
			RuntimeVersion:   version,
			SchemaVersion:    2,
			RunID:            runID,
			IntervalSeconds:  int(interval / time.Second),
			RuntimeStartedAt: started.UTC().Format(time.RFC3339),
			Harness:          envelope,
		},
		Versioned: true,
		Interval:  interval,
		Events:    events,
		Warn:      stderr,
		Now:       time.Now,
		Jitter:    keiruntime.JitterInterval,
		AppendLifecycle: func(e keiruntime.LifecycleEvent) error {
			return appendLifecycleEvent(auditPath, auditMax, e)
		},
	}
	identity, code := resolveIdentity(ctx, client, loop, cfg)
	if identity == nil {
		if code == heartbeatExitUnauthorized {
			RevokePolicyState(cfg)
		}
		return code
	}
	loop.PolicyBundle = func() *policybundlehealth.Health { return currentPolicyBundleHealth(cfg, identity) }
	events.Identity(toHeartbeatIdentity(identity), version)
	// The first beat is sent at once and stands in for bootstrap's heartbeat.
	stopCollector := keiruntime.StartCollector(ctx, cfg, keiruntime.ResolveAuditPath(cfg.AuditPath, cfg.RuntimeStateDir), collectorPollInterval, shutdownFlushTimeout)
	defer stopCollector()
	whoami := func() (*keiruntime.Identity, error) {
		return identityFromRoot(identity), nil
	}
	syncBundle := func(id *keiruntime.Identity) error {
		return SyncPolicyBundle(ctx, cfg, &RuntimeIdentity{
			ID: id.ID, OrgID: id.OrgID, WorkspaceID: id.WorkspaceID,
		}, timeout)
	}
	stopRefresher := keiruntime.StartPolicyRefresher(ctx, cfg, whoami, syncBundle, IsRuntimeRevocation, func() { RevokePolicyState(cfg) }, nil, nil,
		keiruntime.WithHarnessResync(keiruntime.NewHarnessResync(cfg, getenv)))
	defer stopRefresher()
	err := loop.Run(ctx, true)
	if IsRuntimeRevocation(err) {
		RevokePolicyState(cfg)
	}
	return heartbeatExitFor(err, events)
}

// classifyWhoamiError places a whoami failure on the runtime -> catalog leg. A
// response that decodes badly or lacks identity fields is a contract failure,
// reported as catalog_rejected so it is not retried.
func classifyWhoamiError(err error) HeartbeatOutcome {
	var failure *WhoamiFailure
	if !errors.As(err, &failure) {
		return classifyTransportError(err)
	}
	switch failure.Category {
	case WhoamiFailureHTTPStatus:
		return classifyHeartbeatStatus(failure.StatusCode)
	case WhoamiFailureDecode, WhoamiFailureIncomplete:
		return HeartbeatCatalogRejected
	default:
		return classifyTransportError(failure.Wrapped)
	}
}

// heartbeatExitFor emits the terminal event for a loop result and maps it to
// the supervised exit code.
func heartbeatExitFor(err error, events *keiruntime.HeartbeatEmitter) int {
	if err == nil {
		return heartbeatExitOK
	}
	failure := keiruntime.ClassifyHeartbeatError(err)
	switch failure.Outcome {
	case HeartbeatUnauthorized:
		events.Terminal(string(HeartbeatUnauthorized))
		return heartbeatExitUnauthorized
	case HeartbeatCatalogRejected:
		events.Terminal(string(HeartbeatCatalogRejected))
		return heartbeatExitContract
	default:
		return heartbeatExitTransient
	}
}

func bootstrapRuntimeWithClient(ctx context.Context, cfg Config, timeout time.Duration, newClient runtimeClientFactory) (*RuntimeIdentity, error) {
	if !cfg.IsRuntime() {
		return nil, errors.New("KEI_RUNTIME_TOKEN is required for runtime bootstrap")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client := newClient(cfg.RuntimeControlPlaneURL, timeout)
	identity, err := client.WhoAmI(ctx, cfg.RuntimeToken)
	if err != nil {
		return nil, fmt.Errorf("resolve runtime installation: %w", err)
	}
	if identity == nil {
		return nil, errors.New("runtime identity response is incomplete")
	}
	if err := client.Heartbeat(ctx, cfg.RuntimeToken, HeartbeatReport{RuntimeVersion: version}); err != nil {
		return nil, fmt.Errorf("report runtime heartbeat: %w", err)
	}
	if err := registerCredentialSyncKey(ctx, client, cfg); err != nil {
		return nil, err
	}
	return identity, nil
}

// registerCredentialSyncKey registers the runtime's sync public key when a
// credential store is configured. Runtimes without one skip it; once
// configured, registration is idempotent.
// syncToolManifest reads KEI_TOOL_MANIFEST and PUTs it to the catalog tool
// registry. V2/v3 migration schemas remain supported; v4 requires explicit
// catalog negotiation and acknowledgment. V1 and schema-less manifests are
// rejected at load. Failures are logged and never crash
// bootstrap; an unregistered tool falls back to bare-name policies which
// already fail closed.
func syncToolManifest(ctx context.Context, cfg Config, timeout time.Duration, newClient runtimeClientFactory, stderr io.Writer) {
	if cfg.ToolManifestPath == "" {
		return
	}
	manifest, err := LoadToolManifest(cfg.ToolManifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "runtime bootstrap: tool manifest: %v\n", err)
		return
	}
	client := newClient(cfg.RuntimeControlPlaneURL, timeout)
	if err := client.SyncTools(ctx, cfg.RuntimeToken, manifest); err != nil {
		fmt.Fprintf(stderr, "runtime bootstrap: tool sync: %v\n", err)
		return
	}
}

func registerCredentialSyncKey(ctx context.Context, client RuntimeClient, cfg Config) error {
	if cfg.CredentialStoreInstallationID == "" || cfg.CredentialSyncKeyID == "" || cfg.CredentialSyncPrivateKey == "" {
		return nil
	}
	publicKey, err := crypto.PublicKey(cfg.CredentialSyncPrivateKey)
	if err != nil {
		return fmt.Errorf("derive credential sync public key: %w", err)
	}
	if err := client.RegisterCredentialSyncKey(ctx, cfg.RuntimeToken, cfg.CredentialStoreInstallationID, cfg.CredentialSyncKeyID, publicKey); err != nil {
		return fmt.Errorf("register credential sync key: %w", err)
	}
	return nil
}

func writeRuntimeBootstrapOutput(stdout io.Writer, identity *RuntimeIdentity, stderr io.Writer) int {
	if err := json.NewEncoder(stdout).Encode(runtimeBootstrapOutput{
		InstallationID: identity.ID,
		OrgID:          identity.OrgID,
		WorkspaceID:    identity.WorkspaceID,
		Platform:       identity.Platform,
		Status:         identity.Status,
		BindingStatus:  identity.BindingStatus,
	}); err != nil {
		fmt.Fprintf(stderr, "runtime bootstrap failed: write response: %v\n", err)
		return 1
	}
	return 0
}
