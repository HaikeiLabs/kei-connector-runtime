package connectorruntime

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func runCollector(args []string) int {
	fs := flag.NewFlagSet("collector", flag.ContinueOnError)
	jsonlPath := fs.String("jsonl", "", "audit JSONL file path (default $KEI_PROXY_AUDIT, else $KEI_RUNTIME_STATE_DIR/audit/harness-tool.jsonl)")
	controlPlaneURL := fs.String("control-plane-url", "", "Kei control-plane URL (default $KEI_RUNTIME_CONTROL_PLANE_URL)")
	batchSize := fs.Int("batch-size", 100, "records per flush batch")
	timeout := fs.Int("timeout", 30, "control-plane request timeout in seconds")
	poll := fs.Bool("poll", false, "poll for new records until terminated")
	pollInterval := fs.Duration("poll-interval", time.Minute, "poll interval when --poll is enabled")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg := configFromEnv()
	if *jsonlPath == "" {
		*jsonlPath = keiruntime.ResolveAuditPath(cfg.AuditPath, cfg.RuntimeStateDir)
	}
	if *controlPlaneURL != "" {
		cfg.RuntimeControlPlaneURL = *controlPlaneURL
	}
	if *jsonlPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --jsonl, KEI_PROXY_AUDIT, or KEI_RUNTIME_STATE_DIR is required")
		return 1
	}
	if !cfg.IsRuntime() {
		fmt.Fprintln(os.Stderr, "Error: invalid collector configuration: KEI_RUNTIME_TOKEN is required")
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid collector configuration: %v\n", err)
		return 1
	}

	client := keiruntime.NewABACFlushClientFromConfig(cfg, time.Duration(*timeout)*time.Second)
	lifecycleClient := keiruntime.NewLifecycleFlushClientFromConfig(cfg, time.Duration(*timeout)*time.Second)
	harnessToolClient := keiruntime.NewHarnessToolFlushClientFromConfig(cfg, time.Duration(*timeout)*time.Second)
	credentialClient := keiruntime.NewCredentialFlushClientFromConfig(cfg, time.Duration(*timeout)*time.Second)
	collector := keiruntime.NewCollector(*jsonlPath, client, *batchSize)
	collector.LifecycleClient = lifecycleClient
	collector.HarnessToolClient = harnessToolClient
	collector.HarnessAuditClient = keiruntime.NewHarnessAuditFlushClientFromConfig(cfg, time.Duration(*timeout)*time.Second)
	collector.CredentialClient = credentialClient
	if *poll {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := collector.RunPolling(ctx, *pollInterval); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	}

	sent, err := collector.Run(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(os.Stdout, "flushed %d records\n", sent)
	return 0
}
