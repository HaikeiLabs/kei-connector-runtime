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
	jsonlPath := fs.String("jsonl", "", "audit JSONL file path (default $KEI_PROXY_AUDIT)")
	abacURL := fs.String("abac-url", "", "ABAC Engine URL (default $ABAC_URL)")
	batchSize := fs.Int("batch-size", 100, "records per flush batch")
	timeout := fs.Int("timeout", 30, "ABAC request timeout in seconds")
	poll := fs.Bool("poll", false, "poll for new records until terminated")
	pollInterval := fs.Duration("poll-interval", time.Minute, "poll interval when --poll is enabled")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg := configFromEnv()
	if *jsonlPath == "" {
		*jsonlPath = cfg.AuditPath
	}
	if *abacURL != "" {
		cfg.ABACURL = *abacURL
		if cfg.IsRuntime() {
			cfg.RuntimeControlPlaneURL = *abacURL
		}
	}
	if *jsonlPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --jsonl or KEI_PROXY_AUDIT is required")
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
