// Package run executes child processes that need connector credentials.
// Resolved values flow only from the runtime into the child process
// environment; kei-proxy commands, logs, errors, and audit records never
// surface credential values. Harness developers are responsible for keeping
// credentials secure when debugging inside the harness.
package run
