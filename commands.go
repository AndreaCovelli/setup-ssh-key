package main

import (
	"context"
	"errors"
	"io"
	"os/exec"
)

type commandRunner interface {
	lookPath(string) (string, error)
	run(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error
	combinedOutput(string, []string) ([]byte, error)
}

type systemRunner struct{}

func (systemRunner) lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (systemRunner) run(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func (systemRunner) combinedOutput(name string, args []string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type exitCoder interface {
	error
	ExitCode() int
}

func sshAgentAvailable(runner commandRunner) bool {
	_, err := runner.combinedOutput("ssh-add", []string{"-l"})
	if err == nil {
		return true
	}

	var exitErr exitCoder
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}
