package main

import (
	"io"
	"os/exec"
)

type commandRunner interface {
	lookPath(string) (string, error)
	run(string, []string, io.Reader, io.Writer, io.Writer) error
	combinedOutput(string, []string) ([]byte, error)
}

type systemRunner struct{}

func (systemRunner) lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (systemRunner) run(name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func (systemRunner) combinedOutput(name string, args []string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}
