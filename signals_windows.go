//go:build windows

package main

import "os"

func generationSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
