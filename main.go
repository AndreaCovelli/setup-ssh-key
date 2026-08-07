package main

import (
	"os"
)

func main() {
	app := newApp(os.Stdin, os.Stdout, os.Stderr)
	os.Exit(app.run(os.Args[1:]))
}
