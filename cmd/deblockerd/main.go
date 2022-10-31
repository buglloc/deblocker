package main

import (
	"fmt"
	"os"

	_ "go.uber.org/automaxprocs"

	"github.com/buglloc/deblocker/internal/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
