package main

import (
	"fmt"
	_ "go.uber.org/automaxprocs"
	"os"

	"github.com/buglloc/deblocker/internal/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
