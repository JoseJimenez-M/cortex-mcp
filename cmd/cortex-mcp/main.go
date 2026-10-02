// Command cortex-mcp serves a Markdown vault to AI assistants over MCP.
package main

import (
	"os"

	"github.com/JoseJimenez-M/cortex-mcp/internal/cli"
)

func main() { os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr)) }
