// Command leash is the Leash control plane binary.
//
//	leash serve    operator API, dashboard and MCP endpoint (-fake for a
//	               credential-free demo against a fake PayPal)
//	leash demo     run the attack-vs-protected story and a legitimate purchase,
//	               in-process, against a fake PayPal (no credentials, no network)
package main

import (
	"fmt"
	"os"
)

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		if err := runServe(os.Args[2:], os.Stdout, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
	case "demo":
		if err := runDemo(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "demo failed:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: leash demo | leash serve [-fake] [flags]")
		if cmd != "help" && cmd != "-h" && cmd != "--help" {
			os.Exit(2)
		}
	}
}
