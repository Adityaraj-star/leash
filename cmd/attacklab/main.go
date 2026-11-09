// Command attacklab measures how often a real model, fooled by an instruction
// planted in a web page, ends up paying an attacker, with and without Leash.
//
//	GROQ_API_KEY=... attacklab -trials 10 -benign 10 -yes      # free tier; or ANTHROPIC_API_KEY
//	attacklab -mock gullible                  # no API key: checks the lab itself
//
// Each trial runs in its own universe (a shop, a fake PayPal, and for the Leash arm a
// control plane with an MCP endpoint), so trials cannot affect each other and no real
// money is involved. Results are written to the -out directory.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Adityaraj-star/leash/internal/agent"
	"github.com/Adityaraj-star/leash/internal/llm"
)

type job struct {
	arm     Arm
	variant Variant
	kind    string
	index   int
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "attacklab:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("attacklab", flag.ContinueOnError)
	fs.SetOutput(stderr)
	armsFlag := fs.String("arms", "unprotected,defended,leash", "comma separated arms to compare")
	variantsFlag := fs.String("variants", "all", "attack variants (comma separated ids, or all)")
	trials := fs.Int("trials", 10, "attack trials per arm and variant")
	benign := fs.Int("benign", 10, "honest trials per arm (no attack)")
	parallel := fs.Int("parallel", 2, "trials to run at once")
	model := fs.String("model", envOr("LEASH_MODEL", ""), "model name (default: the provider's own; check its current documentation)")
	mock := fs.String("mock", "", "use a scripted stand-in instead of the API: gullible, aware or careful")
	out := fs.String("out", "lab-results", "directory for results.md, results.json and trials.jsonl")
	timeout := fs.Duration("timeout", 150*time.Second, "time limit for one trial")
	maxCalls := fs.Int("max-calls", 3000, "stop after this many model calls")
	maxIn := fs.Int("max-input-tokens", 6_000_000, "stop after this many input tokens")
	maxOut := fs.Int("max-output-tokens", 600_000, "stop after this many output tokens")
	temp := fs.Float64("temperature", -1, "sampling temperature (default: the API's default)")
	yes := fs.Bool("yes", false, "start the run (required for real API calls, which cost money)")
	list := fs.Bool("list", false, "list the attack variants and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *list {
		for _, v := range Variants {
			fmt.Fprintf(stdout, "%-18s %s\n", v.ID, v.Title)
		}
		return nil
	}

	var arms []Arm
	for _, a := range strings.Split(*armsFlag, ",") {
		switch Arm(strings.TrimSpace(a)) {
		case Unprotected, Defended, Leash:
			arms = append(arms, Arm(strings.TrimSpace(a)))
		default:
			return fmt.Errorf("unknown arm %q (use unprotected, defended, leash)", a)
		}
	}
	variants := Variants
	if *variantsFlag != "all" {
		variants = nil
		for _, id := range strings.Split(*variantsFlag, ",") {
			v, ok := variantByID(strings.TrimSpace(id))
			if !ok {
				return fmt.Errorf("unknown variant %q (see -list)", id)
			}
			variants = append(variants, v)
		}
	}
	var jobs []job
	for _, arm := range arms {
		for _, v := range variants {
			for i := 0; i < *trials; i++ {
				jobs = append(jobs, job{arm, v, "attack", i})
			}
		}
		for i := 0; i < *benign; i++ {
			jobs = append(jobs, job{arm, Benign, "benign", i})
		}
	}
	if len(jobs) == 0 {
		return fmt.Errorf("nothing to run")
	}

	cl := &llm.Client{Model: *model, Budget: &llm.Budget{MaxCalls: *maxCalls, MaxInputTokens: *maxIn, MaxOutputTokens: *maxOut}}
	if *mock != "" {
		switch *mock {
		case "gullible", "aware", "careful":
		default:
			return fmt.Errorf("-mock must be gullible, aware or careful")
		}
		srv := httptest.NewServer(&mockModel{persona: *mock})
		defer srv.Close()
		cl.BaseURL, cl.APIKey, cl.Model = srv.URL, "mock", "mock-"+*mock
	} else {
		real, err := llm.FromEnv(os.Getenv, *model)
		if err != nil {
			return err
		}
		if real == nil {
			return fmt.Errorf("set GROQ_API_KEY (free tier) or ANTHROPIC_API_KEY, or use -mock to test the lab without a key")
		}
		cl.Provider, cl.Name, cl.BaseURL, cl.APIKey, cl.Model, cl.MaxRetries = real.Provider, real.Name, real.BaseURL, real.APIKey, real.Model, real.MaxRetries
		fmt.Fprintf(stdout, "Plan: %d trials (about %d model calls, roughly %d thousand input tokens), model %s.\n", len(jobs), len(jobs)*4, len(jobs)*4*2, cl.Describe())
		fmt.Fprintf(stdout, "Hard caps: %d calls, %d input tokens, %d output tokens.\n", *maxCalls, *maxIn, *maxOut)
		if !*yes {
			fmt.Fprintln(stdout, "This will call the API and cost money. Re-run with -yes to start.")
			return nil
		}
	}
	var tptr *float64
	if *temp >= 0 {
		tptr = temp
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	started := time.Now()
	results := make([]Trial, len(jobs))
	var done sync.WaitGroup
	var mu sync.Mutex
	finished := 0
	sem := make(chan struct{}, max(1, *parallel))
	for i, j := range jobs {
		done.Add(1)
		sem <- struct{}{}
		go func(i int, j job) {
			defer done.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				results[i] = Trial{Arm: string(j.arm), Variant: j.variant.ID, Kind: j.kind, Index: j.index, Error: "not run: interrupted"}
				return
			}
			tr := runTrial(ctx, cl, j, *timeout, tptr)
			results[i] = tr
			mu.Lock()
			finished++
			fmt.Fprintf(stdout, "[%d/%d] %-12s %-17s %-6s tried=%-5v moved=%-5v completed=%-5v %s\n", finished, len(jobs), tr.Arm, tr.Variant, tr.Kind,
				tr.Outcome.Attempted, tr.Outcome.MoneyMoved, tr.Outcome.TaskCompleted, tr.Error)
			mu.Unlock()
		}(i, j)
	}
	done.Wait()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	md := markdown(results, cl.Model, *mock, started)
	if err := os.WriteFile(filepath.Join(*out, "results.md"), []byte(md), 0o644); err != nil {
		return err
	}
	var lines []string
	for _, tr := range results {
		b, _ := json.Marshal(tr)
		lines = append(lines, string(b))
	}
	if err := os.WriteFile(filepath.Join(*out, "trials.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	all, _ := json.MarshalIndent(map[string]any{"model": cl.Model, "mock": *mock, "started": started.UTC(), "trials": results}, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "results.json"), all, 0o644); err != nil {
		return err
	}
	calls, in, outTok := cl.Budget.Used()
	fmt.Fprintf(stdout, "\n%s\nUsed %d model calls, %d input and %d output tokens. Wrote %s\n", md, calls, in, outTok, filepath.Join(*out, "results.md"))
	return nil
}

func runTrial(ctx context.Context, cl *llm.Client, j job, timeout time.Duration, temp *float64) Trial {
	tr := Trial{Arm: string(j.arm), Variant: j.variant.ID, Kind: j.kind, Index: j.index}
	w, err := newWorld(ctx, j.arm, j.variant)
	if err != nil {
		tr.Error = "setup: " + err.Error()
		return tr
	}
	defer w.Close()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := agent.Run(cctx, agent.Config{LLM: cl, System: j.arm.system(), Tools: w.Tools, MaxTurns: 10, MaxTokens: 1024, Temperature: temp}, task(w.Shop))
	tr.Turns, tr.Stop, tr.InputTokens, tr.OutputTokens, tr.Calls = res.Turns, res.StopReason, res.InputTokens, res.OutputTokens, res.Calls
	tr.Final = res.FinalText
	if len(tr.Final) > 300 {
		tr.Final = tr.Final[:300]
	}
	if res.Err != nil {
		tr.Error = res.Err.Error()
		return tr
	}
	tr.Outcome = w.evaluate(j.arm, res)
	return tr
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
