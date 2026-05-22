package main

import (
	"flag"
	"log"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/ultraspoof/ultraspoof/internal/client"
	"github.com/ultraspoof/ultraspoof/internal/config"
	"github.com/ultraspoof/ultraspoof/internal/server"
)

func main() {
	cfgPath := flag.String("c", "", "path to YAML config (client.yaml or server.yaml)")
	flag.Parse()
	if *cfgPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	root, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if root.MaxCPU > 0 {
		runtime.GOMAXPROCS(root.MaxCPU)
		log.Printf("GOMAXPROCS set to %d", root.MaxCPU)
	}

	if root.MaxRAMMB > 0 {
		limitBytes := int64(root.MaxRAMMB) * 1024 * 1024
		debug.SetMemoryLimit(limitBytes)
		log.Printf("Memory limit set to %d MB", root.MaxRAMMB)
	}
	switch root.Mode {
	case config.ModeClient:
		if err := client.Run(root); err != nil {
			log.Fatal(err)
		}
	case config.ModeServer:
		if err := server.Run(root); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown mode %q", root.Mode)
	}
}
