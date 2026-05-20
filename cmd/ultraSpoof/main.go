package main

import (
	"flag"
	"log"
	"os"

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
