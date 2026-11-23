// Build-time helper for the site composers; not shipped as an agentprov command.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/byteyellow/agentprovenance/internal/cli"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
)

func main() {
	root := flag.String("dir", "", "extracted unsigned reading copy")
	run := flag.String("run", "", "initial run")
	gallery := flag.Bool("gallery", false, "add hosted gallery links")
	public := flag.Bool("public", false, "build the HTTP gallery reader, without changing recorded data")
	flag.Parse()
	if *public {
		files, err := cli.PublicDemoReaderFiles(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		writeFiles(*root, files)
		return
	}
	data, err := os.ReadFile(filepath.Join(*root, "export-inventory.json"))
	if err != nil {
		log.Fatal(err)
	}
	var inventory dashboard.ReplayInventory
	if err = json.Unmarshal(data, &inventory); err != nil {
		log.Fatal(err)
	}
	files, err := dashboard.DemoReaderFiles(context.Background(), inventory, *run, *gallery)
	if err != nil {
		log.Fatal(err)
	}
	writeFiles(*root, files)
}

func writeFiles(root string, files map[string][]byte) {
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), b, 0644); err != nil {
			log.Fatal(err)
		}
	}
}
