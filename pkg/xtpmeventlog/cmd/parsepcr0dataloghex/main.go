package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/xtpmeventlog"
)

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()
	if flag.NArg() > 1 {
		log.Fatalf("syntax: parsepcr0dataloghex [file path]")
	}
	input := os.Stdin
	if flag.NArg() == 1 {
		filePath := flag.Arg(0)
		f, err := os.Open(filePath)
		assertNoError(err)
		defer f.Close()
		input = f
	}

	trimmed := newTrimmer(input)

	decoder := hex.NewDecoder(trimmed)

	eventData, err := io.ReadAll(decoder)
	assertNoError(err)

	result, err := xtpmeventlog.ParsePCR0DATALog(eventData)
	assertNoError(err)

	b, err := json.MarshalIndent(result, "", " ")
	assertNoError(err)
	fmt.Printf("%s\n", string(b))
}
