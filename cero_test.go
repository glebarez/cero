package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_main_addr(t *testing.T) {
	// handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	}

	// test TLS server
	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer ts.Close()

	// grab URL of test TLS server
	tsURL, _ := url.Parse(ts.URL)

	// test atomic addr
	os.Args = []string{"cero-test", tsURL.Host}
	flag.CommandLine = flag.NewFlagSet("", flag.ExitOnError)

	output := captureOutput(main)
	assert.Equal(t, "example.com", strings.TrimSpace(output))

	// test CIDR
	host, port := splitHostPort(tsURL.Host)
	os.Args = []string{"cero-test", fmt.Sprintf("%s/30:%s", host, port)}
	flag.CommandLine = flag.NewFlagSet("", flag.ExitOnError)

	output = captureOutput(main)
	assert.Equal(t, "example.com", strings.TrimSpace(output))
}

// helper utility to grab stdout, stderr
func captureOutput(f func()) string {
	// create os pipe to emulate file interface
	reader, writer, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	// save original descriptors for restoring later
	stdout := os.Stdout
	stderr := os.Stderr
	defer func() {
		os.Stdout = stdout
		os.Stderr = stderr
	}()

	// replace standard descriptors
	os.Stdout = writer
	os.Stderr = writer

	// create output channel
	out := make(chan string)

	// run background goroutine to capture output
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		var buf bytes.Buffer
		wg.Done()
		if _, err := io.Copy(&buf, reader); err != nil {
			log.Fatal(err)
		}

		out <- buf.String()
	}()
	wg.Wait()

	// run the function
	f()

	// return grabbed output
	writer.Close()
	return <-out
}
