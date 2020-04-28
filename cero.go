package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

/* result of processing a domain name */
type procResult struct {
	addr  string
	names []string
	err   error
}

func main() {
	/* parse flags */
	var verbose bool
	flag.BoolVar(&verbose, "v", false, `Be verbose: Output results as 'addr -- [result list]', output errors to stderr as 'addr -- error message'`)

	var concurrency int
	flag.IntVar(&concurrency, "c", 100, "Concurrency level")

	var defaultPorts string
	flag.StringVar(&defaultPorts, "p", "443", "TLS ports to use, if not specified explicitly in host address. Use comma-separated list")

	var timeout int
	flag.IntVar(&timeout, "t", 4, "TLS Connection timeout in seconds")
	flag.Parse()

	// parse default port list into string slice
	defaultPortsS := strings.Split(defaultPorts, `,`)

	// channels
	chanInput := make(chan string)
	chanResult := make(chan *procResult)

	/* start input workers */
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	var workersWG sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workersWG.Add(1)
		go func() {
			for addr := range chanInput {
				result := &procResult{addr: addr}
				result.names, result.err = grabCert(addr, dialer)
				chanResult <- result
			}
			workersWG.Done()
		}()
	}

	// close result channel when workers are done
	go func() {
		workersWG.Wait()
		close(chanResult)
	}()

	/* start result-processing worker */
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		for result := range chanResult {
			// in verbose mode, print all errors and results, with corresponding input values
			if verbose {
				if result.err != nil {
					fmt.Fprintf(os.Stderr, "%s -- %s\n", result.addr, result.err)
				} else {
					fmt.Fprintf(os.Stdout, "%s -- %s\n", result.addr, result.names)
				}
			} else {
				// non-verbose: just print scraped names, one at line
				for _, name := range result.names {
					fmt.Fprintln(os.Stdout, name)
				}
			}
		}
		outputWG.Done()
	}()

	/* input item parser
	if any errors occurred during parsing, they are pushed straight to result channel */
	parseInput := func(input string) {
		// initial inputs are skipped
		input = strings.TrimSpace(input)
		if input == "" {
			return
		}

		// split input to host and port (if specified)
		host, port := splitHostPort(input)

		// get ports list to use
		var ports []string
		if port == "" {
			// use ports from default list if not specified explicitly
			ports = defaultPortsS
		} else {
			ports = []string{port}
		}

		// CIDR?
		if isCIDR(host) {
			// expand CIDR
			ips, err := expandCIDR(host)
			if err != nil {
				chanResult <- &procResult{addr: input, err: err}
				return
			}

			// feed IPs from CIDR to input channel
			for ip := range ips {
				for _, port := range ports {
					chanInput <- net.JoinHostPort(ip, port)
				}
			}
		} else {
			// feed atomic host to input channel
			for _, port := range ports {
				chanInput <- net.JoinHostPort(host, port)
			}
		}
	}

	/* decide on where to consume input from:
	if non-flag arguments are specified, treat them as input hosts,
	otherwise consume input from stdin */
	if len(flag.Args()) > 0 {
		for _, addr := range flag.Args() {
			parseInput(addr)
		}
	} else {
		// every line of stdin is considered as a input
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			addr := strings.TrimSpace(sc.Text())
			parseInput(addr)
		}
	}

	// close input channel when input fully consumed
	close(chanInput)

	// wait for processing to finish
	outputWG.Wait()
}

/* connects to addr and grabs certificate information.
returns slice of domain names from grabbed certificate */
func grabCert(addr string, dialer *net.Dialer) ([]string, error) {
	// dial
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// get first certificate in chain
	cert := conn.ConnectionState().PeerCertificates[0]

	// get CommonName and all SANs into a slice
	names := make([]string, 0, len(cert.DNSNames)+1)
	names = append(names, cert.Subject.CommonName)

	// append all SANs, excluding one that is equal to CN (if any)
	for _, name := range cert.DNSNames {
		if name != cert.Subject.CommonName {
			names = append(names, name)
		}
	}

	return names, nil
}
