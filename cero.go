package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
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

	// channels for async communications
	chanInput := make(chan string)
	chanResult := make(chan *procResult)

	// parse default port list into string slice
	defaultPortsS := strings.Split(defaultPorts, `,`)

	/* the function processes input item and feeds it into input channel */
	processInput := func(addr string) {
		// empty lines are skipped
		if addr == "" {
			return
		}

		// parse port from addr, or use default port
		var host string
		var ports []string

		hostPort := strings.SplitN(addr, `:`, 2)
		if len(hostPort) == 1 {
			// use ports from default list if not specified explicitly
			host = addr
			ports = defaultPortsS
		} else {
			// use explicitly specified port
			host = hostPort[0]
			ports = []string{hostPort[1]}
		}

		// expand if CIDR
		if strings.Contains(host, `/`) {
			ips, err := expandCIDR4(host)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			// feed IPs from CIDR
			for _, ip := range ips {
				for _, port := range ports {
					chanInput <- fmt.Sprintf(`%s:%s`, ip, port)
				}
			}
		} else {
			// atomic addr
			for _, port := range ports {
				chanInput <- fmt.Sprintf(`%s:%s`, host, port)
			}
		}
	}

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

	/* result printing function */
	printResult := func(result *procResult) {
		// in verbose mode, print all errors and results, relatively to input addr
		if verbose {
			if result.err != nil {
				fmt.Fprintf(os.Stderr, "%s -- %s\n", result.addr, result.err)
			} else {
				fmt.Fprintf(os.Stdout, "%s -- %s\n", result.addr, result.names)
			}
		} else {
			// non-verbose: just print names, one at line
			for _, name := range result.names {
				fmt.Fprintln(os.Stdout, name)
			}
		}
	}

	/* start output worker */
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		for result := range chanResult {
			printResult(result)
		}
		outputWG.Done()
	}()

	/* decide on where to consume input from:
	if non-flag arguments are specified, treat them as input hosts
	otherwise, consume input from stdin */
	if len(flag.Args()) > 0 {
		for _, addr := range flag.Args() {
			processInput(addr)
		}
	} else {
		// every line of stdin is considered as a host addr
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			addr := strings.TrimSpace(sc.Text())
			processInput(addr)
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

/* expands IPv4 CIDR into slice of IPs (as strings)*/
func expandCIDR4(CIDR string) ([]string, error) {
	// parse CIDR
	_, net, err := net.ParseCIDR(CIDR)
	if err != nil {
		return nil, err
	}

	// check for IPv4
	if net.IP.To4() == nil {
		return nil, fmt.Errorf("CIDR %s must be IPv4", CIDR)
	}

	// convert IP and Mask to Uint32
	ip32 := binary.BigEndian.Uint32(net.IP)
	mask32 := binary.BigEndian.Uint32([]byte(net.Mask))

	// populate IP slice
	ips := make([]string, 0, ^mask32)
	for mask := uint32(0); mask <= ^mask32; mask++ {
		ips = append(ips, int2IP(mask^ip32).String())
	}

	return ips, nil
}

/* converts Uint32 to net.IP */
func int2IP(i uint32) net.IP {
	return net.IP{
		byte(i >> 24),
		byte(i >> 16),
		byte(i >> 8),
		byte(i),
	}
}
