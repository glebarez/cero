package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
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
	/* parse arguments */
	var verbose bool
	flag.BoolVar(&verbose, "v", false, `Be verbose: Output results as 'addr -- [result list]', output errors to stderr as 'addr -- error message'`)

	var concurrency int
	flag.IntVar(&concurrency, "c", 100, "Concurrency level")

	var defaultPort int
	flag.IntVar(&defaultPort, "p", 443, "Default TLS port to use, if not specified explicitly in host address")
	flag.Parse()
	defaultPortStr := strconv.Itoa(defaultPort)

	// channels for async communications
	chanInput := make(chan string)
	chanResult := make(chan *procResult)

	/* processes input addr */
	processInput := func(addr string) {
		// empty lines are skipped
		if addr == "" {
			return
		}

		// parse port from addr, or use default port
		var host, port string
		hostPort := strings.SplitN(addr, `:`, 2)
		if len(hostPort) == 1 {
			host = addr
			port = defaultPortStr
		} else {
			host = hostPort[0]
			port = hostPort[1]
		}

		// expand if CIDR
		if strings.Contains(host, `/`) {
			ips, err := expandCIDR4(host)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			for _, ip := range ips {
				chanInput <- fmt.Sprintf(`%s:%s`, ip, port)
			}
			// atomic addr
		} else {
			chanInput <- fmt.Sprintf(`%s:%s`, host, port)
		}
	}

	/* start input workers */
	var workersWG sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		workersWG.Add(1)

		go func() {
			for addr := range chanInput {
				result := &procResult{addr: addr}

				names, err := grabCert(addr)
				if err != nil {
					result.err = err
				} else {
					result.names = names
				}
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

	/* start output worker */
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		for result := range chanResult {
			if result.err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "%s -- %s\n", result.addr, result.err)
				}
			} else {
				if verbose {
					fmt.Fprintf(os.Stdout, "%s -- %s\n", result.addr, result.names)
				} else {
					for _, name := range result.names {
						fmt.Fprintln(os.Stdout, name)
					}
				}
			}
		}
		outputWG.Done()
	}()

	/* if non-flag arguments are specified, treat them as input hosts
	otherwise, consume input from stdin */
	if len(flag.Args()) > 0 {
		for _, addr := range flag.Args() {
			processInput(addr)
		}
	} else {
		// every line is of stdin considered as a host addr
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
func grabCert(addr string) ([]string, error) {
	// dialer
	d := &net.Dialer{
		Timeout: time.Duration(5) * time.Second,
	}

	// dial
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// get first certificate in chain
	cert := conn.ConnectionState().PeerCertificates[0]

	// get CommonName and all SANs into a slice
	names := make([]string, 0, len(cert.DNSNames)+1)
	names = append(names, cert.Subject.CommonName)

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
		return nil, fmt.Errorf("CIDR %s : %s", CIDR, err)
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

// converts
func int2IP(i uint32) net.IP {
	return net.IP{
		byte(i >> 24),
		byte(i >> 16),
		byte(i >> 8),
		byte(i),
	}
}
