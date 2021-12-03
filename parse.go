package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
)

/* expands IP/IPv6 CIDR into atomic IPs
returns channel from which string IPs must be consumed
returns error if mask is too wide, or CIDR is not syntaxed properly
supported masks:
	- for IPv4: /[0-32] (whole IPv4 space)
	- for IPv6: /[64-128]: (up to 2^64 IPs) */
func expandCIDR(CIDR string) (chan string, error) {
	// parse CIDR
	_, ipnet, err := net.ParseCIDR(CIDR)
	if err != nil {
		return nil, err
	}

	// general check for unsupported cases
	mOnes, mBits := ipnet.Mask.Size()
	if mBits == 128 && mOnes < 64 {
		return nil, fmt.Errorf("%s: IPv6 mask is too wide, use one from range /[64-128]", CIDR)
	}

	// create channel to deliver output
	outputChan := make(chan string)

	// switch branch to IPv4 / IPv6
	switch mBits {
	case 32: // IPv4:
		go func() {
			// convert to uint32, for convenient bitwise operation
			ip32 := binary.BigEndian.Uint32(ipnet.IP)
			mask32 := binary.BigEndian.Uint32(ipnet.Mask)

			// create buffer
			buf := new(bytes.Buffer)
			for mask := uint32(0); mask <= ^mask32; mask++ {
				// build IP as byte slice
				buf.Reset()
				err := binary.Write(buf, binary.BigEndian, ip32^mask)
				if err != nil {
					panic(err)
				}
				// yield stringified IP
				outputChan <- net.IP(buf.Bytes()).String()
			}
			close(outputChan)
		}()

	case 128: // IPv6
		go func() {
			// convert lower halves to uint64, for convenient bitwise operation
			ip64 := binary.BigEndian.Uint64(ipnet.IP[8:])
			mask64 := binary.BigEndian.Uint64(ipnet.Mask[8:])

			buf := new(bytes.Buffer)

			// write portion of IP that will not change during expansion
			buf.Write(ipnet.IP[:8])
			for mask := uint64(0); mask <= ^mask64; mask++ {
				// build IP as byte slice
				buf.Truncate(8)
				err := binary.Write(buf, binary.BigEndian, ip64^mask)
				if err != nil {
					panic(err)
				}
				// yield stringified IP
				outputChan <- net.IP(buf.Bytes()).String()
			}
			close(outputChan)
		}()
	}
	return outputChan, nil
}

/* every value with slash is condiered as CIDR
if it's not a valid one, it will fail at later processing */
func isCIDR(value string) bool {
	return strings.Contains(value, `/`)
}

var portRegexp, bracketRegexp *regexp.Regexp

func init() {
	portRegexp = regexp.MustCompile(`^(.*?)(:(\d+))?$`)
	bracketRegexp = regexp.MustCompile(`^\[.*\]$`)
}

/* parses input addr into -> host, port.
if port is not specified, returns ports as empty string.
tolerates IPv6 port specification without enclosing IP into square brackets.
in truly ambiguous cases for IPv6, treat as portless
Doesn't check for errors, just splits
*/
func splitHostPort(addr string) (host, port string) {
	// split host and port
	portMatch := portRegexp.FindStringSubmatch(addr)
	host = portMatch[1]
	port = portMatch[3]
	isIPv6 := strings.Contains(host, `:`)

	// skip further checks for bracketed IPv6
	if isIPv6 && bracketRegexp.MatchString(host) {
		host = strings.TrimPrefix(host, `[`)
		host = strings.TrimSuffix(host, `]`)
		return
	}

	// no port found, skip futher checks
	if port == "" {
		return
	}

	// skip futher checks for CIDR
	if isCIDR(host) {
		return
	}

	// check ambiguous cases for IPv6
	if isIPv6 {
		// if port is longer than 4 digits -> it is truly a port
		if len(port) > 4 {
			return
		}

		// cancel port if whole thing parses as valid IPv6
		hostPort := fmt.Sprintf(`%s:%s`, host, port)
		if net.ParseIP(hostPort) != nil {
			host, port = hostPort, ``
			return
		}
	}
	return
}

// isDomainName checks if a string is a presentation-format domain name
// (currently restricted to hostname-compatible "preferred name" LDH labels and
func isDomainName(s string) bool {
	// See RFC 1035, RFC 3696.
	// Presentation format has dots before every label except the first, and the
	// terminal empty label is optional here because we assume fully-qualified
	// (absolute) input. We must therefore reserve space for the first and last
	// labels' length octets in wire format, where they are necessary and the
	// maximum total length is 255.
	// So our _effective_ maximum is 253, but 254 is not rejected if the last
	// character is a dot.
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	nonNumeric := false // true once we've seen a letter or hyphen
	partlen := 0
	parts := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
			parts++
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return nonNumeric && (parts > 1 || parts > 0 && last != '.')
}
