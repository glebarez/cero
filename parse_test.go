package main

import (
	"net"
	"testing"
)

const maxCount = 1000000

func Test_expandCIDR(t *testing.T) {
	type args struct {
		CIDR string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"IPv4_32", args{CIDR: `192.168.1.1/32`}, false},
		{"IPv4_30", args{CIDR: `192.168.1.13/30`}, false},
		{"IPv4_16", args{CIDR: `192.168.1.17/16`}, false},
		{"IPv4_12", args{CIDR: `192.15.1.17/12`}, false},
		{"IPv4_0", args{CIDR: `192.15.1.17/1`}, false},
		{"IPv6_128", args{CIDR: `ff:2:04::/128`}, false},
		{"IPv6_115", args{CIDR: `0:f:2::14/115`}, false},
		{"IPv6_64", args{CIDR: `0:f:2:4::/64`}, false},
		{"too wide mask", args{CIDR: `0:f:2:4::/63`}, true},
		{"too wide mask", args{CIDR: `0:f:2:4::/0`}, true},
		{"invalid CIDR", args{CIDR: `0:f:2:4:/63`}, true},
		{"invalid CIDR", args{CIDR: `[0:f:2:4::]/63`}, true},
		{"invalid CIDR", args{CIDR: `127.0.0.1/63`}, true},
		{"invalid CIDR", args{CIDR: `127..1/0`}, true},
		{"not CIDR", args{CIDR: `::1`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandCIDR(tt.args.CIDR)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("expandCIDR() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			// test number of IPs corresponds to mask CIDR size
			// and all of those belong to the CIDR
			var (
				count int
				ipnet *net.IPNet
			)

			for ip := range got {
				count++
				if count < 3 {
					t.Log(ip)
				}

				_, ipnet, _ = net.ParseCIDR(tt.args.CIDR)
				if !ipnet.Contains(net.ParseIP(ip)) {
					t.Errorf("%s doesn't belong to CIDR", ip)
					return
				}

				if count == maxCount {
					break
				}
			}

			// skip count check if exceeded test limit
			if count == maxCount {
				return
			}

			// check number of IPs is correct
			mBits, mSize := ipnet.Mask.Size()
			IPCount := 1 << (mSize - mBits)
			if IPCount != count {
				t.Errorf("Number of IPs is not right")
			}

			t.Logf("range fully tested")

		})
	}
}

func Test_splitHostPort(t *testing.T) {
	type args struct {
		addr string
	}
	tests := []struct {
		name     string
		args     args
		wantHost string
		wantPort string
	}{
		{`Initial input`, args{addr: ``}, ``, ``},
		{`Portless IPv4`, args{addr: `1.1.1.1`}, `1.1.1.1`, ``},
		{`Portfull IPv4`, args{addr: `1.1.1.1:443`}, `1.1.1.1`, `443`},
		{`Portless IPv4 CIDR`, args{addr: `1.1.1.1/32`}, `1.1.1.1/32`, ``},
		{`Portfull IPv4 CIDR`, args{addr: `1.1.1.1/32:443`}, `1.1.1.1/32`, `443`},
		{`Portless IPv6`, args{addr: `::1`}, `::1`, ``},
		{`Ambiguous port IPv6`, args{addr: `::1:443`}, `::1:443`, ``},
		{`Bracket IPv6 with port`, args{addr: `[::1]:443`}, `::1`, `443`},
		{`Wrong bracket port IPv6`, args{addr: `::1]:443`}, `::1]`, `443`},
		{`Unambiguous port IPv6`, args{addr: `::1:44300`}, `::1`, `44300`},
		{`Unambiguous port IPv6`, args{addr: `::1:44300`}, `::1`, `44300`},
		{`Unambiguous port IPv6`, args{addr: `1:1:1:1:1:1:1:1:80`}, `1:1:1:1:1:1:1:1`, `80`},
		{`ambiguous port IPv6`, args{addr: `1:1:1:1:1:1:1:80`}, `1:1:1:1:1:1:1:80`, ``},
		{`Portless IPv6 CIDR`, args{addr: `::1/64`}, `::1/64`, ``},
		{`Portfull IPv6 CIDR`, args{addr: `::1/64:443`}, `::1/64`, `443`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPort := splitHostPort(tt.args.addr)
			if gotHost != tt.wantHost {
				t.Errorf("splitHostPort() gotHost = %v, want %v", gotHost, tt.wantHost)
			}
			if gotPort != tt.wantPort {
				t.Errorf("splitHostPort() gotPort = %v, want %v", gotPort, tt.wantPort)
			}
		})
	}
}

func Test_isDomainName(t *testing.T) {
	cases := []struct {
		host     string
		expected bool
	}{
		// -- valid
		{"test.com.ru", true},
		{"test-1.com", true},
		{"1.1.1.com", true},
		{"test.com.", true}, // yes trailing dot is allowed by RFC

		// -- invalid
		{"127.0.0.1", false},
		{"test", false},  // single level
		{"test.", false}, // single level
		{"test_test.com", false},
		{".test", false},
		{"*.test.com", false},
		{"test-.com", false},
		{"te!st.com", false},
		{"!.dot.com", false},
	}

	for _, c := range cases {
		actual := isDomainName(c.host)
		if actual != c.expected {
			t.Errorf("isDomainName(%s) expected to be %v", c.host, c.expected)
		}
	}
}
