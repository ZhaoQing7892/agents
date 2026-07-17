/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package network provides shared utilities for network CIDR/IP validation
// and normalization used by the e2b API layer and the sandbox-manager infra layer.
package network

import (
	"net"
	"regexp"
	"strings"
)

// AllTrafficCIDR represents all IPv4 addresses (0.0.0.0/0). It is used both
// as the default deny rule in TrafficPolicy whitelist mode and as the
// deny-all entry when allowInternetAccess is false.
const AllTrafficCIDR = "0.0.0.0/0"

// AllTrafficCIDRIPv6 represents all IPv6 addresses (::/0). It is used alongside
// AllTrafficCIDR to block all traffic on dual-stack clusters.
const AllTrafficCIDRIPv6 = "::/0"

// DNSServerCIDR is the default DNS server CIDR that is automatically allowed
// when allowOut contains domain entries, to ensure DNS resolution works under
// default-deny.
// See: https://e2b.dev/docs/network/internet-access
const DNSServerCIDR = "8.8.8.8/32"

// IsCIDROrIP returns true if the entry is a valid CIDR or bare IP address.
func IsCIDROrIP(entry string) bool {
	if _, _, err := net.ParseCIDR(entry); err == nil {
		return true
	}
	return net.ParseIP(entry) != nil
}

// ContainsCIDR returns true if the CIDR list contains the target CIDR.
func ContainsCIDR(cidrs []string, target string) bool {
	for _, cidr := range cidrs {
		if cidr == target {
			return true
		}
	}
	return false
}

// ContainsAllTrafficCIDR returns true if the CIDR list contains 0.0.0.0/0 or ::/0.
func ContainsAllTrafficCIDR(cidrs []string) bool {
	for _, cidr := range cidrs {
		if cidr == AllTrafficCIDR || cidr == AllTrafficCIDRIPv6 {
			return true
		}
	}
	return false
}

// fqdnRegex matches FQDNs. Wildcards are not supported: the traffic-extension
// resolves FQDNs to IPs at runtime, and wildcards cannot resolve to a concrete IP.
var fqdnRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// IsFQDN returns true if the entry is a valid FQDN. Wildcard domains are not supported.
func IsFQDN(entry string) bool {
	return fqdnRegex.MatchString(entry)
}

// SplitAllowOut separates allowOut entries into CIDR/IP entries and domain entries.
func SplitAllowOut(allowOut []string) (cidrs, domains []string) {
	for _, entry := range allowOut {
		if IsCIDROrIP(entry) {
			cidrs = append(cidrs, NormalizeToCIDR(entry))
		} else {
			domains = append(domains, entry)
		}
	}
	return cidrs, domains
}

// NormalizeToCIDR converts a bare IP to CIDR notation (/32 for IPv4, /128 for IPv6).
// Uses string notation (presence of ':') rather than To4() to correctly handle
// IPv4-mapped IPv6 addresses (e.g., "::ffff:1.2.3.4").
func NormalizeToCIDR(entry string) string {
	if _, _, err := net.ParseCIDR(entry); err == nil {
		return entry
	}
	if ip := net.ParseIP(entry); ip != nil {
		if !strings.Contains(entry, ":") {
			return entry + "/32"
		}
		return entry + "/128"
	}
	return entry
}
