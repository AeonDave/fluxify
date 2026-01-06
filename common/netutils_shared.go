package common

// AddHostRouteUnified adds a host route via the given gateway/device, handling IPv4/IPv6.
func AddHostRouteUnified(ip, via, dev string, isV6 bool) error {
	if isV6 {
		return AddHostRoute6(ip, via, dev)
	}
	return AddHostRoute(ip, via, dev)
}

// EnsureHostRouteUnified ensures a host route via the given gateway/device, handling IPv4/IPv6.
func EnsureHostRouteUnified(ip, via, dev string, isV6 bool) error {
	if isV6 {
		return EnsureHostRoute6(ip, via, dev)
	}
	return EnsureHostRoute(ip, via, dev)
}

// DeleteHostRouteUnified removes a host route, handling IPv4/IPv6.
func DeleteHostRouteUnified(ip string, isV6 bool) error {
	if isV6 {
		return DeleteHostRoute6(ip)
	}
	return DeleteHostRoute(ip)
}
