package conn

import "net"

// Ports of the standard bind.
//
// wireguard-go opened the IPv4 socket on the port asked for (0: any), then the IPv6 socket on the
// IPv4 socket's port, and the device opens the bind again with the port it got on every network
// change. Each of these binds a UDP socket to an explicit port on every address, and Windows takes
// that for a server: it asks the user to allow the app through its firewall ("Windows Firewall has
// blocked some features of Hiddify Core"), for a client that never takes a connection. A socket on
// port 0 is never asked about.
//
// So a bind opened without a port binds each family to port 0, its own ephemeral port, and keeps
// doing so when opened again with the port it picked. A port asked for (a server's listen_port) is
// bound as before, on both families.

// requestedPort is the port Open binds: 0 again for the port the bind picked itself.
func (s *StdNetBind) requestedPort(uport uint16) uint16 {
	if uport != 0 && uport == s.ephemeralPort {
		return 0
	}
	return uport
}

// ipv6Port is the port the IPv6 socket is bound to: its own ephemeral port when none was asked
// for, else the IPv4 socket's port, as both listen on a port asked for.
func ipv6Port(uport uint16, ipv4Port int) int {
	if uport == 0 {
		return 0
	}
	return ipv4Port
}

// openedPort is the port Open reports, the IPv4 socket's (the IPv6 socket's without one), and
// remembers it as picked by the bind when none was asked for.
func (s *StdNetBind) openedPort(uport uint16, ipv4Conn *net.UDPConn, ipv4Port int, port int) uint16 {
	if ipv4Conn != nil {
		port = ipv4Port
	}
	if uport == 0 {
		s.ephemeralPort = uint16(port)
	} else {
		s.ephemeralPort = 0
	}
	return uint16(port)
}
