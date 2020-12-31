package topology // import "github.com/nathanaelle/wireguard-topology"

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type (
	Host struct {
		Name                string                 `json:"host"`
		Templates           []string               `json:"templates"`
		Iface               string                 `json:"iface"`
		PersistentKeepalive *uint16                `json:"persistent-keepalive"`
		ListenPort          uint16                 `json:"port"`
		PrivateIPv6         string                 `json:"-"`
		AllowedIPv6         []string               `json:"-"`
		PrivateIPv6CIDR     string                 `json:"ipv6"`
		PrivateKey          string                 `json:"-"`
		PublicKey           string                 `json:"public-key"`
		Misc                map[string]interface{} `json:"Misc"`
	}

	Cluster struct {
		ClusterName string   `json:"cluster"`
		Templates   []string `json:"templates"`
		Members     []string `json:"members"`
		// ExposedTo           []string          `json:"exposed-to"`
	}

	Config struct {
		ConfigName          string                 `json:"config-name"`
		IPv6Prefix          string                 `json:"prefix-ipv6/cidr"`
		PersistentKeepalive *uint16                `json:"persistent-keepalive"`
		Iface               string                 `json:"iface"`
		ListenPort          uint16                 `json:"port"`
		Hosts               []*Host                `json:"hosts"`
		HostsMap            map[string]*Host       `json:"-"`
		Clusters            []*Cluster             `json:"clusters"`
		Misc                map[string]interface{} `json:"Misc"`
	}
)

// ValidateConf takes the json Config, validates some input and propagate parameters
func ValidateConf(config *Config, noKey bool) error {
	zeroPKA := uint16(0)
	emptyStringList := []string{}

	config.PersistentKeepalive = validatePersistentKeepalive(config.PersistentKeepalive, &zeroPKA)
	config.ListenPort = validateListenPort(config.ListenPort, 17815)
	config.Iface = validateIface(config.Iface, "wg")

	ipv6, netv6, err := net.ParseCIDR(strings.ToLower(config.IPv6Prefix))
	if err != nil {
		return err
	}
	cidrv6, _ := netv6.Mask.Size()

	if cidrv6 > 96 {
		return fmt.Errorf("invalid cidr %v must be at most 96", cidrv6)
	}

	prefixv6 := strings.TrimRight(ipv6.Mask(net.CIDRMask(96, 128)).String(), ":") + ":"

	for i := range config.Clusters {
		config.Clusters[i].Templates = validateTemplates(config.Clusters[i].Templates, emptyStringList)
	}

	if config.HostsMap == nil {
		config.HostsMap = make(map[string]*Host)
	}

	for i := range config.Hosts {
		config.Hosts[i].Name = strings.Trim(config.Hosts[i].Name, " \t\r\n")
		if config.Hosts[i].Name == "" {
			return fmt.Errorf("invalid hostname for host %v", i)
		}

		config.HostsMap[config.Hosts[i].Name] = config.Hosts[i]

		config.Hosts[i].Templates = validateTemplates(config.Hosts[i].Templates, emptyStringList)
		config.Hosts[i].PersistentKeepalive = validatePersistentKeepalive(config.Hosts[i].PersistentKeepalive, config.PersistentKeepalive)
		config.Hosts[i].ListenPort = validateListenPort(config.Hosts[i].ListenPort, config.ListenPort)
		config.Hosts[i].Iface = validateIface(config.Hosts[i].Iface, config.Iface)

		switch config.Hosts[i].PrivateIPv6CIDR {
		case "":
			ipv6, err := generatePrivateIPv6FromHostname(prefixv6, config.Hosts[i].Name)
			if err != nil {
				return err
			}
			config.Hosts[i].PrivateIPv6CIDR = ipv6 + "/" + strconv.Itoa(cidrv6)
			config.Hosts[i].PrivateIPv6 = ipv6
			config.Hosts[i].AllowedIPv6 = []string{ipv6 + "/128"}
		default:
			ipv6, netv6, err := net.ParseCIDR(strings.ToLower(config.Hosts[i].PrivateIPv6CIDR))
			if err != nil {
				return err
			}
			cidrv6, _ := netv6.Mask.Size()
			if cidrv6 > 96 {
				return fmt.Errorf("invalid cidr %v must be at most 96 for host %q", cidrv6, config.Hosts[i].Name)
			}

			config.Hosts[i].PrivateIPv6 = ipv6.String()
			config.Hosts[i].AllowedIPv6 = []string{ipv6.String() + "/128"}
		}

		if err := generateConfigKeyPairs(config.Hosts[i], noKey); err != nil {
			return err
		}
	}

	return nil
}

func generateConfigKeyPairs(host *Host, noKey bool) error {
	// don't generate any key even if there is already a public key
	if noKey {
		host.PrivateKey = fmt.Sprintf("<private key for %q >", host.Name)
		host.PublicKey = fmt.Sprintf("<public key for %q >", host.Name)
		return nil
	}

	// use the already known keys
	if host.PublicKey != "" {
		host.PrivateKey = fmt.Sprintf("<please replace this with the corresponding private key for host %q >", host.Name)
		return nil
	}

	privk, pubk, err := GenKeyPair()
	if err != nil {
		return fmt.Errorf("can't generate keypair for host %q : %v", host.Name, err)
	}
	host.PrivateKey = privk
	host.PublicKey = pubk

	return nil
}

func validatePersistentKeepalive(proposed, fallback *uint16) *uint16 {
	if proposed == nil {
		return fallback
	}
	return proposed
}

func validateListenPort(proposed, fallback uint16) uint16 {
	if proposed == 0 {
		return fallback
	}
	return proposed
}

func validateIface(proposed, fallback string) string {
	cleaned := strings.Trim(proposed, " \t\r\n")
	if cleaned == "" {
		return fallback
	}
	return cleaned
}

func validateTemplates(proposed, fallback []string) []string {
	if proposed == nil {
		return fallback
	}
	cleaned := make([]string, 0, len(proposed))
	for _, p := range proposed {
		c := strings.Trim(p, " \t\r\n")
		if c != "" {
			cleaned = append(cleaned, c)
		}
	}

	if len(cleaned) == 0 {
		return fallback
	}
	return cleaned
}

func generatePrivateIPv6FromHostname(prefix, hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", fmt.Errorf("Warning : can't resolv to IP for host %q : %v", hostname, err)
	}

	for i := range ips {
		IPv4 := ips[i].To4()
		if IPv4 == nil {
			continue
		}

		ip := fmt.Sprintf("%02x%02x:%02x%02x", ips[i][12], ips[i][13], ips[i][14], ips[i][15])

		return prefix + ip, nil
	}

	return "", fmt.Errorf("Warning : no valid IPv4 found for %q", hostname)

}
