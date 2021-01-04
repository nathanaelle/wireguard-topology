# Wireguard Topology

## Table of Contents

  * [What is Wireguard Topology](#what-is-wireguard-topology)
  * [Use Case](#use-case)
  * [Usage](#usage)
  * [JSON Configuration](#json-configuration)
  * [Example](#example)
  * [Main Goals](#main-goals)
  * [Security Statements](#security-statements)
  * [License & credits](#license-credits)

  * [To do](#to-do)

## What is Wireguard Topology

Wireguard Topology is a tool that create all the necessary files for `systemd-networkd` to run a full-secured **wireguard VPNs** with optionnaly some others network services like `vxlan`s.

## Use Case

If you have 10 linux servers, and you want to create a **mesh VPN** between them with **Wireguard**, then you have to :

  * generate 10 private keys
  * generate 45 Pre Shared Keys
  * write 20 files and 10 of theses files must list 10 combinaisons of 9 pair of public keys and IP Addresses

If you want to use only 1 `vxlan` to have a **layer 2 VPN** then you will 20 others files and again 10 of theses files must list 10 combinaison of 9 IP Addresses

It's a lot of files, and Wireguard Topology can generate them from only 1 single JSON.

## Usage

### Installation

`go install -u github.com/nathanaelle/wireguard-topology/cmd/wg-topology`

### command line options

  * `-dont-generate-cryptographic-keys` this option is useful for tests or when the crypto part is delegated to another process
  * `-in <JSON source>` this mandatory option specify the JSON source file. "-" means stdin.
  * `-out <destination>` this option specify the destination directory or tar file. the default output destination is the current directory
  * `-tmpl <templates>` this mandatory option specify the templates directory. The template use the official [`text/template`](https://golang.org/pkg/text/template/) grammar.

## JSON configuration

  * `config-name` specify the name of the destination where all the configuration will be created
  * `prefix-ipv6/cidr` mandatory option in case of DNS resolution 
  * `hosts` is a list of unique hosts
    * `host` is a mandatory unique field which should contain a [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) and may contain a unique identifier when `ipv6` is provided
    * `ipv6` is an optionnal field which contains an IPv6. this field will be constructed from the global `prefix-ipv6/cidr` and the first IPv4 found in the resolution of the [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) in `host`.
  * `clusters` is a list of cluster
    * `cluster` is a mandatory non unique field wich describe a dense sub network
    * `members` is the list of [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) which each peer is connected to every others.

You can read the type declaration in [config.go](config.go) to find all the available options.

## Example

the following configuration will produce a VPN where each peer is connected to the 3 others :

```
{
	"config-name" : "1-network",
	"iface": "wg",
	"prefix-ipv6/cidr": "fd00::/16",
	"hosts": [
		{	"host": "n1",	"ipv6": "fd00:dead:1dea::1/96"	},
		{	"host": "n2",	"ipv6": "fd00:dead:1dea::2/96"	},
		{	"host": "n3",	"ipv6": "fd00:dead:1dea::3/96"	},
		{	"host": "n4",	"ipv6": "fd00:dead:1dea::4/96"	}
	],
	"clusters": [
		{
			"cluster": "network",
			"templates": [ "wg.netdev", "wg.network" ],
			"members": [ "n1", "n2", "n3", "n4" ]
		}
	]
}
````

There is others examples in [examples/](examples/)

## Main Goals

  * [x] `systemd-networkd` compliant
  * [x] secure Wireguard mesh with unique PSK per edge
  * [x] can configure `vxlan`s
  * [x] use templating for config files
  * [x] use a linear description for a combinatorial situation
  * [ ] Coping with custom `AllowedIP`

## Security Statements

  * this code was audited 0 time

## License & credits

### License

2-Clause BSD

### Credits

Thanks to [Bruno Bellamy](https://www.facebook.com/bellaminettes) to allow me to use one of his draw as an illustration.

## To do

  * Coping with custom `AllowedIP`
  * cleanup some historical weird stuff in the configuration
  * Improve code comments
  * Improve documentations

