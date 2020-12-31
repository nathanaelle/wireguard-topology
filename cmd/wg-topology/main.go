package main // import "github.com/nathanaelle/wireguard-topology/cmd/wg-topology"

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	wgtplg "github.com/nathanaelle/wireguard-topology"
)

type (
	hostConf struct {
		Name       string
		IPs        []string
		PrivateKey string
		PublicKey  string
	}
)

func main() {
	var inputName string
	var outputDir string
	var tmplDir string
	var noKey bool

	var source io.Reader
	var templates wgtplg.Template

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("can't get current working directory : %v", err)
	}

	flag.StringVar(&inputName, "in", "", "JSON source file. \"-\" means stdin.")
	flag.StringVar(&tmplDir, "tmpl", "", "template directory.")
	flag.StringVar(&outputDir, "out", cwd, "destination directory or tar file.")
	flag.BoolVar(&noKey, "dont-generate-cryptographic-keys", false, "only useful for tests or when this tool is used on a untrusted host.")

	flag.Parse()
	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		return
	}

	switch inputName {
	case "":
		log.Fatal("missing source file")
	case "-":
		source = os.Stdin
	default:
		f, err := os.Open(inputName)
		if err != nil {
			log.Fatalf("can't open file %q : %v", inputName, err)
		}
		source = f
	}

	outputDir = filepath.Clean(outputDir)
	switch outputDir {
	case "":
		log.Fatal("missing destination dir")
	default:
		if outputDir[0:1] != "/" {
			outputDir = filepath.Join(cwd, outputDir)
		}
	}

	tmplDir = filepath.Clean(tmplDir)
	switch tmplDir {
	case "":
		log.Fatal("missing template dir")
	default:
		var err error

		if tmplDir[0:1] != "/" {
			tmplDir = filepath.Join(cwd, tmplDir)
		}

		templates, err = wgtplg.LoadTemplates(tmplDir)
		if err != nil {
			log.Fatalf("can't load templates : %v\n", err)
		}
	}

	jsonDecoder := json.NewDecoder(source)

	for jsonDecoder.More() {
		jsonConf := &wgtplg.Config{}

		if err := jsonDecoder.Decode(jsonConf); err != nil {
			log.Fatalf("can't load config : %v", err)
		}

		if err := wgtplg.ValidateConf(jsonConf, noKey); err != nil {
			log.Fatalf("can't validate conf : %v", err)
		}

		nodes := make([]string, 0, len(jsonConf.Hosts))
		for i := range jsonConf.Hosts {
			nodes = append(nodes, jsonConf.Hosts[i].Name)
		}

		Clusters := wgtplg.NewForest()
		Clusters.AddNodes(nodes)

		edgeFunc := chooseEdgeFunc(noKey)

		for _, cluster := range jsonConf.Clusters {
			if err := Clusters.AddDenseSubGraph(cluster.ClusterName, cluster.Members, edgeFunc); err != nil {
				log.Fatalf("Fatal AddDenseSubGraph %q : %v\n", cluster.ClusterName, err)
			}
		}

		res := make(map[string]*wgtplg.NetCluster, len(jsonConf.Clusters))

		for _, cluster := range jsonConf.Clusters {
			clusterName := cluster.ClusterName
			if _, ok := res[clusterName]; !ok {
				res[clusterName] = &wgtplg.NetCluster{
					Ifaces: make(map[string]*wgtplg.WGInterface, len(nodes)),
				}
			}

			for _, host := range cluster.Members {
				conf := jsonConf.HostsMap[host]
				localName := conf.Name

				if _, ok := res[clusterName].Ifaces[host]; !ok {
					res[clusterName].Ifaces[host] = &wgtplg.WGInterface{
						Host:       localName,
						Iface:      conf.Iface,
						Address:    conf.PrivateIPv6CIDR,
						LocalIP:    conf.PrivateIPv6,
						PrivateKey: conf.PrivateKey,
						ListenPort: conf.ListenPort,
						Peers:      make(map[string]*wgtplg.WGPeer, len(nodes)),
					}
				}

				for _, hostPeer := range cluster.Members {
					confPeer := jsonConf.HostsMap[hostPeer]
					if host == hostPeer {
						continue
					}

					peerName := confPeer.Name
					psk, ok := Clusters.GetEdge(clusterName, host, hostPeer)
					if !ok || psk == "" {
						continue
					}

					res[clusterName].Ifaces[host].Peers[peerName] = &wgtplg.WGPeer{
						Host:                peerName,
						Address:             confPeer.PrivateIPv6CIDR,
						PeerIP:              confPeer.PrivateIPv6,
						PublicKey:           confPeer.PublicKey,
						PreSharedKey:        psk,
						PersistentKeepalive: *conf.PersistentKeepalive,
						AllowedIPs:          strings.Join(confPeer.AllowedIPv6, " , "),
						EndPoint:            fmt.Sprintf("%s:%d", peerName, confPeer.ListenPort),
					}
				}
				templates := make([]string, 0, len(cluster.Templates)+len(conf.Templates))
				templates = append(templates, cluster.Templates...)
				templates = append(templates, conf.Templates...)

				res[clusterName].Ifaces[host].Templates = templates
				res[clusterName].Ifaces[host].Misc = conf.Misc

				//log.Printf("%q -> %q\n", clusterName, localName)
			}
		}

		output := wgtplg.NewDirOutput(filepath.Join(outputDir, jsonConf.ConfigName))
		if err := wgtplg.Render(output, templates, res); err != nil {
			log.Fatalf("Render error : %v", err)
		}

	}

}

func chooseEdgeFunc(noKey bool) wgtplg.EdgeFunc {
	if noKey {
		return func(nodeA, nodeB string) (string, error) {
			return fmt.Sprintf("<secret PSK for ( %q , %q ) >", nodeA, nodeB), nil
		}

	}

	return func(nodeA, nodeB string) (string, error) {
		return wgtplg.GenPSK()
	}
}
