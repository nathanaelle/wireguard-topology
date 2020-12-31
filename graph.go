package topology // import "github.com/nathanaelle/wireguard-topology"

import "fmt"

type (
	//Graph is a graph of PreSharedKeys between two hosts
	Graph map[string]map[string]string

	//Forest is a set of graph
	Forest struct {
		Nodes  map[string]nothing
		Graphs map[string]Graph
	}

	nothing struct{}

	EdgeFunc func(nodeA, nodeB string) (string, error)
)

var empty nothing = struct{}{}

//NewForest create a set of graphs
func NewForest() *Forest {
	return &Forest{
		Nodes:  make(map[string]nothing),
		Graphs: make(map[string]Graph),
	}
}

//AddNodes prepare a new graph to a set of Graphs
func (f *Forest) AddNodes(nodes []string) {
	for _, node := range nodes {
		f.Nodes[node] = empty
	}
}

//AddDenseSubGraph connects a subset of nodes a dense subgraph
func (f *Forest) AddDenseSubGraph(graphName string, nodes []string, applyOnPair EdgeFunc) error {

	if _, ok := f.Graphs[graphName]; !ok {
		f.Graphs[graphName] = make(map[string]map[string]string, len(f.Nodes))
		for hi := range f.Nodes {
			f.Graphs[graphName][hi] = make(map[string]string)
		}
	}

	// produce a dense graph of len(confs) nodes
	for i, hi := range nodes {
		for j, hj := range nodes {
			if i <= j {
				continue
			}

			psk, err := applyOnPair(hi, hj)
			if err != nil {
				return fmt.Errorf("can't generate psk for host pair %q %q : %v", hi, hj, err)
			}

			if _, ok := f.Graphs[graphName][hi]; !ok {
				return fmt.Errorf(" missing host declaration for %q", hi)
			}

			if _, ok := f.Graphs[graphName][hj]; !ok {
				return fmt.Errorf(" missing host declaration for %q", hj)
			}

			f.Graphs[graphName][hi][hj] = psk
			f.Graphs[graphName][hj][hi] = psk
		}
	}
	return nil
}

func (f *Forest) Len(graphName string) int {
	if _, ok := f.Graphs[graphName]; !ok {
		return 0
	}

	return len(f.Graphs[graphName])
}

func (f *Forest) GetEdge(graphName string, nodeA, nodeB string) (string, bool) {
	if _, ok := f.Graphs[graphName]; !ok {
		return "", false
	}
	if _, ok := f.Graphs[graphName][nodeA]; !ok {
		return "", false
	}
	if _, ok := f.Graphs[graphName][nodeA][nodeB]; !ok {
		return "", false
	}
	return f.Graphs[graphName][nodeA][nodeB], true
}

func (f *Forest) GetEdges(graphName string, node string) ([]string, bool) {
	if _, ok := f.Graphs[graphName]; !ok {
		return nil, false
	}
	if _, ok := f.Graphs[graphName][node]; !ok {
		return nil, false
	}

	ret := make([]string, 0, len(f.Graphs[graphName][node]))

	for k := range f.Graphs[graphName][node] {
		ret = append(ret, k)
	}
	return ret, true
}

func (f *Forest) ForNodes(nodeFunc func(node string) error) error {
	for k := range f.Nodes {
		if err := nodeFunc(k); err != nil {
			return err
		}
	}
	return nil
}
