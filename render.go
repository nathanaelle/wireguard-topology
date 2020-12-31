package topology // import "github.com/nathanaelle/wireguard-topology"

import (
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"text/template"
)

type (
	Template interface {
		Execute(template string, dest io.Writer, data interface{}) (err error)
	}

	tmpls struct {
		templates map[string]*template.Template
	}

	NetCluster struct {
		Ifaces map[string]*WGInterface
	}

	WGInterface struct {
		Host         string
		Address      string
		LocalIP      string
		Iface        string
		PrivateKey   string
		ListenPort   uint16
		FirewallMark uint32
		Peers        map[string]*WGPeer
		Templates    []string
		Misc         map[string]interface{}
	}

	WGPeer struct {
		Host                string
		PublicKey           string
		PreSharedKey        string
		AllowedIPs          string
		Address             string
		PeerIP              string
		EndPoint            string
		PersistentKeepalive uint16
	}
)

// LoadTemplates compiles all the available templates in a folder (not the subfolders)
// a template is a file with the extension .tmpl
func LoadTemplates(dir string) (Template, error) {
	var err error

	t := &tmpls{
		templates: make(map[string]*template.Template),
	}

	if dir == "" {
		return t, nil
	}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("can't read %q : %v", dir, err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if file.Size() == 0 {
			continue
		}
		if filepath.Ext(file.Name()) != ".tmpl" {
			continue
		}

		fileData, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("can't read template %q : %v", file.Name(), err)
		}
		tmplName := file.Name()
		tmplName = tmplName[0 : len(tmplName)-5]
		t.templates[tmplName], err = template.New(tmplName).Parse(string(fileData))
		if err != nil {
			return nil, fmt.Errorf("can't parse template %q : %v", file.Name(), err)
		}
	}

	return t, nil
}

func (t *tmpls) Execute(template string, dest io.Writer, data interface{}) error {
	if tmpl, ok := t.templates[template]; ok {
		return tmpl.Execute(dest, data)
	}

	return fmt.Errorf("can't load template %q", template)
}

//Render applys templates on the data and export the result in output
func Render(output Output, t Template, clusters map[string]*NetCluster) error {
	for _, cluster := range clusters {
		for _, wgiface := range cluster.Ifaces {
			if err := output.AddFolder(wgiface.Host); err != nil {
				return err
			}

			for _, template := range wgiface.Templates {
				writecloser, err := output.AddEntry(wgiface.Host, template)
				if err != nil {
					return err
				}
				defer writecloser.Close()

				if err := t.Execute(template, writecloser, wgiface); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
