package inspect

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"text/template"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/Masterminds/sprig/v3"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/spf13/cobra"
)

const (
	createDesc = `
'inspect' command creates creates a configuration file ready to use for the go sdk`
	createExample = `  kubectl hlf inspect --output hlf-cfg.yaml`
	yamlFormat    = "yaml"
	jsonFormat    = "json"
)

type inspectCmd struct {
	fileOutput    string
	organizations []string
	internal      bool
	format        string
	namespaces    []string
	ordererNodes  []string
	channels      []string
}

func (c *inspectCmd) validate() error {
	return nil
}

type OrderingService struct {
	MSPID        string
	OrderingNode string
}
type OrderingNode struct {
	TLSCert string
	URL     string
}
type Peer struct {
	URL     string
	TLSCert string
}

const tmplGoConfig = `
name: hlf-network
version: 1.0.0
client:
  organization: "{{ .Organization }}"
{{- if not .Organizations }}
organizations: {}
{{- else }}
organizations:
  {{ range $mspID, $org := .Organizations }}
  {{$mspID}}:
    mspid: {{$mspID}}
    cryptoPath: /tmp/cryptopath
    users: {}
{{- if not $org.Peers }}
    peers: []
{{- else }}
    peers:
      {{- range $peer := $org.Peers }}
      - {{ $peer.Name }}
 	  {{- end }}
{{- end }}
{{- if not $org.OrdererNodes }}
    orderers: []
{{- else }}
    orderers:
      {{- range $orderer := $org.OrdererNodes }}
      - {{ $orderer.Name }}
 	  {{- end }}

    {{- end }}
{{- end }}
{{- end }}

{{- if not .Orderers }}
orderers: []
{{- else }}
orderers:
{{- range $orderer := .Orderers }}
  {{$orderer.Name}}:
{{if $.Internal }}
    url: grpcs://{{ $orderer.PrivateURL }}
{{ else }}
    url: grpcs://{{ $orderer.PublicURL }}
{{ end }}
    grpcOptions:
      allow-insecure: false
    tlsCACerts:
      pem: |
{{ or $orderer.Status.TlsCACert $orderer.Status.TlsCert | indent 8 }}
{{- end }}
{{- end }}

{{- if not .Peers }}
peers: {}
{{- else }}
peers:
  {{- range $peer := .Peers }}
  {{$peer.Name}}:
{{if $.Internal }}
    url: grpcs://{{ $peer.PrivateURL }}
{{ else }}
    url: grpcs://{{ $peer.PublicURL }}
{{ end }}
    grpcOptions:
      allow-insecure: false
    tlsCACerts:
      pem: |
{{ $peer.Status.TlsCACert | indent 8 }}
{{- end }}
{{- end }}

{{- if not .CertAuths }}
certificateAuthorities: {}
{{- else }}
certificateAuthorities:
{{- range $ca := .CertAuths }}
  
  {{ $ca.Name }}:
{{if $.Internal }}
    url: https://{{ $ca.PrivateURL }}
{{ else }}
    url: https://{{ $ca.PublicURL }}
{{ end }}
{{if $ca.EnrollID }}
    registrar:
        enrollId: {{ $ca.EnrollID }}
        enrollSecret: "{{ $ca.EnrollPWD }}"
{{ end }}
    caName: ca
    tlsCACerts:
      pem: 
       - |
{{ $ca.Status.TlsCert | indent 12 }}

{{- end }}
{{- end }}

channels:
{{- range $channel := .Channels }}
  {{ $channel }}:
{{- if not $.Orderers }}
    orderers: []
{{- else }}
    orderers:
{{- range $orderer := $.Orderers }}
      - {{$orderer.Name}}
{{- end }}
{{- end }}
{{- if not $.Peers }}
    peers: {}
{{- else }}
    peers:
{{- range $peer := $.Peers }}
       {{$peer.Name}}:
        discover: true
        endorsingPeer: true
        chaincodeQuery: true
        ledgerQuery: true
        eventSource: true
{{- end }}
{{- end }}
{{- end }}

`

func (c *inspectCmd) run(out io.Writer) error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	ns := ""
	certAuths, err := helpers.GetClusterCAs(clientSet, oclient, ns)
	if err != nil {
		return err
	}
	filterByOrgs := len(c.organizations) > 0
	filterByNS := len(c.namespaces) > 0
	filterByOrdererNodes := len(c.ordererNodes) > 0
	var certAuthsFiltered []*helpers.ClusterCA
	for _, certAuth := range certAuths {
		if filterByNS && !utils.Contains(c.namespaces, certAuth.Namespace) {
			continue
		}
		certAuthsFiltered = append(certAuthsFiltered, certAuth)
	}
	clusterOrderersNodes, err := helpers.GetClusterOrdererNodes(clientSet, oclient, "")
	if err != nil {
		return err
	}
	peerOrgs, clusterPeers, err := helpers.GetClusterPeers(clientSet, oclient, ns)
	if err != nil {
		return err
	}
	log.Infof("Found %d organizations", len(peerOrgs))
	orgMap := map[string]*helpers.Organization{}
	for _, ordererNode := range clusterOrderersNodes {
		if filterByNS && !utils.Contains(c.namespaces, ordererNode.Namespace) {
			continue
		}
		if filterByOrdererNodes && !utils.Contains(c.ordererNodes, ordererNode.Name) {
			continue
		}
		if (filterByOrgs && utils.Contains(c.organizations, ordererNode.Spec.MspID)) || !filterByOrgs {
			org, ok := orgMap[ordererNode.Spec.MspID]
			if ok {
				org.OrdererNodes = append(org.OrdererNodes, ordererNode)
			} else {
				orgMap[ordererNode.Spec.MspID] = &helpers.Organization{
					Type:         helpers.OrdererType,
					MspID:        ordererNode.Spec.MspID,
					OrdererNodes: []*helpers.ClusterOrdererNode{ordererNode},
					Peers:        []*helpers.ClusterPeer{},
				}
			}
		}
	}
	for _, v := range peerOrgs {
		if !filterByOrgs {
			orgMap[v.MspID] = v
		} else if filterByOrgs && utils.Contains(c.organizations, v.MspID) {
			orgMap[v.MspID] = v
		}
	}
	var peers []*helpers.ClusterPeer
	for _, peer := range clusterPeers {
		if filterByNS && !utils.Contains(c.namespaces, peer.Namespace) {
			continue
		}
		if (filterByOrgs && utils.Contains(c.organizations, peer.MSPID)) || !filterByOrgs {
			peers = append(peers, peer)
		}
	}

	var orderers []*helpers.ClusterOrdererNode
	for _, orderer := range clusterOrderersNodes {
		if filterByNS && !utils.Contains(c.namespaces, orderer.Namespace) {
			continue
		}
		if filterByOrdererNodes && !utils.Contains(c.ordererNodes, orderer.Name) {
			continue
		}
		if !filterByOrgs {
			orderers = append(orderers, orderer)
		} else if filterByOrgs && utils.Contains(c.organizations, orderer.Item.Spec.MspID) {
			orderers = append(orderers, orderer)
		}
	}
	tmpl, err := template.New("test").Funcs(sprig.HermeticTxtFuncMap()).Parse(tmplGoConfig)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]interface{}{
		"Peers":         peers,
		"Orderers":      orderers,
		"Organizations": orgMap,
		"CertAuths":     certAuthsFiltered,
		"Internal":      c.internal,
		"Channels":      c.channels,
	})
	if err != nil {
		return err
	}

	var data []byte
	if c.format != yamlFormat && c.format != jsonFormat {
		fmt.Fprint(out, "Invalid output format... Default to yaml")
		c.format = yamlFormat
	}

	if c.format == jsonFormat {
		data, err = yaml.YAMLToJSON(buf.Bytes())
		if err != nil {
			return err
		}
	} else {
		data = buf.Bytes()
	}

	if c.fileOutput != "" {
		err = ioutil.WriteFile(c.fileOutput, data, 0644)
		if err != nil {
			return err
		}
	} else {
		_, err = fmt.Fprint(out, string(data))
		if err != nil {
			return err
		}
	}

	return nil
}

func NewInspectHLFConfig(out io.Writer) *cobra.Command {
	c := &inspectCmd{}
	cmd := &cobra.Command{
		Use:     "inspect",
		Short:   "Inspect the components deployed",
		Long:    createDesc,
		Example: createExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(out)
		},
	}

	f := cmd.Flags()
	f.StringVar(&c.fileOutput, "output", "", "Output file")
	f.BoolVar(&c.internal, "internal", false, "Use kubernetes service names")
	f.StringArrayVarP(&c.organizations, "organizations", "o", []string{}, "Organizations to export")
	f.StringArrayVarP(&c.ordererNodes, "ordererNodes", "", []string{}, "Orderer nodes to export")
	f.StringVar(&c.format, "format", yamlFormat, "Connection profile output format (yaml/json)")
	f.StringArrayVarP(&c.namespaces, "namespace", "n", []string{}, "Namespace scope for this request")
	f.StringArrayVarP(&c.channels, "channels", "c", []string{"_default"}, "Channels for the network config")

	return cmd
}
