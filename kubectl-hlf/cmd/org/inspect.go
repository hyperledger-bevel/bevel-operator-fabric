package org

import (
	"bytes"
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"github.com/kfsoftware/hlf-operator/controllers/utils"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"text/template"
)

type InspectOptions struct {
	Orgs       []string
	CAs        []string
	OutputPath string
}

func (o InspectOptions) Validate() error {
	return nil
}

const tmplGoConfigtx = `
---
################################################################################
#
#   ORGANIZATIONS
#
#   This section defines the organizational identities that can be referenced
#   in the configuration profiles.
#
################################################################################
Organizations:
{{ range $mspID, $org := .Organizations }}
  # {{$mspID}} defines an MSP using the sampleconfig. It should never be used
  # in production but may be used as a template for other definitions.
  -
    # Name is the key by which this org will be referenced in channel
    # configuration transactions.
    # Name can include alphanumeric characters as well as dots and dashes.
    Name: {{$mspID}}

    # SkipAsForeign can be set to true for org definitions which are to be
    # inherited from the orderer system channel during channel creation.  This
    # is especially useful when an admin of a single org without access to the
    # MSP directories of the other orgs wishes to create a channel.  Note
    # this property must always be set to false for orgs included in block
    # creation.
    SkipAsForeign: false

    # ID is the key by which this org's MSP definition will be referenced.
    # ID can include alphanumeric characters as well as dots and dashes.
    ID: {{$mspID}}

    # MSPDir is the filesystem path which contains the MSP configuration.
    MSPDir: {{$org.MPSDir}}
    MSPType: bccsp

    # Policies defines the set of policies at this level of the config tree
    # For organization policies, their canonical path is usually
    #   /Channel/<Application|Orderer>/<OrgName>/<PolicyName>
    Policies: &{{$mspID}}Policies
      Readers:
        Type: Signature
        Rule: "OR('{{$mspID}}.member')"
        # If your MSP is configured with the new NodeOUs, you might
        # want to use a more specific rule like the following:
        # Rule: "OR('{{$mspID}}.admin', '{{$mspID}}.peer', '{{$mspID}}.client')"
      Writers:
        Type: Signature
        Rule: "OR('{{$mspID}}.member')"
        # If your MSP is configured with the new NodeOUs, you might
        # want to use a more specific rule like the following:
        # Rule: "OR('{{$mspID}}.admin', '{{$mspID}}.client')"
      Admins:
        Type: Signature
        Rule: "OR('{{$mspID}}.admin')"
      Endorsement:
        Type: Signature
        Rule: "OR('{{$mspID}}.member')"
{{- end }}

`

type inspectCmd struct {
	out    io.Writer
	errOut io.Writer
	caOpts InspectOptions
}
type OrganizationItem struct {
	MPSDir string
}

func (c *inspectCmd) validate() error {
	return c.caOpts.Validate()
}
func (c *inspectCmd) run(args []string) error {
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	baseOutputPath := c.caOpts.OutputPath
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	peerOrgs, _, err := helpers.GetClusterPeers(clientSet, oclient, "")
	if err != nil {
		return err
	}
	cas, err := helpers.GetClusterCAs(clientSet, oclient, "")
	if err != nil {
		return err
	}
	orgMap := map[string]OrganizationItem{}
	for _, ca := range cas {
		for _, caNameAndNS := range c.caOpts.CAs {
			chunks := strings.Split(caNameAndNS, ";")
			if len(chunks) != 2 {
				return fmt.Errorf("invalid ca name and namespace: %s", caNameAndNS)
			}
			mspID := chunks[1]
			if !(ca.Name == chunks[0]) {
				continue
			}
			orgPath := path.Join(baseOutputPath, "peerOrganizations", mspID)
			mspPath := path.Join(orgPath, "msp")
			mspCaCerts := path.Join(mspPath, "cacerts")
			mspTLSCaCerts := path.Join(mspPath, "tlscacerts")

			err = os.MkdirAll(mspCaCerts, os.ModePerm)
			if err != nil {
				return err
			}
			err = os.MkdirAll(mspTLSCaCerts, os.ModePerm)
			if err != nil {
				return err
			}
			mspCACertPath := path.Join(mspCaCerts, "ca.pem")
			err = ioutil.WriteFile(mspCACertPath, []byte(ca.Status.CACert), os.ModePerm)
			if err != nil {
				return err
			}
			mspTLSCACertPath := path.Join(mspTLSCaCerts, "tlsca.pem")
			err = ioutil.WriteFile(mspTLSCACertPath, []byte(ca.Status.TLSCACert), os.ModePerm)
			if err != nil {
				return err
			}
			nodeOusContent := `
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/ca.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/ca.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/ca.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/ca.pem
    OrganizationalUnitIdentifier: orderer
`
			nodeOusPath := path.Join(mspPath, "config.yaml")
			err = ioutil.WriteFile(nodeOusPath, []byte(nodeOusContent), 0600)
			if err != nil {
				return err
			}
			orgMap[mspID] = OrganizationItem{MPSDir: mspPath}
		}

	}
	for _, peerOrg := range peerOrgs {
		firstPeer := peerOrg.Peers[0]
		if !utils.Contains(c.caOpts.Orgs, firstPeer.MSPID) {
			continue
		}
		log.Infof("Found peer org %s", peerOrg.MspID)
		caHost := strings.Split(firstPeer.Spec.Secret.Enrollment.Component.Cahost, ".")[0]
		certAuth, err := helpers.GetCertAuthByURL(
			clientSet,
			oclient,
			caHost,
			firstPeer.Spec.Secret.Enrollment.Component.Caport,
		)
		if err != nil {
			return err
		}
		orgPath := path.Join(baseOutputPath, "peerOrganizations", peerOrg.MspID)
		mspPath := path.Join(orgPath, "msp")
		mspCaCerts := path.Join(mspPath, "cacerts")
		mspTLSCaCerts := path.Join(mspPath, "tlscacerts")

		err = os.MkdirAll(mspCaCerts, 0750)
		if err != nil {
			return err
		}
		err = os.MkdirAll(mspTLSCaCerts, 0750)
		if err != nil {
			return err
		}
		mspCACertPath := path.Join(mspCaCerts, "ca.pem")
		err = ioutil.WriteFile(mspCACertPath, []byte(certAuth.Status.CACert), 0600)
		if err != nil {
			return err
		}
		mspTLSCACertPath := path.Join(mspTLSCaCerts, "tlsca.pem")
		err = ioutil.WriteFile(mspTLSCACertPath, []byte(certAuth.Status.TLSCACert), 0600)
		if err != nil {
			return err
		}
		nodeOusContent := `
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/ca.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/ca.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/ca.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/ca.pem
    OrganizationalUnitIdentifier: orderer
`
		nodeOusPath := path.Join(mspPath, "config.yaml")
		err = ioutil.WriteFile(nodeOusPath, []byte(nodeOusContent), 0600)
		if err != nil {
			return err
		}
		orgMap[peerOrg.MspID] = OrganizationItem{MPSDir: mspPath}
	}
	tmpl, err := template.New("test").Funcs(sprig.HermeticTxtFuncMap()).Parse(tmplGoConfigtx)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]interface{}{
		"Organizations": orgMap,
	})
	if err != nil {
		return err
	}
	err = ioutil.WriteFile("configtx.yaml", buf.Bytes(), 0600)
	if err != nil {
		return err
	}
	return nil
}
func newOrgInspectCmd(out io.Writer, errOut io.Writer) *cobra.Command {
	c := inspectCmd{out: out, errOut: errOut}
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inpects and dumps the crypto material for the organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(args)
		},
	}
	f := cmd.Flags()
	f.StringSliceVarP(&c.caOpts.Orgs, "orgs", "o", []string{}, "Organizations to inspect")
	f.StringSliceVarP(&c.caOpts.CAs, "cas", "", []string{}, `Certification authorities to add (orgs without peers) Example: --cas=ca-org1.default;Org1MSP`)
	f.StringVarP(&c.caOpts.OutputPath, "output-path", "", "", "Output path")

	return cmd
}
