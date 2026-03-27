package export

import (
	"archive/zip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/kfsoftware/hlf-operator/kubectl-hlf/cmd/helpers"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

type exportFopCmd struct {
	outFile string
}

func (c exportFopCmd) validate() error {
	if c.outFile == "" {
		return fmt.Errorf("outFile is required")
	}
	return nil
}

func (c exportFopCmd) run() error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	file, err := os.OpenFile(c.outFile, flags, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	zipw := zip.NewWriter(file)
	defer zipw.Close()
	oclient, err := helpers.GetKubeOperatorClient()
	if err != nil {
		return err
	}
	clientSet, err := helpers.GetKubeClient()
	if err != nil {
		return err
	}
	certAuths, err := helpers.GetClusterCAs(clientSet, oclient, "")
	if err != nil {
		return err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // required for CA communication
	}
	client := &http.Client{Transport: tr}
	for _, fabricCA := range certAuths {
		displayName := fmt.Sprintf("%s_%s", fabricCA.Object.Name, fabricCA.Object.Namespace)
		caURL := fmt.Sprintf("https://%s", fabricCA.PublicURL)
		res, err := client.Get(fmt.Sprintf("%s/cainfo", caURL))
		if err != nil {
			return err
		}
		defer res.Body.Close()
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		baseFileName := fmt.Sprintf("%s", fmt.Sprintf("%s_%s.json", fabricCA.Object.Name, fabricCA.Object.Namespace))
		if err := appendFile(baseFileName, bodyBytes, zipw); err != nil {
			return err
		}
		ca := mapFabricOperationsCA(fabricCA)
		caBytes, err := json.MarshalIndent(ca, "", "  ")
		if err != nil {
			return err
		}
		fileName := fmt.Sprintf("%s/%s/%s", "assets", "Certificate_Authorities", fmt.Sprintf("%s_%s.json", fabricCA.Object.Name, fabricCA.Object.Namespace))
		if err := appendFile(fileName, caBytes, zipw); err != nil {
			return err
		}

		org := FabricOperationsOrg{
			DisplayName:  displayName,
			MspId:        fabricCA.Object.Name,
			Type:         "msp",
			Admins:       nil,
			RootCerts:    []string{fabricCA.Status.CACert},
			TlsRootCerts: []string{fabricCA.Status.TLSCACert},
			FabricNodeOus: FabricNodeOus{
				AdminOuIdentifier: FabricOrgOUIdentifier{
					Certificate:                  fabricCA.Status.CACert,
					OrganizationalUnitIdentifier: "admin",
				},
				ClientOuIdentifier: FabricOrgOUIdentifier{
					Certificate:                  fabricCA.Status.CACert,
					OrganizationalUnitIdentifier: "client",
				},
				Enable: true,
				OrdererOuIdentifier: FabricOrgOUIdentifier{
					Certificate:                  fabricCA.Status.CACert,
					OrganizationalUnitIdentifier: "orderer",
				},
				PeerOuIdentifier: FabricOrgOUIdentifier{
					Certificate:                  fabricCA.Status.CACert,
					OrganizationalUnitIdentifier: "peer",
				},
			},
			HostUrl: "http://console.hlf.kfs.es",
			Name:    displayName,
		}
		orgBytes, err := json.MarshalIndent(org, "", "  ")
		if err != nil {
			return err
		}
		orgFileName := fmt.Sprintf("%s/%s/%s", "assets", "Organizations", fmt.Sprintf("%s_%s.json", fabricCA.Object.Name, fabricCA.Object.Namespace))
		if err := appendFile(orgFileName, orgBytes, zipw); err != nil {
			return err
		}
	}
	return nil
}

func NewExportCmd(stdOut io.Writer, stdErr io.Writer) *cobra.Command {
	c := &exportFopCmd{}
	cmd := &cobra.Command{
		Use: "export",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	cmd.AddCommand(
		newExportCACMD(),
		newExportOrdererCMD(),
		newExportPeerCMD(),
		newExportCACMD(),
		newExportOrgCMD(),
	)
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&c.outFile, "out", "p", "", "ZIP Output file")
	cmd.MarkPersistentFlagRequired("out")
	return cmd
}
