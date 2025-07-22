import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */
const sidebars: SidebarsConfig = {
	// By default, Docusaurus generates a sidebar from the docs folder structure
	mainSidebar: {
		Operator: ["intro/intro", "intro/getting-started", "intro/getting-started-3-0"],
		"Operator Guide": [
			"operator-guide/state-db",
			"operator-guide/monitoring",
			"operator-guide/configuration",
			"operator-guide/migrate-network",
			"operator-guide/increase-resources",
			"operator-guide/increase-storage",
			"operator-guide/renew-certificates",
			"operator-guide/istio",
			"operator-guide/upgrade-hlf-operator",
			"operator-guide/auto-renew-certificates",
		],
		"User Guide": [
			"user-guide/network-config",
			"user-guide/network-config-kubernetes",
			"user-guide/hashicorp-vault",
			"user-guide/create-channel",
			"user-guide/install-chaincode",
			"user-guide/enroll-users",
			"user-guide/develop-chaincode-locally",
		],
		"Chaincode development": [
			"chaincode-development/architecture",
			"chaincode-development/getting-started",
		],
		"Security": [
			"security/revoke-identities",
		],
		"Chaincode deployment": [
			"chaincode-deployment/getting-started",
			"chaincode-deployment/external-chaincode-as-a-service",
			"chaincode-deployment/k8s-builder",
			"chaincode-deployment/install-crd",
		],
		"Channel management": [
			"channel-management/getting-started",
			"channel-management/manage",
		],
		"Kubectl Plugin": ["kubectl-plugin/installation", "kubectl-plugin/upgrade"],
		"Identity": ["identity-crd/manage-identities"],
		"Gateway API": [
			"gateway-api/introduction",
			"gateway-api/getting-started",
			"gateway-api/implementation"
		],
		CouchDB: ["couchdb/external-couchdb", "couchdb/custom-image"],
		"GRPC Proxy": ["grpc-proxy/enable-peers", "grpc-proxy/enable-orderers"],
		"Operations Console": [
			"operations-console/getting-started",
			"operations-console/adding-cas",
			"operations-console/adding-peers",
			"operations-console/adding-orderers",
			"operations-console/adding-orgs",
		],
		"Operator UI": [
			"operator-ui/getting-started",
			"operator-ui/deploy-operator-ui",
			"operator-ui/deploy-operator-api",
		],
	},
	// But you can create a sidebar manually
	/*
	tutorialSidebar: [
	  'intro',
	  'hello',
	  {
		type: 'category',
		label: 'Tutorial',
		items: ['tutorial-basics/create-a-document'],
	  },
	],
	 */
};

export default sidebars;
