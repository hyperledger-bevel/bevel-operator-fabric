(window.webpackJsonp=window.webpackJsonp||[]).push([[46],{117:function(e,n,t){"use strict";t.r(n),t.d(n,"frontMatter",(function(){return c})),t.d(n,"metadata",(function(){return i})),t.d(n,"toc",(function(){return s})),t.d(n,"default",(function(){return p}));var a=t(3),r=t(7),l=(t(0),t(129)),o=["components"],c={id:"getting-started",title:"Getting started"},i={unversionedId:"getting-started",id:"getting-started",isDocsHomePage:!1,title:"Getting started",description:"Tutorial",source:"@site/docs/getting-started.md",slug:"/getting-started",permalink:"/bevel-operator-fabric/docs/getting-started",editUrl:"https://github.com/hyperledger/bevel-operator-fabric/edit/master/website/docs/getting-started.md",version:"current",sidebar:"someSidebar1",previous:{title:"Introduction",permalink:"/bevel-operator-fabric/docs/"},next:{title:"LevelDB / CouchDB",permalink:"/bevel-operator-fabric/docs/operator-guide/state-db"}},s=[{value:"Create Kubernetes Cluster",id:"create-kubernetes-cluster",children:[]},{value:"Install Kubernetes operator",id:"install-kubernetes-operator",children:[{value:"Install the Kubectl plugin",id:"install-the-kubectl-plugin",children:[]},{value:"Install Istio",id:"install-istio",children:[]}]},{value:"Deploy a <code>Peer</code> organization",id:"deploy-a-peer-organization",children:[{value:"Environment Variables for AMD (Default)",id:"environment-variables-for-amd-default",children:[]},{value:"Environment Variables for ARM (Mac M1)",id:"environment-variables-for-arm-mac-m1",children:[]},{value:"Configurar DNS interno",id:"configurar-dns-interno",children:[]},{value:"Deploy a certificate authority",id:"deploy-a-certificate-authority",children:[]},{value:"Deploy a peer",id:"deploy-a-peer",children:[]}]},{value:"Deploy an <code>Orderer</code> organization",id:"deploy-an-orderer-organization",children:[{value:"Create the certification authority",id:"create-the-certification-authority",children:[]},{value:"Register user <code>orderer</code>",id:"register-user-orderer",children:[]},{value:"Deploy orderer",id:"deploy-orderer",children:[]}]},{value:"Prepare connection string to interact with orderer",id:"prepare-connection-string-to-interact-with-orderer",children:[]},{value:"Create channel",id:"create-channel",children:[{value:"Register and enrolling OrdererMSP identity",id:"register-and-enrolling-orderermsp-identity",children:[]},{value:"Register and enrolling Org1MSP identity",id:"register-and-enrolling-org1msp-identity",children:[]},{value:"Create the secret",id:"create-the-secret",children:[]},{value:"Create main channel",id:"create-main-channel",children:[]}]},{value:"Join peer to the channel",id:"join-peer-to-the-channel",children:[]},{value:"Install a chaincode",id:"install-a-chaincode",children:[{value:"Prepare connection string for a peer",id:"prepare-connection-string-for-a-peer",children:[]},{value:"Create metadata file",id:"create-metadata-file",children:[]},{value:"Prepare connection file",id:"prepare-connection-file",children:[]}]},{value:"Deploy chaincode container on cluster",id:"deploy-chaincode-container-on-cluster",children:[]},{value:"Check installed chaincodes",id:"check-installed-chaincodes",children:[]},{value:"Approve chaincode",id:"approve-chaincode",children:[]},{value:"Commit chaincode",id:"commit-chaincode",children:[]},{value:"Invoke a transaction on the channel",id:"invoke-a-transaction-on-the-channel",children:[]},{value:"Query assets in the channel",id:"query-assets-in-the-channel",children:[]},{value:"Cleanup the environment",id:"cleanup-the-environment",children:[]},{value:"Troubleshooting",id:"troubleshooting",children:[{value:"Chaincode installation/build error",id:"chaincode-installationbuild-error",children:[]}]}],d={toc:s};function p(e){var n=e.components,t=Object(r.a)(e,o);return Object(l.b)("wrapper",Object(a.a)({},d,t,{components:n,mdxType:"MDXLayout"}),Object(l.b)("h1",{id:"tutorial"},"Tutorial"),Object(l.b)("p",null,"Resources:"),Object(l.b)("ul",null,Object(l.b)("li",{parentName:"ul"},Object(l.b)("a",{parentName:"li",href:"https://www.polarsparc.com/xhtml/Hyperledger-ARM-Build.html"},"Hyperledger Fabric build ARM"))),Object(l.b)("h2",{id:"create-kubernetes-cluster"},"Create Kubernetes Cluster"),Object(l.b)("p",null,"To start deploying our red fabric we have to have a Kubernetes cluster. For this we will use KinD."),Object(l.b)("p",null,"Ensure you have these ports available before creating the cluster:"),Object(l.b)("ul",null,Object(l.b)("li",{parentName:"ul"},"80"),Object(l.b)("li",{parentName:"ul"},"443")),Object(l.b)("p",null,"If these ports are not available this tutorial will not work."),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"cat << EOF > kind-config.yaml\nkind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n  extraPortMappings:\n  - containerPort: 30949\n    hostPort: 80\n  - containerPort: 30950\n    hostPort: 443\nEOF\n\nkind create cluster --config=./kind-config.yaml\n\n")),Object(l.b)("h2",{id:"install-kubernetes-operator"},"Install Kubernetes operator"),Object(l.b)("p",null,"In this step we are going to install the kubernetes operator for Fabric, this will install:"),Object(l.b)("ul",null,Object(l.b)("li",{parentName:"ul"},"CRD (Custom Resource Definitions) to deploy Certification Fabric Peers, Orderers and Authorities"),Object(l.b)("li",{parentName:"ul"},"Deploy the program to deploy the nodes in Kubernetes")),Object(l.b)("p",null,"To install helm: ",Object(l.b)("a",{parentName:"p",href:"https://helm.sh/docs/intro/install/"},"https://helm.sh/docs/intro/install/")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"helm repo add kfs https://kfsoftware.github.io/hlf-helm-charts --force-update\n\nhelm install hlf-operator --version=1.8.0 kfs/hlf-operator\n")),Object(l.b)("h3",{id:"install-the-kubectl-plugin"},"Install the Kubectl plugin"),Object(l.b)("p",null,"To install the kubectl plugin, you must first install Krew:\n",Object(l.b)("a",{parentName:"p",href:"https://krew.sigs.k8s.io/docs/user-guide/setup/install/"},"https://krew.sigs.k8s.io/docs/user-guide/setup/install/")),Object(l.b)("p",null,"Afterwards, the plugin can be installed with the following command:"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl krew install hlf\n")),Object(l.b)("h3",{id:"install-istio"},"Install Istio"),Object(l.b)("p",null,"Install Istio binaries on the machine:"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"curl -L https://istio.io/downloadIstio | sh -\n")),Object(l.b)("p",null,"Install Istio on the Kubernetes cluster:"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"\nkubectl create namespace istio-system\n\nistioctl operator init\n\nkubectl apply -f - <<EOF\napiVersion: install.istio.io/v1alpha1\nkind: IstioOperator\nmetadata:\n  name: istio-gateway\n  namespace: istio-system\nspec:\n  addonComponents:\n    grafana:\n      enabled: false\n    kiali:\n      enabled: false\n    prometheus:\n      enabled: false\n    tracing:\n      enabled: false\n  components:\n    ingressGateways:\n      - enabled: true\n        k8s:\n          hpaSpec:\n            minReplicas: 1\n          resources:\n            limits:\n              cpu: 500m\n              memory: 512Mi\n            requests:\n              cpu: 100m\n              memory: 128Mi\n          service:\n            ports:\n              - name: http\n                port: 80\n                targetPort: 8080\n                nodePort: 30949\n              - name: https\n                port: 443\n                targetPort: 8443\n                nodePort: 30950\n            type: NodePort\n        name: istio-ingressgateway\n    pilot:\n      enabled: true\n      k8s:\n        hpaSpec:\n          minReplicas: 1\n        resources:\n          limits:\n            cpu: 300m\n            memory: 512Mi\n          requests:\n            cpu: 100m\n            memory: 128Mi\n  meshConfig:\n    accessLogFile: /dev/stdout\n    enableTracing: false\n    outboundTrafficPolicy:\n      mode: ALLOW_ANY\n  profile: default\n\nEOF\n\n")),Object(l.b)("h2",{id:"deploy-a-peer-organization"},"Deploy a ",Object(l.b)("inlineCode",{parentName:"h2"},"Peer")," organization"),Object(l.b)("h3",{id:"environment-variables-for-amd-default"},"Environment Variables for AMD (Default)"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"export PEER_IMAGE=hyperledger/fabric-peer\nexport PEER_VERSION=2.4.6\n\nexport ORDERER_IMAGE=hyperledger/fabric-orderer\nexport ORDERER_VERSION=2.4.6\n\n")),Object(l.b)("h3",{id:"environment-variables-for-arm-mac-m1"},"Environment Variables for ARM (Mac M1)"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"export PEER_IMAGE=bswamina/fabric-peer\nexport PEER_VERSION=2.4.6\n\nexport ORDERER_IMAGE=bswamina/fabric-orderer\nexport ORDERER_VERSION=2.4.6\n\n")),Object(l.b)("h3",{id:"configurar-dns-interno"},"Configurar DNS interno"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"CLUSTER_IP=$(kubectl -n istio-system get svc istio-ingressgateway -o json | jq -r .spec.clusterIP)\nkubectl apply -f - <<EOF\nkind: ConfigMap\napiVersion: v1\nmetadata:\n  name: coredns\n  namespace: kube-system\ndata:\n  Corefile: |\n    .:53 {\n        errors\n        health {\n           lameduck 5s\n        }\n        rewrite name regex (.*)\\.localho\\.st host.ingress.internal\n        hosts {\n          ${CLUSTER_IP} host.ingress.internal\n          fallthrough\n        }\n        ready\n        kubernetes cluster.local in-addr.arpa ip6.arpa {\n           pods insecure\n           fallthrough in-addr.arpa ip6.arpa\n           ttl 30\n        }\n        prometheus :9153\n        forward . /etc/resolv.conf {\n           max_concurrent 1000\n        }\n        cache 30\n        loop\n        reload\n        loadbalance\n    }\nEOF\n")),Object(l.b)("h3",{id:"deploy-a-certificate-authority"},"Deploy a certificate authority"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"\nkubectl hlf ca create --storage-class=standard --capacity=1Gi --name=org1-ca \\\n    --enroll-id=enroll --enroll-pw=enrollpw --hosts=org1-ca.localho.st --istio-port=443\n\nkubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all\n")),Object(l.b)("p",null,"Check that the certification authority is deployed and works:"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"curl -k https://org1-ca.localho.st:443/cainfo\n")),Object(l.b)("p",null,"Register a user in the certification authority of the peer organization (Org1MSP)"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"# register user in CA for peers\nkubectl hlf ca register --name=org1-ca --user=peer --secret=peerpw --type=peer \\\n --enroll-id enroll --enroll-secret=enrollpw --mspid Org1MSP\n\n")),Object(l.b)("h3",{id:"deploy-a-peer"},"Deploy a peer"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf peer create --statedb=couchdb --image=$PEER_IMAGE --version=$PEER_VERSION --storage-class=standard --enroll-id=peer --mspid=Org1MSP \\\n        --enroll-pw=peerpw --capacity=5Gi --name=org1-peer0 --ca-name=org1-ca.default \\\n        --hosts=peer0-org1.localho.st --istio-port=443\n\n\nkubectl hlf peer create --statedb=couchdb --image=$PEER_IMAGE --version=$PEER_VERSION --storage-class=standard --enroll-id=peer --mspid=Org1MSP \\\n        --enroll-pw=peerpw --capacity=5Gi --name=org1-peer1 --ca-name=org1-ca.default \\\n        --hosts=peer1-org1.localho.st --istio-port=443\n\nkubectl wait --timeout=180s --for=condition=Running fabricpeers.hlf.kungfusoftware.es --all\n")),Object(l.b)("p",null,"Check that the peer is deployed and works:"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"curl -vik https://peer0-org1.localho.st:443\n")),Object(l.b)("h2",{id:"deploy-an-orderer-organization"},"Deploy an ",Object(l.b)("inlineCode",{parentName:"h2"},"Orderer")," organization"),Object(l.b)("p",null,"To deploy an ",Object(l.b)("inlineCode",{parentName:"p"},"Orderer")," organization we have to:"),Object(l.b)("ol",null,Object(l.b)("li",{parentName:"ol"},"Create a certification authority"),Object(l.b)("li",{parentName:"ol"},"Register user ",Object(l.b)("inlineCode",{parentName:"li"},"orderer")," with password ",Object(l.b)("inlineCode",{parentName:"li"},"ordererpw")),Object(l.b)("li",{parentName:"ol"},"Create orderer")),Object(l.b)("h3",{id:"create-the-certification-authority"},"Create the certification authority"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"\nkubectl hlf ca create --storage-class=standard --capacity=1Gi --name=ord-ca \\\n    --enroll-id=enroll --enroll-pw=enrollpw --hosts=ord-ca.localho.st --istio-port=443\n\nkubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all\n\n")),Object(l.b)("p",null,"Check that the certification authority is deployed and works:"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"curl -vik https://ord-ca.localho.st:443/cainfo\n")),Object(l.b)("h3",{id:"register-user-orderer"},"Register user ",Object(l.b)("inlineCode",{parentName:"h3"},"orderer")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},'kubectl hlf ca register --name=ord-ca --user=orderer --secret=ordererpw \\\n    --type=orderer --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP --ca-url="https://ord-ca.localho.st:443"\n\n')),Object(l.b)("h3",{id:"deploy-orderer"},"Deploy orderer"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \\\n    --storage-class=standard --enroll-id=orderer --mspid=OrdererMSP \\\n    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node1 --ca-name=ord-ca.default \\\n    --hosts=orderer0-ord.localho.st --istio-port=443\n\nkubectl wait --timeout=180s --for=condition=Running fabricorderernodes.hlf.kungfusoftware.es --all\n")),Object(l.b)("p",null,"Check that the orderer is running:"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl get pods\n")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"curl -vik https://orderer0-ord.localho.st:443\n")),Object(l.b)("h2",{id:"prepare-connection-string-to-interact-with-orderer"},"Prepare connection string to interact with orderer"),Object(l.b)("p",null,"To prepare the connection string, we have to:"),Object(l.b)("ul",null,Object(l.b)("li",{parentName:"ul"},"Get the connection string without users"),Object(l.b)("li",{parentName:"ul"},"Register a user in the certification authority for signature"),Object(l.b)("li",{parentName:"ul"},"Get the certificates using the user created above"),Object(l.b)("li",{parentName:"ul"},"Attach the user to the connection string")),Object(l.b)("ol",null,Object(l.b)("li",{parentName:"ol"},"Get the connection string without users")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf inspect --output ordservice.yaml -o OrdererMSP\n")),Object(l.b)("ol",{start:2},Object(l.b)("li",{parentName:"ol"},"Register a user in the TLS certification authority")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf ca register --name=ord-ca --user=admin --secret=adminpw \\\n    --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP\n")),Object(l.b)("ol",{start:3},Object(l.b)("li",{parentName:"ol"},"Get the certificates using the certificate")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf ca enroll --name=ord-ca --user=admin --secret=adminpw --mspid OrdererMSP \\\n        --ca-name ca  --output admin-ordservice.yaml\n")),Object(l.b)("ol",{start:4},Object(l.b)("li",{parentName:"ol"},"Attach the user to the connection string")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre"},"kubectl hlf utils adduser --userPath=admin-ordservice.yaml --config=ordservice.yaml --username=admin --mspid=OrdererMSP\n")),Object(l.b)("h2",{id:"create-channel"},"Create channel"),Object(l.b)("p",null,"To create the channel we need to first create the wallet secret, which will contain the identities used by the operator to manage the channel"),Object(l.b)("h3",{id:"register-and-enrolling-orderermsp-identity"},"Register and enrolling OrdererMSP identity"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"# register\nkubectl hlf ca register --name=ord-ca --user=admin --secret=adminpw \\\n    --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP\n\n# enroll\n\nkubectl hlf ca enroll --name=ord-ca --namespace=default \\\n    --user=admin --secret=adminpw --mspid OrdererMSP \\\n    --ca-name tlsca  --output orderermsp.yaml\n")),Object(l.b)("h3",{id:"register-and-enrolling-org1msp-identity"},"Register and enrolling Org1MSP identity"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"# register\nkubectl hlf ca register --name=org1-ca --namespace=default --user=admin --secret=adminpw \\\n    --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=Org1MSP\n\n# enroll\nkubectl hlf ca enroll --name=org1-ca --namespace=default \\\n    --user=admin --secret=adminpw --mspid Org1MSP \\\n    --ca-name ca  --output org1msp.yaml\n\n")),Object(l.b)("h3",{id:"create-the-secret"},"Create the secret"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"\nkubectl create secret generic wallet --namespace=default \\\n        --from-file=org1msp.yaml=$PWD/org1msp.yaml \\\n        --from-file=orderermsp.yaml=$PWD/orderermsp.yaml\n")),Object(l.b)("h3",{id:"create-main-channel"},"Create main channel"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},'export PEER_ORG_SIGN_CERT=$(kubectl get fabriccas org1-ca -o=jsonpath=\'{.status.ca_cert}\')\nexport PEER_ORG_TLS_CERT=$(kubectl get fabriccas org1-ca -o=jsonpath=\'{.status.tlsca_cert}\')\nexport IDENT_8=$(printf "%8s" "")\nexport ORDERER_TLS_CERT=$(kubectl get fabriccas ord-ca -o=jsonpath=\'{.status.tlsca_cert}\' | sed -e "s/^/${IDENT_8}/" )\nexport ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath=\'{.status.tlsCert}\' | sed -e "s/^/${IDENT_8}/" )\n\nkubectl apply -f - <<EOF\napiVersion: hlf.kungfusoftware.es/v1alpha1\nkind: FabricMainChannel\nmetadata:\n  name: demo\nspec:\n  name: demo\n  adminOrdererOrganizations:\n    - mspID: OrdererMSP\n  adminPeerOrganizations:\n    - mspID: Org1MSP\n  channelConfig:\n    application:\n      acls: null\n      capabilities:\n        - V2_0\n      policies: null\n    capabilities:\n      - V2_0\n    orderer:\n      batchSize:\n        absoluteMaxBytes: 1048576\n        maxMessageCount: 10\n        preferredMaxBytes: 524288\n      batchTimeout: 2s\n      capabilities:\n        - V2_0\n      etcdRaft:\n        options:\n          electionTick: 10\n          heartbeatTick: 1\n          maxInflightBlocks: 5\n          snapshotIntervalSize: 16777216\n          tickInterval: 500ms\n      ordererType: etcdraft\n      policies: null\n      state: STATE_NORMAL\n    policies: null\n  externalOrdererOrganizations: []\n  peerOrganizations:\n    - mspID: Org1MSP\n      caName: "org1-ca"\n      caNamespace: "default"\n  identities:\n    OrdererMSP:\n      secretKey: orderermsp.yaml\n      secretName: wallet\n      secretNamespace: default\n    Org1MSP:\n      secretKey: org1msp.yaml\n      secretName: wallet\n      secretNamespace: default\n  externalPeerOrganizations: []\n  ordererOrganizations:\n    - caName: "ord-ca"\n      caNamespace: "default"\n      externalOrderersToJoin:\n        - host: ord-node1\n          port: 7053\n      mspID: OrdererMSP\n      ordererEndpoints:\n        - ord-node1:7050\n      orderersToJoin: []\n  orderers:\n    - host: ord-node1\n      port: 7050\n      tlsCert: |-\n${ORDERER0_TLS_CERT}\n\nEOF\n')),Object(l.b)("h2",{id:"join-peer-to-the-channel"},"Join peer to the channel"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},'\nexport IDENT_8=$(printf "%8s" "")\nexport ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath=\'{.status.tlsCert}\' | sed -e "s/^/${IDENT_8}/" )\n\nkubectl apply -f - <<EOF\napiVersion: hlf.kungfusoftware.es/v1alpha1\nkind: FabricFollowerChannel\nmetadata:\n  name: demo-org1msp\nspec:\n  anchorPeers:\n    - host: org1-peer0.default\n      port: 7051\n  hlfIdentity:\n    secretKey: org1msp.yaml\n    secretName: wallet\n    secretNamespace: default\n  mspId: Org1MSP\n  name: demo\n  externalPeersToJoin: []\n  orderers:\n    - certificate: |\n${ORDERER0_TLS_CERT}\n      url: grpcs://ord-node1.default:7050\n  peersToJoin:\n    - name: org1-peer0\n      namespace: default\n    - name: org1-peer1\n      namespace: default\nEOF\n\n\n')),Object(l.b)("h2",{id:"install-a-chaincode"},"Install a chaincode"),Object(l.b)("h3",{id:"prepare-connection-string-for-a-peer"},"Prepare connection string for a peer"),Object(l.b)("p",null,"To prepare the connection string, we have to:"),Object(l.b)("ol",null,Object(l.b)("li",{parentName:"ol"},Object(l.b)("p",{parentName:"li"},"Get connection string without users for organization Org1MSP and OrdererMSP")),Object(l.b)("li",{parentName:"ol"},Object(l.b)("p",{parentName:"li"},"Register a user in the certification authority for signing (register)")),Object(l.b)("li",{parentName:"ol"},Object(l.b)("p",{parentName:"li"},"Obtain the certificates using the previously created user (enroll)")),Object(l.b)("li",{parentName:"ol"},Object(l.b)("p",{parentName:"li"},"Attach the user to the connection string")),Object(l.b)("li",{parentName:"ol"},Object(l.b)("p",{parentName:"li"},"Get connection string without users for organization Org1MSP and OrdererMSP"))),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf inspect --output org1.yaml -o Org1MSP -o OrdererMSP\n")),Object(l.b)("ol",{start:2},Object(l.b)("li",{parentName:"ol"},"Register a user in the certification authority for signing")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf ca register --name=org1-ca --user=admin --secret=adminpw --type=admin \\\n --enroll-id enroll --enroll-secret=enrollpw --mspid Org1MSP  \n")),Object(l.b)("ol",{start:3},Object(l.b)("li",{parentName:"ol"},"Get the certificates using the user created above")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf ca enroll --name=org1-ca --user=admin --secret=adminpw --mspid Org1MSP \\\n        --ca-name ca  --output peer-org1.yaml\n")),Object(l.b)("ol",{start:4},Object(l.b)("li",{parentName:"ol"},"Attach the user to the connection string")),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf utils adduser --userPath=peer-org1.yaml --config=org1.yaml --username=admin --mspid=Org1MSP\n")),Object(l.b)("h3",{id:"create-metadata-file"},"Create metadata file"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},'# remove the code.tar.gz chaincode.tgz if they exist\nrm code.tar.gz chaincode.tgz\nexport CHAINCODE_NAME=asset\nexport CHAINCODE_LABEL=asset\ncat << METADATA-EOF > "metadata.json"\n{\n    "type": "ccaas",\n    "label": "${CHAINCODE_LABEL}"\n}\nMETADATA-EOF\n## chaincode as a service\n')),Object(l.b)("h3",{id:"prepare-connection-file"},"Prepare connection file"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},'cat > "connection.json" <<CONN_EOF\n{\n  "address": "${CHAINCODE_NAME}:7052",\n  "dial_timeout": "10s",\n  "tls_required": false\n}\nCONN_EOF\n\ntar cfz code.tar.gz connection.json\ntar cfz chaincode.tgz metadata.json code.tar.gz\nexport PACKAGE_ID=$(kubectl hlf chaincode calculatepackageid --path=chaincode.tgz --language=node --label=$CHAINCODE_LABEL)\necho "PACKAGE_ID=$PACKAGE_ID"\n\nkubectl hlf chaincode install --path=./chaincode.tgz \\\n    --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL --user=admin --peer=org1-peer0.default\nkubectl hlf chaincode install --path=./chaincode.tgz \\\n    --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL --user=admin --peer=org1-peer1.default\n\n')),Object(l.b)("h2",{id:"deploy-chaincode-container-on-cluster"},"Deploy chaincode container on cluster"),Object(l.b)("p",null,"The following command will create or update the CRD based on the packageID, chaincode name, and docker image."),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf externalchaincode sync --image=kfsoftware/chaincode-external:latest \\\n    --name=$CHAINCODE_NAME \\\n    --namespace=default \\\n    --package-id=$PACKAGE_ID \\\n    --tls-required=false \\\n    --replicas=1\n")),Object(l.b)("h2",{id:"check-installed-chaincodes"},"Check installed chaincodes"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf chaincode queryinstalled --config=org1.yaml --user=admin --peer=org1-peer0.default\n")),Object(l.b)("h2",{id:"approve-chaincode"},"Approve chaincode"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},'export SEQUENCE=1\nexport VERSION="1.0"\nkubectl hlf chaincode approveformyorg --config=org1.yaml --user=admin --peer=org1-peer0.default \\\n    --package-id=$PACKAGE_ID \\\n    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \\\n    --policy="OR(\'Org1MSP.member\')" --channel=demo\n')),Object(l.b)("h2",{id:"commit-chaincode"},"Commit chaincode"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},'kubectl hlf chaincode commit --config=org1.yaml --user=admin --mspid=Org1MSP \\\n    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \\\n    --policy="OR(\'Org1MSP.member\')" --channel=demo\n')),Object(l.b)("h2",{id:"invoke-a-transaction-on-the-channel"},"Invoke a transaction on the channel"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf chaincode invoke --config=org1.yaml \\\n    --user=admin --peer=org1-peer0.default \\\n    --chaincode=asset --channel=demo \\\n    --fcn=initLedger -a '[]'\n")),Object(l.b)("h2",{id:"query-assets-in-the-channel"},"Query assets in the channel"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf chaincode query --config=org1.yaml \\\n    --user=admin --peer=org1-peer0.default \\\n    --chaincode=asset --channel=demo \\\n    --fcn=GetAllAssets -a '[]'\n")),Object(l.b)("p",null,"At this point, you should have:"),Object(l.b)("ul",null,Object(l.b)("li",{parentName:"ul"},"Ordering service with 1 nodes and a CA"),Object(l.b)("li",{parentName:"ul"},"Peer organization with a peer and a CA"),Object(l.b)("li",{parentName:"ul"},"A channel ",Object(l.b)("strong",{parentName:"li"},"demo")),Object(l.b)("li",{parentName:"ul"},"A chaincode install in peer0"),Object(l.b)("li",{parentName:"ul"},"A chaincode approved and committed")),Object(l.b)("p",null,"If something went wrong or didn't work, please, open an issue."),Object(l.b)("h2",{id:"cleanup-the-environment"},"Cleanup the environment"),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-bash"},"kubectl delete fabricorderernodes.hlf.kungfusoftware.es --all-namespaces --all\nkubectl delete fabricpeers.hlf.kungfusoftware.es --all-namespaces --all\nkubectl delete fabriccas.hlf.kungfusoftware.es --all-namespaces --all\nkubectl delete fabricchaincode.hlf.kungfusoftware.es --all-namespaces --all\n")),Object(l.b)("h2",{id:"troubleshooting"},"Troubleshooting"),Object(l.b)("h3",{id:"chaincode-installationbuild-error"},"Chaincode installation/build error"),Object(l.b)("p",null,"Chaincode installation/build can fail due to unsupported local kubertenes version such as ",Object(l.b)("a",{parentName:"p",href:"https://github.com/kubernetes/minikube"},"minikube"),"."),Object(l.b)("pre",null,Object(l.b)("code",{parentName:"pre",className:"language-shell"},"$ kubectl hlf chaincode install --path=./fixtures/chaincodes/fabcar/go \\\n        --config=org1.yaml --language=golang --label=fabcar --user=admin --peer=org1-peer0.default\n\nError: Transaction processing for endorser [192.168.49.2:31278]: Chaincode status Code: (500) UNKNOWN.\nDescription: failed to invoke backing implementation of 'InstallChaincode': could not build chaincode:\nexternal builder failed: external builder failed to build: external builder 'my-golang-builder' failed:\nexit status 1\n")),Object(l.b)("p",null,"If your purpose is to test the hlf-operator please consider to switch to ",Object(l.b)("a",{parentName:"p",href:"https://github.com/kubernetes-sigs/kind"},"kind")," that is tested and supported."))}p.isMDXComponent=!0},129:function(e,n,t){"use strict";t.d(n,"a",(function(){return p})),t.d(n,"b",(function(){return h}));var a=t(0),r=t.n(a);function l(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function o(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);n&&(a=a.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,a)}return t}function c(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?o(Object(t),!0).forEach((function(n){l(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function i(e,n){if(null==e)return{};var t,a,r=function(e,n){if(null==e)return{};var t,a,r={},l=Object.keys(e);for(a=0;a<l.length;a++)t=l[a],n.indexOf(t)>=0||(r[t]=e[t]);return r}(e,n);if(Object.getOwnPropertySymbols){var l=Object.getOwnPropertySymbols(e);for(a=0;a<l.length;a++)t=l[a],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(r[t]=e[t])}return r}var s=r.a.createContext({}),d=function(e){var n=r.a.useContext(s),t=n;return e&&(t="function"==typeof e?e(n):c(c({},n),e)),t},p=function(e){var n=d(e.components);return r.a.createElement(s.Provider,{value:n},e.children)},b={inlineCode:"code",wrapper:function(e){var n=e.children;return r.a.createElement(r.a.Fragment,{},n)}},u=r.a.forwardRef((function(e,n){var t=e.components,a=e.mdxType,l=e.originalType,o=e.parentName,s=i(e,["components","mdxType","originalType","parentName"]),p=d(t),u=a,h=p["".concat(o,".").concat(u)]||p[u]||b[u]||l;return t?r.a.createElement(h,c(c({ref:n},s),{},{components:t})):r.a.createElement(h,c({ref:n},s))}));function h(e,n){var t=arguments,a=n&&n.mdxType;if("string"==typeof e||a){var l=t.length,o=new Array(l);o[0]=u;var c={};for(var i in n)hasOwnProperty.call(n,i)&&(c[i]=n[i]);c.originalType=e,c.mdxType="string"==typeof e?e:a,o[1]=c;for(var s=2;s<l;s++)o[s]=t[s];return r.a.createElement.apply(null,o)}return r.a.createElement.apply(null,t)}u.displayName="MDXCreateElement"}}]);