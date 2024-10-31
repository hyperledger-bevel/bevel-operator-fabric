"use strict";(self.webpackChunkwebsite_docs=self.webpackChunkwebsite_docs||[]).push([[342],{168:(e,n,r)=>{r.r(n),r.d(n,{assets:()=>o,contentTitle:()=>l,default:()=>h,frontMatter:()=>s,metadata:()=>i,toc:()=>c});var a=r(4848),t=r(8453);const s={id:"getting-started",title:"Getting started"},l="Hyperledger Fabric Operator",i={id:"intro/getting-started",title:"Getting started",description:"Features",source:"@site/docs/intro/getting-started.md",sourceDirName:"intro",slug:"/intro/getting-started",permalink:"/bevel-operator-fabric/docs/intro/getting-started",draft:!1,unlisted:!1,editUrl:"https://github.com/hyperledger-bevel/bevel-operator-fabric/edit/master/website/docs/intro/getting-started.md",tags:[],version:"current",frontMatter:{id:"getting-started",title:"Getting started"},sidebar:"mainSidebar",previous:{title:"Introduction",permalink:"/bevel-operator-fabric/docs/"},next:{title:"Getting started with Hyperledger Fabric 3.0",permalink:"/bevel-operator-fabric/docs/intro/getting-started-3-0"}},o={},c=[{value:"Features",id:"features",level:2},{value:"Stay Up-to-Date",id:"stay-up-to-date",level:2},{value:"Discord",id:"discord",level:2},{value:"Hyperledger Meetups",id:"hyperledger-meetups",level:2},{value:"Tutorial Videos",id:"tutorial-videos",level:2},{value:"Hyperledger Workshops",id:"hyperledger-workshops",level:2},{value:"Sponsor",id:"sponsor",level:2},{value:"Getting started",id:"getting-started",level:2},{value:"Create Kubernetes Cluster",id:"create-kubernetes-cluster",level:2},{value:"Using K3D",id:"using-k3d",level:3},{value:"Using KinD",id:"using-kind",level:3},{value:"Install Kubernetes operator",id:"install-kubernetes-operator",level:2},{value:"Install the Kubectl plugin",id:"install-the-kubectl-plugin",level:3},{value:"Install Istio",id:"install-istio",level:3},{value:"Deploy a <code>Peer</code> organization",id:"deploy-a-peer-organization",level:2},{value:"Environment Variables for AMD (Default)",id:"environment-variables-for-amd-default",level:3},{value:"Environment Variables for ARM (Mac M1)",id:"environment-variables-for-arm-mac-m1",level:3},{value:"Configure Internal DNS",id:"configure-internal-dns",level:3},{value:"Configure Storage Class",id:"configure-storage-class",level:3},{value:"Deploy a certificate authority",id:"deploy-a-certificate-authority",level:3},{value:"Deploy a peer",id:"deploy-a-peer",level:3},{value:"Deploy an <code>Orderer</code> organization",id:"deploy-an-orderer-organization",level:2},{value:"Create the certification authority",id:"create-the-certification-authority",level:3},{value:"Register user <code>orderer</code>",id:"register-user-orderer",level:3},{value:"Deploy orderer",id:"deploy-orderer",level:3},{value:"Create channel",id:"create-channel",level:2},{value:"Register and enrolling OrdererMSP identity",id:"register-and-enrolling-orderermsp-identity",level:3},{value:"Register and enrolling Org1MSP Orderer identity",id:"register-and-enrolling-org1msp-orderer-identity",level:3},{value:"Register and enrolling Org1MSP identity",id:"register-and-enrolling-org1msp-identity",level:3},{value:"Create the secret",id:"create-the-secret",level:3},{value:"Create main channel",id:"create-main-channel",level:3},{value:"Join peer to the channel",id:"join-peer-to-the-channel",level:2},{value:"Install a chaincode",id:"install-a-chaincode",level:2},{value:"Prepare connection string for a peer",id:"prepare-connection-string-for-a-peer",level:3},{value:"Create metadata file",id:"create-metadata-file",level:3},{value:"Prepare connection file",id:"prepare-connection-file",level:3},{value:"Deploy chaincode container on cluster",id:"deploy-chaincode-container-on-cluster",level:2},{value:"Check installed chaincodes",id:"check-installed-chaincodes",level:2},{value:"Approve chaincode",id:"approve-chaincode",level:2},{value:"Commit chaincode",id:"commit-chaincode",level:2},{value:"Invoke a transaction on the channel",id:"invoke-a-transaction-on-the-channel",level:2},{value:"Query assets in the channel",id:"query-assets-in-the-channel",level:2},{value:"Cleanup the environment",id:"cleanup-the-environment",level:2},{value:"Troubleshooting",id:"troubleshooting",level:2},{value:"Chaincode installation/build error",id:"chaincode-installationbuild-error",level:3}];function d(e){const n={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",header:"header",img:"img",input:"input",li:"li",ol:"ol",p:"p",pre:"pre",strong:"strong",table:"table",tbody:"tbody",td:"td",th:"th",thead:"thead",tr:"tr",ul:"ul",...(0,t.R)(),...e.components};return(0,a.jsxs)(a.Fragment,{children:[(0,a.jsx)(n.header,{children:(0,a.jsx)(n.h1,{id:"hyperledger-fabric-operator",children:"Hyperledger Fabric Operator"})}),"\n",(0,a.jsx)(n.h2,{id:"features",children:"Features"}),"\n",(0,a.jsxs)(n.ul,{className:"contains-task-list",children:["\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","Create certificates authorities (CA)"]}),"\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","Create peers"]}),"\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","Create ordering services"]}),"\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","Create resources without manual provisioning of cryptographic material"]}),"\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","Domain routing with SNI using Istio"]}),"\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","Run chaincode as external chaincode in Kubernetes"]}),"\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","Support Hyperledger Fabric 2.3+"]}),"\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","Managed genesis for Ordering services"]}),"\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","E2E testing including the execution of chaincodes in KIND"]}),"\n",(0,a.jsxs)(n.li,{className:"task-list-item",children:[(0,a.jsx)(n.input,{type:"checkbox",checked:!0,disabled:!0})," ","Renewal of certificates"]}),"\n"]}),"\n",(0,a.jsx)(n.h2,{id:"stay-up-to-date",children:"Stay Up-to-Date"}),"\n",(0,a.jsxs)(n.p,{children:[(0,a.jsx)(n.code,{children:"hlf-operator"})," is currently in stable. Watch ",(0,a.jsx)(n.strong,{children:"releases"})," of this repository to be notified for future updates:"]}),"\n",(0,a.jsx)(n.p,{children:(0,a.jsx)(n.img,{src:"https://user-images.githubusercontent.com/6862893/123808402-022aa800-d8f1-11eb-8df4-8a9552f126a2.gif",alt:"hlf-operator-star-github"})}),"\n",(0,a.jsx)(n.h2,{id:"discord",children:"Discord"}),"\n",(0,a.jsx)(n.p,{children:"For discussions and questions, please join the Hyperledger Foundation Discord:"}),"\n",(0,a.jsx)(n.p,{children:(0,a.jsx)(n.a,{href:"https://discord.com/invite/hyperledger",children:"https://discord.com/invite/hyperledger"})}),"\n",(0,a.jsxs)(n.p,{children:["The channel is located under ",(0,a.jsx)(n.code,{children:"BEVEL"}),", named ",(0,a.jsx)(n.a,{href:"https://discordapp.com/channels/905194001349627914/967823782712594442",children:(0,a.jsx)(n.code,{children:"bevel-operator-fabric"})}),"."]}),"\n",(0,a.jsx)(n.h2,{id:"hyperledger-meetups",children:"Hyperledger Meetups"}),"\n",(0,a.jsx)(n.p,{children:"You can watch this video to see how to use it to deploy your own network:"}),"\n",(0,a.jsxs)(n.p,{children:[(0,a.jsx)(n.a,{href:"https://www.youtube.com/watch?v=4taLwa_pl9U",title:"Deploying a Network Using SmartBFT in Hyperledger Fabric 3.0",children:(0,a.jsx)(n.img,{src:"http://img.youtube.com/vi/4taLwa_pl9U/0.jpg",alt:"Deploying a Network Using SmartBFT in Hyperledger Fabric 3.0"})}),"\n",(0,a.jsx)(n.a,{href:"https://www.youtube.com/watch?v=vM_UzryCOqs",title:"Hyperledger Fabric on Kubernetes",children:(0,a.jsx)(n.img,{src:"http://img.youtube.com/vi/vM_UzryCOqs/0.jpg",alt:"Deploying a Network Using SmartBFT in Hyperledger Fabric 3.0"})}),"\n",(0,a.jsx)(n.a,{href:"http://www.youtube.com/watch?v=namKDeJf5QI",title:"Hyperledger Fabric on Kubernetes",children:(0,a.jsx)(n.img,{src:"http://img.youtube.com/vi/namKDeJf5QI/0.jpg",alt:"Hyperledger Fabric on Kubernetes"})})]}),"\n",(0,a.jsx)(n.h2,{id:"tutorial-videos",children:"Tutorial Videos"}),"\n",(0,a.jsx)(n.p,{children:"Step-by-step video tutorials to setup hlf-operator in Kubernetes"}),"\n",(0,a.jsx)(n.p,{children:(0,a.jsx)(n.a,{href:"https://www.youtube.com/playlist?list=PLuAZTZDgj0csRQuNMY8wbYqOCpzggAuMo",title:"Hyperledger Fabric on Kubernetes",children:(0,a.jsx)(n.img,{src:"https://img.youtube.com/vi/e04TcJHUI5M/0.jpg",alt:"Hyperledger Fabric on Kubernetes"})})}),"\n",(0,a.jsx)(n.p,{children:"This workshop provides an in-depth hands on discussion and demonstration of using Bevel and the new Bevel-Operator-Fabric to deploy Hyperledger Fabric on Kubernetes."}),"\n",(0,a.jsx)(n.h2,{id:"hyperledger-workshops",children:"Hyperledger Workshops"}),"\n",(0,a.jsx)(n.p,{children:"This workshop provides an in-depth, hands-on discussion and demonstration of using Bevel and the new Bevel-Operator-Fabric to deploy Hyperledger Fabric on Kubernetes."}),"\n",(0,a.jsx)(n.p,{children:(0,a.jsx)(n.a,{href:"https://www.youtube.com/live/YUC12ahY5_k?feature=share&t=4430",children:(0,a.jsx)(n.img,{src:"https://img.youtube.com/vi/YUC12ahY5_k/0.jpg",alt:"How to Deploy Hyperledger Fabric on Kubernetes with Hyperledger Bevel"})})}),"\n",(0,a.jsx)(n.h2,{id:"sponsor",children:"Sponsor"}),"\n",(0,a.jsxs)(n.table,{children:[(0,a.jsx)(n.thead,{children:(0,a.jsxs)(n.tr,{children:[(0,a.jsx)(n.th,{}),(0,a.jsx)(n.th,{})]})}),(0,a.jsxs)(n.tbody,{children:[(0,a.jsxs)(n.tr,{children:[(0,a.jsx)(n.td,{children:(0,a.jsx)(n.img,{src:"https://avatars.githubusercontent.com/u/135145372?s=200&v=4",alt:"galagames logo"})}),(0,a.jsx)(n.td,{children:"Gala Games is a blockchain gaming platform that empowers players to earn cryptocurrencies and NFTs through gameplay. Founded in 2018 by Eric Schiermeyer, co-founder of Zynga, it aims to create a new type of gaming experience. The platform offers limited edition NFTs and allows players to earn Gala tokens"})]}),(0,a.jsxs)(n.tr,{children:[(0,a.jsx)(n.td,{children:(0,a.jsx)(n.img,{src:"https://avatars.githubusercontent.com/u/74511895?s=200&v=4",alt:"kfs logo"})}),(0,a.jsxs)(n.td,{children:["If you want to design and deploy a secure Blockchain network based on the latest version of Hyperledger Fabric, feel free to contact ",(0,a.jsx)(n.a,{href:"mailto:dviejo@kungfusoftware.es",children:"dviejo@kungfusoftware.es"})," or visit ",(0,a.jsx)(n.a,{href:"https://kfs.es/blockchain",children:"https://kfs.es/blockchain"})]})]})]})]}),"\n",(0,a.jsx)(n.h2,{id:"getting-started",children:"Getting started"}),"\n",(0,a.jsx)(n.h1,{id:"tutorial",children:"Tutorial"}),"\n",(0,a.jsx)(n.p,{children:"Resources:"}),"\n",(0,a.jsxs)(n.ul,{children:["\n",(0,a.jsx)(n.li,{children:(0,a.jsx)(n.a,{href:"https://www.polarsparc.com/xhtml/Hyperledger-ARM-Build.html",children:"Hyperledger Fabric build ARM"})}),"\n"]}),"\n",(0,a.jsx)(n.h2,{id:"create-kubernetes-cluster",children:"Create Kubernetes Cluster"}),"\n",(0,a.jsx)(n.p,{children:"To start deploying our red fabric we have to have a Kubernetes cluster. For this we will use KinD."}),"\n",(0,a.jsx)(n.p,{children:"Ensure you have these ports available before creating the cluster:"}),"\n",(0,a.jsxs)(n.ul,{children:["\n",(0,a.jsx)(n.li,{children:"80"}),"\n",(0,a.jsx)(n.li,{children:"443"}),"\n"]}),"\n",(0,a.jsx)(n.p,{children:"If these ports are not available this tutorial will not work."}),"\n",(0,a.jsx)(n.h3,{id:"using-k3d",children:"Using K3D"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:'k3d cluster create  -p "80:30949@agent:0" -p "443:30950@agent:0" --agents 2 k8s-hlf\n'})}),"\n",(0,a.jsx)(n.h3,{id:"using-kind",children:"Using KinD"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"cat << EOF > kind-config.yaml\nkind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n  image: kindest/node:v1.30.2\n  extraPortMappings:\n  - containerPort: 30949\n    hostPort: 80\n  - containerPort: 30950\n    hostPort: 443\nEOF\n\nkind create cluster --config=./kind-config.yaml\n\n"})}),"\n",(0,a.jsx)(n.h2,{id:"install-kubernetes-operator",children:"Install Kubernetes operator"}),"\n",(0,a.jsx)(n.p,{children:"In this step we are going to install the kubernetes operator for Fabric, this will install:"}),"\n",(0,a.jsxs)(n.ul,{children:["\n",(0,a.jsx)(n.li,{children:"CRD (Custom Resource Definitions) to deploy Certification Fabric Peers, Orderers and Authorities"}),"\n",(0,a.jsx)(n.li,{children:"Deploy the program to deploy the nodes in Kubernetes"}),"\n"]}),"\n",(0,a.jsxs)(n.p,{children:["To install helm: ",(0,a.jsx)(n.a,{href:"https://helm.sh/docs/intro/install/",children:"https://helm.sh/docs/intro/install/"})]}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"helm repo add kfs https://kfsoftware.github.io/hlf-helm-charts --force-update\n\nhelm install hlf-operator --version=1.10.0 -- kfs/hlf-operator\n"})}),"\n",(0,a.jsx)(n.h3,{id:"install-the-kubectl-plugin",children:"Install the Kubectl plugin"}),"\n",(0,a.jsxs)(n.p,{children:["To install the kubectl plugin, you must first install Krew:\n",(0,a.jsx)(n.a,{href:"https://krew.sigs.k8s.io/docs/user-guide/setup/install/",children:"https://krew.sigs.k8s.io/docs/user-guide/setup/install/"})]}),"\n",(0,a.jsx)(n.p,{children:"Afterwards, the plugin can be installed with the following command:"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl krew install hlf\n"})}),"\n",(0,a.jsx)(n.h3,{id:"install-istio",children:"Install Istio"}),"\n",(0,a.jsx)(n.p,{children:"Install Istio binaries on the machine:"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"curl -L https://istio.io/downloadIstio | sh -\n"})}),"\n",(0,a.jsx)(n.p,{children:"Install Istio on the Kubernetes cluster:"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:'\nkubectl create namespace istio-system\n\nexport ISTIO_PATH=$(echo $PWD/istio-*/bin)\nexport PATH="$PATH:$ISTIO_PATH"\n\nistioctl operator init\n\nkubectl apply -f - <<EOF\napiVersion: install.istio.io/v1alpha1\nkind: IstioOperator\nmetadata:\n  name: istio-gateway\n  namespace: istio-system\nspec:\n  addonComponents:\n    grafana:\n      enabled: false\n    kiali:\n      enabled: false\n    prometheus:\n      enabled: false\n    tracing:\n      enabled: false\n  components:\n    ingressGateways:\n      - enabled: true\n        k8s:\n          hpaSpec:\n            minReplicas: 1\n          resources:\n            limits:\n              cpu: 500m\n              memory: 512Mi\n            requests:\n              cpu: 100m\n              memory: 128Mi\n          service:\n            ports:\n              - name: http\n                port: 80\n                targetPort: 8080\n                nodePort: 30949\n              - name: https\n                port: 443\n                targetPort: 8443\n                nodePort: 30950\n            type: NodePort\n        name: istio-ingressgateway\n    pilot:\n      enabled: true\n      k8s:\n        hpaSpec:\n          minReplicas: 1\n        resources:\n          limits:\n            cpu: 300m\n            memory: 512Mi\n          requests:\n            cpu: 100m\n            memory: 128Mi\n  meshConfig:\n    accessLogFile: /dev/stdout\n    enableTracing: false\n    outboundTrafficPolicy:\n      mode: ALLOW_ANY\n  profile: default\n\nEOF\n\n'})}),"\n",(0,a.jsxs)(n.h2,{id:"deploy-a-peer-organization",children:["Deploy a ",(0,a.jsx)(n.code,{children:"Peer"})," organization"]}),"\n",(0,a.jsx)(n.h3,{id:"environment-variables-for-amd-default",children:"Environment Variables for AMD (Default)"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"export PEER_IMAGE=hyperledger/fabric-peer\nexport PEER_VERSION=3.0.0\n\nexport ORDERER_IMAGE=hyperledger/fabric-orderer\nexport ORDERER_VERSION=3.0.0\n\nexport CA_IMAGE=hyperledger/fabric-ca\nexport CA_VERSION=1.5.13\n"})}),"\n",(0,a.jsx)(n.h3,{id:"environment-variables-for-arm-mac-m1",children:"Environment Variables for ARM (Mac M1)"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"export PEER_IMAGE=hyperledger/fabric-peer\nexport PEER_VERSION=3.0.0\n\nexport ORDERER_IMAGE=hyperledger/fabric-orderer\nexport ORDERER_VERSION=3.0.0\n\nexport CA_IMAGE=hyperledger/fabric-ca             \nexport CA_VERSION=1.5.13\n\n"})}),"\n",(0,a.jsx)(n.h3,{id:"configure-internal-dns",children:"Configure Internal DNS"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl apply -f - <<EOF\nkind: ConfigMap\napiVersion: v1\nmetadata:\n  name: coredns\n  namespace: kube-system\ndata:\n  Corefile: |\n    .:53 {\n        errors\n        health {\n           lameduck 5s\n        }\n        rewrite name regex (.*)\\.localho\\.st istio-ingressgateway.istio-system.svc.cluster.local\n        hosts {\n          fallthrough\n        }\n        ready\n        kubernetes cluster.local in-addr.arpa ip6.arpa {\n           pods insecure\n           fallthrough in-addr.arpa ip6.arpa\n           ttl 30\n        }\n        prometheus :9153\n        forward . /etc/resolv.conf {\n           max_concurrent 1000\n        }\n        cache 30\n        loop\n        reload\n        loadbalance\n    }\nEOF\n"})}),"\n",(0,a.jsx)(n.h3,{id:"configure-storage-class",children:"Configure Storage Class"}),"\n",(0,a.jsx)(n.p,{children:"Set storage class depending on the Kubernetes cluster you are using:"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"# for Kind\nexport SC_NAME=standard\n# for K3D\nexport SC_NAME=local-path\n"})}),"\n",(0,a.jsx)(n.h3,{id:"deploy-a-certificate-authority",children:"Deploy a certificate authority"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf ca create  --image=$CA_IMAGE --version=$CA_VERSION --storage-class=$SC_NAME --capacity=1Gi --name=org1-ca \\\n    --enroll-id=enroll --enroll-pw=enrollpw --hosts=org1-ca.localho.st --istio-port=443\n\nkubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all\n"})}),"\n",(0,a.jsx)(n.p,{children:"Check that the certification authority is deployed and works:"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"curl -k https://org1-ca.localho.st:443/cainfo\n"})}),"\n",(0,a.jsx)(n.p,{children:"Register a user in the certification authority of the peer organization (Org1MSP)"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"# register user in CA for peers\nkubectl hlf ca register --name=org1-ca --user=peer --secret=peerpw --type=peer \\\n --enroll-id enroll --enroll-secret=enrollpw --mspid Org1MSP\n\n"})}),"\n",(0,a.jsx)(n.h3,{id:"deploy-a-peer",children:"Deploy a peer"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf peer create --statedb=leveldb --image=$PEER_IMAGE --version=$PEER_VERSION --storage-class=$SC_NAME --enroll-id=peer --mspid=Org1MSP \\\n        --enroll-pw=peerpw --capacity=5Gi --name=org1-peer0 --ca-name=org1-ca.default \\\n        --hosts=peer0-org1.localho.st --istio-port=443\n\n\nkubectl wait --timeout=180s --for=condition=Running fabricpeers.hlf.kungfusoftware.es --all\n"})}),"\n",(0,a.jsx)(n.p,{children:"Check that the peer is deployed and works:"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"openssl s_client -connect peer0-org1.localho.st:443\n"})}),"\n",(0,a.jsxs)(n.h2,{id:"deploy-an-orderer-organization",children:["Deploy an ",(0,a.jsx)(n.code,{children:"Orderer"})," organization"]}),"\n",(0,a.jsxs)(n.p,{children:["To deploy an ",(0,a.jsx)(n.code,{children:"Orderer"})," organization we have to:"]}),"\n",(0,a.jsxs)(n.ol,{children:["\n",(0,a.jsx)(n.li,{children:"Create a certification authority"}),"\n",(0,a.jsxs)(n.li,{children:["Register user ",(0,a.jsx)(n.code,{children:"orderer"})," with password ",(0,a.jsx)(n.code,{children:"ordererpw"})]}),"\n",(0,a.jsx)(n.li,{children:"Create orderer"}),"\n"]}),"\n",(0,a.jsx)(n.h3,{id:"create-the-certification-authority",children:"Create the certification authority"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"\nkubectl hlf ca create  --image=$CA_IMAGE --version=$CA_VERSION --storage-class=$SC_NAME --capacity=1Gi --name=ord-ca \\\n    --enroll-id=enroll --enroll-pw=enrollpw --hosts=ord-ca.localho.st --istio-port=443\n\nkubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all\n\n"})}),"\n",(0,a.jsx)(n.p,{children:"Check that the certification authority is deployed and works:"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"curl -vik https://ord-ca.localho.st:443/cainfo\n"})}),"\n",(0,a.jsxs)(n.h3,{id:"register-user-orderer",children:["Register user ",(0,a.jsx)(n.code,{children:"orderer"})]}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:'kubectl hlf ca register --name=ord-ca --user=orderer --secret=ordererpw \\\n    --type=orderer --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP --ca-url="https://ord-ca.localho.st:443"\n\n'})}),"\n",(0,a.jsx)(n.h3,{id:"deploy-orderer",children:"Deploy orderer"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"\nkubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \\\n    --storage-class=$SC_NAME --enroll-id=orderer --mspid=OrdererMSP \\\n    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node1 --ca-name=ord-ca.default \\\n    --hosts=orderer0-ord.localho.st --admin-hosts=admin-orderer0-ord.localho.st --istio-port=443\n\n\nkubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \\\n    --storage-class=$SC_NAME --enroll-id=orderer --mspid=OrdererMSP \\\n    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node2 --ca-name=ord-ca.default \\\n    --hosts=orderer1-ord.localho.st --admin-hosts=admin-orderer1-ord.localho.st --istio-port=443\n\n\nkubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \\\n    --storage-class=$SC_NAME --enroll-id=orderer --mspid=OrdererMSP \\\n    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node3 --ca-name=ord-ca.default \\\n    --hosts=orderer2-ord.localho.st --admin-hosts=admin-orderer2-ord.localho.st --istio-port=443\n\n\nkubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \\\n    --storage-class=$SC_NAME --enroll-id=orderer --mspid=OrdererMSP \\\n    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node4 --ca-name=ord-ca.default \\\n    --hosts=orderer3-ord.localho.st --admin-hosts=admin-orderer3-ord.localho.st --istio-port=443\n\n\n\nkubectl wait --timeout=180s --for=condition=Running fabricorderernodes.hlf.kungfusoftware.es --all\n"})}),"\n",(0,a.jsx)(n.p,{children:"Check that the orderer is running:"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl get pods\n"})}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"openssl s_client -connect orderer0-ord.localho.st:443\nopenssl s_client -connect orderer1-ord.localho.st:443\nopenssl s_client -connect orderer2-ord.localho.st:443\nopenssl s_client -connect orderer3-ord.localho.st:443\n"})}),"\n",(0,a.jsx)(n.h2,{id:"create-channel",children:"Create channel"}),"\n",(0,a.jsx)(n.p,{children:"To create the channel we need to first create the wallet secret, which will contain the identities used by the operator to manage the channel"}),"\n",(0,a.jsx)(n.h3,{id:"register-and-enrolling-orderermsp-identity",children:"Register and enrolling OrdererMSP identity"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"# register\nkubectl hlf ca register --name=ord-ca --user=admin --secret=adminpw \\\n    --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP\n\n# enroll\n\nkubectl hlf ca enroll --name=ord-ca --namespace=default \\\n    --user=admin --secret=adminpw --mspid OrdererMSP \\\n    --ca-name tlsca  --output orderermsp.yaml\n    \nkubectl hlf ca enroll --name=ord-ca --namespace=default \\\n    --user=admin --secret=adminpw --mspid OrdererMSP \\\n    --ca-name ca  --output orderermspsign.yaml\n"})}),"\n",(0,a.jsx)(n.h3,{id:"register-and-enrolling-org1msp-orderer-identity",children:"Register and enrolling Org1MSP Orderer identity"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"# register\nkubectl hlf ca register --name=org1-ca --user=admin --secret=adminpw \\\n    --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=Org1MSP\n\n# enroll\n\nkubectl hlf ca enroll --name=org1-ca --namespace=default \\\n    --user=admin --secret=adminpw --mspid Org1MSP \\\n    --ca-name tlsca  --output org1msp-tlsca.yaml\n"})}),"\n",(0,a.jsx)(n.h3,{id:"register-and-enrolling-org1msp-identity",children:"Register and enrolling Org1MSP identity"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"# register\nkubectl hlf ca register --name=org1-ca --namespace=default --user=admin --secret=adminpw \\\n    --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=Org1MSP\n\n# enroll\nkubectl hlf ca enroll --name=org1-ca --namespace=default \\\n    --user=admin --secret=adminpw --mspid Org1MSP \\\n    --ca-name ca  --output org1msp.yaml\n\n# enroll\nkubectl hlf identity create --name org1-admin --namespace default \\\n    --ca-name org1-ca --ca-namespace default \\\n    --ca ca --mspid Org1MSP --enroll-id admin --enroll-secret adminpw\n\n\n"})}),"\n",(0,a.jsx)(n.h3,{id:"create-the-secret",children:"Create the secret"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl create secret generic wallet --namespace=default \\\n        --from-file=org1msp.yaml=$PWD/org1msp.yaml \\\n        --from-file=orderermsp.yaml=$PWD/orderermsp.yaml \\\n        --from-file=orderermspsign.yaml=$PWD/orderermspsign.yaml\n\n"})}),"\n",(0,a.jsx)(n.h3,{id:"create-main-channel",children:"Create main channel"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:'export PEER_ORG_SIGN_CERT=$(kubectl get fabriccas org1-ca -o=jsonpath=\'{.status.ca_cert}\')\nexport PEER_ORG_TLS_CERT=$(kubectl get fabriccas org1-ca -o=jsonpath=\'{.status.tlsca_cert}\')\n\nexport IDENT_8=$(printf "%8s" "")\nexport ORDERER_TLS_CERT=$(kubectl get fabriccas ord-ca -o=jsonpath=\'{.status.tlsca_cert}\' | sed -e "s/^/${IDENT_8}/" )\nexport ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath=\'{.status.tlsCert}\' | sed -e "s/^/${IDENT_8}/" )\nexport ORDERER1_TLS_CERT=$(kubectl get fabricorderernodes ord-node2 -o=jsonpath=\'{.status.tlsCert}\' | sed -e "s/^/${IDENT_8}/" )\nexport ORDERER2_TLS_CERT=$(kubectl get fabricorderernodes ord-node3 -o=jsonpath=\'{.status.tlsCert}\' | sed -e "s/^/${IDENT_8}/" )\nexport ORDERER3_TLS_CERT=$(kubectl get fabricorderernodes ord-node4 -o=jsonpath=\'{.status.tlsCert}\' | sed -e "s/^/${IDENT_8}/" )\n\nkubectl apply -f - <<EOF\napiVersion: hlf.kungfusoftware.es/v1alpha1\nkind: FabricMainChannel\nmetadata:\n  name: demo\nspec:\n  name: demo\n  adminOrdererOrganizations:\n    - mspID: OrdererMSP\n  adminPeerOrganizations:\n    - mspID: Org1MSP\n  channelConfig:\n    application:\n      acls: null\n      capabilities:\n        - V2_0\n        - V2_5\n      policies: null\n    capabilities:\n      - V2_0\n    orderer:\n      batchSize:\n        absoluteMaxBytes: 1048576\n        maxMessageCount: 10\n        preferredMaxBytes: 524288\n      batchTimeout: 2s\n      capabilities:\n        - V2_0\n      etcdRaft:\n        options:\n          electionTick: 10\n          heartbeatTick: 1\n          maxInflightBlocks: 5\n          snapshotIntervalSize: 16777216\n          tickInterval: 500ms\n      ordererType: etcdraft\n      policies: null\n      state: STATE_NORMAL\n    policies: null\n  externalOrdererOrganizations: []\n  externalPeerOrganizations: []\n  peerOrganizations:\n    - mspID: Org1MSP\n      caName: "org1-ca"\n      caNamespace: "default"\n\n  identities:\n    OrdererMSP:\n      secretKey: orderermsp.yaml\n      secretName: wallet\n      secretNamespace: default\n    OrdererMSP-tls:\n      secretKey: orderermsp.yaml\n      secretName: wallet\n      secretNamespace: default\n    OrdererMSP-sign:\n      secretKey: orderermspsign.yaml\n      secretName: wallet\n      secretNamespace: default\n    Org1MSP:\n      secretKey: org1msp.yaml\n      secretName: wallet\n      secretNamespace: default\n\n  ordererOrganizations:\n    - caName: "ord-ca"\n      caNamespace: "default"\n      externalOrderersToJoin:\n        - host: ord-node1.default\n          port: 7053\n        - host: ord-node2.default\n          port: 7053\n        - host: ord-node3.default\n          port: 7053\n        - host: ord-node4.default\n          port: 7053\n      mspID: OrdererMSP\n      ordererEndpoints:\n        - orderer0-ord.localho.st:443\n        - orderer1-ord.localho.st:443\n        - orderer2-ord.localho.st:443\n        - orderer3-ord.localho.st:443\n      orderersToJoin: []\n  orderers:\n    - host: orderer0-ord.localho.st\n      port: 443\n      tlsCert: |-\n${ORDERER0_TLS_CERT}\n    - host: orderer1-ord.localho.st\n      port: 443\n      tlsCert: |-\n${ORDERER1_TLS_CERT}\n    - host: orderer2-ord.localho.st\n      port: 443\n      tlsCert: |-\n${ORDERER2_TLS_CERT}\n    - host: orderer3-ord.localho.st\n      port: 443\n      tlsCert: |-\n${ORDERER3_TLS_CERT}\n\nEOF\n\n'})}),"\n",(0,a.jsx)(n.h2,{id:"join-peer-to-the-channel",children:"Join peer to the channel"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:'\nexport IDENT_8=$(printf "%8s" "")\nexport ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath=\'{.status.tlsCert}\' | sed -e "s/^/${IDENT_8}/" )\n\nkubectl apply -f - <<EOF\napiVersion: hlf.kungfusoftware.es/v1alpha1\nkind: FabricFollowerChannel\nmetadata:\n  name: demo-org1msp\nspec:\n  anchorPeers:\n    - host: peer0-org1.localho.st\n      port: 443\n  hlfIdentity:\n    secretKey: org1msp.yaml\n    secretName: wallet\n    secretNamespace: default\n  mspId: Org1MSP\n  name: demo\n  externalPeersToJoin: []\n  orderers:\n    - certificate: |\n${ORDERER0_TLS_CERT}\n      url: grpcs://ord-node1.default:7050\n  peersToJoin:\n    - name: org1-peer0\n      namespace: default\nEOF\n\n\n'})}),"\n",(0,a.jsx)(n.h2,{id:"install-a-chaincode",children:"Install a chaincode"}),"\n",(0,a.jsx)(n.h3,{id:"prepare-connection-string-for-a-peer",children:"Prepare connection string for a peer"}),"\n",(0,a.jsx)(n.p,{children:"To prepare the connection string, we have to:"}),"\n",(0,a.jsxs)(n.ol,{children:["\n",(0,a.jsxs)(n.li,{children:["\n",(0,a.jsx)(n.p,{children:"Get connection string without users for organization Org1MSP and OrdererMSP"}),"\n"]}),"\n",(0,a.jsxs)(n.li,{children:["\n",(0,a.jsx)(n.p,{children:"Register a user in the certification authority for signing (register)"}),"\n"]}),"\n",(0,a.jsxs)(n.li,{children:["\n",(0,a.jsx)(n.p,{children:"Obtain the certificates using the previously created user (enroll)"}),"\n"]}),"\n",(0,a.jsxs)(n.li,{children:["\n",(0,a.jsx)(n.p,{children:"Attach the user to the connection string"}),"\n"]}),"\n",(0,a.jsxs)(n.li,{children:["\n",(0,a.jsx)(n.p,{children:"Get connection string without users for organization Org1MSP and OrdererMSP"}),"\n"]}),"\n"]}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf inspect --output org1.yaml -o Org1MSP -o OrdererMSP\n"})}),"\n",(0,a.jsxs)(n.ol,{start:"2",children:["\n",(0,a.jsx)(n.li,{children:"Register a user in the certification authority for signing"}),"\n"]}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf ca register --name=org1-ca --user=admin --secret=adminpw --type=admin \\\n --enroll-id enroll --enroll-secret=enrollpw --mspid Org1MSP  \n"})}),"\n",(0,a.jsxs)(n.ol,{start:"3",children:["\n",(0,a.jsx)(n.li,{children:"Get the certificates using the user created above"}),"\n"]}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf ca enroll --name=org1-ca --user=admin --secret=adminpw --mspid Org1MSP \\\n        --ca-name ca  --output peer-org1.yaml\n"})}),"\n",(0,a.jsxs)(n.ol,{start:"4",children:["\n",(0,a.jsx)(n.li,{children:"Attach the user to the connection string"}),"\n"]}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf utils adduser --userPath=peer-org1.yaml --config=org1.yaml --username=admin --mspid=Org1MSP\n"})}),"\n",(0,a.jsx)(n.h3,{id:"create-metadata-file",children:"Create metadata file"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:'# remove the code.tar.gz chaincode.tgz if they exist\nrm code.tar.gz chaincode.tgz\nexport CHAINCODE_NAME=asset\nexport CHAINCODE_LABEL=asset\ncat << METADATA-EOF > "metadata.json"\n{\n    "type": "ccaas",\n    "label": "${CHAINCODE_LABEL}"\n}\nMETADATA-EOF\n## chaincode as a service\n'})}),"\n",(0,a.jsx)(n.h3,{id:"prepare-connection-file",children:"Prepare connection file"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:'cat > "connection.json" <<CONN_EOF\n{\n  "address": "${CHAINCODE_NAME}:7052",\n  "dial_timeout": "10s",\n  "tls_required": false\n}\nCONN_EOF\n\ntar cfz code.tar.gz connection.json\ntar cfz chaincode.tgz metadata.json code.tar.gz\nexport PACKAGE_ID=$(kubectl hlf chaincode calculatepackageid --path=chaincode.tgz --language=node --label=$CHAINCODE_LABEL)\necho "PACKAGE_ID=$PACKAGE_ID"\n\nkubectl hlf chaincode install --path=./chaincode.tgz \\\n    --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL --user=admin --peer=org1-peer0.default\nkubectl hlf chaincode install --path=./chaincode.tgz \\\n    --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL --user=admin --peer=org1-peer1.default\n\n'})}),"\n",(0,a.jsx)(n.h2,{id:"deploy-chaincode-container-on-cluster",children:"Deploy chaincode container on cluster"}),"\n",(0,a.jsx)(n.p,{children:"The following command will create or update the CRD based on the packageID, chaincode name, and docker image."}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf externalchaincode sync --image=kfsoftware/chaincode-external:latest \\\n    --name=$CHAINCODE_NAME \\\n    --namespace=default \\\n    --package-id=$PACKAGE_ID \\\n    --tls-required=false \\\n    --replicas=1\n"})}),"\n",(0,a.jsx)(n.h2,{id:"check-installed-chaincodes",children:"Check installed chaincodes"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf chaincode queryinstalled --config=org1.yaml --user=admin --peer=org1-peer0.default\n"})}),"\n",(0,a.jsx)(n.h2,{id:"approve-chaincode",children:"Approve chaincode"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:'export SEQUENCE=1\nexport VERSION="1.0"\nkubectl hlf chaincode approveformyorg --config=org1.yaml --user=admin --peer=org1-peer0.default \\\n    --package-id=$PACKAGE_ID \\\n    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \\\n    --policy="OR(\'Org1MSP.member\')" --channel=testbft02\n'})}),"\n",(0,a.jsx)(n.h2,{id:"commit-chaincode",children:"Commit chaincode"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:'kubectl hlf chaincode commit --config=org1.yaml --user=admin --mspid=Org1MSP \\\n    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \\\n    --policy="OR(\'Org1MSP.member\')" --channel=testbft02\n'})}),"\n",(0,a.jsx)(n.h2,{id:"invoke-a-transaction-on-the-channel",children:"Invoke a transaction on the channel"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf chaincode invoke --config=org1.yaml \\\n    --user=admin --peer=org1-peer0.default \\\n    --chaincode=asset --channel=testbft02 \\\n    --fcn=initLedger -a '[]'\n"})}),"\n",(0,a.jsx)(n.h2,{id:"query-assets-in-the-channel",children:"Query assets in the channel"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl hlf chaincode query --config=org1.yaml \\\n    --user=admin --peer=org1-peer0.default \\\n    --chaincode=asset --channel=testbft02 \\\n    --fcn=GetAllAssets -a '[]'\n"})}),"\n",(0,a.jsx)(n.p,{children:"At this point, you should have:"}),"\n",(0,a.jsxs)(n.ul,{children:["\n",(0,a.jsx)(n.li,{children:"Ordering service with 1 nodes and a CA"}),"\n",(0,a.jsx)(n.li,{children:"Peer organization with a peer and a CA"}),"\n",(0,a.jsxs)(n.li,{children:["A channel ",(0,a.jsx)(n.strong,{children:"demo"})]}),"\n",(0,a.jsx)(n.li,{children:"A chaincode install in peer0"}),"\n",(0,a.jsx)(n.li,{children:"A chaincode approved and committed"}),"\n"]}),"\n",(0,a.jsx)(n.p,{children:"If something went wrong or didn't work, please, open an issue."}),"\n",(0,a.jsx)(n.h2,{id:"cleanup-the-environment",children:"Cleanup the environment"}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-bash",children:"kubectl delete fabricorderernodes.hlf.kungfusoftware.es --all-namespaces --all\nkubectl delete fabricpeers.hlf.kungfusoftware.es --all-namespaces --all\nkubectl delete fabriccas.hlf.kungfusoftware.es --all-namespaces --all\nkubectl delete fabricchaincode.hlf.kungfusoftware.es --all-namespaces --all\nkubectl delete fabricmainchannels --all-namespaces --all\nkubectl delete fabricfollowerchannels --all-namespaces --all\n"})}),"\n",(0,a.jsx)(n.h2,{id:"troubleshooting",children:"Troubleshooting"}),"\n",(0,a.jsx)(n.h3,{id:"chaincode-installationbuild-error",children:"Chaincode installation/build error"}),"\n",(0,a.jsxs)(n.p,{children:["Chaincode installation/build can fail due to unsupported local kubertenes version such as ",(0,a.jsx)(n.a,{href:"https://github.com/kubernetes/minikube",children:"minikube"}),"."]}),"\n",(0,a.jsx)(n.pre,{children:(0,a.jsx)(n.code,{className:"language-shell",children:"$ kubectl hlf chaincode install --path=./fixtures/chaincodes/fabcar/go \\\n        --config=org1.yaml --language=golang --label=fabcar --user=admin --peer=org1-peer0.default\n\nError: Transaction processing for endorser [192.168.49.2:31278]: Chaincode status Code: (500) UNKNOWN.\nDescription: failed to invoke backing implementation of 'InstallChaincode': could not build chaincode:\nexternal builder failed: external builder failed to build: external builder 'my-golang-builder' failed:\nexit status 1\n"})}),"\n",(0,a.jsxs)(n.p,{children:["If your purpose is to test the hlf-operator please consider to switch to ",(0,a.jsx)(n.a,{href:"https://github.com/kubernetes-sigs/kind",children:"kind"})," that is tested and supported."]})]})}function h(e={}){const{wrapper:n}={...(0,t.R)(),...e.components};return n?(0,a.jsx)(n,{...e,children:(0,a.jsx)(d,{...e})}):d(e)}},8453:(e,n,r)=>{r.d(n,{R:()=>l,x:()=>i});var a=r(6540);const t={},s=a.createContext(t);function l(e){const n=a.useContext(s);return a.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function i(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(t):e.components||t:l(e.components),a.createElement(s.Provider,{value:n},e.children)}}}]);