(window.webpackJsonp=window.webpackJsonp||[]).push([[4],{139:function(e,t,n){"use strict";n.r(t),t.default=n.p+"assets/images/istio_hlf-387a32a088ebc7ff5d4f85672c9eab19.png"},74:function(e,t,n){"use strict";n.r(t),n.d(t,"frontMatter",(function(){return s})),n.d(t,"metadata",(function(){return c})),n.d(t,"toc",(function(){return l})),n.d(t,"default",(function(){return d}));var r=n(3),o=n(7),a=(n(0),n(97)),i=["components"],s={id:"istio",title:"Istio set up"},c={unversionedId:"operator-guide/istio",id:"operator-guide/istio",isDocsHomePage:!1,title:"Istio set up",description:"Istio is a service mesh that provides a secure, high-performance networking platform for microservices and applications running on Kubernetes.",source:"@site/docs/operator-guide/istio.md",slug:"/operator-guide/istio",permalink:"/hlf-operator/docs/operator-guide/istio",editUrl:"https://github.com/kfsoftware/hlf-operator/edit/master/website/docs/operator-guide/istio.md",version:"current",sidebar:"someSidebar1",previous:{title:"Renew certificates",permalink:"/hlf-operator/docs/operator-guide/renew-certificates"},next:{title:"Using external CouchDB",permalink:"/hlf-operator/docs/operator-guide/external-couchdb"}},l=[{value:"Installing istio",id:"installing-istio",children:[]},{value:"Locate the public IP or hostname of the ingress gateway",id:"locate-the-public-ip-or-hostname-of-the-ingress-gateway",children:[{value:"Running on KinD/Minikube",id:"running-on-kindminikube",children:[]},{value:"Running with load balancer IP",id:"running-with-load-balancer-ip",children:[]},{value:"Running with load balancer hostname",id:"running-with-load-balancer-hostname",children:[]}]},{value:"Set up DNS",id:"set-up-dns",children:[{value:"Local DNS set up in Linux/Mac (for MiniKube and KinD)",id:"local-dns-set-up-in-linuxmac-for-minikube-and-kind",children:[]},{value:"Set up DNS in your DNS provider",id:"set-up-dns-in-your-dns-provider",children:[]}]},{value:"Set up the network",id:"set-up-the-network",children:[{value:"Deploying a Certificate Authority",id:"deploying-a-certificate-authority",children:[]},{value:"Create the peer",id:"create-the-peer",children:[]},{value:"Create the Certificate Authority for the orderer",id:"create-the-certificate-authority-for-the-orderer",children:[]},{value:"Deploying the Orderer nodes node",id:"deploying-the-orderer-nodes-node",children:[]},{value:"Testing orderer node connection",id:"testing-orderer-node-connection",children:[]},{value:"Create the Certificate Authority with Istio",id:"create-the-certificate-authority-with-istio",children:[]},{value:"Testing CA node connection",id:"testing-ca-node-connection",children:[]}]}],u={toc:l};function d(e){var t=e.components,s=Object(o.a)(e,i);return Object(a.b)("wrapper",Object(r.a)({},u,s,{components:t,mdxType:"MDXLayout"}),Object(a.b)("p",null,"Istio is a service mesh that provides a secure, high-performance networking platform for microservices and applications running on Kubernetes."),Object(a.b)("p",null,"Node port solutions can work in the short term, but they are not long-term solutions, neither for production, as they require opening up multiple ports to the public internet."),Object(a.b)("p",null,"The following diagram represents the architecture with Istio configured\n",Object(a.b)("img",{alt:"Istio",src:n(139).default})),Object(a.b)("p",null,"As you can see, we can note the following:"),Object(a.b)("ul",null,Object(a.b)("li",{parentName:"ul"},"The Istio service mesh is running in the Kubernetes cluster"),Object(a.b)("li",{parentName:"ul"},"The service only has one port exposed, which is the port of the Istio ingress gateway service."),Object(a.b)("li",{parentName:"ul"},"The ingress gateway routes the traffic to the peer, OSN or CA depending on the request.")),Object(a.b)("h2",{id:"installing-istio"},"Installing istio"),Object(a.b)("p",null,"You can refer to your version of choice by going to this tutorial from the ",Object(a.b)("a",{parentName:"p",href:"https://istio.io/latest/docs/setup/getting-started/"},"istio docs")," to get Istio installed in your Kubernetes cluster."),Object(a.b)("p",null,"Alternatively, you can just execute this command to install the latest Istio version in your Kubernetes cluster:"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"curl -L https://istio.io/downloadIstio | sh - # download istioctl CLI\n\nistioctl install --set profile=default -y # install Istio\n")),Object(a.b)("h2",{id:"locate-the-public-ip-or-hostname-of-the-ingress-gateway"},"Locate the public IP or hostname of the ingress gateway"),Object(a.b)("h3",{id:"running-on-kindminikube"},"Running on KinD/Minikube"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"PUBLIC_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type==\"InternalIP\")].address}')\n# get node port\n\nPORT=$(kubectl get svc istio-ingressgateway -n istio-system -o jsonpath='{.spec.ports[?(@.name==\"https\")].nodePort}')\n")),Object(a.b)("h3",{id:"running-with-load-balancer-ip"},"Running with load balancer IP"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"PUBLIC_IP=$(kubectl get svc istio-ingressgateway -n istio-system -o json | jq -r '.status.loadBalancer.ingress[0].ip')\nPORT=443\n")),Object(a.b)("h3",{id:"running-with-load-balancer-hostname"},"Running with load balancer hostname"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"PUBLIC_HOSTNAME=$(kubectl get svc istio-ingressgateway -n istio-system -o json | jq -r '.status.loadBalancer.ingress[0].hostname')\nPORT=443\n")),Object(a.b)("h2",{id:"set-up-dns"},"Set up DNS"),Object(a.b)("h3",{id:"local-dns-set-up-in-linuxmac-for-minikube-and-kind"},"Local DNS set up in Linux/Mac (for MiniKube and KinD)"),Object(a.b)("p",null,"Open up /etc/hosts"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"<PUBLIC_IP> peer0.org1.example.com\n<PUBLIC_IP> ord1.ord-org.example.com\n# and so on\n")),Object(a.b)("h3",{id:"set-up-dns-in-your-dns-provider"},"Set up DNS in your DNS provider"),Object(a.b)("p",null,"You will need to point the domain names you will use to the public IP of the ingress gateway, with either a A record, if you got a public IP, or a CNAME, if you got an ingress hostname"),Object(a.b)("h2",{id:"set-up-the-network"},"Set up the network"),Object(a.b)("h3",{id:"deploying-a-certificate-authority"},"Deploying a Certificate Authority"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf ca create --storage-class=standard --capacity=2Gi --name=org1-ca \\\n    --enroll-id=enroll --enroll-pw=enrollpw  \nkubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all\n\n# register user for the peers\nkubectl hlf ca register --name=org1-ca --user=peer --secret=peerpw --type=peer \\\n --enroll-id enroll --enroll-secret=enrollpw --mspid Org1MSP\n")),Object(a.b)("h3",{id:"create-the-peer"},"Create the peer"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"PEER1_DOMAIN=peer0.org1.example.com # domain for the peer\nISTIO_INGRESSGATEWAY=ingressgateway # name of the ingress gateway, in case there are many\nISTIO_GW_PORT=443 # port of the ingress gateway\nkubectl hlf peer create --storage-class=standard --enroll-id=peer --mspid=Org1MSP \\\n        --enroll-pw=peerpw --capacity=5Gi --name=org1-peer0 --ca-name=org1-ca.default \\\n        --hosts=$PEER1_DOMAIN --istio-ingressgateway=$ISTIO_INGRESSGATEWAY --istio-port=$ISTIO_GW_PORT\n\nkubectl wait --timeout=180s --for=condition=Running fabricpeers.hlf.kungfusoftware.es --all\n")),Object(a.b)("p",null,"If we inspect the virtual services and gateways of Istio, we must see a record per peer."),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"kubectl get virtualservices.networking.istio.io -A  # list all virtual services\nkubectl get gateways.networking.istio.io -A  # list all gateways\n")),Object(a.b)("p",null,"To test that you can connect to the peer, you can use the following command to test directly from the command line(this test doesn't require DNS records to be set up):"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},'echo "PUBLIC_IP=$PUBLIC_IP PORT=$PORT DOMAIN=$PEER1_DOMAIN"\nopenssl s_client -connect $PUBLIC_IP:$PORT -servername $PEER1_DOMAIN  -showcerts </dev/null\n')),Object(a.b)("h3",{id:"create-the-certificate-authority-for-the-orderer"},"Create the Certificate Authority for the orderer"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf ca create --storage-class=standard --capacity=2Gi --name=ord-ca \\\n    --enroll-id=enroll --enroll-pw=enrollpw\nkubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all\nkubectl hlf ca register --name=ord-ca --user=orderer --secret=ordererpw \\\n    --type=orderer --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP\n")),Object(a.b)("h3",{id:"deploying-the-orderer-nodes-node"},"Deploying the Orderer nodes node"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"ORD1_DOMAIN=ord1.org1-node.example.com # domain for the orderer\nISTIO_INGRESSGATEWAY=ingressgateway # name of the ingress gateway, in case there are many\nISTIO_GW_PORT=443\nkubectl hlf ordnode create --storage-class=standard --enroll-id=orderer --mspid=OrdererMSP \\\n    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node1 --ca-name=ord-ca.default \\\n    --hosts=$ORD1_DOMAIN --istio-ingressgateway=$ISTIO_INGRESSGATEWAY --istio-port=$ISTIO_GW_PORT\n\nkubectl wait --timeout=180s --for=condition=Running fabricorderernodes.hlf.kungfusoftware.es --all\n")),Object(a.b)("h3",{id:"testing-orderer-node-connection"},"Testing orderer node connection"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},'echo "PUBLIC_IP=$PUBLIC_IP PORT=$PORT DOMAIN=$ORD1_DOMAIN"\nopenssl s_client -connect $PUBLIC_IP:$PORT -servername $ORD1_DOMAIN  -showcerts </dev/null\n')),Object(a.b)("h3",{id:"create-the-certificate-authority-with-istio"},"Create the Certificate Authority with Istio"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},"CA_ORG2=ca.org2.example.com # domain for the orderer\nISTIO_INGRESSGATEWAY=ingressgateway # name of the ingress gateway, in case there are many\nISTIO_GW_PORT=443\n\nkubectl hlf ca create --storage-class=standard --capacity=2Gi --name=org2-ca \\\n    --enroll-id=enroll --enroll-pw=enrollpw \\\n    --hosts=$CA_ORG2 --istio-ingressgateway=$ISTIO_INGRESSGATEWAY --istio-port=$ISTIO_GW_PORT\n\nkubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all\n")),Object(a.b)("h3",{id:"testing-ca-node-connection"},"Testing CA node connection"),Object(a.b)("pre",null,Object(a.b)("code",{parentName:"pre",className:"language-bash"},'echo "PUBLIC_IP=$PUBLIC_IP PORT=$PORT DOMAIN=$CA_ORG2"\nopenssl s_client -connect $PUBLIC_IP:$PORT -servername $CA_ORG2  -showcerts </dev/null\n')))}d.isMDXComponent=!0},97:function(e,t,n){"use strict";n.d(t,"a",(function(){return d})),n.d(t,"b",(function(){return h}));var r=n(0),o=n.n(r);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function s(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function c(e,t){if(null==e)return{};var n,r,o=function(e,t){if(null==e)return{};var n,r,o={},a=Object.keys(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||(o[n]=e[n]);return o}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var l=o.a.createContext({}),u=function(e){var t=o.a.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):s(s({},t),e)),n},d=function(e){var t=u(e.components);return o.a.createElement(l.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return o.a.createElement(o.a.Fragment,{},t)}},b=o.a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,a=e.originalType,i=e.parentName,l=c(e,["components","mdxType","originalType","parentName"]),d=u(n),b=r,h=d["".concat(i,".").concat(b)]||d[b]||p[b]||a;return n?o.a.createElement(h,s(s({ref:t},l),{},{components:n})):o.a.createElement(h,s({ref:t},l))}));function h(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var a=n.length,i=new Array(a);i[0]=b;var s={};for(var c in t)hasOwnProperty.call(t,c)&&(s[c]=t[c]);s.originalType=e,s.mdxType="string"==typeof e?e:r,i[1]=s;for(var l=2;l<a;l++)i[l]=n[l];return o.a.createElement.apply(null,i)}return o.a.createElement.apply(null,n)}b.displayName="MDXCreateElement"}}]);