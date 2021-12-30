(window.webpackJsonp=window.webpackJsonp||[]).push([[7],{77:function(e,r,t){"use strict";t.r(r),t.d(r,"frontMatter",(function(){return i})),t.d(r,"metadata",(function(){return s})),t.d(r,"toc",(function(){return l})),t.d(r,"default",(function(){return p}));var n=t(3),a=t(7),o=(t(0),t(97)),c=["components"],i={id:"renew-certificates",title:"Renew certificates"},s={unversionedId:"operator-guide/renew-certificates",id:"operator-guide/renew-certificates",isDocsHomePage:!1,title:"Renew certificates",description:"In order to trigger the renewal of the certificates, either for the orderer or for the peer, we can use the hlf ca renew  command.",source:"@site/docs/operator-guide/renew-certificates.md",slug:"/operator-guide/renew-certificates",permalink:"/hlf-operator/docs/operator-guide/renew-certificates",editUrl:"https://github.com/kfsoftware/hlf-operator/edit/master/website/docs/operator-guide/renew-certificates.md",version:"current",sidebar:"someSidebar1",previous:{title:"Increase storage",permalink:"/hlf-operator/docs/operator-guide/increase-storage"},next:{title:"Istio set up",permalink:"/hlf-operator/docs/operator-guide/istio"}},l=[{value:"Renewing certificates for the peer",id:"renewing-certificates-for-the-peer",children:[]},{value:"Renewing certificates for the orderer",id:"renewing-certificates-for-the-orderer",children:[{value:"!!!! IMPORTANT !!!!",id:"-important-",children:[]}]},{value:"Renewing certificates for the consenter",id:"renewing-certificates-for-the-consenter",children:[{value:"Generate channel block update",id:"generate-channel-block-update",children:[]},{value:"Submit update channel",id:"submit-update-channel",children:[]}]}],u={toc:l};function p(e){var r=e.components,t=Object(a.a)(e,c);return Object(o.b)("wrapper",Object(n.a)({},u,t,{components:r,mdxType:"MDXLayout"}),Object(o.b)("p",null,"In order to trigger the renewal of the certificates, either for the orderer or for the peer, we can use the ",Object(o.b)("inlineCode",{parentName:"p"},"hlf ca renew <node_type>")," command."),Object(o.b)("h2",{id:"renewing-certificates-for-the-peer"},"Renewing certificates for the peer"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"PEER_NAME=org1-peer0\nPEER_NS=default\nkubectl hlf peer renew --name=$PEER_NAME --namespace=$PEER_NS\n")),Object(o.b)("p",null,"You can monitor the state of the renewal by using:"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"kubectl get fabricpeers.hlf.kungfusoftware.es  -w\n")),Object(o.b)("h2",{id:"renewing-certificates-for-the-orderer"},"Renewing certificates for the orderer"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"ORDERER_NAME=ord-node1\nORDERER_NS=default\nkubectl hlf ordnode renew --name=$ORDERER_NAME --namespace=$ORDERER_NS\n")),Object(o.b)("p",null,"You can monitor the state of the renewal by using:"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"kubectl get fabricorderernodes.hlf.kungfusoftware.es  -w\n")),Object(o.b)("h3",{id:"-important-"},"!!!! IMPORTANT !!!!"),Object(o.b)("p",null,"When renewing the orderer certificates, the channel which the orderer is consenter of must be updated with the new certificates generated by the operator."),Object(o.b)("p",null,"This operation is not handled by the operator, since the operator does not know the channels that the orderer is consenter of, neither has the authority to update the channel since the signatures needed can vary depending on the configuration."),Object(o.b)("h2",{id:"renewing-certificates-for-the-consenter"},"Renewing certificates for the consenter"),Object(o.b)("p",null,"For this operation to work, the ordering service must have at least 3 nodes, for the consensus to work, since for 2 nodes or less, the consensus will not be able to reach a quorum."),Object(o.b)("h3",{id:"generate-channel-block-update"},"Generate channel block update"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},'CHANNEL_NAME=demo\nkubectl hlf channel consenter replace --config=ordservice.yaml \\\n    --orderer="$ORDERER_NAME.$ORDERER_NS" \\\n    --user=admin --channel=$CHANNEL_NAME \\\n    --mspid=OrdererMSP --output=replace_orderers_consenter.pb\n')),Object(o.b)("h3",{id:"submit-update-channel"},"Submit update channel"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf channel update --channel=$CHANNEL_NAME -f replace_orderers_consenter.pb \\\n   --config=ordservice.yaml --user=admin --mspid=OrdererMSP\n")))}p.isMDXComponent=!0},97:function(e,r,t){"use strict";t.d(r,"a",(function(){return p})),t.d(r,"b",(function(){return b}));var n=t(0),a=t.n(n);function o(e,r,t){return r in e?Object.defineProperty(e,r,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[r]=t,e}function c(e,r){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);r&&(n=n.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),t.push.apply(t,n)}return t}function i(e){for(var r=1;r<arguments.length;r++){var t=null!=arguments[r]?arguments[r]:{};r%2?c(Object(t),!0).forEach((function(r){o(e,r,t[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):c(Object(t)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(t,r))}))}return e}function s(e,r){if(null==e)return{};var t,n,a=function(e,r){if(null==e)return{};var t,n,a={},o=Object.keys(e);for(n=0;n<o.length;n++)t=o[n],r.indexOf(t)>=0||(a[t]=e[t]);return a}(e,r);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)t=o[n],r.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(a[t]=e[t])}return a}var l=a.a.createContext({}),u=function(e){var r=a.a.useContext(l),t=r;return e&&(t="function"==typeof e?e(r):i(i({},r),e)),t},p=function(e){var r=u(e.components);return a.a.createElement(l.Provider,{value:r},e.children)},d={inlineCode:"code",wrapper:function(e){var r=e.children;return a.a.createElement(a.a.Fragment,{},r)}},f=a.a.forwardRef((function(e,r){var t=e.components,n=e.mdxType,o=e.originalType,c=e.parentName,l=s(e,["components","mdxType","originalType","parentName"]),p=u(t),f=n,b=p["".concat(c,".").concat(f)]||p[f]||d[f]||o;return t?a.a.createElement(b,i(i({ref:r},l),{},{components:t})):a.a.createElement(b,i({ref:r},l))}));function b(e,r){var t=arguments,n=r&&r.mdxType;if("string"==typeof e||n){var o=t.length,c=new Array(o);c[0]=f;var i={};for(var s in r)hasOwnProperty.call(r,s)&&(i[s]=r[s]);i.originalType=e,i.mdxType="string"==typeof e?e:n,c[1]=i;for(var l=2;l<o;l++)c[l]=t[l];return a.a.createElement.apply(null,c)}return a.a.createElement.apply(null,t)}f.displayName="MDXCreateElement"}}]);