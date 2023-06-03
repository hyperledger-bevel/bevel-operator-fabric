(window.webpackJsonp=window.webpackJsonp||[]).push([[47],{118:function(e,n,t){"use strict";t.r(n),t.d(n,"frontMatter",(function(){return c})),t.d(n,"metadata",(function(){return p})),t.d(n,"toc",(function(){return l})),t.d(n,"default",(function(){return b}));var r=t(3),a=t(7),o=(t(0),t(129)),i=["components"],c={id:"manage",title:"Manage the channel"},p={unversionedId:"channel-management/manage",id:"channel-management/manage",isDocsHomePage:!1,title:"Manage the channel",description:"Add peer organization to the channel",source:"@site/docs/channel-management/manage.md",slug:"/channel-management/manage",permalink:"/bevel-operator-fabric/docs/channel-management/manage",editUrl:"https://github.com/hyperledger/bevel-operator-fabric/edit/master/website/docs/channel-management/manage.md",version:"current",sidebar:"someSidebar1",previous:{title:"Getting started",permalink:"/bevel-operator-fabric/docs/channel-management/getting-started"},next:{title:"Installation",permalink:"/bevel-operator-fabric/docs/kubectl-plugin/installation"}},l=[{value:"Add peer organization to the channel",id:"add-peer-organization-to-the-channel",children:[]},{value:"Add orderer organization to the channel",id:"add-orderer-organization-to-the-channel",children:[]}],d={toc:l};function b(e){var n=e.components,t=Object(a.a)(e,i);return Object(o.b)("wrapper",Object(r.a)({},d,t,{components:n,mdxType:"MDXLayout"}),Object(o.b)("h2",{id:"add-peer-organization-to-the-channel"},"Add peer organization to the channel"),Object(o.b)("p",null,"You can add more organizations by updating the ",Object(o.b)("inlineCode",{parentName:"p"},"peerOrganizations")," or ",Object(o.b)("inlineCode",{parentName:"p"},"externalPeerOrganizations")," property in the ",Object(o.b)("a",{parentName:"p",href:"/bevel-operator-fabric/docs/reference/reference#hlf.kungfusoftware.es/v1alpha1.FabricMainChannel"},Object(o.b)("inlineCode",{parentName:"a"},"FabricMainChannel"))," CRD."),Object(o.b)("p",null,"If the organization is not in the cluster, you need to add the organization to the ",Object(o.b)("inlineCode",{parentName:"p"},"externalPeerOrganizations")," property, with the ",Object(o.b)("inlineCode",{parentName:"p"},"mspID"),", ",Object(o.b)("inlineCode",{parentName:"p"},"signRootCert")," and ",Object(o.b)("inlineCode",{parentName:"p"},"tlsRootCert"),"."),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-yaml"},"  externalPeerOrganizations:\n    - mspID: <MSP_ID>\n      signRootCert: |\n        <SIGN_ROOT_CRT_PEM>\n      tlsRootCert: |\n        <TLS_ROOT_CRT_PEM>\n")),Object(o.b)("p",null,"If the organization is in the cluster, you need to add the organization to the ",Object(o.b)("inlineCode",{parentName:"p"},"peerOrganizations")," property, with the ",Object(o.b)("inlineCode",{parentName:"p"},"mspID"),", ",Object(o.b)("inlineCode",{parentName:"p"},"signRootCert")," and ",Object(o.b)("inlineCode",{parentName:"p"},"tlsRootCert"),"."),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-yaml"},"  peerOrganizations:\n    - caName: <CA_NAME>\n      caNamespace: <CA_NS>\n      mspID: <MSP_ID>\n")),Object(o.b)("h2",{id:"add-orderer-organization-to-the-channel"},"Add orderer organization to the channel"),Object(o.b)("p",null,"You can add more organizations by updating the ",Object(o.b)("inlineCode",{parentName:"p"},"peerOrganizations")," or ",Object(o.b)("inlineCode",{parentName:"p"},"externalPeerOrganizations")," property in the ",Object(o.b)("a",{parentName:"p",href:"/bevel-operator-fabric/docs/reference/reference#hlf.kungfusoftware.es/v1alpha1.FabricMainChannel"},Object(o.b)("inlineCode",{parentName:"a"},"FabricMainChannel"))," CRD."),Object(o.b)("p",null,"If the organization is not in the cluster, you need to add the organization to the ",Object(o.b)("inlineCode",{parentName:"p"},"externalPeerOrganizations")," property, with the ",Object(o.b)("inlineCode",{parentName:"p"},"mspID"),", ",Object(o.b)("inlineCode",{parentName:"p"},"signRootCert")," and ",Object(o.b)("inlineCode",{parentName:"p"},"tlsRootCert"),"."),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-yaml"},"  externalOrdererOrganizations:\n    - mspID: <MSP_ID>\n      signRootCert: |\n        <SIGN_ROOT_CRT_PEM>\n      tlsRootCert: |\n        <TLS_ROOT_CRT_PEM>\n      ordererEndpoints: # orderer endpoints for the organization in the channel configuration\n        - <ORDERER0_ENDPOINT>\n")),Object(o.b)("p",null,"If the organization is in the cluster, you need to add the organization to the ",Object(o.b)("inlineCode",{parentName:"p"},"peerOrganizations")," property, with the ",Object(o.b)("inlineCode",{parentName:"p"},"mspID"),", ",Object(o.b)("inlineCode",{parentName:"p"},"signRootCert")," and ",Object(o.b)("inlineCode",{parentName:"p"},"tlsRootCert"),"."),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-yaml"},"  ordererOrganizations:\n    - caName: <CA_NAME>\n      caNamespace: <CA_NS>\n      externalOrderersToJoin:\n        - host: <ADMIN_ORDERER_HOST>\n          port: <ADMIN_ORDERER_PORT>\n      mspID: <MSP_ID>\n      ordererEndpoints: # orderer endpoints for the organization in the channel configuration\n        - <ORDERER0_ENDPOINT>\n      orderersToJoin: []\n")))}b.isMDXComponent=!0},129:function(e,n,t){"use strict";t.d(n,"a",(function(){return b})),t.d(n,"b",(function(){return u}));var r=t(0),a=t.n(r);function o(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function i(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);n&&(r=r.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,r)}return t}function c(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?i(Object(t),!0).forEach((function(n){o(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):i(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function p(e,n){if(null==e)return{};var t,r,a=function(e,n){if(null==e)return{};var t,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||(a[t]=e[t]);return a}(e,n);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(a[t]=e[t])}return a}var l=a.a.createContext({}),d=function(e){var n=a.a.useContext(l),t=n;return e&&(t="function"==typeof e?e(n):c(c({},n),e)),t},b=function(e){var n=d(e.components);return a.a.createElement(l.Provider,{value:n},e.children)},s={inlineCode:"code",wrapper:function(e){var n=e.children;return a.a.createElement(a.a.Fragment,{},n)}},m=a.a.forwardRef((function(e,n){var t=e.components,r=e.mdxType,o=e.originalType,i=e.parentName,l=p(e,["components","mdxType","originalType","parentName"]),b=d(t),m=r,u=b["".concat(i,".").concat(m)]||b[m]||s[m]||o;return t?a.a.createElement(u,c(c({ref:n},l),{},{components:t})):a.a.createElement(u,c({ref:n},l))}));function u(e,n){var t=arguments,r=n&&n.mdxType;if("string"==typeof e||r){var o=t.length,i=new Array(o);i[0]=m;var c={};for(var p in n)hasOwnProperty.call(n,p)&&(c[p]=n[p]);c.originalType=e,c.mdxType="string"==typeof e?e:r,i[1]=c;for(var l=2;l<o;l++)i[l]=t[l];return a.a.createElement.apply(null,i)}return a.a.createElement.apply(null,t)}m.displayName="MDXCreateElement"}}]);