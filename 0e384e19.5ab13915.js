(window.webpackJsonp=window.webpackJsonp||[]).push([[3],{64:function(e,t,r){"use strict";r.r(t),r.d(t,"frontMatter",(function(){return c})),r.d(t,"metadata",(function(){return l})),r.d(t,"toc",(function(){return s})),r.d(t,"default",(function(){return u}));var n=r(3),o=r(7),a=(r(0),r(97)),i=["components"],c={id:"intro",title:"Introduction",sidebar_label:"Introduction",slug:"/"},l={unversionedId:"intro",id:"intro",isDocsHomePage:!1,title:"Introduction",description:"What's HLF Operator?",source:"@site/docs/intro.md",slug:"/",permalink:"/hlf-operator/docs/",editUrl:"https://github.com/kfsoftware/hlf-operator/edit/master/website/docs/intro.md",version:"current",sidebar_label:"Introduction",sidebar:"someSidebar1",next:{title:"Getting started",permalink:"/hlf-operator/docs/getting-started"}},s=[{value:"What&#39;s HLF Operator?",id:"whats-hlf-operator",children:[]},{value:"Why another tool to manage Hyperledger Fabric networks?",id:"why-another-tool-to-manage-hyperledger-fabric-networks",children:[]}],p={toc:s};function u(e){var t=e.components,r=Object(o.a)(e,i);return Object(a.b)("wrapper",Object(n.a)({},p,r,{components:t,mdxType:"MDXLayout"}),Object(a.b)("h2",{id:"whats-hlf-operator"},"What's HLF Operator?"),Object(a.b)("p",null,"HLF Operator is a Kubernetes Operator built with the ",Object(a.b)("a",{parentName:"p",href:"https://sdk.operatorframework.io/"},"operator sdk")," to manage the Hyperledger Fabric components:"),Object(a.b)("ul",null,Object(a.b)("li",{parentName:"ul"},"Peer"),Object(a.b)("li",{parentName:"ul"},"Ordering service nodes(OSN)"),Object(a.b)("li",{parentName:"ul"},"Certificate authorities")),Object(a.b)("h2",{id:"why-another-tool-to-manage-hyperledger-fabric-networks"},"Why another tool to manage Hyperledger Fabric networks?"),Object(a.b)("p",null,"There are some alternatives such as:"),Object(a.b)("ul",null,Object(a.b)("li",{parentName:"ul"},Object(a.b)("a",{parentName:"li",href:"https://github.com/hyperledger/cello"},"Cello")),Object(a.b)("li",{parentName:"ul"},Object(a.b)("a",{parentName:"li",href:"https://github.com/hyfen-nl/PIVT"},"Workflow based on Helm Charts and ArgoCD workflows"))),Object(a.b)("p",null,"These tools are much complex, since they require a deep knowledge in Hyperledger Fabric in order to get the most from these tools and they require more components apart from Kubernetes to get started, such as external databases, external services, etc."),Object(a.b)("p",null,"Instead, what if we could we get the simplicity of Kubernetes and the power from Hyperledger Fabric? This is when this operator comes in. With CRDs(Custom resource definition) for the Peer, Certificate Authority and Ordering Services we can set up a fully network."))}u.isMDXComponent=!0},97:function(e,t,r){"use strict";r.d(t,"a",(function(){return u})),r.d(t,"b",(function(){return f}));var n=r(0),o=r.n(n);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function c(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function l(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},a=Object.keys(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var s=o.a.createContext({}),p=function(e){var t=o.a.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):c(c({},t),e)),r},u=function(e){var t=p(e.components);return o.a.createElement(s.Provider,{value:t},e.children)},b={inlineCode:"code",wrapper:function(e){var t=e.children;return o.a.createElement(o.a.Fragment,{},t)}},d=o.a.forwardRef((function(e,t){var r=e.components,n=e.mdxType,a=e.originalType,i=e.parentName,s=l(e,["components","mdxType","originalType","parentName"]),u=p(r),d=n,f=u["".concat(i,".").concat(d)]||u[d]||b[d]||a;return r?o.a.createElement(f,c(c({ref:t},s),{},{components:r})):o.a.createElement(f,c({ref:t},s))}));function f(e,t){var r=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var a=r.length,i=new Array(a);i[0]=d;var c={};for(var l in t)hasOwnProperty.call(t,l)&&(c[l]=t[l]);c.originalType=e,c.mdxType="string"==typeof e?e:n,i[1]=c;for(var s=2;s<a;s++)i[s]=r[s];return o.a.createElement.apply(null,i)}return o.a.createElement.apply(null,r)}d.displayName="MDXCreateElement"}}]);