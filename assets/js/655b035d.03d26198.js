"use strict";(self.webpackChunkwebsite_docs=self.webpackChunkwebsite_docs||[]).push([[5453],{2015:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>c,contentTitle:()=>o,default:()=>h,frontMatter:()=>s,metadata:()=>a,toc:()=>l});var i=n(4848),r=n(8453);const s={id:"revoke-identities",title:"Revoking Identity Credentials"},o="Revoking Identity Credentials",a={id:"security/revoke-identities",title:"Revoking Identity Credentials",description:"Note: This feature requires HLF Operator version 1.12.0 or later.",source:"@site/docs/security/revoke-identities.md",sourceDirName:"security",slug:"/security/revoke-identities",permalink:"/bevel-operator-fabric/docs/security/revoke-identities",draft:!1,unlisted:!1,editUrl:"https://github.com/hyperledger-bevel/bevel-operator-fabric/edit/master/website/docs/security/revoke-identities.md",tags:[],version:"current",frontMatter:{id:"revoke-identities",title:"Revoking Identity Credentials"},sidebar:"mainSidebar",previous:{title:"Getting started",permalink:"/bevel-operator-fabric/docs/chaincode-development/getting-started"},next:{title:"Getting started",permalink:"/bevel-operator-fabric/docs/chaincode-deployment/getting-started"}},c={},l=[{value:"Before You Begin",id:"before-you-begin",level:2},{value:"Step-by-Step Revocation Process",id:"step-by-step-revocation-process",level:2},{value:"1. Configure Environment Variables",id:"1-configure-environment-variables",level:3},{value:"2. Authenticate as Admin",id:"2-authenticate-as-admin",level:3},{value:"3. Execute the Revocation",id:"3-execute-the-revocation",level:3},{value:"4. Generate and Apply the CRL",id:"4-generate-and-apply-the-crl",level:3}];function d(e){const t={blockquote:"blockquote",code:"code",h1:"h1",h2:"h2",h3:"h3",header:"header",li:"li",p:"p",pre:"pre",strong:"strong",ul:"ul",...(0,r.R)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsxs)(t.blockquote,{children:["\n",(0,i.jsxs)(t.p,{children:[(0,i.jsx)(t.strong,{children:"Note:"})," This feature requires HLF Operator version 1.12.0 or later."]}),"\n"]}),"\n",(0,i.jsx)(t.header,{children:(0,i.jsx)(t.h1,{id:"revoking-identity-credentials",children:"Revoking Identity Credentials"})}),"\n",(0,i.jsx)(t.p,{children:"This guide walks you through the process of revoking identity credentials in a Hyperledger Fabric network managed by HLF Operator. Identity revocation is a critical security operation when credentials are compromised or when users leave your organization."}),"\n",(0,i.jsx)(t.h2,{id:"before-you-begin",children:"Before You Begin"}),"\n",(0,i.jsx)(t.p,{children:"To revoke credentials, you must have an admin identity with the proper permissions. The following attributes are required:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-yaml",children:"identities:\n  - affiliation: ''\n    attrs:\n      hf.AffiliationMgr: false\n      hf.GenCRL: true\n      hf.IntermediateCA: false\n      hf.Registrar.Attributes: '*'\n      hf.Registrar.Roles: '*'\n      hf.Registrar.DelegateRoles: '*'\n      hf.Revoker: true\n    name: ${ADMIN_NAME}\n    pass: ${ADMIN_PASSWORD}\n    type: admin\n"})}),"\n",(0,i.jsx)(t.p,{children:"The critical attributes for revocation are:"}),"\n",(0,i.jsxs)(t.ul,{children:["\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.code,{children:"hf.GenCRL: true"})," - Allows generation of Certificate Revocation Lists"]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.code,{children:"hf.Revoker: true"})," - Grants permission to revoke certificates"]}),"\n",(0,i.jsxs)(t.li,{children:[(0,i.jsx)(t.code,{children:"hf.Registrar.Roles: '*'"})," - Manages roles for the CA"]}),"\n"]}),"\n",(0,i.jsx)(t.h2,{id:"step-by-step-revocation-process",children:"Step-by-Step Revocation Process"}),"\n",(0,i.jsx)(t.h3,{id:"1-configure-environment-variables",children:"1. Configure Environment Variables"}),"\n",(0,i.jsx)(t.p,{children:"First, set up your environment to connect to the Certificate Authority:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",children:"# Set CA URL\nexport FABRIC_CA_CLIENT_URL=https://${CA_HOST}:${CA_PORT}\n\n# Set TLS certificate path\n# You can obtain this from the `status.tls_cert` field of the CA custom resource\nexport FABRIC_CA_CLIENT_TLS_CERTFILES=${PWD}/${TLS_CERT_FILE}\n"})}),"\n",(0,i.jsx)(t.h3,{id:"2-authenticate-as-admin",children:"2. Authenticate as Admin"}),"\n",(0,i.jsx)(t.p,{children:"Enroll the admin user that has revocation privileges:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",children:"fabric-ca-client enroll -u https://${ADMIN_NAME}:${ADMIN_PASSWORD}@${CA_HOST}:${CA_PORT}\n"})}),"\n",(0,i.jsx)(t.h3,{id:"3-execute-the-revocation",children:"3. Execute the Revocation"}),"\n",(0,i.jsx)(t.p,{children:"Revoke the target identity using its enrollment ID:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",children:"fabric-ca-client revoke -e ${TARGET_IDENTITY}\n"})}),"\n",(0,i.jsx)(t.h3,{id:"4-generate-and-apply-the-crl",children:"4. Generate and Apply the CRL"}),"\n",(0,i.jsx)(t.p,{children:"After revoking the identity, create a Certificate Revocation List:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-bash",children:"fabric-ca-client gencrl\n"})}),"\n",(0,i.jsx)(t.p,{children:"Apply the generated CRL to your FabricFollowerChannel custom resource:"}),"\n",(0,i.jsx)(t.pre,{children:(0,i.jsx)(t.code,{className:"language-yaml",children:"apiVersion: hlf.kungfusoftware.es/v1alpha1\nkind: FabricFollowerChannel\nmetadata:\n  name: ${CHANNEL_NAME}\nspec:\n  # ...other configuration...\n  revocationList:\n    - |\n      <CRL_GENERATED_ABOVE>\n"})})]})}function h(e={}){const{wrapper:t}={...(0,r.R)(),...e.components};return t?(0,i.jsx)(t,{...e,children:(0,i.jsx)(d,{...e})}):d(e)}},8453:(e,t,n)=>{n.d(t,{R:()=>o,x:()=>a});var i=n(6540);const r={},s=i.createContext(r);function o(e){const t=i.useContext(s);return i.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function a(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(r):e.components||r:o(e.components),i.createElement(s.Provider,{value:t},e.children)}}}]);