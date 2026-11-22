import {validIPv4,compactNetworks} from './objectRouting';
export type BridgeLan={enabled:boolean;pvid:string;address:string;dhcp:boolean;poolStart:string;poolEnd:string;ospf:boolean};
export const defaultBridge=():BridgeLan=>({enabled:false,pvid:'1',address:'',dhcp:false,poolStart:'',poolEnd:'',ospf:true});
export function bridgeNetwork(b:BridgeLan){
 if(!b.enabled)return undefined;
 const [gateway,bits,...rest]=b.address.split('/');
 if(rest.length||!validIPv4(gateway)||! /^(?:[0-9]|[12][0-9]|30)$/.test(bits||''))return undefined;
 const subnet=compactNetworks([b.address])[0];
 if(!subnet)return undefined;
 return {subnet,gateway,ospf:b.ospf};
}
