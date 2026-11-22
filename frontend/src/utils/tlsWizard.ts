// Conservative stage selection: unknown/error states need diagnosis, not blind writes.
export type TlsCache=Record<string,{status:string;enabled?:boolean|null;detail?:string}>;
type DeviceRef={id:number;host:string;port?:number;username?:string;use_tls?:boolean;tls_fingerprint?:string|null};
type ScanEntry={id:number;host:string;port?:number;username?:string;tls?:boolean;pin?:string|null;state:string;result?:{eligible?:boolean;fingerprint?:string;port?:number}};
type ScanJob<E extends ScanEntry>={id:number;state:string;entries:E[]};
export function tlsPlan(devices:DeviceRef[],cache:TlsCache){
 const plan={audit:[] as number[],prepare:[] as number[],scan:[] as number[],verify:[] as number[],secure:0,diagnose:0};
 for(const d of devices){
   plan.audit.push(d.id);
   const s=cache[String(d.id)];
   if(d.use_tls && d.tls_fingerprint){plan.verify.push(d.id);if(s?.status==='secure')plan.secure++;else plan.diagnose++;continue;}
   if(d.use_tls && !d.tls_fingerprint){plan.scan.push(d.id);continue;}
   if(d.use_tls!==false){plan.diagnose++;continue;}
   if(s?.enabled===false && (s.status==='none'||s.status==='issued'||(s.status==='attention'&&s.detail?.includes('неподписанный шаблон')))){plan.prepare.push(d.id);continue;}
   if(s?.enabled===true && (s.status==='attention'||s.status==='issued')){plan.scan.push(d.id);continue;}
   plan.diagnose++;
 }
 return plan;
}
export function scanRows<E extends ScanEntry>(devices:DeviceRef[],job?:ScanJob<E>):E[]{
 if(!job||!['done','failed','stopped','interrupted'].includes(job.state)||job.entries.some(e=>e.state==='running'))return [];
 const byId=new Map(devices.map(d=>[d.id,d]));
 return job.entries.filter(e=>{
   const d=byId.get(e.id),r=e.result;
   // Match the same endpoint the server binds to the original scan. Already pinned TLS is not a migration candidate.
   return Boolean(d&&!(d.use_tls&&d.tls_fingerprint)&&e.state==='done'&&r?.eligible&&/^[0-9a-f]{64}$/i.test(r.fingerprint||'')&&Number.isInteger(r.port)&&Number(r.port)>0&&Number(r.port)<=65535&&e.host===d.host&&e.username===d.username&&e.port===d.port&&e.tls===d.use_tls&&(e.pin??null)===(d.tls_fingerprint??null));
 });
}
