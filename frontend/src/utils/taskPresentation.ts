/** Derive UI statuses without changing persisted queue states or authorization. */
export type ResultEntry = {state:string;result?:{attention?:boolean;eligible?:boolean;fingerprint?:string;awaiting_confirmation?:boolean}};
export type PresentedJob = {action?:string;mode?:string;due?:string;state:string;entries:ResultEntry[]};
export const activeJob=(j:PresentedJob)=>['queued','running'].includes(j.state)||j.entries.some(e=>e.state==='running');
// Historical tls-scan results had attention=true. Only real, valid eligible fingerprints count as review.
export const awaitingReview=(action:string|undefined,e:ResultEntry)=>action==='tls-scan'&&e.state==='done'&&!!e.result?.eligible&&/^[0-9a-f]{64}$/i.test(e.result?.fingerprint||'');
export const entryHasProblem=(action:string|undefined,e:ResultEntry)=>['failed','unknown'].includes(e.state)||(!awaitingReview(action,e)&&!!e.result?.attention);
export function jobCounts(j:PresentedJob){
 const review=j.entries.filter(e=>awaitingReview(j.action,e)).length;
 const errors=j.entries.filter(e=>['failed','unknown'].includes(e.state)).length;
 const warnings=j.entries.filter(e=>!['failed','unknown'].includes(e.state)&&entryHasProblem(j.action,e)).length;
 const ok=j.entries.filter(e=>e.state==='done'&&!awaitingReview(j.action,e)&&!entryHasProblem(j.action,e)).length;
 const processed=j.entries.filter(e=>!['pending','running'].includes(e.state)).length;
 return {review,errors,warnings,ok,processed};
}
export const hasJobProblem=(j:PresentedJob)=>['failed','interrupted'].includes(j.state)||j.entries.some(e=>entryHasProblem(j.action,e));
const labels:Record<string,string>={queued:'В очереди',running:'Выполняется',planned:'План (без запуска)',done:'Завершено',failed:'Ошибки',interrupted:'Прервано',stopped:'Остановлено',pending:'Ожидает',unknown:'Не подтверждено'};
export function jobLabel(j:PresentedJob){
 if(activeJob(j))return j.state==='queued'&&j.mode==='upgrade'&&j.due&&Date.parse(j.due)>Date.now()?'Запланировано':labels[j.state]||j.state;
 const {review,errors,warnings}=jobCounts(j);
 if(j.state==='stopped'||j.state==='interrupted')return labels[j.state]+(review?` · на сверку: ${review}`:'')+(errors?` · ошибок: ${errors}`:'');
 if(review)return `Ожидает сверки (${review})`+(errors?` · ошибок: ${errors}`:j.state==='failed'?' · есть ошибка':'')+(warnings?` · замечаний: ${warnings}`:'');
 if(j.state==='done'&&hasJobProblem(j))return 'С замечаниями';
 return labels[j.state]||j.state;
}
export function entryLabel(action:string|undefined,e:ResultEntry){
 return awaitingReview(action,e)?'Ожидает сверки':e.state==='done'&&e.result?.attention?'Требует внимания':labels[e.state]||e.state;
}
export function jobColor(j:PresentedJob){
 if(activeJob(j))return '#3b82f6';
 if(j.state==='stopped')return '#8490a3';
 const {review}=jobCounts(j);
 if(review&&j.state!=='interrupted')return '#eab308';
 if(['failed','interrupted'].includes(j.state)||j.entries.some(e=>['failed','unknown'].includes(e.state)))return '#ef4444';
 return hasJobProblem(j)?'#eab308':j.state==='done'?'#22c55e':'#8490a3';
}
export function countsText(j:PresentedJob){const c=jobCounts(j);return `${c.processed}/${j.entries.length} · ${c.ok} OK · ${c.review} на сверку · ${c.errors} ошибок · ${c.warnings} замечаний`;}
