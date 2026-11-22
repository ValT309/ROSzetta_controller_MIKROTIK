// SVG-мокапы лицевых панелей MikroTik. Подсвечивают живые порты по InterfaceInfo[].
// Сейчас реализован hAP ac lite (RB952Ui-5ac2nD): синий корпус, 5 ethernet,
// первый — PoE in (Internet), 2–4 LAN, 5 — PoE out (оранжевая обводка).

import { createContext, useContext, useState, useEffect, useRef, type ReactNode, type CSSProperties } from 'react';
import PortNetworkDetails from './PortNetworkDetails';
import { InterfaceInfo } from '@/api/client';
import { findPort, isWiredPort, portState, formatBytes, trafficPoint, trafficPath, formatRate, getPortDiagnostics, type TrafficPoint } from './portDetails';

export interface DeviceMockupProps {
  /** Имя модели из RouterOS (board-name), например "hAP ac lite". */
  boardName: string | null | undefined;
  /** Текущий снимок интерфейсов с устройства. */
  interfaces: InterfaceInfo[];
  deviceId?: number;
  snapshotAt?: number | null;
  snapshotError?: boolean;
}

const isHapAcLite = (b?: string | null): boolean =>
  !!b && /h\s*A\s*P\s*ac\s*lite/i.test(b);

// hAP ac² (RBD52G-5HacD2HnD): отличаем по цифре «2» / «²» после «ac»,
// чтобы случайно не перехватить hAP ac lite.
const isHapAc2 = (b?: string | null): boolean =>
  !!b && (/h\s*A\s*P\s*ac[\s\^]*[²2]/i.test(b) || /RBD52G/i.test(b));

const isHapLike = (b?: string | null): boolean => !!b && /\bh\s*A\s*P\b/i.test(b);

const isRb5009 = (b?: string | null): boolean =>
  !!b && /RB?\s*5009/i.test(b);

const isChr = (b?: string | null): boolean =>
  !!b && /\bCHR\b/i.test(b);

const isHexS = (b?: string | null): boolean =>
  !!b && /h\s*EX\s*S|RB?\s*760/i.test(b);

const isL009 = (b?: string | null): boolean =>
  !!b && /\bL\s*009/i.test(b);

const isRb4011 = (b?: string | null): boolean =>
  !!b && /RB?\s*4011/i.test(b);

// RB3011UiAS-RM — чёрный 1U: USB-3.0 + SFP (1G) + 10×GigE двумя группами
// с центральной LED-матрицей, справа LCD-экран.
const isRb3011 = (b?: string | null): boolean =>
  !!b && /RB?\s*3011/i.test(b);

// CRS317-1G-16S+ — белый 1U-свич: 16×SFP+ + 1 GigE (ETH/BOOT).
const isCrs317 = (b?: string | null): boolean =>
  !!b && /CRS\s*317(?:-?\s*1G)?(?:-?\s*16S)?/i.test(b);

// CRS328-24P-4S+RM — 1U-свич: 24×GigE PoE-out + 4×SFP+.
const isCrs328 = (b?: string | null): boolean =>
  !!b && /CRS\s*328/i.test(b);

// CRS354-48P-4S+2Q+RM — 1U-свич: 48×GigE PoE-out + 4×SFP+ + 2×QSFP+ (40G).
const isCrs354 = (b?: string | null): boolean =>
  !!b && /CRS\s*354/i.test(b);

// CCR2116-12G-4S+ — 1U-роутер: 12×GigE + 4×SFP+ (10G), CONSOLE, USB.
const isCcr2116 = (b?: string | null): boolean =>
  !!b && /CCR\s*2116/i.test(b);

// CRS326-24G-2S+RM — 1U-свич: 24×GigE + 2×SFP+ (10G), CONSOLE.
const isCrs326 = (b?: string | null): boolean =>
  !!b && /CRS\s*326(?!-?\s*24S)/i.test(b);

// hAP ax² (C52iG-5HaxD2HaxD): board-name в RouterOS — «hAP ax^2».
const isHapAx2 = (b?: string | null): boolean =>
  !!b && (/h\s*A\s*P\s*ax[\s\^]*[²2]/i.test(b) || /C52iG/i.test(b));

// CRS326-24S+2Q+RM — 1U-свич: 24×SFP+ (10G) + 2×QSFP+ (40G) + ether1 (управление).
const isCrs326S2Q = (b?: string | null): boolean =>
  !!b && /CRS\s*326-?\s*24S/i.test(b);

// CRS309-1G-8S+IN — настольный свич: 8×SFP+ (10G) + 1×GigE (ether1).
const isCrs309 = (b?: string | null): boolean =>
  !!b && /CRS\s*309/i.test(b);

// Модели с SFP28 (25G) и QSFP28 (100G).
const isCrs504 = (b?: string | null): boolean => !!b && /CRS\s*504/i.test(b);
const isCrs510 = (b?: string | null): boolean => !!b && /CRS\s*510/i.test(b);
const isCrs518 = (b?: string | null): boolean => !!b && /CRS\s*518/i.test(b);
const isCrs520 = (b?: string | null): boolean => !!b && /CRS\s*520/i.test(b);
const isCcr2216 = (b?: string | null): boolean => !!b && /CCR\s*2216/i.test(b);

// Найти интерфейс по базовому имени, допуская суффиксы вида `ether1-Uztelecom`,
// `ether2_LAN`, `ether3 description` и т.п. Сначала пробуем точное совпадение, потом по префиксу.
// -------- Цветомаркировка скоростей линка --------
//
// Палитра единая для всех мокапов и легенд. Цвет берётся по link_speed:
//   no link / disabled / нет данных → серый
//   10  Mb/s                        → тёмно-зелёный
//   100 Mb/s                        → бирюзовый
//   1   Gb/s (и 2.5G)               → зелёный  (как RJ45 на пиктограмме)
//   10  Gb/s (и 25G/40G/100G)       → фиолетовый
//
// link_speed приходит каноничной строкой ("10M", "100M", "1G", "2.5G", "10G", ...).

interface SpeedPalette {
  /** Главный цвет: используется как обводка иконки порта и LED. */
  color: string;
  /** Подпись для тултипа и легенды ("1 Gb/s", "no link"). */
  label: string;
}

function speedToMbps(s?: string | null): number | null {
  if (!s) return null;
  // «10G», «100Gbps», «25G-baseCR», «2.5G», «100M»…
  const m = String(s).match(/^\s*(\d+(?:[.,]\d+)?)\s*([MG])/i);
  if (!m) return null;
  const v = parseFloat(m[1].replace(',', '.'));
  if (!isFinite(v)) return null;
  return m[2].toUpperCase() === 'G' ? v * 1000 : v;
}

function paletteForSpeed(mbps: number | null): SpeedPalette {
  if (mbps == null)        return { color: '#9ca3af', label: 'no link'  };
  if (mbps <= 10)          return { color: '#166534', label: '10 Mb/s'  };
  if (mbps <= 100)         return { color: '#14b8a6', label: '100 Mb/s' };
  if (mbps <= 2500)        return { color: '#22c55e', label: `${mbps / 1000} Gb/s` };
  if (mbps <= 10000)       return { color: '#a855f7', label: `${mbps / 1000} Gb/s` };
  if (mbps <= 25000)       return { color: '#ec4899', label: '25 Gb/s'  };
  if (mbps <= 40000)       return { color: '#3b82f6', label: '40 Gb/s'  };
  if (mbps <= 50000)       return { color: '#eab308', label: '50 Gb/s'  };
  return                          { color: '#f43f5e', label: '100 Gb/s' };
}

/** Палитра порта: учитывает link_speed; при отсутствии — деградирует к running/down. */
function portPalette(it: InterfaceInfo | undefined): SpeedPalette {
  if (!it || it.disabled)     return { color: '#9ca3af', label: it?.disabled ? 'disabled' : 'нет данных' };
  if (!it.running)            return { color: '#9ca3af', label: 'no link' };
  const mbps = speedToMbps(it.link_speed);
  if (mbps != null)           return paletteForSpeed(mbps);
  // running, но link_speed нет (не ethernet или старая прошивка) — считаем «up» зелёным.
  return                            { color: '#22c55e', label: 'up' };
}

// -------- Иконки портов (общие для всех мокапов) --------
//
// Стилизованный RJ45 — чёрный корпус, цветной контур, серые «пины» внутри,
// сверху небольшой выступ-фиксатор. Внешний вид одинаков везде; меняется только
// прямоугольник позиционирования (x, y, w, h) и сама палитра (из link_speed).

interface PortIconExtras {
  /** Дополнительный текст в тултипе (PoE in/out, 2.5G, Internet и т.п.). */
  detail?: string;
  /** Кастомное имя для отображения в тултипе, если интерфейс не найден. */
  fallbackName?: string;
}

// Масштаб иконки относительно bounding-box, занимаемого портом в мокапе.
// 0.65 = иконка на 35% меньше; центрируется внутри прежнего bbox.
const PORT_ICON_SCALE = 0.65;

function rj45SvgPort(
  bx: number,
  by: number,
  bw: number,
  bh: number,
  it: InterfaceInfo | undefined,
  extras: PortIconExtras = {},
) {
  const pal = portPalette(it);
  // Уменьшаем иконку и центрируем её внутри переданного bbox.
  const w = bw * PORT_ICON_SCALE;
  const h = bh * PORT_ICON_SCALE;
  const x = bx + (bw - w) / 2;
  const y = by + (bh - h) / 2;
  // Толщина обводки берётся от меньшей стороны, чтобы иконка оставалась пропорциональной.
  const stroke = Math.max(1, Math.min(w, h) * 0.10);
  // Координаты «фиксатора» — выступ сверху по центру: 40% ширины, 18% высоты.
  const clipW = w * 0.40;
  const clipH = h * 0.18;
  const cx = x + w / 2;
  const clipX = cx - clipW / 2;
  const bodyTop = y + clipH;
  const bodyH = h - clipH;
  // Силуэт RJ45: фиксатор сверху + основной прямоугольник корпуса.
  const path = [
    `M ${clipX} ${y}`,
    `L ${clipX + clipW} ${y}`,
    `L ${clipX + clipW} ${bodyTop}`,
    `L ${x + w} ${bodyTop}`,
    `L ${x + w} ${y + h}`,
    `L ${x} ${y + h}`,
    `L ${x} ${bodyTop}`,
    `L ${clipX} ${bodyTop}`,
    'Z',
  ].join(' ');
  // 4 пина — строго симметричны относительно вертикальной оси корпуса.
  const pinAreaW = w * 0.64;            // ширина зоны пинов = 64% от ширины корпуса
  const pinAreaX = cx - pinAreaW / 2;   // центрирована
  const pinW = pinAreaW * 0.13;
  const pinGap = (pinAreaW - 4 * pinW) / 3;
  const pinTop = bodyTop + bodyH * 0.42;
  const pinH = bodyH * 0.42;
  const pinColor = '#7a7a7a';
  const name = it?.name || extras.fallbackName || '—';
  const tooltipLines: string[] = [];
  tooltipLines.push(extras.detail ? `${name} · ${extras.detail}` : name);
  tooltipLines.push(`состояние: ${portState(it)}; скорость: ${it?.running && !it.disabled ? it.link_speed || 'не получена' : '—'}`);
  if (it?.comment) tooltipLines.push(`comment: ${it.comment}`);
  if (it?.mac_address) tooltipLines.push(`mac: ${it.mac_address}`);
  // Внешний ободок порта — всегда серый, не меняется по статусу.
  // Цвет статуса/скорости отражает только внутренняя RJ45-иконка.
  const bezelR = Math.max(1, Math.min(bw, bh) * 0.08);
  const bezelStroke = Math.max(0.6, Math.min(bw, bh) * 0.06);
  return (
    <PortTarget it={it} name={name} bounds={[bx, by, bw, bh]}>
      {/* Постоянный серый ободок (как «металл» вокруг разъёма) */}
      <rect
        x={bx + bezelStroke / 2}
        y={by + bezelStroke / 2}
        width={bw - bezelStroke}
        height={bh - bezelStroke}
        rx={bezelR}
        ry={bezelR}
        fill="#0a0a0a"
        stroke="#9ca3af"
        strokeWidth={bezelStroke}
      />
      {/* Стилизованная RJ45-иконка внутри — цвет берётся из палитры скоростей */}
      <path d={path} fill="#0a0a0a" stroke={pal.color} strokeWidth={stroke} strokeLinejoin="miter" />
      {[0, 1, 2, 3].map((i) => (
        <rect
          key={i}
          x={pinAreaX + i * (pinW + pinGap)}
          y={pinTop}
          width={pinW}
          height={pinH}
          fill={pinColor}
        />
      ))}
      <title>{tooltipLines.join('\n')}</title>
    </PortTarget>
  );
}

function sfpSvgPort(
  bx: number,
  by: number,
  bw: number,
  bh: number,
  it: InterfaceInfo | undefined,
  extras: PortIconExtras = {},
) {
  const pal = portPalette(it);
  const w = bw * PORT_ICON_SCALE;
  const h = bh * PORT_ICON_SCALE;
  const x = bx + (bw - w) / 2;
  const y = by + (bh - h) / 2;
  const stroke = Math.max(1, Math.min(w, h) * 0.10);
  // Прямоугольная клетка SFP без верхнего выступа, с двумя тёмными полосами по бокам.
  const sidebarW = w * 0.16;
  const name = it?.name || extras.fallbackName || '—';
  const tooltipLines: string[] = [];
  tooltipLines.push(extras.detail ? `${name} · ${extras.detail}` : `${name} · SFP`);
  tooltipLines.push(`состояние: ${portState(it)}; скорость: ${it?.running && !it.disabled ? it.link_speed || 'не получена' : '—'}`);
  if (it?.comment) tooltipLines.push(`comment: ${it.comment}`);
  if (it?.mac_address) tooltipLines.push(`mac: ${it.mac_address}`);
  return (
    <PortTarget it={it} name={name} bounds={[bx, by, bw, bh]}>
      <rect x={x} y={y} width={w} height={h} fill="#0a0a0a" stroke={pal.color} strokeWidth={stroke} />
      <rect x={x + stroke / 2} y={y + stroke / 2} width={sidebarW} height={h - stroke} fill="#1f1f1f" />
      <rect x={x + w - sidebarW - stroke / 2} y={y + stroke / 2} width={sidebarW} height={h - stroke} fill="#1f1f1f" />
      <title>{tooltipLines.join('\n')}</title>
    </PortTarget>
  );
}

type PortSelection = { name: string; fallback?: boolean };
const PortContext = createContext<{ selected: PortSelection | null; select: (p: PortSelection) => void }>({ selected: null, select: () => {} });

function PortTarget({ it, name, bounds, children }: { it?: InterfaceInfo; name: string; bounds: [number, number, number, number]; children: ReactNode }) {
  const { selected, select } = useContext(PortContext);
  const active = selected?.name === name && Boolean(selected?.fallback) === !it;
  const [x,y,w,h] = bounds;
  const activate = () => select({ name, fallback: !it });
  return <g role="button" tabIndex={0} aria-label={`${name}: ${portState(it)}`} aria-pressed={active}
    style={{ cursor: 'pointer' }} onClick={activate} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); } }}>
    {children}
    <rect x={x} y={y} width={w} height={h} rx={2} fill="transparent" stroke={active ? '#60a5fa' : 'transparent'} strokeWidth={2} pointerEvents="all" />
  </g>;
}

// Enlarge the front panel without stretching its physical aspect ratio.
function frontPanelStyle(w: number, h: number): CSSProperties {
  const height=h>=200?116:108;
  return {width:`${Math.round(w/h*height)}px`,height:'auto',maxWidth:'100%',display:'block'};
}

function TrafficGraph({points}: {points:TrafficPoint[]}) {
  const max=Math.max(1,...points.flatMap(p=>[p.rx??0,p.tx??0]));
  const hasData=points.some(p=>p.rx!==null||p.tx!==null);
  const time=(ms:number)=>new Date(ms).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  if (!hasData) return <p className="text-mk-mute">График появится после двух пригодных снимков счётчиков.</p>;
  return <div className="space-y-1"><div className="flex justify-between gap-2"><b>Трафик порта</b><span className="text-mk-mute">{formatRate(max)} (верх шкалы)</span></div>
    <svg viewBox="0 0 560 108" role="img" aria-label="История измеренного RX и TX в битах в секунду" className="w-full h-auto" style={{maxHeight:'150px'}}>
      {[0,25,50,75,100].map(y=><line key={y} x1="0" y1={y+4} x2="560" y2={y+4} stroke="currentColor" opacity={.12} strokeDasharray="3 4"/>)}
      <g transform="translate(0 4)"><path d={trafficPath(points,'rx',max)} fill="none" stroke="#22c55e" strokeWidth="2" vectorEffect="non-scaling-stroke"/><path d={trafficPath(points,'tx',max)} fill="none" stroke="#60a5fa" strokeWidth="2" vectorEffect="non-scaling-stroke"/>
      {points.length===2&&(['rx','tx'] as const).map((key,i)=>{const v=points[1][key];return v!==null?<circle key={key} cx="557" cy={100*(1-v/max)} r="3" fill={i?'#60a5fa':'#22c55e'}/>:null})}</g>
    </svg><div className="flex justify-between text-mk-mute"><span>{time(points[0].at)}</span><span>{time(points[points.length-1].at)}</span></div>
    <div className="flex gap-3"><span style={{color:'#22c55e'}}>● RX</span><span style={{color:'#60a5fa'}}>● TX</span><span className="text-mk-mute">До 40 снимков этой сессии</span></div></div>;
}

export default function DeviceMockup({ boardName, interfaces, snapshotAt, snapshotError, deviceId }: DeviceMockupProps) {
  const [selected, setSelected] = useState<PortSelection | null>(null);
  const [history,setHistory]=useState<Record<string,TrafficPoint[]>>({});
  const previous=useRef<Record<string,InterfaceInfo>>({});
  const latestSample=useRef<number|null>(null);
  useEffect(()=>{
    if(!snapshotAt||snapshotError||latestSample.current===snapshotAt)return;
    latestSample.current=snapshotAt;
    const next: Record<string,InterfaceInfo>={};
    const samples: Record<string,TrafficPoint>={};
    for(const item of interfaces.filter(isWiredPort)){
      const key=item.name;next[key]=item;
      const point=trafficPoint(previous.current[key],item);
      if(point)samples[key]=point;
    }
    previous.current=next;
    setHistory(old=>Object.fromEntries(Object.keys(next).map(key=>{
      const point=samples[key], prior=old[key]??[];
      // A server clock step or refreshed old sample is not a valid continuation.
      const list=point&&prior.length&&point.at<=prior[prior.length-1].at?[]:prior;
      return [key,point?[...list,point].slice(-40):list];
    })));
  },[snapshotAt,snapshotError,interfaces]);
  const physical = interfaces.filter(isWiredPort);
  const current = selected ? (selected.fallback ? findPort(interfaces, selected.name) : interfaces.find(i => i.name === selected.name)) : undefined;
  const points=current?history[current.name]??[]:[];
  const last=points[points.length-1];
  const diagnostic=getPortDiagnostics(current);
  const rows = current ? [
    ['Заводское имя', current.default_name || '—'], ['Тип', current.type || '—'],
    ['MAC', current.mac_address || '—'], ['Комментарий', current.comment || '—'],
    ['RX (счётчик)', current.rx_counter===null?'—':formatBytes(current.rx_bytes)], ['TX (счётчик)', current.tx_counter===null?'—':formatBytes(current.tx_bytes)],
  ] : [];
  return <PortContext.Provider value={{ selected, select: setSelected }}>
    <div className="min-w-0 space-y-2">
      <DevicePanel boardName={boardName} interfaces={interfaces} />
      <div className="card space-y-2 text-xs">
        <div className="flex flex-wrap items-center gap-2"><b>Физические порты · v1.4</b><span className="text-mk-mute">{physical.filter(i=>i.running&&!i.disabled).length} активных из {physical.length} полученных</span></div>
        <p className={snapshotError?'text-mk-warn':'text-mk-mute'}>{snapshotError?'Опрос не удался. '+(snapshotAt?'Показан последний снимок.':'Данные не получены.'):snapshotAt?'Последний снимок: '+new Date(snapshotAt).toLocaleTimeString():'Ожидание данных'}</p>
        <p className="text-mk-mute">Нажмите на порт схемы или выберите его в списке. Только чтение.</p>
        <div className="flex flex-wrap gap-1 max-h-36 overflow-auto">{physical.map(i=>{const poe=i.diagnostics?.['poe-out-status'];return <button key={i.name} type="button" className={selected?.name===i.name?'btn-primary !px-2 !py-1':'btn-secondary !px-2 !py-1'} aria-pressed={selected?.name===i.name} onClick={()=>setSelected({name:i.name})}><span style={{color:portPalette(i).color}}>●</span> {i.name}{poe&&<span className={poe==='powered-on'?'text-mk-ok':poe==='off'||poe==='waiting-for-load'?'text-mk-mute':'text-mk-warn'} title={'PoE: '+poe}> · PoE</span>}</button>})}</div>
        {selected && <div className="border border-mk-border rounded-lg p-3 space-y-3 max-w-[1100px]">
          <div className="flex items-center gap-2"><b className="break-all text-sm">{current?.name || selected.name}</b><span style={{color:portPalette(current).color}}>{portState(current)}</span><button type="button" className="btn-secondary ml-auto" onClick={()=>setSelected(null)}>Закрыть</button></div>
          {!current?<p className="text-mk-mute">Нет данных для этого порта в текущем снимке.</p>:<>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div className="space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {[['Скорость линка',current.running&&!current.disabled?current.link_speed||'Не получена':'—'],['RX, среднее',formatRate(snapshotError?null:last?.rx)],['TX, среднее',formatRate(snapshotError?null:last?.tx)]].map(([label,value])=><div key={label} className="border border-mk-border rounded p-2"><div className="text-mk-mute">{label}</div><b className="text-sm">{value}</b></div>)}
              </div>
              <div className="text-mk-mute">{snapshotError?'Текущая скорость неизвестна, график исторический.':last?.seconds?`Среднее за ${Math.round(last.seconds)} с между опросами (не мгновенная скорость).`:'Нужны два последовательных измерения без сброса счётчиков.'}</div>
              <TrafficGraph points={points}/>
              <div className="grid grid-cols-2 gap-2">{rows.map(([label,value])=><div key={label} className="min-w-0 border-t border-mk-border pt-1"><span className="text-mk-mute">{label}</span><div className="break-all">{value}</div></div>)}</div>
            </div>
            <div className="space-y-2"><b>Диагностика порта</b>{diagnostic.length?diagnostic.map(g=><div key={g.title} className="border border-mk-border rounded p-2"><b>{g.title}</b><div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-1">{g.rows.map(([label,value])=><div key={label}><div className="text-mk-mute">{label}</div><div className="break-words">{value}</div></div>)}</div></div>):<p className="text-mk-mute">Дополнительная диагностика не получена.</p>}<p className="text-mk-mute">Неподдерживаемые или недоступные показатели не отображаются. Нулевые ошибки показываются только если получены от устройства.</p></div>
          </div>{deviceId!=null&&<PortNetworkDetails key={`${deviceId}:${current.name}`} deviceId={deviceId} port={current.name}/>}</>}
        </div>}
      </div>
    </div>
  </PortContext.Provider>;
}

function DevicePanel({ boardName, interfaces }: DeviceMockupProps) {
  if (isHapAcLite(boardName)) {
    return <HapAcLiteMockup interfaces={interfaces} />;
  }
  if (isHapAx2(boardName)) {
    return <HapAx2Mockup interfaces={interfaces} />;
  }
  if (isHapAc2(boardName)) {
    return <HapAc2Mockup interfaces={interfaces} />;
  }
  if (isHapLike(boardName) && interfaces.filter((it) => /^ether/i.test(it.default_name || it.name) && isWiredPort(it)).length === 5) {
    return <HapAcLiteMockup interfaces={interfaces} />;
  }
  if (isRb5009(boardName)) {
    return <Rb5009Mockup interfaces={interfaces} />;
  }
  if (isRb4011(boardName)) {
    return <Rb4011Mockup interfaces={interfaces} />;
  }
  if (isRb3011(boardName)) {
    return <Rb3011Mockup interfaces={interfaces} />;
  }
  if (isCrs317(boardName)) {
    return <Crs317Mockup interfaces={interfaces} />;
  }
  if (isCrs328(boardName)) {
    return <Crs328Mockup interfaces={interfaces} />;
  }
  if (isCrs354(boardName)) {
    return <Crs354Mockup interfaces={interfaces} />;
  }
  if (isCcr2116(boardName)) {
    return <Ccr2116Mockup interfaces={interfaces} />;
  }
  if (isCrs326(boardName)) {
    return <Crs326Mockup interfaces={interfaces} />;
  }
  if (isCrs326S2Q(boardName)) {
    return <Crs326S2QMockup interfaces={interfaces} />;
  }
  if (isCrs309(boardName)) {
    return <Crs309Mockup interfaces={interfaces} />;
  }
  if (isCrs504(boardName)) {
    return <DenseSfpMockup interfaces={interfaces} model="CRS504-4XQ-IN" brand="Cloud Router Switch" sfp28={0} qsfp={4} />;
  }
  if (isCrs510(boardName)) {
    return <DenseSfpMockup interfaces={interfaces} model="CRS510-8XS-2XQ-IN" brand="Cloud Router Switch" sfp28={8} qsfp={2} />;
  }
  if (isCrs518(boardName)) {
    return <DenseSfpMockup interfaces={interfaces} model="CRS518-16XS-2XQ-RM" brand="Cloud Router Switch" sfp28={16} qsfp={2} />;
  }
  if (isCrs520(boardName)) {
    return <DenseSfpMockup interfaces={interfaces} model="CRS520-4XS-16XQ-RM" brand="Cloud Router Switch" sfp28={4} qsfp={16} />;
  }
  if (isCcr2216(boardName)) {
    return <DenseSfpMockup interfaces={interfaces} model="CCR2216-1G-12XS-2XQ" brand="Cloud Core Router" dark sfp28={12} qsfp={2} />;
  }
  if (isHexS(boardName)) {
    return <HexSMockup interfaces={interfaces} />;
  }
  if (isL009(boardName)) {
    return <L009Mockup interfaces={interfaces} />;
  }
  if (isChr(boardName)) {
    return <ChrMockup interfaces={interfaces} />;
  }
  // Для всех моделей без собственного мокапа — универсальная CHR-схема портов.
  return <ChrMockup interfaces={interfaces} boardName={boardName} generic />;
}

// --------- hAP ac lite ---------

function HapAcLiteMockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const byName = new Map(interfaces.map((it) => [it.name, it]));
  // Раскладка портов: ether1 = Internet/PoE in, ether2..ether4 = LAN, ether5 = PoE out.
  const ports = [
    { name: 'ether1', label: 'Internet',         poe: 'in'  as const },
    { name: 'ether2', label: '2',                poe: null  as const },
    { name: 'ether3', label: '3',                poe: null  as const },
    { name: 'ether4', label: '4',                poe: null  as const },
    { name: 'ether5', label: '5',                poe: 'out' as const },
  ];

  // Размеры в условных единицах — масштабируются через viewBox.
  const W = 1180, H = 230;
  const bodyR = 14;
  const portW = 130, portH = 110;
  const firstPortX = 360;
  const portGap = 12;
  const portsTopY = 50;

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>hAP ac lite</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
        >
          {/* Корпус */}
          <rect x="2" y="2" width={W - 4} height={H - 4} rx={bodyR} ry={bodyR} fill="#5cb4e5" stroke="#3990c2" strokeWidth="2" />

          {/* Power разъём + подпись */}
          <text x="60" y="35" fontSize="20" fill="#ffffff" fontWeight="700">Power</text>
          <circle cx="60" cy="100" r="28" fill="#0a0a0a" stroke="#143d59" strokeWidth="3" />
          <circle cx="60" cy="100" r="9"  fill="#1a1a1a" stroke="#0a0a0a" strokeWidth="2" />
          <text x="60" y="180" fontSize="13" fill="#ffffff" textAnchor="middle">DC10-28V</text>

          {/* hAPaclite лого */}
          <text x="225" y="40" fontSize="34" fill="#ffffff" fontWeight="800" fontFamily="Inter, sans-serif">hAP</text>
          <text x="310" y="27" fontSize="13" fill="#ffffff" fontWeight="700">ac</text>
          <text x="310" y="42" fontSize="13" fill="#ffffff" fontWeight="700">lite</text>
          {/* WiFi-дуга над лого */}
          <path d="M 230 14 Q 260 -2 290 14" fill="none" stroke="#ffffff" strokeWidth="2.5" />

          {/* RES (кнопка с кругом и подписью WPS) */}
          <circle cx="160" cy="100" r="14" fill="none" stroke="#d04848" strokeWidth="3" />
          <circle cx="160" cy="100" r="4"  fill="#222" />
          <text x="160" y="78" fontSize="13" fill="#ffffff" textAnchor="middle" fontWeight="700">RES</text>
          <text x="160" y="135" fontSize="11" fill="#ffffff" textAnchor="middle">WPS</text>

          {/* PWR кнопка (квадрат) */}
          <text x="210" y="78" fontSize="13" fill="#ffffff" textAnchor="middle" fontWeight="700">PWR</text>
          <rect x="197" y="88" width="26" height="22" rx="3" fill="#444" stroke="#222" strokeWidth="2" />

          {/* USR светодиод */}
          <text x="260" y="78" fontSize="13" fill="#ffffff" textAnchor="middle" fontWeight="700">USR</text>
          <rect x="251" y="92" width="18" height="14" rx="2" fill="#1f6f1f" />

          {/* Тёмная полоса фоны для верхних/нижних лейблов */}
          <rect x="350" y="8"  width={W - 360} height="26" fill="#1c1c1c" />
          <rect x="350" y="178" width={W - 360} height="40" fill="#1c1c1c" />

          {/* Оранжевая зона PoE out над портом 5 */}
          <rect
            x={firstPortX + 4 * (portW + portGap) - 6}
            y="8"
            width={portW + 12}
            height="26"
            fill="#f0851a"
          />
          {/* Оранжевая зона PoE out внизу */}
          <rect
            x={firstPortX + 4 * (portW + portGap) - 6}
            y="178"
            width={portW + 12}
            height="40"
            fill="#f0851a"
          />

          {/* Порты */}
          {ports.map((p, i) => {
            const x = firstPortX + i * (portW + portGap);
            const it = findPort(interfaces, p.name);
            const detail =
              p.poe === 'in' ? `${p.label} · PoE in`
              : p.poe === 'out' ? `${p.label} · PoE out`
              : `LAN ${p.label}`;
            return (
              <g key={p.name}>
                {/* Верхний лейбл (Internet / 2 / 3 / 4 / 5) */}
                <text
                  x={x + portW / 2}
                  y="27"
                  fontSize="16"
                  fill="#ffffff"
                  fontWeight="700"
                  textAnchor="middle"
                >
                  {p.label}
                </text>

                {rj45SvgPort(x, portsTopY, portW, portH, it, { detail, fallbackName: p.name })}

                {/* Имя интерфейса под портом */}
                <text x={x + portW / 2} y={portsTopY + portH + 14} fontSize="11" fill="#ffffff" textAnchor="middle">{p.name}</text>
              </g>
            );
          })}

          {/* Нижние подписи: PoE in / LAN / PoE out */}
          <text x={firstPortX + portW / 2} y="202" fontSize="14" fill="#ffffff" textAnchor="middle" fontWeight="600">PoE in</text>
          <text x={firstPortX + portW + portGap + (portW * 3 + portGap * 2) / 2} y="202" fontSize="14" fill="#ffffff" textAnchor="middle" fontWeight="600">LAN</text>
          <text x={firstPortX + 4 * (portW + portGap) + portW / 2} y="202" fontSize="14" fill="#ffffff" textAnchor="middle" fontWeight="600">PoE out</text>
        </svg>
      </div>

      <MockupLegend />
    </div>
  );
}

// --------- hAP ac² ---------
// Чёрный пластиковый корпус (RBD52G-5HacD2HnD).
// Слева: DC 12-28V, утопленная кнопка res/wps, индикаторы pwr / usr.
// Справа: 5 GigE портов — ether1 «Internet/PoE in», ether2..ether5 «LAN».
// PoE-out нет (в отличие от hAP ac lite).

function HapAc2Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const ports = [
    { name: 'ether1', label: '1', accent: 'poe-in' as const },
    { name: 'ether2', label: '2', accent: null     as const },
    { name: 'ether3', label: '3', accent: null     as const },
    { name: 'ether4', label: '4', accent: null     as const },
    { name: 'ether5', label: '5', accent: null     as const },
  ];

  // Соотношение фото задней панели ~4.3:1. При height: 62px ширина ≈ 268px.
  const W = 1180, H = 274;
  const bodyR = 20;
  const portW = 130, portH = 130;
  const portGap = 14;
  const firstPortX = 410;
  const portsTopY = 60;
  const lanStartX = firstPortX + portW + portGap;
  const lanSpanW = 4 * portW + 3 * portGap;

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>hAP ac²</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
        >
          {/* Чёрный пластиковый корпус */}
          <rect x="2" y="2" width={W - 4} height={H - 4} rx={bodyR} ry={bodyR} fill="#1f1f1f" stroke="#050505" strokeWidth="2" />
          {/* Утопленная плашка отсека (чуть темнее, со внутренней тенью обводки) */}
          <rect x="20" y="22" width={W - 40} height={H - 64} rx="12" fill="#161616" stroke="#000" strokeWidth="1" />

          {/* DC разъём */}
          <circle cx="92" cy="148" r="36" fill="#0a0a0a" stroke="#3a3a3a" strokeWidth="3" />
          <circle cx="92" cy="148" r="10" fill="#1a1a1a" stroke="#000" strokeWidth="2" />
          <text x="92" y="235" fontSize="22" fill="#ffffff" textAnchor="middle" fontWeight="700">DC</text>
          <text x="92" y="256" fontSize="14" fill="#cccccc" textAnchor="middle">12-28V</text>

          {/* res/wps — утопленная кнопка */}
          <circle cx="188" cy="148" r="10" fill="#0a0a0a" stroke="#555" strokeWidth="1.5" />
          <circle cx="188" cy="148" r="3"  fill="#222" />
          <text x="188" y="92" fontSize="14" fill="#ffffff" textAnchor="middle" fontWeight="600">res/wps</text>

          {/* pwr LED */}
          <circle cx="252" cy="148" r="5" fill="#1f6f1f" />
          <text x="252" y="92" fontSize="14" fill="#ffffff" textAnchor="middle" fontWeight="600">pwr</text>

          {/* usr LED */}
          <circle cx="312" cy="148" r="5" fill="#3a3a3a" />
          <text x="312" y="92" fontSize="14" fill="#ffffff" textAnchor="middle" fontWeight="600">usr</text>

          {/* Цифры над портами */}
          {ports.map((p, i) => {
            const x = firstPortX + i * (portW + portGap);
            return (
              <text
                key={`lbl-${p.name}`}
                x={x + portW / 2}
                y="48"
                fontSize="22"
                fill="#ffffff"
                fontWeight="700"
                textAnchor="middle"
              >
                {p.label}
              </text>
            );
          })}

          {/* Порты */}
          {ports.map((p, i) => {
            const x = firstPortX + i * (portW + portGap);
            const it = findPort(interfaces, p.name);
            const detail = p.accent === 'poe-in' ? `${p.label} · Internet / PoE in` : `LAN ${p.label}`;
            return (
              <g key={p.name}>
                {rj45SvgPort(x, portsTopY, portW, portH, it, { detail, fallbackName: p.name })}
                {/* Имя интерфейса под портом */}
                <text x={x + portW / 2} y={portsTopY + portH + 16} fontSize="11" fill="#bbbbbb" textAnchor="middle">
                  {p.name}
                </text>
              </g>
            );
          })}

          {/* Группа Internet/PoE in под портом 1 */}
          <line x1={firstPortX - 2} y1={H - 36} x2={firstPortX + portW + 2} y2={H - 36} stroke="#9aa0a6" strokeWidth="1.2" />
          <circle cx={firstPortX - 2} cy={H - 36} r="3" fill="#9aa0a6" />
          <circle cx={firstPortX + portW + 2} cy={H - 36} r="3" fill="#9aa0a6" />
          <text x={firstPortX + portW / 2} y={H - 14} fontSize="14" fill="#ffffff" textAnchor="middle" fontWeight="600">
            Internet/PoE in
          </text>

          {/* Группа LAN под портами 2-5 */}
          <line x1={lanStartX - 2} y1={H - 36} x2={lanStartX + lanSpanW + 2} y2={H - 36} stroke="#9aa0a6" strokeWidth="1.2" />
          <circle cx={lanStartX - 2} cy={H - 36} r="3" fill="#9aa0a6" />
          <circle cx={lanStartX + lanSpanW + 2} cy={H - 36} r="3" fill="#9aa0a6" />
          <text x={lanStartX + lanSpanW / 2} y={H - 14} fontSize="14" fill="#ffffff" textAnchor="middle" fontWeight="600">
            LAN
          </text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- RB5009UG+S+ ---------
// Чёрный корпус, 8 GigE портов (ether1..ether8) + 1 SFP+ (sfp-sfpplus1).
// Слева: DC jack 12-57V, кнопка R (reset), USB 3.0 порт.
// ether1 — PoE in (жёлтая обводка), ether8 — 2.5GbE (синяя обводка), sfp-sfpplus1 — 10G.

function Rb5009Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const byName = new Map(interfaces.map((it) => [it.name, it]));
  const W = 520, H = 66;
  const portW = 32, portH = 32, gap = 3;
  const portsY = (H - portH) / 2 - 1;
  const portsStartX = 132;
  const sfpW = 60;
  const sfp = findPort(interfaces, 'sfp-sfpplus1') || findPort(interfaces, 'sfpplus1');

  const ports = [
    { name: 'ether1', label: '1', accent: 'poe' as const  },
    { name: 'ether2', label: '2', accent: null  as const },
    { name: 'ether3', label: '3', accent: null  as const },
    { name: 'ether4', label: '4', accent: null  as const },
    { name: 'ether5', label: '5', accent: null  as const },
    { name: 'ether6', label: '6', accent: null  as const },
    { name: 'ether7', label: '7', accent: null  as const },
    { name: 'ether8', label: '8', accent: '2g5' as const  },
  ];

  const accentColor = (a: 'poe' | '2g5' | null) =>
    a === 'poe' ? '#f0851a' : a === '2g5' ? '#2563eb' : null;
  const sfpX = portsStartX + ports.length * (portW + gap) + 6;

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>RB5009UG+S+</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Чёрный корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="4" fill="#1a1a1a" stroke="#3a3a3a" strokeWidth="1" />

          {/* DC jack */}
          <text x="14" y="9" fontSize="3.5" fill="#cccccc" fontWeight="700" textAnchor="middle">12-57V DC</text>
          <circle cx="14" cy="32" r="9" fill="#0a0a0a" stroke="#444" strokeWidth="0.8" />
          <circle cx="14" cy="32" r="3" fill="#222" />
          <text x="14" y="58" fontSize="3" fill="#888" textAnchor="middle">DC IN</text>

          {/* RES */}
          <text x="38" y="9" fontSize="4" fill="#cccccc" fontWeight="700" textAnchor="middle">R</text>
          <circle cx="38" cy="22" r="2.5" fill="none" stroke="#d04848" strokeWidth="0.8" />
          <circle cx="38" cy="22" r="1" fill="#222" />
          <text x="38" y="58" fontSize="3" fill="#888" textAnchor="middle">RES</text>

          {/* USB 3.0 */}
          <text x="72" y="9" fontSize="4" fill="#cccccc" fontWeight="700" textAnchor="middle">USB</text>
          <rect x="56" y="20" width="32" height="22" rx="1" fill="#0a0a0a" stroke="#666" strokeWidth="0.5" />
          <rect x="58" y="22" width="28" height="18" fill="#1a4b8c" />
          <rect x="66" y="26" width="12" height="6" fill="#0a0a0a" />
          <text x="72" y="58" fontSize="3" fill="#888" textAnchor="middle">USB 3.0</text>

          {/* PWR/USR LED */}
          <circle cx="104" cy="12" r="2" fill="#22c55e" />
          <text x="104" y="22" fontSize="3" fill="#888" textAnchor="middle">PWR</text>
          <circle cx="120" cy="12" r="2" fill="#1f6f1f" />
          <text x="120" y="22" fontSize="3" fill="#888" textAnchor="middle">USR</text>

          {/* Лейблы цифр над портами + полоса акцента (PoE/2.5G) */}
          {ports.map((p, i) => {
            const x = portsStartX + i * (portW + gap);
            const accent = accentColor(p.accent);
            return (
              <g key={`lbl-${p.name}`}>
                {accent && (
                  <rect x={x} y="1" width={portW} height="3" fill={accent} />
                )}
                <text x={x + portW / 2} y="10" fontSize="6" fill="#ffffff" fontWeight="800" textAnchor="middle">{p.label}</text>
              </g>
            );
          })}

          {/* Порты */}
          {ports.map((p, i) => {
            const x = portsStartX + i * (portW + gap);
            const it = findPort(interfaces, p.name);
            const detail =
              p.accent === 'poe' ? `порт ${p.label} · PoE in`
              : p.accent === '2g5' ? `порт ${p.label} · 2.5 GbE`
              : `порт ${p.label}`;
            return (
              <g key={p.name}>
                {rj45SvgPort(x, portsY, portW, portH, it, { detail, fallbackName: p.name })}
              </g>
            );
          })}

          {/* SFP+ слот */}
          {(() => {
            return (
              <g>
                <rect x={sfpX} y="1" width={sfpW} height="3" fill="#7c3aed" />
                <text x={sfpX + sfpW / 2} y="10" fontSize="6" fill="#ffffff" fontWeight="800" textAnchor="middle">SFP+</text>
                {sfpSvgPort(sfpX, portsY, sfpW, portH, sfp, { detail: '10 GbE SFP+', fallbackName: 'sfp-sfpplus1' })}
                <text x={sfpX + sfpW / 2} y={H - 2} fontSize="3.5" fill="#888" textAnchor="middle">10G SFP+</text>
              </g>
            );
          })()}

          {/* Подписи акцентов снизу */}
          <text x={portsStartX + portW / 2} y={H - 2} fontSize="3" fill="#f0851a" textAnchor="middle">PoE in</text>
          <text x={portsStartX + 7 * (portW + gap) + portW / 2} y={H - 2} fontSize="3" fill="#2563eb" textAnchor="middle">2.5G</text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- RB4011iGS+ ---------
// Чёрный корпус 1U: слева RESET + PWR LED, затем SFP+ слот, 5 GigE портов (1-5, PoE-in 18-57V на ether1),
// центральная LED-матрица статусов (1-5 сверху, 6-10 снизу) и 5 GigE портов (6-10, PoE-out на ether10).

function Rb4011Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const W = 500, H = 66;
  const portW = 32, portH = 32, gap = 3;
  const portsY = (H - portH) / 2 - 1;
  const sfpW = 50;
  const sfpX = 30;
  const group1StartX = sfpX + sfpW + 4;
  const ledBlockW = 24;
  const ledBlockGap = 4;
  const group2StartX =
    group1StartX + 5 * (portW + gap) - gap + ledBlockGap + ledBlockW + ledBlockGap;

  const sfp = findPort(interfaces, 'sfp-sfpplus1') || findPort(interfaces, 'sfpplus1');

  const portsLeft = [
    { name: 'ether1', label: '1' },
    { name: 'ether2', label: '2' },
    { name: 'ether3', label: '3' },
    { name: 'ether4', label: '4' },
    { name: 'ether5', label: '5' },
  ];
  const portsRight = [
    { name: 'ether6',  label: '6'  },
    { name: 'ether7',  label: '7'  },
    { name: 'ether8',  label: '8'  },
    { name: 'ether9',  label: '9'  },
    { name: 'ether10', label: '10' },
  ];

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>RB4011iGS+</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Чёрный корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="4" fill="#1a1a1a" stroke="#3a3a3a" strokeWidth="1" />

          {/* RESET кнопка */}
          <circle cx="10" cy="24" r="3" fill="none" stroke="#d04848" strokeWidth="0.8" />
          <circle cx="10" cy="24" r="1.2" fill="#222" />
          <text x="10" y="44" fontSize="3.5" fill="#888" textAnchor="middle">RESET</text>

          {/* PWR LED */}
          <text x="22" y="20" fontSize="3.5" fill="#cccccc" fontWeight="700" textAnchor="middle">PWR</text>
          <circle cx="22" cy="26" r="1.6" fill="#22c55e" />

          {/* SFP+ слот */}
          {(() => {
            return (
              <g>
                <rect x={sfpX} y="1" width={sfpW} height="3" fill="#7c3aed" />
                <text x={sfpX + sfpW / 2} y="10" fontSize="5.5" fill="#ffffff" fontWeight="800" textAnchor="middle">SFP+</text>
                {sfpSvgPort(sfpX, portsY, sfpW, portH, sfp, { detail: '10 GbE SFP+', fallbackName: 'sfp-sfpplus1' })}
                <text x={sfpX + sfpW / 2} y={H - 2} fontSize="3.5" fill="#aaaaaa" textAnchor="middle">SFP+ 10G</text>
              </g>
            );
          })()}

          {/* Акцентная полоска PoE-in над ether1 */}
          <rect x={group1StartX} y="1" width={portW} height="3" fill="#f0851a" />

          {/* Лейблы цифр над портами 1-5 */}
          {portsLeft.map((p, i) => {
            const x = group1StartX + i * (portW + gap);
            return (
              <text key={`lbl-${p.name}`} x={x + portW / 2} y="10" fontSize="6" fill="#ffffff" fontWeight="800" textAnchor="middle">
                {p.label}
              </text>
            );
          })}
          {/* Порты 1-5 */}
          {portsLeft.map((p, i) => {
            const x = group1StartX + i * (portW + gap);
            const it = findPort(interfaces, p.name);
            const isPoeIn = i === 0;
            const detail = isPoeIn ? `порт ${p.label} · PoE in 18-57V` : `порт ${p.label}`;
            return (
              <g key={p.name}>
                {rj45SvgPort(x, portsY, portW, portH, it, { detail, fallbackName: p.name })}
              </g>
            );
          })}

          {/* Подпись группы 1-5 снизу */}
          <text
            x={group1StartX + (5 * (portW + gap) - gap) / 2}
            y={H - 2}
            fontSize="3.5"
            fill="#f0851a"
            textAnchor="middle"
            fontWeight="700"
          >
            PoE in 18-57V
          </text>

          {/* Центральная LED-матрица статусов */}
          {(() => {
            const lx = group1StartX + 5 * (portW + gap) - gap + ledBlockGap;
            const cy1 = portsY + 9;
            const cy2 = portsY + portH - 9;
            return (
              <g>
                <rect x={lx} y={portsY} width={ledBlockW} height={portH} rx="1.5" fill="#0a0a0a" stroke="#444" strokeWidth="0.4" />
                {[0, 1, 2, 3, 4].map((i) => {
                  const cx = lx + 3.5 + i * 4.2;
                  const top = findPort(interfaces, `ether${i + 1}`);
                  const bot = findPort(interfaces, `ether${i + 6}`);
                  const tp = portPalette(top);
                  const bp = portPalette(bot);
                  return (
                    <g key={`led-${i}`}>
                      <circle cx={cx} cy={cy1} r="1.3" fill={tp.color}>
                        <title>{`ether${i + 1}: ${tp.label}`}</title>
                      </circle>
                      <circle cx={cx} cy={cy2} r="1.3" fill={bp.color}>
                        <title>{`ether${i + 6}: ${bp.label}`}</title>
                      </circle>
                    </g>
                  );
                })}
              </g>
            );
          })()}

          {/* Акцентная полоска PoE-out над ether10 */}
          <rect x={group2StartX + 4 * (portW + gap)} y="1" width={portW} height="3" fill="#f0851a" />

          {/* Лейблы цифр над портами 6-10 */}
          {portsRight.map((p, i) => {
            const x = group2StartX + i * (portW + gap);
            return (
              <text key={`lbl-${p.name}`} x={x + portW / 2} y="10" fontSize="6" fill="#ffffff" fontWeight="800" textAnchor="middle">
                {p.label}
              </text>
            );
          })}
          {/* Порты 6-10 */}
          {portsRight.map((p, i) => {
            const x = group2StartX + i * (portW + gap);
            const it = findPort(interfaces, p.name);
            const isPoeOut = i === 4;
            const detail = isPoeOut ? `порт ${p.label} · PoE out` : `порт ${p.label}`;
            return (
              <g key={p.name}>
                {rj45SvgPort(x, portsY, portW, portH, it, { detail, fallbackName: p.name })}
              </g>
            );
          })}

          {/* Подпись группы 6-10 снизу */}
          <text
            x={group2StartX + (5 * (portW + gap) - gap) / 2}
            y={H - 2}
            fontSize="3.5"
            fill="#f0851a"
            textAnchor="middle"
            fontWeight="700"
          >
            PoE out
          </text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- RB3011UiAS-RM ---------
// Чёрный 1U: слева USB-3.0 (синий) + SFP (1G), полоска POE IN над ether1.
// Две группы по 5 GigE портов (ETH1-5 / ETH6-10) с центральной LED-матрицей 5×2.
// Справа — LCD-экран и лого MikroTik RouterBOARD.
// PoE-out на ether10 (помечается жёлтой ★ на корпусе).

function Rb3011Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const H = 66;
  const portW = 36, portH = 32, gap = 3;
  const portsY = (H - portH) / 2 - 1;

  // Слева: USB → SFP → POE IN полоска
  const usbX = 8;
  const usbW = 26;
  const sfpX = usbX + usbW + 6;          // 40
  const sfpW = 36;
  const group1StartX = sfpX + sfpW + 14; // 90 — начало ETH1
  const ledBlockW = 36;                  // центральный LED-блок
  const ledBlockGap = 6;
  const group2StartX =
    group1StartX + 5 * (portW + gap) - gap + ledBlockGap + ledBlockW + ledBlockGap;
  const lcdSize = 56;
  const lcdX = group2StartX + 5 * (portW + gap) - gap + 8;
  // W подбирается под контент: LCD + лого справа. Лого ~92 px (routerboard, fontSize=9).
  const W = lcdX + lcdSize + 96;

  const sfp =
    findPort(interfaces, 'sfp1') ||
    findPort(interfaces, 'sfp-sfpplus1');

  const portsLeft = [
    { name: 'ether1', label: '1' },
    { name: 'ether2', label: '2' },
    { name: 'ether3', label: '3' },
    { name: 'ether4', label: '4' },
    { name: 'ether5', label: '5' },
  ];
  const portsRight = [
    { name: 'ether6',  label: '6'  },
    { name: 'ether7',  label: '7'  },
    { name: 'ether8',  label: '8'  },
    { name: 'ether9',  label: '9'  },
    { name: 'ether10', label: '10' },
  ];

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>RB3011UiAS-RM</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Чёрный корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="3" fill="#1a1a1a" stroke="#3a3a3a" strokeWidth="1" />

          {/* Декоративные вентрешётки по верху/низу */}
          {[6, H - 8].map((vy) => (
            <g key={`vent-${vy}`} opacity="0.6">
              {Array.from({ length: 40 }).map((_, vi) => (
                <rect key={vi} x={4 + vi * 4.5} y={vy} width={3} height={1} fill="#555" />
              ))}
            </g>
          ))}

          {/* USB 3.0 (синий разъём) */}
          <text x={usbX + usbW / 2} y={9} fontSize="3" fill="#888" textAnchor="middle" fontWeight="700">SS←→</text>
          <rect x={usbX} y={portsY + 4} width={usbW} height={portH - 8} rx="1" fill="#0a0a0a" stroke="#666" strokeWidth="0.5" />
          <rect x={usbX + 2} y={portsY + 6} width={usbW - 4} height={portH - 12} fill="#1a4b8c" />
          <rect x={usbX + 6} y={portsY + 9} width={usbW - 12} height={portH - 18} fill="#0a0a0a" />
          <text x={usbX + usbW / 2} y={H - 2} fontSize="3" fill="#888" textAnchor="middle">USB 3.0</text>

          {/* SFP-слот (1G) */}
          <text x={sfpX + sfpW / 2} y={9} fontSize="3.5" fill="#aaa" textAnchor="middle" fontWeight="700">SFP</text>
          {sfpSvgPort(sfpX, portsY, sfpW, portH, sfp, { detail: 'SFP · 1 GbE', fallbackName: 'sfp1' })}
          <text x={sfpX + sfpW / 2} y={H - 2} fontSize="3" fill="#888" textAnchor="middle">SFP</text>

          {/* «POE IN» — подпись над портом ether1 */}
          <text
            x={group1StartX + portW / 2}
            y={9}
            fontSize="3.5"
            fill="#f0851a"
            textAnchor="middle"
            fontWeight="700"
          >
            POE IN
          </text>
          {/* Оранжевая полоска над ether1 */}
          <rect x={group1StartX} y="11" width={portW} height="2" fill="#f0851a" />

          {/* «GIGABIT ETHERNET» — подпись над группой 1 */}
          <text
            x={group1StartX + (5 * (portW + gap) - gap) / 2 + 18}
            y={9}
            fontSize="3.5"
            fill="#cccccc"
            textAnchor="middle"
            fontWeight="700"
          >
            GIGABIT ETHERNET
          </text>

          {/* Лейблы цифр ETH1-5 */}
          {portsLeft.map((p, i) => {
            const x = group1StartX + i * (portW + gap);
            return (
              <text key={`lbl-${p.name}`} x={x + portW / 2} y="17" fontSize="5" fill="#ffffff" fontWeight="800" textAnchor="middle">
                {p.label}
              </text>
            );
          })}
          {/* Порты ETH1-5 */}
          {portsLeft.map((p, i) => {
            const x = group1StartX + i * (portW + gap);
            const it = findPort(interfaces, p.name);
            const isPoeIn = i === 0;
            const detail = isPoeIn ? `порт ${p.label} · PoE in` : `порт ${p.label}`;
            return (
              <g key={p.name}>
                {rj45SvgPort(x, portsY, portW, portH, it, { detail, fallbackName: p.name })}
              </g>
            );
          })}
          {/* Подпись «ETH1»…«ETH5» снизу */}
          {portsLeft.map((p, i) => {
            const x = group1StartX + i * (portW + gap);
            return (
              <text key={`b-${p.name}`} x={x + portW / 2} y={H - 2} fontSize="3" fill="#aaa" textAnchor="middle" fontWeight="700">
                ETH{p.label}
              </text>
            );
          })}

          {/* Центральная LED-матрица статусов 5×2 */}
          {(() => {
            const lx = group1StartX + 5 * (portW + gap) - gap + ledBlockGap;
            const cy1 = portsY + 9;
            const cy2 = portsY + portH - 9;
            return (
              <g>
                <text x={lx + ledBlockW / 2} y={portsY - 1} fontSize="3" fill="#888" textAnchor="middle">1·2·3·4·5</text>
                <text x={lx + ledBlockW / 2} y={portsY + portH + 8} fontSize="3" fill="#888" textAnchor="middle">6·7·8·9·10</text>
                <rect x={lx} y={portsY + 2} width={ledBlockW} height={portH - 4} rx="1.5" fill="#0a0a0a" stroke="#444" strokeWidth="0.4" />
                {[0, 1, 2, 3, 4].map((i) => {
                  const cx = lx + 4 + i * 7;
                  const top = findPort(interfaces, `ether${i + 1}`);
                  const bot = findPort(interfaces, `ether${i + 6}`);
                  const tp = portPalette(top);
                  const bp = portPalette(bot);
                  return (
                    <g key={`led-${i}`}>
                      <circle cx={cx} cy={cy1} r="1.4" fill={tp.color}>
                        <title>{`ether${i + 1}: ${tp.label}`}</title>
                      </circle>
                      <circle cx={cx} cy={cy2} r="1.4" fill={bp.color}>
                        <title>{`ether${i + 6}: ${bp.label}`}</title>
                      </circle>
                    </g>
                  );
                })}
              </g>
            );
          })()}

          {/* «GIGABIT ETHERNET» — подпись над группой 2 */}
          <text
            x={group2StartX + (5 * (portW + gap) - gap) / 2}
            y={9}
            fontSize="3.5"
            fill="#cccccc"
            textAnchor="middle"
            fontWeight="700"
          >
            GIGABIT ETHERNET
          </text>
          {/* Жёлтая ★ над ether10 (PoE out) */}
          <text
            x={group2StartX + 4 * (portW + gap) + portW / 2}
            y={13}
            fontSize="5"
            fill="#f5d600"
            textAnchor="middle"
            fontWeight="900"
          >
            ★
          </text>

          {/* Лейблы цифр ETH6-10 */}
          {portsRight.map((p, i) => {
            const x = group2StartX + i * (portW + gap);
            return (
              <text key={`lbl-${p.name}`} x={x + portW / 2} y="17" fontSize="5" fill="#ffffff" fontWeight="800" textAnchor="middle">
                {p.label}
              </text>
            );
          })}
          {/* Порты ETH6-10 */}
          {portsRight.map((p, i) => {
            const x = group2StartX + i * (portW + gap);
            const it = findPort(interfaces, p.name);
            const isPoeOut = i === 4;
            const detail = isPoeOut ? `порт ${p.label} · PoE out` : `порт ${p.label}`;
            return (
              <g key={p.name}>
                {rj45SvgPort(x, portsY, portW, portH, it, { detail, fallbackName: p.name })}
              </g>
            );
          })}
          {/* Подписи «ETH6»…«ETH10» снизу */}
          {portsRight.map((p, i) => {
            const x = group2StartX + i * (portW + gap);
            return (
              <text key={`b-${p.name}`} x={x + portW / 2} y={H - 2} fontSize="3" fill="#aaa" textAnchor="middle" fontWeight="700">
                ETH{p.label}
              </text>
            );
          })}

          {/* LCD-экран справа */}
          <rect x={lcdX} y={(H - lcdSize) / 2} width={lcdSize} height={lcdSize} rx="2" fill="#bdbdb6" stroke="#444" strokeWidth="0.6" />
          <rect x={lcdX + 4} y={(H - lcdSize) / 2 + 4} width={lcdSize - 8} height={lcdSize - 8} fill="#a0a39a" />

          {/* Лого справа */}
          <text x={W - 6} y={20} fontSize="6.5" fill="#ffffff" textAnchor="end" fontWeight="800" fontFamily="Inter, sans-serif">MikroTik</text>
          <text x={W - 6} y={36} fontSize="9" fill="#ffffff" textAnchor="end" fontWeight="900" fontFamily="Inter, sans-serif">routerboard</text>
          <text x={W - 6} y={H - 4} fontSize="4" fill="#aaaaaa" textAnchor="end" fontFamily="Inter, sans-serif" letterSpacing="0.5">RB 3011 UiAS-RM</text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- CRS317-1G-16S+ ---------
// Белый 1U-свич: 16 портов SFP+ в 4 группах по 4, над каждым портом пара
// светодиодов ACT и 10G. Справа: CONSOLE (RJ45), ETH/BOOT (Gigabit RJ45
// для управления = ether1), кнопка RESET и блок статусных LED (USR,
// FAULT, PWR2, PWR1). Имена SFP-портов в RouterOS — sfp-sfpplus1…16.

function Crs317Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const W = 700, H = 66;
  const portW = 28, portH = 26, gap = 3;
  const groupGap = 8;
  const portsY = 28;
  const portsStartX = 78;

  // Управляющий Gigabit-порт ETH/BOOT = ether1. Допускаем альт-имена на случай переименования.
  const ethBoot =
    findPort(interfaces, 'ether1') ||
    findPort(interfaces, 'eth1') ||
    findPort(interfaces, 'boot');

  // Группа из 4 портов: индексы 0..3, 4..7, 8..11, 12..15. Между группами — groupGap.
  const xOf = (i: number) => portsStartX + i * (portW + gap) + Math.floor(i / 4) * groupGap;

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>CRS317-1G-16S+</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Белый корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="3" fill="#f4f4f1" stroke="#bdbdb6" strokeWidth="1" />

          {/* Левая декоративная зона: 4 ряда вентиляционных решёток (по числу групп портов) */}
          {Array.from({ length: 4 }).map((_, gi) => {
            const gx = portsStartX + gi * (4 * (portW + gap) + groupGap) - 4;
            return (
              <g key={`vent-${gi}`} opacity="0.85">
                {Array.from({ length: 16 }).map((__, vi) => (
                  <rect
                    key={vi}
                    x={gx + vi * 7}
                    y={6}
                    width={4}
                    height={1.2}
                    fill="#8e8e88"
                  />
                ))}
              </g>
            );
          })}

          {/* Лейблы ACT / 10G над каждым портом + сами светодиоды */}
          {Array.from({ length: 16 }).map((_, i) => {
            const x = xOf(i);
            const it = findPort(interfaces, `sfp-sfpplus${i + 1}`)
                    || findPort(interfaces, `sfpplus${i + 1}`);
            const pal = portPalette(it);
            const isLink = !!it?.running;
            return (
              <g key={`leds-${i}`}>
                <text x={x + portW * 0.3} y="14" fontSize="3" fill="#444" textAnchor="middle" fontWeight="700">ACT</text>
                <text x={x + portW * 0.7} y="14" fontSize="3" fill="#444" textAnchor="middle" fontWeight="700">10G</text>
                {/* «коробочки» светодиодов: цвет по скорости линка */}
                <rect x={x + portW * 0.3 - 2.2} y={16} width={4.4} height={3.2} rx={0.5}
                      fill={isLink ? pal.color : '#dadad4'} stroke="#9c9c95" strokeWidth="0.3" />
                <rect x={x + portW * 0.7 - 2.2} y={16} width={4.4} height={3.2} rx={0.5}
                      fill={isLink ? pal.color : '#dadad4'} stroke="#9c9c95" strokeWidth="0.3" />
              </g>
            );
          })}

          {/* SFP+ слоты (16 шт.) */}
          {Array.from({ length: 16 }).map((_, i) => {
            const x = xOf(i);
            const it = findPort(interfaces, `sfp-sfpplus${i + 1}`)
                    || findPort(interfaces, `sfpplus${i + 1}`);
            return (
              <g key={`sfp-${i}`}>
                {sfpSvgPort(x, portsY, portW, portH, it, { detail: `SFP+${i + 1} · 10 GbE`, fallbackName: `sfp-sfpplus${i + 1}` })}
                {/* Подпись «SFP+ i» под портом */}
                <text x={x + portW / 2} y={H - 4} fontSize="3.5" fill="#555" textAnchor="middle" fontWeight="700">
                  SFP+{i + 1}
                </text>
              </g>
            );
          })}

          {/* Правая колонка: CONSOLE, ETH/BOOT, RESET, статусные LED, лого */}
          {(() => {
            const rightX = portsStartX + 16 * (portW + gap) + 3 * groupGap + 6;
            const consoleY = 18;
            const ethY = 38;
            return (
              <g>
                {/* CONSOLE — RJ45 для serial */}
                <text x={rightX + 12} y="14" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">CONSOLE</text>
                <rect x={rightX} y={consoleY} width="24" height="14" rx="1.5" fill="#c8c8c8" stroke="#666" strokeWidth="0.5" />
                <rect x={rightX + 4} y={consoleY + 3} width="16" height="8" fill="#0a0a0a" />
                <rect x={rightX + 8} y={consoleY + 6} width="8" height="2.5" fill="#222" />

                {/* ETH/BOOT — управляющий Gigabit (ether1) */}
                <text x={rightX + 12} y={ethY - 2} fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">ETH/BOOT</text>
                {rj45SvgPort(rightX, ethY, 24, 20, ethBoot, { detail: 'ETH/BOOT (Gigabit, management)', fallbackName: 'ether1' })}

                {/* RESET — утопленная кнопка */}
                <circle cx={rightX + 38} cy={ethY + 10} r="2.6" fill="none" stroke="#888" strokeWidth="0.6" />
                <circle cx={rightX + 38} cy={ethY + 10} r="0.8" fill="#444" />
                <text x={rightX + 38} y={H - 4} fontSize="3.5" fill="#555" textAnchor="middle" fontWeight="700">RESET</text>

                {/* Блок статусных LED справа */}
                {(() => {
                  const lx = rightX + 50;
                  const labels = [
                    { name: 'USR',   color: '#f5d600' },
                    { name: 'FAULT', color: '#d04848' },
                    { name: 'PWR 2', color: '#22c55e' },
                    { name: 'PWR 1', color: '#22c55e' },
                  ];
                  return (
                    <g>
                      {labels.map((l, idx) => (
                        <g key={l.name}>
                          <circle cx={lx} cy={10 + idx * 11} r="2" fill={l.color} stroke="#7a7a72" strokeWidth="0.3" />
                          <text x={lx + 5} y={11.5 + idx * 11} fontSize="3.5" fill="#444" fontWeight="700">{l.name}</text>
                        </g>
                      ))}
                    </g>
                  );
                })()}

                {/* Лого + название модели — справа сверху, как на корпусе */}
                <text x={W - 8} y={18} fontSize="9" fill="#222" textAnchor="end" fontWeight="800" fontFamily="Inter, sans-serif">
                  Cloud Router Switch
                </text>
                <text x={W - 8} y={28} fontSize="5.5" fill="#444" textAnchor="end" fontFamily="Inter, sans-serif" letterSpacing="1">
                  CRS 317-1G-16S+
                </text>
                <text x={W - 8} y={H - 4} fontSize="6" fill="#1a1a1a" textAnchor="end" fontWeight="900" fontFamily="Inter, sans-serif">
                  MikroTik
                </text>
              </g>
            );
          })()}
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- CRS328-24P-4S+RM ---------
// Светлый 1U-свич: 24 GigE PoE-out (ether1…24) в два ряда — сверху нечётные,
// снизу чётные; справа блок 4×SFP+ (sfp-sfpplus1…4) 2×2, ещё правее — лого.
// Слева: CONSOLE (RJ45), RESET, светодиоды PWR/USR.
// Раскладку SFP+ можно поправить в SFP_LAYOUT (строка × столбец → номер порта).

function Crs328Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const W = 680, H = 82;
  const portW = 30, portH = 26, gap = 3;
  const row1Y = 14;
  const row2Y = row1Y + portH + 4;
  const portsStartX = 84;
  const colW = portW + gap;
  const cols = 12;
  const sfpW = 36, sfpGap = 4;
  const sfpX = portsStartX + cols * colW + 14;
  // Строки × столбцы → номер sfp-sfpplusN. Если SFP+ в один ряд: [[1, 2, 3, 4]].
  const SFP_LAYOUT: number[][] = [[1, 3], [2, 4]];
  const sfpCols = SFP_LAYOUT[0].length;
  const sfpPort = (n: number) =>
    findPort(interfaces, `sfp-sfpplus${n}`) || findPort(interfaces, `sfpplus${n}`);

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>CRS328-24P-4S+RM</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Светлый корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="3" fill="#f4f4f1" stroke="#bdbdb6" strokeWidth="1" />

          {/* CONSOLE — RJ45 для serial */}
          <text x="20" y="24" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">CONSOLE</text>
          <rect x="8" y="27" width="24" height="14" rx="1.5" fill="#c8c8c8" stroke="#666" strokeWidth="0.5" />
          <rect x="12" y="30" width="16" height="8" fill="#0a0a0a" />
          <rect x="16" y="33" width="8" height="2.5" fill="#222" />

          {/* RESET — утопленная кнопка */}
          <text x="54" y="24" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">RESET</text>
          <circle cx="54" cy="34" r="2.6" fill="none" stroke="#888" strokeWidth="0.6" />
          <circle cx="54" cy="34" r="0.8" fill="#444" />

          {/* Светодиоды PWR / USR */}
          <circle cx="14" cy="58" r="2" fill="#22c55e" stroke="#7a7a72" strokeWidth="0.3" />
          <text x="14" y="68" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">PWR</text>
          <circle cx="34" cy="58" r="2" fill="#f5d600" stroke="#7a7a72" strokeWidth="0.3" />
          <text x="34" y="68" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">USR</text>

          {/* 24 × RJ45: сверху нечётные, снизу чётные */}
          {Array.from({ length: cols }).map((_, c) => {
            const x = portsStartX + c * colW;
            const top = 2 * c + 1;
            const bot = 2 * c + 2;
            return (
              <g key={`col-${c}`}>
                <text x={x + portW / 2} y="10" fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">{top}</text>
                {rj45SvgPort(x, row1Y, portW, portH, findPort(interfaces, `ether${top}`), {
                  detail: `порт ${top} · PoE out`,
                  fallbackName: `ether${top}`,
                })}
                {rj45SvgPort(x, row2Y, portW, portH, findPort(interfaces, `ether${bot}`), {
                  detail: `порт ${bot} · PoE out`,
                  fallbackName: `ether${bot}`,
                })}
                <text x={x + portW / 2} y={H - 3} fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">{bot}</text>
              </g>
            );
          })}

          {/* Блок SFP+ */}
          <rect x={sfpX} y="2" width={sfpCols * sfpW + (sfpCols - 1) * sfpGap} height="2" fill="#7c3aed" />
          <text
            x={sfpX + (sfpCols * sfpW + (sfpCols - 1) * sfpGap) / 2}
            y="11"
            fontSize="5"
            fill="#444"
            textAnchor="middle"
            fontWeight="800"
          >
            SFP+
          </text>
          {SFP_LAYOUT.map((row, r) =>
            row.map((n, c) => {
              const x = sfpX + c * (sfpW + sfpGap);
              const y = SFP_LAYOUT.length === 1 ? (row1Y + row2Y) / 2 : r === 0 ? row1Y : row2Y;
              return (
                <g key={`sfp-${n}`}>
                  {sfpSvgPort(x, y, sfpW, portH, sfpPort(n), {
                    detail: `SFP+${n} · 10 GbE`,
                    fallbackName: `sfp-sfpplus${n}`,
                  })}
                </g>
              );
            }),
          )}
          <text
            x={sfpX + (sfpCols * sfpW + (sfpCols - 1) * sfpGap) / 2}
            y={H - 3}
            fontSize="4"
            fill="#555"
            textAnchor="middle"
            fontWeight="700"
          >
            SFP+ 1-4 · 10G
          </text>

          {/* Лого справа */}
          <text x={W - 8} y="22" fontSize="9" fill="#222" textAnchor="end" fontWeight="800" fontFamily="Inter, sans-serif">
            Cloud Router Switch
          </text>
          <text x={W - 8} y="34" fontSize="5.5" fill="#444" textAnchor="end" fontFamily="Inter, sans-serif" letterSpacing="1">
            CRS328-24P-4S+RM
          </text>
          <text x={W - 8} y={H - 8} fontSize="8" fill="#1a1a1a" textAnchor="end" fontWeight="900" fontFamily="Inter, sans-serif">
            MikroTik
          </text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- CRS354-48P-4S+2Q+RM ---------
// Светлый 1U-свич: 48 GigE PoE-out (ether1…48) в два ряда — сверху нечётные,
// снизу чётные; справа блок 4×SFP+ (sfp-sfpplus1…4) и 2×QSFP+ 40G
// (qsfpplus1-1…4 и qsfpplus2-1…4 — по 4 «дорожки» на разъём; иконка берёт
// первую поднятую дорожку). Раскладку SFP+ можно поправить в SFP_LAYOUT.

function Crs354Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const H = 82;
  const portW = 26, portH = 24, gap = 3;
  const row1Y = 14;
  const row2Y = row1Y + portH + 4;
  const portsStartX = 84;
  const colW = portW + gap;
  const cols = 24;
  const sfpW = 34, sfpGap = 4;
  const sfpX = portsStartX + cols * colW + 14;
  // Строки × столбцы → номер sfp-sfpplusN. Для одного ряда: [[1, 2, 3, 4]].
  const SFP_LAYOUT: number[][] = [[1, 3], [2, 4]];
  const sfpCols = SFP_LAYOUT[0].length;
  const sfpBlockW = sfpCols * sfpW + (sfpCols - 1) * sfpGap;
  const qsfpW = 44;
  const qsfpX = sfpX + sfpBlockW + 10;
  const W = qsfpX + qsfpW + 150;

  const sfpPort = (n: number) =>
    findPort(interfaces, `sfp-sfpplus${n}`) || findPort(interfaces, `sfpplus${n}`);
  const qsfpPort = (k: number): InterfaceInfo | undefined => {
    const lanes = [1, 2, 3, 4]
      .map((n) => findPort(interfaces, `qsfpplus${k}-${n}`))
      .filter(Boolean) as InterfaceInfo[];
    return lanes.find((l) => l.running) || lanes[0] || findPort(interfaces, `qsfpplus${k}`);
  };

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>CRS354-48P-4S+2Q+RM</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Светлый корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="3" fill="#f4f4f1" stroke="#bdbdb6" strokeWidth="1" />

          {/* CONSOLE — RJ45 для serial */}
          <text x="20" y="24" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">CONSOLE</text>
          <rect x="8" y="27" width="24" height="14" rx="1.5" fill="#c8c8c8" stroke="#666" strokeWidth="0.5" />
          <rect x="12" y="30" width="16" height="8" fill="#0a0a0a" />
          <rect x="16" y="33" width="8" height="2.5" fill="#222" />

          {/* RESET — утопленная кнопка */}
          <text x="54" y="24" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">RESET</text>
          <circle cx="54" cy="34" r="2.6" fill="none" stroke="#888" strokeWidth="0.6" />
          <circle cx="54" cy="34" r="0.8" fill="#444" />

          {/* Светодиоды PWR / USR */}
          <circle cx="14" cy="58" r="2" fill="#22c55e" stroke="#7a7a72" strokeWidth="0.3" />
          <text x="14" y="68" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">PWR</text>
          <circle cx="34" cy="58" r="2" fill="#f5d600" stroke="#7a7a72" strokeWidth="0.3" />
          <text x="34" y="68" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">USR</text>

          {/* 48 × RJ45: сверху нечётные, снизу чётные */}
          {Array.from({ length: cols }).map((_, c) => {
            const x = portsStartX + c * colW;
            const top = 2 * c + 1;
            const bot = 2 * c + 2;
            return (
              <g key={`col-${c}`}>
                <text x={x + portW / 2} y="10" fontSize="4.5" fill="#444" textAnchor="middle" fontWeight="800">{top}</text>
                {rj45SvgPort(x, row1Y, portW, portH, findPort(interfaces, `ether${top}`), {
                  detail: `порт ${top} · PoE out`,
                  fallbackName: `ether${top}`,
                })}
                {rj45SvgPort(x, row2Y, portW, portH, findPort(interfaces, `ether${bot}`), {
                  detail: `порт ${bot} · PoE out`,
                  fallbackName: `ether${bot}`,
                })}
                <text x={x + portW / 2} y={H - 3} fontSize="4.5" fill="#444" textAnchor="middle" fontWeight="800">{bot}</text>
              </g>
            );
          })}

          {/* Блок SFP+ */}
          <rect x={sfpX} y="2" width={sfpBlockW} height="2" fill="#7c3aed" />
          <text x={sfpX + sfpBlockW / 2} y="11" fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">SFP+</text>
          {SFP_LAYOUT.map((row, r) =>
            row.map((n, c) => {
              const x = sfpX + c * (sfpW + sfpGap);
              const y = SFP_LAYOUT.length === 1 ? (row1Y + row2Y) / 2 : r === 0 ? row1Y : row2Y;
              return (
                <g key={`sfp-${n}`}>
                  {sfpSvgPort(x, y, sfpW, portH, sfpPort(n), {
                    detail: `SFP+${n} · 10 GbE`,
                    fallbackName: `sfp-sfpplus${n}`,
                  })}
                </g>
              );
            }),
          )}
          <text x={sfpX + sfpBlockW / 2} y={H - 3} fontSize="4" fill="#555" textAnchor="middle" fontWeight="700">
            SFP+ 1-4 · 10G
          </text>

          {/* Блок QSFP+ (2 порта, 40G) */}
          <rect x={qsfpX} y="2" width={qsfpW} height="2" fill="#7c3aed" />
          <text x={qsfpX + qsfpW / 2} y="11" fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">QSFP+</text>
          {[1, 2].map((k) => {
            const y = k === 1 ? row1Y : row2Y;
            return (
              <g key={`qsfp-${k}`}>
                {sfpSvgPort(qsfpX, y, qsfpW, portH, qsfpPort(k), {
                  detail: `QSFP+${k} · 40 GbE`,
                  fallbackName: `qsfpplus${k}-1`,
                })}
              </g>
            );
          })}
          <text x={qsfpX + qsfpW / 2} y={H - 3} fontSize="4" fill="#555" textAnchor="middle" fontWeight="700">
            QSFP+ 1-2 · 40G
          </text>

          {/* Лого справа */}
          <text x={W - 8} y="22" fontSize="9" fill="#222" textAnchor="end" fontWeight="800" fontFamily="Inter, sans-serif">
            Cloud Router Switch
          </text>
          <text x={W - 8} y="34" fontSize="5.5" fill="#444" textAnchor="end" fontFamily="Inter, sans-serif" letterSpacing="1">
            CRS354-48P-4S+2Q+RM
          </text>
          <text x={W - 8} y={H - 8} fontSize="8" fill="#1a1a1a" textAnchor="end" fontWeight="900" fontFamily="Inter, sans-serif">
            MikroTik
          </text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- CCR2116-12G-4S+ ---------
// Тёмный 1U-роутер: слева CONSOLE (RJ45), USB, RESET и светодиоды питания,
// затем 12 GigE (ether1…12) в один ряд и 4 SFP+ (sfp-sfpplus1…4) справа.
// Расположение сделано по памяти: если на корпусе иначе, поправьте
// константы ниже (GROUP_AFTER — разрыв после N портов, SFP_ROWS — раскладка SFP+).

function Ccr2116Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const H = 66;
  const portW = 32, portH = 32, gap = 3;
  const portsY = (H - portH) / 2 - 1;
  const portsStartX = 124;
  const GROUP_AFTER = 0;            // 0 = без разрыва; 6 = разрыв после 6-го порта
  const groupGap = GROUP_AFTER > 0 ? 8 : 0;
  const xOf = (i: number) =>
    portsStartX + i * (portW + gap) + (GROUP_AFTER > 0 && i >= GROUP_AFTER ? groupGap : 0);
  const ethEndX = xOf(11) + portW;

  const sfpW = 36, sfpGap = 4;
  const sfpX = ethEndX + 14;
  const SFP_ROWS: number[][] = [[1, 2, 3, 4]];   // для двух рядов: [[1, 3], [2, 4]]
  const sfpCols = SFP_ROWS[0].length;
  const sfpBlockW = sfpCols * sfpW + (sfpCols - 1) * sfpGap;
  const W = sfpX + sfpBlockW + 150;
  const sfpPort = (n: number) =>
    findPort(interfaces, `sfp-sfpplus${n}`) || findPort(interfaces, `sfpplus${n}`);

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>CCR2116-12G-4S+</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Тёмный корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="4" fill="#1a1a1a" stroke="#3a3a3a" strokeWidth="1" />

          {/* CONSOLE — RJ45 для serial */}
          <text x="20" y="12" fontSize="3.5" fill="#cccccc" textAnchor="middle" fontWeight="700">CONSOLE</text>
          <rect x="8" y="16" width="24" height="14" rx="1.5" fill="#2b2b2b" stroke="#666" strokeWidth="0.5" />
          <rect x="12" y="19" width="16" height="8" fill="#0a0a0a" />
          <rect x="16" y="22" width="8" height="2.5" fill="#333" />

          {/* USB */}
          <text x="52" y="12" fontSize="3.5" fill="#cccccc" textAnchor="middle" fontWeight="700">USB</text>
          <rect x="40" y="16" width="24" height="14" rx="1" fill="#0a0a0a" stroke="#888" strokeWidth="0.5" />
          <rect x="42" y="18" width="20" height="10" fill="#1a4b8c" />
          <rect x="47" y="21" width="10" height="4" fill="#0a0a0a" />

          {/* RESET */}
          <text x="84" y="12" fontSize="3.5" fill="#cccccc" textAnchor="middle" fontWeight="700">RESET</text>
          <circle cx="84" cy="23" r="3" fill="none" stroke="#d04848" strokeWidth="0.8" />
          <circle cx="84" cy="23" r="1" fill="#222" />

          {/* Светодиоды: PWR1, PWR2, USR */}
          {[
            { x: 14, label: 'PWR1', color: '#22c55e' },
            { x: 36, label: 'PWR2', color: '#22c55e' },
            { x: 58, label: 'USR',  color: '#f5d600' },
          ].map((l) => (
            <g key={l.label}>
              <circle cx={l.x} cy="46" r="2" fill={l.color} />
              <text x={l.x} y="57" fontSize="3.5" fill="#aaaaaa" textAnchor="middle" fontWeight="700">{l.label}</text>
            </g>
          ))}

          {/* 12 × GigE RJ45 */}
          {Array.from({ length: 12 }).map((_, i) => {
            const x = xOf(i);
            const name = `ether${i + 1}`;
            return (
              <g key={name}>
                <text x={x + portW / 2} y="10" fontSize="6" fill="#ffffff" fontWeight="800" textAnchor="middle">{i + 1}</text>
                {rj45SvgPort(x, portsY, portW, portH, findPort(interfaces, name), {
                  detail: `порт ${i + 1} · 1 GbE`,
                  fallbackName: name,
                })}
              </g>
            );
          })}
          <text x={(portsStartX + ethEndX) / 2} y={H - 2} fontSize="3.5" fill="#aaaaaa" textAnchor="middle" fontWeight="700">
            GIGABIT ETHERNET
          </text>

          {/* SFP+ */}
          <rect x={sfpX} y="1" width={sfpBlockW} height="3" fill="#7c3aed" />
          <text x={sfpX + sfpBlockW / 2} y="10" fontSize="5.5" fill="#ffffff" fontWeight="800" textAnchor="middle">SFP+</text>
          {SFP_ROWS.map((row, r) =>
            row.map((n, c) => {
              const x = sfpX + c * (sfpW + sfpGap);
              const h = SFP_ROWS.length === 1 ? portH : 22;
              const y = SFP_ROWS.length === 1 ? portsY : portsY + r * (h + 4) - 4;
              return (
                <g key={`sfp-${n}`}>
                  {sfpSvgPort(x, y, sfpW, h, sfpPort(n), {
                    detail: `SFP+${n} · 10 GbE`,
                    fallbackName: `sfp-sfpplus${n}`,
                  })}
                </g>
              );
            }),
          )}
          <text x={sfpX + sfpBlockW / 2} y={H - 2} fontSize="3.5" fill="#aaaaaa" textAnchor="middle" fontWeight="700">
            SFP+ 1-4 · 10G
          </text>

          {/* Лого справа */}
          <text x={W - 8} y="22" fontSize="9" fill="#ffffff" textAnchor="end" fontWeight="800" fontFamily="Inter, sans-serif">
            Cloud Core Router
          </text>
          <text x={W - 8} y="34" fontSize="5.5" fill="#bbbbbb" textAnchor="end" fontFamily="Inter, sans-serif" letterSpacing="1">
            CCR2116-12G-4S+
          </text>
          <text x={W - 8} y={H - 8} fontSize="8" fill="#ffffff" textAnchor="end" fontWeight="900" fontFamily="Inter, sans-serif">
            MikroTik
          </text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- CRS326-24G-2S+RM ---------
// Светлый 1U-свич: 24 GigE (ether1…24) в два ряда — сверху нечётные, снизу чётные;
// справа 2×SFP+ (sfp-sfpplus1…2) друг над другом. Слева CONSOLE, RESET, светодиоды.
// Раскладка сделана по памяти: если на корпусе иначе, поправьте SFP_LAYOUT
// (один ряд: [[1, 2]]) и формулы нумерации (2 * c + 1 / 2 * c + 2).

function Crs326Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const H = 82;
  const portW = 30, portH = 26, gap = 3;
  const row1Y = 14;
  const row2Y = row1Y + portH + 4;
  const portsStartX = 84;
  const colW = portW + gap;
  const cols = 12;
  const sfpW = 40;
  const sfpX = portsStartX + cols * colW + 14;
  // Строки × столбцы → номер sfp-sfpplusN
  const SFP_LAYOUT: number[][] = [[1], [2]];
  const sfpCols = SFP_LAYOUT[0].length;
  const sfpGap = 4;
  const sfpBlockW = sfpCols * sfpW + (sfpCols - 1) * sfpGap;
  const W = sfpX + sfpBlockW + 150;
  const sfpPort = (n: number) =>
    findPort(interfaces, `sfp-sfpplus${n}`) || findPort(interfaces, `sfpplus${n}`);

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>CRS326-24G-2S+RM</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Светлый корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="3" fill="#f4f4f1" stroke="#bdbdb6" strokeWidth="1" />

          {/* CONSOLE — RJ45 для serial */}
          <text x="20" y="24" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">CONSOLE</text>
          <rect x="8" y="27" width="24" height="14" rx="1.5" fill="#c8c8c8" stroke="#666" strokeWidth="0.5" />
          <rect x="12" y="30" width="16" height="8" fill="#0a0a0a" />
          <rect x="16" y="33" width="8" height="2.5" fill="#222" />

          {/* RESET — утопленная кнопка */}
          <text x="54" y="24" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">RESET</text>
          <circle cx="54" cy="34" r="2.6" fill="none" stroke="#888" strokeWidth="0.6" />
          <circle cx="54" cy="34" r="0.8" fill="#444" />

          {/* Светодиоды PWR / USR */}
          <circle cx="14" cy="58" r="2" fill="#22c55e" stroke="#7a7a72" strokeWidth="0.3" />
          <text x="14" y="68" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">PWR</text>
          <circle cx="34" cy="58" r="2" fill="#f5d600" stroke="#7a7a72" strokeWidth="0.3" />
          <text x="34" y="68" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">USR</text>

          {/* 24 × RJ45: сверху нечётные, снизу чётные */}
          {Array.from({ length: cols }).map((_, c) => {
            const x = portsStartX + c * colW;
            const top = 2 * c + 1;
            const bot = 2 * c + 2;
            return (
              <g key={`col-${c}`}>
                <text x={x + portW / 2} y="10" fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">{top}</text>
                {rj45SvgPort(x, row1Y, portW, portH, findPort(interfaces, `ether${top}`), {
                  detail: `порт ${top} · 1 GbE`,
                  fallbackName: `ether${top}`,
                })}
                {rj45SvgPort(x, row2Y, portW, portH, findPort(interfaces, `ether${bot}`), {
                  detail: `порт ${bot} · 1 GbE`,
                  fallbackName: `ether${bot}`,
                })}
                <text x={x + portW / 2} y={H - 3} fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">{bot}</text>
              </g>
            );
          })}

          {/* SFP+ */}
          <rect x={sfpX} y="2" width={sfpBlockW} height="2" fill="#7c3aed" />
          <text x={sfpX + sfpBlockW / 2} y="11" fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">SFP+</text>
          {SFP_LAYOUT.map((row, r) =>
            row.map((n, c) => {
              const x = sfpX + c * (sfpW + sfpGap);
              const y = SFP_LAYOUT.length === 1 ? (row1Y + row2Y) / 2 : r === 0 ? row1Y : row2Y;
              return (
                <g key={`sfp-${n}`}>
                  {sfpSvgPort(x, y, sfpW, portH, sfpPort(n), {
                    detail: `SFP+${n} · 10 GbE`,
                    fallbackName: `sfp-sfpplus${n}`,
                  })}
                </g>
              );
            }),
          )}
          <text x={sfpX + sfpBlockW / 2} y={H - 3} fontSize="4" fill="#555" textAnchor="middle" fontWeight="700">
            SFP+ 1-2 · 10G
          </text>

          {/* Лого справа */}
          <text x={W - 8} y="22" fontSize="9" fill="#222" textAnchor="end" fontWeight="800" fontFamily="Inter, sans-serif">
            Cloud Router Switch
          </text>
          <text x={W - 8} y="34" fontSize="5.5" fill="#444" textAnchor="end" fontFamily="Inter, sans-serif" letterSpacing="1">
            CRS326-24G-2S+RM
          </text>
          <text x={W - 8} y={H - 8} fontSize="8" fill="#1a1a1a" textAnchor="end" fontWeight="900" fontFamily="Inter, sans-serif">
            MikroTik
          </text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- hAP ax² ---------
// Светлый корпус, 5 GigE: ether1 — Internet / PoE in, ether2…5 — LAN.
// Слева: DC-разъём и кнопка RES. Нижние подписи и цвет корпуса можно
// поправить ниже, если на вашем экземпляре иначе.

function HapAx2Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const ports = [
    { name: 'ether1', label: '1', accent: 'poe-in' as const },
    { name: 'ether2', label: '2', accent: null      as const },
    { name: 'ether3', label: '3', accent: null      as const },
    { name: 'ether4', label: '4', accent: null      as const },
    { name: 'ether5', label: '5', accent: null      as const },
  ];

  const W = 1000, H = 250;
  const bodyR = 24;
  const portW = 120, portH = 120;
  const portGap = 14;
  const firstPortX = 300;
  const portsTopY = 56;
  const lanStartX = firstPortX + portW + portGap;
  const lanSpanW = 4 * portW + 3 * portGap;

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>hAP ax²</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
        >
          {/* Светлый корпус */}
          <rect x="2" y="2" width={W - 4} height={H - 4} rx={bodyR} ry={bodyR} fill="#f1f1ee" stroke="#c3c3bd" strokeWidth="2" />
          <rect x="16" y="16" width={W - 32} height={H - 44} rx="14" fill="#e6e6e2" stroke="#d0d0ca" strokeWidth="1" />

          {/* Название модели */}
          <text x="40" y="52" fontSize="30" fill="#222" fontWeight="900" fontFamily="Inter, sans-serif">hAP ax²</text>

          {/* DC разъём */}
          <circle cx="86" cy="140" r="32" fill="#0a0a0a" stroke="#3a3a3a" strokeWidth="3" />
          <circle cx="86" cy="140" r="9" fill="#1a1a1a" stroke="#000" strokeWidth="2" />
          <text x="86" y="205" fontSize="16" fill="#333" textAnchor="middle" fontWeight="700">DC</text>
          <text x="86" y="224" fontSize="12" fill="#555" textAnchor="middle">12-57V</text>

          {/* RES — утопленная кнопка */}
          <circle cx="200" cy="140" r="9" fill="#0a0a0a" stroke="#777" strokeWidth="1.5" />
          <circle cx="200" cy="140" r="3" fill="#333" />
          <text x="200" y="98" fontSize="14" fill="#333" textAnchor="middle" fontWeight="700">RES</text>

          {/* Цифры над портами */}
          {ports.map((p, i) => (
            <text key={`l-${p.name}`} x={firstPortX + i * (portW + portGap) + portW / 2} y="44"
                  fontSize="22" fill="#222" fontWeight="800" textAnchor="middle">
              {p.label}
            </text>
          ))}

          {/* Порты */}
          {ports.map((p, i) => {
            const x = firstPortX + i * (portW + portGap);
            const it = findPort(interfaces, p.name);
            const detail = p.accent === 'poe-in' ? `${p.label} · Internet / PoE in` : `LAN ${p.label}`;
            return (
              <g key={p.name}>
                {rj45SvgPort(x, portsTopY, portW, portH, it, { detail, fallbackName: p.name })}
                <text x={x + portW / 2} y={portsTopY + portH + 16} fontSize="11" fill="#555" textAnchor="middle">{p.name}</text>
              </g>
            );
          })}

          {/* Группа Internet / PoE in */}
          <line x1={firstPortX - 2} y1={H - 38} x2={firstPortX + portW + 2} y2={H - 38} stroke="#888" strokeWidth="1.2" />
          <text x={firstPortX + portW / 2} y={H - 14} fontSize="14" fill="#222" textAnchor="middle" fontWeight="600">
            Internet/PoE in
          </text>

          {/* Группа LAN */}
          <line x1={lanStartX - 2} y1={H - 38} x2={lanStartX + lanSpanW + 2} y2={H - 38} stroke="#888" strokeWidth="1.2" />
          <text x={lanStartX + lanSpanW / 2} y={H - 14} fontSize="14" fill="#222" textAnchor="middle" fontWeight="600">
            LAN
          </text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- CRS326-24S+2Q+RM ---------
// Светлый 1U-свич: 24 SFP+ в два ряда по 12 (сверху нечётные, снизу чётные),
// справа 2×QSFP+ (qsfpplus1-1…4, qsfpplus2-1…4 — иконка берёт первую поднятую
// «дорожку»), слева CONSOLE, RESET, ether1 (управление) и светодиоды.
// Раскладка сделана по памяти: нумерацию SFP+ можно поправить в sfpNum().

function Crs326S2QMockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const H = 76;
  const portW = 26, portH = 22, gap = 3;
  const row1Y = 14;
  const row2Y = row1Y + portH + 4;
  const sfpStartX = 96;
  const colW = portW + gap;
  const cols = 12;
  const qW = 40;
  const qX = sfpStartX + cols * colW + 12;
  const W = qX + qW + 150;

  // Номер sfp-sfpplusN для колонки c: сверху 1,3,5…, снизу 2,4,6…
  const sfpNum = (c: number, row: 0 | 1) => 2 * c + 1 + row;
  const sfpPort = (n: number) =>
    findPort(interfaces, `sfp-sfpplus${n}`) || findPort(interfaces, `sfpplus${n}`);
  const qsfpPort = (k: number): InterfaceInfo | undefined => {
    const lanes = [1, 2, 3, 4]
      .map((n) => findPort(interfaces, `qsfpplus${k}-${n}`))
      .filter(Boolean) as InterfaceInfo[];
    return lanes.find((l) => l.running) || lanes[0] || findPort(interfaces, `qsfpplus${k}`);
  };
  const eth = findPort(interfaces, 'ether1');

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>CRS326-24S+2Q+RM</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Светлый корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="3" fill="#f4f4f1" stroke="#bdbdb6" strokeWidth="1" />

          {/* CONSOLE */}
          <text x="20" y="12" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">CONSOLE</text>
          <rect x="8" y="15" width="24" height="14" rx="1.5" fill="#c8c8c8" stroke="#666" strokeWidth="0.5" />
          <rect x="12" y="18" width="16" height="8" fill="#0a0a0a" />
          <rect x="16" y="21" width="8" height="2.5" fill="#222" />

          {/* ether1 — порт управления */}
          <text x="58" y="12" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">ETH</text>
          {rj45SvgPort(46, 14, 26, 22, eth, { detail: 'ether1 · управление', fallbackName: 'ether1' })}

          {/* RESET */}
          <text x="20" y="45" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">RESET</text>
          <circle cx="20" cy="54" r="2.6" fill="none" stroke="#888" strokeWidth="0.6" />
          <circle cx="20" cy="54" r="0.8" fill="#444" />

          {/* Светодиоды PWR / USR */}
          <circle cx="50" cy="52" r="2" fill="#22c55e" stroke="#7a7a72" strokeWidth="0.3" />
          <text x="50" y="62" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">PWR</text>
          <circle cx="72" cy="52" r="2" fill="#f5d600" stroke="#7a7a72" strokeWidth="0.3" />
          <text x="72" y="62" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">USR</text>

          {/* 24 × SFP+ */}
          {Array.from({ length: cols }).map((_, c) => {
            const x = sfpStartX + c * colW;
            const top = sfpNum(c, 0);
            const bot = sfpNum(c, 1);
            return (
              <g key={`col-${c}`}>
                <text x={x + portW / 2} y="10" fontSize="4.5" fill="#444" textAnchor="middle" fontWeight="800">{top}</text>
                {sfpSvgPort(x, row1Y, portW, portH, sfpPort(top), {
                  detail: `SFP+${top} · 10 GbE`, fallbackName: `sfp-sfpplus${top}`,
                })}
                {sfpSvgPort(x, row2Y, portW, portH, sfpPort(bot), {
                  detail: `SFP+${bot} · 10 GbE`, fallbackName: `sfp-sfpplus${bot}`,
                })}
                <text x={x + portW / 2} y={H - 3} fontSize="4.5" fill="#444" textAnchor="middle" fontWeight="800">{bot}</text>
              </g>
            );
          })}

          {/* QSFP+ (2 порта, 40G) */}
          <rect x={qX} y="2" width={qW} height="2" fill="#7c3aed" />
          <text x={qX + qW / 2} y="11" fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">QSFP+</text>
          {[1, 2].map((k) => (
            <g key={`q-${k}`}>
              {sfpSvgPort(qX, k === 1 ? row1Y : row2Y, qW, portH, qsfpPort(k), {
                detail: `QSFP+${k} · 40 GbE`, fallbackName: `qsfpplus${k}-1`,
              })}
            </g>
          ))}
          <text x={qX + qW / 2} y={H - 3} fontSize="4" fill="#555" textAnchor="middle" fontWeight="700">
            QSFP+ 1-2 · 40G
          </text>

          {/* Лого */}
          <text x={W - 8} y="22" fontSize="9" fill="#222" textAnchor="end" fontWeight="800" fontFamily="Inter, sans-serif">
            Cloud Router Switch
          </text>
          <text x={W - 8} y="34" fontSize="5.5" fill="#444" textAnchor="end" fontFamily="Inter, sans-serif" letterSpacing="1">
            CRS326-24S+2Q+RM
          </text>
          <text x={W - 8} y={H - 8} fontSize="8" fill="#1a1a1a" textAnchor="end" fontWeight="900" fontFamily="Inter, sans-serif">
            MikroTik
          </text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- CRS309-1G-8S+IN ---------
// Компактный настольный свич: слева DC и CONSOLE, затем ether1 (GigE)
// и 8×SFP+ (sfp-sfpplus1…8) в один ряд, справа лого.

function Crs309Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const H = 66;
  const portW = 34, portH = 28, gap = 4;
  const portsY = 20;
  const ethX = 74;
  const sfpStartX = ethX + 36 + 16;
  const W = sfpStartX + 8 * (portW + gap) + 140;
  const eth = findPort(interfaces, 'ether1');
  const sfpPort = (n: number) =>
    findPort(interfaces, `sfp-sfpplus${n}`) || findPort(interfaces, `sfpplus${n}`);

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>CRS309-1G-8S+IN</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="4" fill="#e4e4e0" stroke="#a9a9a2" strokeWidth="1" />

          {/* DC */}
          <text x="16" y="12" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">DC</text>
          <circle cx="16" cy="32" r="7" fill="#0a0a0a" stroke="#555" strokeWidth="0.8" />
          <circle cx="16" cy="32" r="2.2" fill="#222" />
          <text x="16" y="52" fontSize="3" fill="#555" textAnchor="middle">12-57V</text>

          {/* CONSOLE */}
          <text x="46" y="12" fontSize="3.5" fill="#444" textAnchor="middle" fontWeight="700">CONSOLE</text>
          <rect x="35" y="20" width="22" height="13" rx="1.5" fill="#c8c8c8" stroke="#666" strokeWidth="0.5" />
          <rect x="38" y="23" width="16" height="7" fill="#0a0a0a" />

          {/* PWR / USR */}
          <circle cx="40" cy="46" r="1.8" fill="#22c55e" />
          <text x="40" y="56" fontSize="3" fill="#444" textAnchor="middle" fontWeight="700">PWR</text>
          <circle cx="54" cy="46" r="1.8" fill="#f5d600" />
          <text x="54" y="56" fontSize="3" fill="#444" textAnchor="middle" fontWeight="700">USR</text>

          {/* ether1 (GigE) */}
          <text x={ethX + 18} y="14" fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">ETH</text>
          {rj45SvgPort(ethX, portsY, 36, portH, eth, { detail: 'ether1 · 1 GbE', fallbackName: 'ether1' })}
          <text x={ethX + 18} y={H - 4} fontSize="3.5" fill="#555" textAnchor="middle" fontWeight="700">1G</text>

          {/* 8 × SFP+ */}
          <rect x={sfpStartX} y="2" width={8 * (portW + gap) - gap} height="2" fill="#7c3aed" />
          {Array.from({ length: 8 }).map((_, i) => {
            const x = sfpStartX + i * (portW + gap);
            return (
              <g key={`sfp-${i}`}>
                <text x={x + portW / 2} y="14" fontSize="5" fill="#444" textAnchor="middle" fontWeight="800">{i + 1}</text>
                {sfpSvgPort(x, portsY, portW, portH, sfpPort(i + 1), {
                  detail: `SFP+${i + 1} · 10 GbE`, fallbackName: `sfp-sfpplus${i + 1}`,
                })}
              </g>
            );
          })}
          <text
            x={sfpStartX + (8 * (portW + gap) - gap) / 2}
            y={H - 4}
            fontSize="3.5" fill="#555" textAnchor="middle" fontWeight="700"
          >
            SFP+ 1-8 · 10G
          </text>

          {/* Лого */}
          <text x={W - 8} y="24" fontSize="8" fill="#222" textAnchor="end" fontWeight="800" fontFamily="Inter, sans-serif">
            Cloud Router Switch
          </text>
          <text x={W - 8} y="35" fontSize="5" fill="#444" textAnchor="end" fontFamily="Inter, sans-serif" letterSpacing="1">
            CRS309-1G-8S+IN
          </text>
          <text x={W - 8} y={H - 8} fontSize="7.5" fill="#1a1a1a" textAnchor="end" fontWeight="900" fontFamily="Inter, sans-serif">
            MikroTik
          </text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- Модели с SFP28 / QSFP28 (25G / 100G) ---------
// Слева CONSOLE, ether1 (управление), RESET и светодиоды; затем SFP28 (при 8 и более портах
// в два ряда: сверху нечётные, снизу чётные) и QSFP28 (в один ряд, при 8 и более в два).
// QSFP28 состоит из «дорожек» qsfp28-K-1…4: иконка берёт первую поднятую.
// Раскладка сделана по памяти: при расхождении с корпусом поправьте rowsS/rowsQ и нумерацию ниже.

function DenseSfpMockup({
  interfaces, model, brand, dark, sfp28, qsfp,
}: {
  interfaces: InterfaceInfo[];
  model: string;
  brand: string;
  dark?: boolean;
  sfp28: number;
  qsfp: number;
}) {
  const H = 82;
  const pw = 26, ph = 22, gap = 3, qw = 46;
  const row1Y = 14;
  const row2Y = row1Y + ph + 4;
  const rowsS = sfp28 >= 8 ? 2 : 1;
  const colsS = sfp28 > 0 ? Math.ceil(sfp28 / rowsS) : 0;
  const rowsQ = qsfp >= 8 ? 2 : 1;
  const colsQ = Math.ceil(qsfp / rowsQ);
  const sx = 100;
  const sW = colsS * (pw + gap);
  const qx = sx + (colsS ? sW + 12 : 0);
  const qW = colsQ * (qw + gap);
  const W = qx + qW + 150;

  const bg = dark ? '#1a1a1a' : '#f4f4f1';
  const stroke = dark ? '#3a3a3a' : '#bdbdb6';
  const text = dark ? '#cccccc' : '#444444';
  const strong = dark ? '#ffffff' : '#1a1a1a';

  const yOf = (rows: number, r: number) =>
    rows === 1 ? (row1Y + row2Y) / 2 : r === 0 ? row1Y : row2Y;
  const numOf = (rows: number, c: number, r: number) => (rows === 1 ? c + 1 : 2 * c + 1 + r);

  const sfpPort = (n: number) =>
    findPort(interfaces, `sfp28-${n}`) ||
    findPort(interfaces, `sfp-sfpplus${n}`) ||
    findPort(interfaces, `sfpplus${n}`);
  const qsfpPort = (k: number): InterfaceInfo | undefined => {
    const lanes = [1, 2, 3, 4]
      .flatMap((l) => [`qsfp28-${k}-${l}`, `qsfpplus${k}-${l}`])
      .map((n) => interfaces.find((x) => x.name === n))
      .filter(Boolean) as InterfaceInfo[];
    return (
      lanes.find((l) => l.running) || lanes[0] ||
      findPort(interfaces, `qsfp28-${k}`) || findPort(interfaces, `qsfpplus${k}`)
    );
  };
  const eth = findPort(interfaces, 'ether1');

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>{model}</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="3" fill={bg} stroke={stroke} strokeWidth="1" />

          {/* CONSOLE */}
          <text x="20" y="12" fontSize="3.5" fill={text} textAnchor="middle" fontWeight="700">CONSOLE</text>
          <rect x="8" y="15" width="24" height="14" rx="1.5" fill="#c8c8c8" stroke="#666" strokeWidth="0.5" />
          <rect x="12" y="18" width="16" height="8" fill="#0a0a0a" />
          <rect x="16" y="21" width="8" height="2.5" fill="#222" />

          {/* ether1 — управление */}
          <text x="58" y="12" fontSize="3.5" fill={text} textAnchor="middle" fontWeight="700">ETH</text>
          {rj45SvgPort(46, 14, 26, 22, eth, { detail: 'ether1 · управление', fallbackName: 'ether1' })}

          {/* RESET и светодиоды */}
          <text x="20" y="45" fontSize="3.5" fill={text} textAnchor="middle" fontWeight="700">RESET</text>
          <circle cx="20" cy="54" r="2.6" fill="none" stroke="#888" strokeWidth="0.6" />
          <circle cx="20" cy="54" r="0.8" fill="#444" />
          <circle cx="50" cy="52" r="2" fill="#22c55e" />
          <text x="50" y="62" fontSize="3.5" fill={text} textAnchor="middle" fontWeight="700">PWR</text>
          <circle cx="72" cy="52" r="2" fill="#f5d600" />
          <text x="72" y="62" fontSize="3.5" fill={text} textAnchor="middle" fontWeight="700">USR</text>

          {/* SFP28 */}
          {colsS > 0 && (
            <>
              <rect x={sx} y="2" width={sW - gap} height="2" fill="#ec4899" />
              <text x={sx + (sW - gap) / 2} y="11" fontSize="5" fill={text} textAnchor="middle" fontWeight="800">SFP28</text>
              {Array.from({ length: rowsS }).flatMap((_, r) =>
                Array.from({ length: colsS }).map((__, c) => {
                  const n = numOf(rowsS, c, r);
                  if (n > sfp28) return null;
                  const x = sx + c * (pw + gap);
                  return (
                    <g key={`s-${n}`}>
                      {sfpSvgPort(x, yOf(rowsS, r), pw, ph, sfpPort(n), {
                        detail: `SFP28 ${n} · 25 GbE`, fallbackName: `sfp28-${n}`,
                      })}
                    </g>
                  );
                }),
              )}
              <text x={sx + (sW - gap) / 2} y={H - 3} fontSize="4" fill={text} textAnchor="middle" fontWeight="700">
                SFP28 1-{sfp28} · 25G
              </text>
            </>
          )}

          {/* QSFP28 */}
          <rect x={qx} y="2" width={qW - gap} height="2" fill="#f43f5e" />
          <text x={qx + (qW - gap) / 2} y="11" fontSize="5" fill={text} textAnchor="middle" fontWeight="800">QSFP28</text>
          {Array.from({ length: rowsQ }).flatMap((_, r) =>
            Array.from({ length: colsQ }).map((__, c) => {
              const k = numOf(rowsQ, c, r);
              if (k > qsfp) return null;
              const x = qx + c * (qw + gap);
              return (
                <g key={`q-${k}`}>
                  {sfpSvgPort(x, yOf(rowsQ, r), qw, ph, qsfpPort(k), {
                    detail: `QSFP28 ${k} · 100 GbE`, fallbackName: `qsfp28-${k}-1`,
                  })}
                  <text x={x + qw / 2} y={yOf(rowsQ, r) - 2} fontSize="4" fill={text} textAnchor="middle" fontWeight="700">{k}</text>
                </g>
              );
            }),
          )}
          <text x={qx + (qW - gap) / 2} y={H - 3} fontSize="4" fill={text} textAnchor="middle" fontWeight="700">
            QSFP28 1-{qsfp} · 100G
          </text>

          {/* Лого */}
          <text x={W - 8} y="22" fontSize="9" fill={strong} textAnchor="end" fontWeight="800" fontFamily="Inter, sans-serif">{brand}</text>
          <text x={W - 8} y="34" fontSize="5.5" fill={text} textAnchor="end" fontFamily="Inter, sans-serif" letterSpacing="1">{model}</text>
          <text x={W - 8} y={H - 8} fontSize="8" fill={strong} textAnchor="end" fontWeight="900" fontFamily="Inter, sans-serif">MikroTik</text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- CHR (Cloud Hosted Router) ---------
// Виртуальная машина MikroTik — нет физической панели.
// Простой белый прямоугольник: слева лейбл «CHR», справа порты ether* в ряд.
// Количество портов — динамическое (сколько отдало устройство).

// generic=true — этот мокап используется как универсальная заглушка для
// модели, у которой нет собственного мокапа (а не как реальный CHR).
function ChrMockup({
  interfaces,
  boardName,
  generic,
}: {
  interfaces: InterfaceInfo[];
  boardName?: string | null;
  generic?: boolean;
}) {
  const ports = interfaces
    .filter(isWiredPort)
    .sort((a, b) => {
      const ai = parseInt((a.default_name || a.name).match(/\d+/)?.[0] || '0', 10);
      const bi = parseInt((b.default_name || b.name).match(/\d+/)?.[0] || '0', 10);
      return ai - bi;
    });

  // Фиксированные размеры: 500×66 px. SVG в viewBox 1:1 пикселям, scale=1.
  // Порты 30×32 px начинаются после блока «mikrotik» слева, если все не помещаются —
  // их можно прокрутить горизонтально через overflow-x-auto обёртки.
  const W = Math.max(500, 108 + ports.length * 34);
  const H = 66;
  const padX = 6;
  const labelW = 92;
  const gap = 4;
  const portW = 30;
  const portH = 32;
  const portsY = (H - portH) / 2 - 2;
  const portsStartX = padX + labelW + 6;

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        {generic ? (
          <>Модель <b>{boardName || '—'}</b> · мокап не подготовлен, показана универсальная схема портов</>
        ) : (
          <>Виртуальный роутер <b>MikroTik CHR</b> · подсветка портов в реальном времени</>
        )}
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Белый фон-корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="6" fill="#ffffff" stroke="#cccccc" strokeWidth="1" />

          {/* Лейбл mikrotik слева (шрифт в 2 раза мельче) */}
          <text x={padX} y={H / 2} fontSize="14" fill="#1a1a1a" fontWeight="800" fontFamily="Inter, sans-serif">MikroTik</text>
          <text x={padX} y={H / 2 + 12} fontSize="6" fill="#666666">{generic ? (boardName || 'RouterOS') : 'Cloud Hosted Router'}</text>

          {/* Разделитель */}
          <line x1={padX + labelW - 4} y1="8" x2={padX + labelW - 4} y2={H - 8} stroke="#dddddd" strokeWidth="1" />

          {/* Порты */}
          {ports.length === 0 && (
            <text x={portsStartX + 10} y={H / 2 + 3} fontSize="7" fill="#888888">нет данных физических интерфейсов</text>
          )}
          {ports.map((it, i) => {
            const x = portsStartX + i * (portW + gap);
            const pal = portPalette(it);
            // Короткий лейбл — только номер порта (ether7 → "7").
            const num = (it.name.match(/(\d+)$/) || [, it.name])[1];
            return (
              <g key={it.name}>
                {(/sfp/i.test(it.default_name || it.name) ? sfpSvgPort : rj45SvgPort)(x, portsY, portW, portH, it, { detail: it.type || 'virtual', fallbackName: it.name })}
                {/* Номер порта над иконкой */}
                <text
                  x={x + portW / 2}
                  y={portsY - 2}
                  fontSize="8"
                  fill={pal.color}
                  fontWeight="700"
                  textAnchor="middle"
                  fontFamily="monospace"
                >
                  {num}
                </text>
                {/* Имя интерфейса под портом */}
                <text
                  x={x + portW / 2}
                  y={portsY + portH + 8}
                  fontSize="5"
                  fill="#888888"
                  textAnchor="middle"
                  fontFamily="monospace"
                >
                  {it.name}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <MockupLegend />
    </div>
  );
}

// --------- hEX S (RB760iGS) ---------
// Тёмно-серый корпус, Power DC + лого, SFP, 5 GigE портов.
// ether1 = INTERNET / PoE in, ether2-4 = LAN, ether5 = PoE out (оранжевый), sfp1.

function HexSMockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const byName = new Map(interfaces.map((it) => [it.name, it]));
  const W = 320, H = 66;
  const padX = 4;
  const portW = 32, portH = 32, gap = 3;
  const portsY = (H - portH) / 2 - 1;
  const portsStartX = 96;
  const sfp = findPort(interfaces, 'sfp1') || findPort(interfaces, 'sfp-sfpplus1');

  const ports = [
    { name: 'ether1', label: '1', accent: 'poe-in'  as const },
    { name: 'ether2', label: '2', accent: null      as const },
    { name: 'ether3', label: '3', accent: null      as const },
    { name: 'ether4', label: '4', accent: null      as const },
    { name: 'ether5', label: '5', accent: 'poe-out' as const },
  ];

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>hEX S</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Корпус тёмно-серый */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="4" fill="#3a3f47" stroke="#1f2227" strokeWidth="1" />

          {/* Power разъём + подпись */}
          <text x="14" y="13" fontSize="5" fill="#dddddd" fontWeight="700">Power</text>
          <circle cx="14" cy="32" r="7" fill="#0a0a0a" stroke="#222" strokeWidth="0.8" />
          <circle cx="14" cy="32" r="2.2" fill="#222" />
          <text x="14" y="48" fontSize="4" fill="#aaaaaa" textAnchor="middle">12-57V DC</text>

          {/* hEX s лого */}
          <text x="44" y="14" fontSize="11" fill="#ffffff" fontWeight="900" fontFamily="Inter, sans-serif">hEX</text>
          <text x="68" y="11" fontSize="5" fill="#ffffff" fontWeight="700">s</text>

          {/* SFP слот */}
          {sfpSvgPort(42, 22, 28, 22, sfp, { detail: 'SFP · Internet', fallbackName: 'sfp1' })}
          <text x="56" y="52" fontSize="4" fill="#aaaaaa" textAnchor="middle">SFP</text>
          <text x="56" y="58" fontSize="4" fill="#888888" textAnchor="middle" fontStyle="italic">INTERNET</text>

          {/* Passive/af/at подпись над портом 1 */}
          <rect x={portsStartX - 1} y="3" width={portW + 2} height="8" rx="2" fill="#1f2227" stroke="#555" strokeWidth="0.4" />
          <text x={portsStartX + portW / 2} y="9" fontSize="4" fill="#dddddd" fontWeight="700" textAnchor="middle">Passive/af/at</text>

          {/* Оранжевая зона над/под портом 5 (PoE out) */}
          <rect x={portsStartX + 4 * (portW + gap) - 1} y="0" width={portW + 2} height="12" fill="#f0851a" />
          <rect x={portsStartX + 4 * (portW + gap) - 1} y={H - 8} width={portW + 2} height="8" fill="#f0851a" />

          {/* Лейблы цифр над портами 2-5 */}
          {ports.slice(1).map((p, idx) => {
            const i = idx + 1;
            const x = portsStartX + i * (portW + gap);
            return (
              <text key={p.label} x={x + portW / 2} y="9" fontSize="6" fill="#ffffff" fontWeight="800" textAnchor="middle">
                {p.label}
              </text>
            );
          })}

          {/* Порты */}
          {ports.map((p, i) => {
            const x = portsStartX + i * (portW + gap);
            const it = findPort(interfaces, p.name);
            const detail =
              p.accent === 'poe-in' ? `порт ${p.label} · PoE in`
              : p.accent === 'poe-out' ? `порт ${p.label} · PoE out`
              : `порт ${p.label}`;
            return (
              <g key={p.name}>
                {rj45SvgPort(x, portsY, portW, portH, it, { detail, fallbackName: p.name })}
              </g>
            );
          })}

          {/* Нижние подписи */}
          <text x={portsStartX + portW / 2} y={H - 2} fontSize="3.5" fill="#dddddd" textAnchor="middle">PoE in</text>
          <text x={portsStartX + (portW + gap) + (3 * (portW + gap) - gap) / 2} y={H - 2} fontSize="3.5" fill="#aaaaaa" textAnchor="middle">LAN</text>
          <text x={portsStartX + 4 * (portW + gap) + portW / 2} y={H - 2} fontSize="3.5" fill="#ffffff" textAnchor="middle" fontWeight="700">PoE out</text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// --------- L009 (L009UiGS-RM) ---------
// Красный 19" rack: RES, DC 24-56V, SFP, USB 3.0, 8 GigE портов.
// ether1 = PoE in, ether8 = PoE out (оранжевый), sfp1.

function L009Mockup({ interfaces }: { interfaces: InterfaceInfo[] }) {
  const byName = new Map(interfaces.map((it) => [it.name, it]));
  const W = 480, H = 66;
  const portW = 36, portH = 32, gap = 3;
  const portsY = (H - portH) / 2 - 1;
  // Слева до портов: RES + DC + SFP + USB ≈ 110px
  const portsStartX = 116;
  // Между ether4 и ether5 — небольшой визуальный разрыв
  const groupGap = 8;
  const sfp = findPort(interfaces, 'sfp1');

  const ports = [
    { name: 'ether1', label: '1', accent: 'poe-in'  as const },
    { name: 'ether2', label: '2', accent: null      as const },
    { name: 'ether3', label: '3', accent: null      as const },
    { name: 'ether4', label: '4', accent: null      as const },
    { name: 'ether5', label: '5', accent: null      as const },
    { name: 'ether6', label: '6', accent: null      as const },
    { name: 'ether7', label: '7', accent: null      as const },
    { name: 'ether8', label: '8', accent: 'poe-out' as const },
  ];

  const xOf = (i: number) => portsStartX + i * (portW + gap) + (i >= 4 ? groupGap : 0);

  return (
    <div className="card">
      <div className="text-xs text-mk-mute mb-2">
        Лицевая панель <b>L009UiGS</b> · подсветка портов в реальном времени
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          xmlns="http://www.w3.org/2000/svg"
          style={frontPanelStyle(W,H)}
          preserveAspectRatio="xMinYMid meet"
        >
          {/* Красный корпус */}
          <rect x="1" y="1" width={W - 2} height={H - 2} rx="4" fill="#c92020" stroke="#7a1010" strokeWidth="1" />

          {/* RES кнопка */}
          <text x="10" y="9" fontSize="4" fill="#ffffff" fontWeight="700" textAnchor="middle">RES</text>
          <circle cx="10" cy="22" r="2.2" fill="none" stroke="#ffffff" strokeWidth="0.8" />
          <circle cx="10" cy="22" r="0.9" fill="#222" />
          {/* power led */}
          <text x="10" y="58" fontSize="3" fill="#ffffff" textAnchor="middle">⏻</text>

          {/* DC разъём */}
          <text x="28" y="9" fontSize="3.5" fill="#ffffff" textAnchor="middle">24-56 V DC</text>
          <circle cx="28" cy="32" r="9" fill="#0a0a0a" stroke="#5a0a0a" strokeWidth="1" />
          <circle cx="28" cy="32" r="3" fill="#222" />
          <text x="28" y="58" fontSize="3" fill="#ffffff" textAnchor="middle">⊖-⊙-⊕</text>

          {/* SFP слот */}
          <text x="60" y="9" fontSize="4" fill="#ffffff" fontWeight="700" textAnchor="middle">SFP</text>
          {sfpSvgPort(48, 16, 24, 32, sfp, { detail: 'SFP', fallbackName: 'sfp1' })}
          <text x="60" y="58" fontSize="3" fill="#ffffff" textAnchor="middle">SFP</text>

          {/* USB 3.0 */}
          <text x="92" y="9" fontSize="4" fill="#ffffff" fontWeight="700" textAnchor="middle">USB</text>
          <rect x="78" y="20" width="28" height="22" rx="1" fill="#0a0a0a" stroke="#888" strokeWidth="0.5" />
          <rect x="80" y="22" width="24" height="18" fill="#1a4b8c" />
          <rect x="88" y="26" width="8" height="6" fill="#0a0a0a" />
          <text x="92" y="58" fontSize="3" fill="#ffffff" textAnchor="middle">USB 3.0</text>

          {/* Оранжевая зона над/под портом 8 (PoE out) */}
          <rect x={xOf(7) - 1} y="0" width={portW + 2} height="11" fill="#f0851a" />
          <rect x={xOf(7) - 1} y={H - 8} width={portW + 2} height="8" fill="#f0851a" />

          {/* Лейблы цифр над портами */}
          {ports.map((p, i) => (
            <text key={p.label} x={xOf(i) + portW / 2} y="8" fontSize="5.5" fill="#ffffff" fontWeight="800" textAnchor="middle">
              {p.label}
            </text>
          ))}

          {/* Порты */}
          {ports.map((p, i) => {
            const x = xOf(i);
            const it = findPort(interfaces, p.name);
            const detail =
              p.accent === 'poe-in' ? `порт ${p.label} · PoE in`
              : p.accent === 'poe-out' ? `порт ${p.label} · PoE out`
              : `порт ${p.label}`;
            return (
              <g key={p.name}>
                {rj45SvgPort(x, portsY, portW, portH, it, { detail, fallbackName: p.name })}
              </g>
            );
          })}

          {/* Нижние подписи скоростей */}
          <text x={xOf(0) + portW / 2} y={H - 2} fontSize="3.5" fill="#ffffff" textAnchor="middle" fontWeight="700">PoE in</text>
          <text x={xOf(7) + portW / 2} y={H - 2} fontSize="3.5" fill="#ffffff" textAnchor="middle" fontWeight="700">PoE out</text>
        </svg>
      </div>
      <MockupLegend />
    </div>
  );
}

// Общая мини-легенда для физических мокапов — цветомаркировка скоростей.
const SPEED_LEGEND: { color: string; label: string }[] = [
  { color: '#9ca3af', label: 'Down / отключён / нет данных' },
  { color: '#166534', label: '10 Mb/s' },
  { color: '#14b8a6', label: '100 Mb/s' },
  { color: '#22c55e', label: '1–2.5 Gb/s / Link UP' },
  { color: '#a855f7', label: '5–10 Gb/s' },
  { color: '#ec4899', label: '25 Gb/s' },
  { color: '#3b82f6', label: '40 Gb/s' },
  { color: '#eab308', label: '50 Gb/s' },
  { color: '#f43f5e', label: '100 Gb/s' },
];

function MockupLegend() {
  return (
    <div className="flex flex-wrap items-center gap-3 mt-2 text-[10px] text-mk-mute">
      {SPEED_LEGEND.map((s) => (
        <span key={s.label} className="inline-flex items-center gap-1">
          <span
            className="inline-block w-3 h-3 rounded-sm border-2"
            style={{ borderColor: s.color, backgroundColor: '#0a0a0a' }}
          />
          {s.label}
        </span>
      ))}
    </div>
  );
}
