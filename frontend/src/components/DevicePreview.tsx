import { memo } from 'react';
import { resolveDevicePreview } from '@/utils/devicePreview';

/** Static silhouette in the list. Live interface data is shown only in the device card. */
export default memo(function DevicePreview({model, kind}: {model?: string | null; kind?: string}) {
  const key = resolveDevicePreview(model, kind);
  const label = model || '—';
  const generic = key.startsWith('generic-');
  const description = generic ? 'Универсальная миниатюра: модель не определена или не поддерживается' : 'Стилизованная модель (без состояния портов): ' + label;
  return <div className="flex items-center gap-2 min-w-[150px]">
    <img src={`${import.meta.env.BASE_URL}device-previews/${key}.svg`} alt="" title={description} width={112} height={36} className="w-28 h-9 shrink-0 object-contain" loading="lazy" decoding="async" draggable={false}/>
    <span className="leading-tight text-mk-mute break-words">{label}</span>
  </div>;
});
