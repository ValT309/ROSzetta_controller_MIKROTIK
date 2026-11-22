// Static local device silhouettes. Never infer link state from a thumbnail.
export type DevicePreviewKey = 'hap-ac-lite' | 'hap-ac2' | 'hap-ax2' | 'hap-ax3' | 'hap-lite' | 'hap' | 'hex' | 'hex-s' | 'hex-poe' | 'rb951' | 'rb2011' | 'rb3011' | 'rb4011' | 'rb5009' | 'l009' | 'ccr2116' | 'ccr2216' | 'crs305' | 'crs309' | 'crs317' | 'crs326' | 'crs326s' | 'crs328' | 'crs354' | 'crs504' | 'crs510' | 'crs518' | 'crs520' | 'generic-router' | 'generic-switch' | 'chr';

const rules: ReadonlyArray<readonly [DevicePreviewKey, RegExp]> = [
  ['hap-ac-lite', /^(?:hapaclite|rb952ui)/],
  ['hap-ac2', /^(?:hapac2|rbd52g)/],
  ['hap-ax2', /^(?:hapax2|c52ig)/],
  ['hap-ax3', /^(?:hapax3|c53uig)/],
  ['hap-lite', /^(?:haplite|rb941)/],
  ['hap', /^hap$/],
  ['hex-poe', /^(?:hexpoe(?!lite)|rb960pgs)/],
  ['hex-s', /^(?:hexs|rb760igs|e60iugs)/],
  ['hex', /^(?:hex$|rb750gr[23])/],
  ['rb951', /^rb951/],
  ['rb2011', /^rb2011/],
  ['rb3011', /^rb3011/],
  ['rb4011', /^rb4011/],
  ['rb5009', /^rb5009/],
  ['l009', /^l009/],
  ['ccr2116', /^ccr2116/],
  ['ccr2216', /^ccr2216/],
  ['crs305', /^crs305/],
  ['crs309', /^crs309/],
  ['crs317', /^crs317/],
  ['crs326s', /^crs32624s/],
  ['crs326', /^crs326(?:24g|$)/],
  ['crs328', /^crs328(?:24p|$)/],
  ['crs354', /^crs354/],
  ['crs504', /^crs504/],
  ['crs510', /^crs510/],
  ['crs518', /^crs518/],
  ['crs520', /^crs520/],
  ['chr', /^(?:chr|cloudhostedrouter|x86_64|x86)$/],
];

export function resolveDevicePreview(model: string | null | undefined, kind?: string): DevicePreviewKey {
  const normalized = (model || '').normalize('NFKC').toLowerCase().replace(/[^a-z0-9_]/g, '');
  for (const [key, pattern] of rules) if (pattern.test(normalized)) return key;
  return kind === 'switch' || /^(crs|css)/.test(normalized) ? 'generic-switch' : 'generic-router';
}
