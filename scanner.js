'use strict';

// ══════════════════════════════════════════
//  THREAT PATTERNS
// ══════════════════════════════════════════
const THREATS = [
  {
    type: 'Загрузчик лоадера (gtaweap4.saa)',
    signatures: ['gtaweap4.saa','loadDynamicLibrary','_sendCommand','callFunction'],
    color: '#ffaa00',
    iconColor: '#ffaa00',
    iconBg: 'rgba(255,170,0,0.1)',
    iconBorder: 'rgba(255,170,0,0.2)',
    icon: 'download_for_offline'
  },
  {
    type: 'Загрузчик стиллера (AntiCrashInfo.asi)',
    signatures: [
      'raw.githubusercontent.com',
      '/zalupaFM/versioncheck/refs/heads/main/ver',
      'barssign','update.bin',
      'C:\\Users\\nzx3r\\Desktop'
    ],
    color: '#ff7043',
    iconColor: '#ff7043',
    iconBg: 'rgba(255,112,67,0.1)',
    iconBorder: 'rgba(255,112,67,0.2)',
    icon: 'warning'
  },
  {
    type: 'Стиллер (AntiCrashInfo.asi)',
    signatures: [
      'OnDialogResponse','GTASA_CustomExec_Mutex_',
      'barssign','hooks.cpp','CSampStealerR3'
    ],
    color: '#ff4060',
    iconColor: '#ff4060',
    iconBg: 'rgba(255,64,96,0.1)',
    iconBorder: 'rgba(255,64,96,0.2)',
    icon: 'bug_report'
  }
];

// ══════════════════════════════════════════
//  CORE LOGIC
// ══════════════════════════════════════════
const _decoder = new TextDecoder('iso-8859-1');

/**
 * Checks whether ALL signatures of a threat are present in the file.
 * Reads the file as latin-1 bytes so binary content is preserved 1:1.
 */
async function containsAllSignatures(file, signatures, maxFileSize) {
  if (maxFileSize !== Infinity && file.size > maxFileSize) return false;
  try {
    const buf = await file.arrayBuffer();
    const str = _decoder.decode(buf);
    return signatures.every(sig => str.includes(sig));
  } catch {
    return false;
  }
}

/**
 * Recursively walks a directory and checks every file against THREATS.
 *
 * @param {FileSystemDirectoryHandle} dirHandle
 * @param {number|Infinity} maxDepth  - max folder depth (1 = root only)
 * @param {number} depth              - current depth (start at 1)
 * @param {string} basePath           - path prefix accumulated so far
 * @param {object} options
 *   @param {() => boolean}        options.isCancelled - return true to stop scan
 *   @param {(path: string) => void} options.onFile    - called for every file visited
 *   @param {(det: object) => void}  options.onThreat  - called when a threat is found
 */
async function scanDirectory(dirHandle, maxDepth, depth, basePath, options) {
  if (options.isCancelled()) return;

  try {
    for await (const [name, handle] of dirHandle.entries()) {
      if (options.isCancelled()) return;

      const path = basePath ? basePath + '/' + name : name;

      if (handle.kind === 'file') {
        options.onFile(path);

        let file;
        try { file = await handle.getFile(); } catch { continue; }

        for (const threat of THREATS) {
          if (await containsAllSignatures(file, threat.signatures, options.maxFileSize ?? Infinity)) {
            options.onThreat({
              type: threat.type,
              path: path,
              handle: handle,
              color: threat.color,
              icon: threat.icon,
              iconColor: threat.iconColor,
              iconBg: threat.iconBg,
              iconBorder: threat.iconBorder,
              id: 'det_' + Date.now() + '_' + Math.random().toString(36).slice(2)
            });
          }
        }

      } else if (handle.kind === 'directory') {
        if (maxDepth === Infinity || depth < maxDepth) {
          await scanDirectory(handle, maxDepth, depth + 1, path, options);
        }
      }
    }
  } catch {}
}
