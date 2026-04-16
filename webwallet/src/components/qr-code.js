/** QR Code generator — renders to SVG using qrcode-generator npm package. */

import qrcodegen from 'qrcode-generator';

/**
 * Generate a QR code SVG string.
 */
export function generateQR(text, size = 200) {
  try {
    const qr = qrcodegen(0, 'L');
    qr.addData(text);
    qr.make();
    const modules = qr.getModuleCount();
    const cellSize = size / modules;

    let paths = '';
    for (let row = 0; row < modules; row++) {
      for (let col = 0; col < modules; col++) {
        if (qr.isDark(row, col)) {
          const x = (col * cellSize).toFixed(2);
          const y = (row * cellSize).toFixed(2);
          const s = cellSize.toFixed(2);
          paths += `M${x},${y}h${s}v${s}h-${s}z`;
        }
      }
    }

    return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <rect width="${size}" height="${size}" fill="white" rx="4"/>
      <path d="${paths}" fill="#08080F"/>
    </svg>`;
  } catch (e) {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <rect width="${size}" height="${size}" fill="white" rx="8"/>
      <text x="50%" y="50%" text-anchor="middle" dy=".3em" fill="#666" font-size="12" font-family="monospace">QR</text>
    </svg>`;
  }
}
