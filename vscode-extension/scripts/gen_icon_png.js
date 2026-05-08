/* eslint-disable no-bitwise */
/**
 * Deterministic 128x128 PNG icon generator (no native deps).
 * Writes vscode-extension/images/icon.png
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const W = 128;
const H = 128;

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      const mask = -(crc & 1);
      crc = (crc >>> 1) ^ (0xedb88320 & mask);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function chunk(type, data) {
  const t = Buffer.from(type, 'ascii');
  const len = u32be(data.length);
  const crc = u32be(crc32(Buffer.concat([t, data])));
  return Buffer.concat([len, t, data, crc]);
}

function setPixel(img, x, y, r, g, b, a) {
  if (x < 0 || y < 0 || x >= W || y >= H) return;
  const idx = (y * W + x) * 4;
  img[idx + 0] = r;
  img[idx + 1] = g;
  img[idx + 2] = b;
  img[idx + 3] = a;
}

function drawDisc(img, cx, cy, rad, r, g, b, a) {
  const r2 = rad * rad;
  const x0 = Math.floor(cx - rad);
  const x1 = Math.ceil(cx + rad);
  const y0 = Math.floor(cy - rad);
  const y1 = Math.ceil(cy + rad);
  for (let y = y0; y <= y1; y++) {
    for (let x = x0; x <= x1; x++) {
      const dx = x - cx;
      const dy = y - cy;
      if (dx * dx + dy * dy <= r2) {
        setPixel(img, x, y, r, g, b, a);
      }
    }
  }
}

function drawLineThick(img, x0, y0, x1, y1, thickness, r, g, b, a) {
  x0 = Math.round(x0); y0 = Math.round(y0);
  x1 = Math.round(x1); y1 = Math.round(y1);
  const dx = Math.abs(x1 - x0);
  const dy = Math.abs(y1 - y0);
  const sx = x0 < x1 ? 1 : -1;
  const sy = y0 < y1 ? 1 : -1;
  let err = dx - dy;
  const rad = Math.max(1, Math.floor(thickness / 2));

  while (true) {
    drawDisc(img, x0, y0, rad, r, g, b, a);
    if (x0 === x1 && y0 === y1) break;
    const e2 = 2 * err;
    if (e2 > -dy) { err -= dy; x0 += sx; }
    if (e2 < dx) { err += dx; y0 += sy; }
  }
}

function drawPolyline(img, pts, thickness, r, g, b, a) {
  for (let i = 0; i < pts.length - 1; i++) {
    const [x0, y0] = pts[i];
    const [x1, y1] = pts[i + 1];
    drawLineThick(img, x0, y0, x1, y1, thickness, r, g, b, a);
  }
}

function fillPolygon(img, pts, r, g, b, a) {
  // Simple scanline fill, assumes non-self-intersecting.
  let minY = Infinity, maxY = -Infinity;
  for (const [, y] of pts) { minY = Math.min(minY, y); maxY = Math.max(maxY, y); }
  minY = Math.max(0, Math.floor(minY));
  maxY = Math.min(H - 1, Math.ceil(maxY));

  for (let y = minY; y <= maxY; y++) {
    const intersections = [];
    for (let i = 0; i < pts.length; i++) {
      const [x0, y0] = pts[i];
      const [x1, y1] = pts[(i + 1) % pts.length];
      if (y0 === y1) continue;
      const ymin = Math.min(y0, y1);
      const ymax = Math.max(y0, y1);
      if (y < ymin || y >= ymax) continue;
      const t = (y - y0) / (y1 - y0);
      intersections.push(x0 + t * (x1 - x0));
    }
    intersections.sort((a, b) => a - b);
    for (let i = 0; i < intersections.length; i += 2) {
      const xStart = Math.max(0, Math.floor(intersections[i]));
      const xEnd = Math.min(W - 1, Math.ceil(intersections[i + 1]));
      for (let x = xStart; x <= xEnd; x++) {
        setPixel(img, x, y, r, g, b, a);
      }
    }
  }
}

function buildPng(rgba) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0);
  ihdr.writeUInt32BE(H, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  const stride = W * 4;
  const raw = Buffer.alloc((stride + 1) * H);
  for (let y = 0; y < H; y++) {
    raw[y * (stride + 1)] = 0; // filter type 0
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const compressed = zlib.deflateSync(raw, { level: 9 });

  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', compressed),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function main() {
  const img = Buffer.alloc(W * H * 4, 0); // transparent background

  // Shield shape (filled) + outline.
  const shield = [
    [64, 10],
    [102, 24],
    [102, 58],
    [64, 114],
    [26, 58],
    [26, 24],
  ];

  // subtle fill
  fillPolygon(img, shield, 32, 210, 220, 26);
  // outline teal
  drawPolyline(img, [...shield, shield[0]], 6, 110, 240, 245, 255);

  // Check mark
  const check = [
    [44, 64],
    [58, 78],
    [86, 46],
  ];
  drawPolyline(img, check, 10, 63, 185, 80, 255);

  const png = buildPng(img);

  const outPath = path.resolve(__dirname, '..', 'images', 'icon.png');
  fs.writeFileSync(outPath, png);
  process.stdout.write(`Wrote ${outPath}\n`);
}

main();

