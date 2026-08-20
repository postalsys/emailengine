#!/usr/bin/env node
'use strict';

// Regenerates static/emailengine.ico, the icon winconf.js stamps into the Windows executable.
// Run it when the logo artwork changes; the result is committed, so a normal build needs
// neither this script nor ImageMagick.
//
// The members are assembled here rather than by a single `magick -define icon:auto-resize=...`
// call because ImageMagick writes every one of them as an uncompressed BMP, and a 256x256 BMP
// alone is 270KB. The resulting icon is large enough to break the packaged exe - see the comment
// on payloadOffset() in winconf.js - so the two biggest sizes are PNG-compressed instead, which
// keeps the whole file around 63KB.

const { load } = require('resedit/cjs');
const { execFileSync } = require('child_process');
const { mkdtempSync, readFileSync, writeFileSync, rmSync } = require('fs');
const { tmpdir } = require('os');
const { join, resolve } = require('path');

const SOURCE = resolve(__dirname, '../static/logo.png');
const TARGET = resolve(__dirname, '../static/emailengine.ico');

// Windows renders the icon at all of these: 16 in the Explorer list view and the title bar, 32
// and 48 in the larger views, 256 for the extra large one. PNG for the two biggest, an
// uncompressed 32-bit DIB for the rest, which is the convention Windows has read since Vista
const PNG_SIZES = [256, 128];
const BMP_SIZES = [64, 48, 32, 24, 16];

function magick(args) {
    try {
        execFileSync('magick', args, { stdio: ['ignore', 'ignore', 'pipe'] });
    } catch (err) {
        if (err.code === 'ENOENT') {
            throw new Error('ImageMagick is required to rebuild the icon: brew install imagemagick', { cause: err });
        }
        throw new Error(`magick ${args.join(' ')} failed: ${String(err.stderr || err.message).trim()}`, { cause: err });
    }
}

load()
    .then(ResEdit => {
        const workDir = mkdtempSync(join(tmpdir(), 'ee-icon-'));

        try {
            const icons = [];

            for (let size of PNG_SIZES) {
                const file = join(workDir, `png-${size}.png`);
                magick([SOURCE, '-background', 'none', '-resize', `${size}x${size}`, '-strip', '-define', 'png:compression-level=9', file]);
                // The dimensions have to be passed in: RawIconItem does not read them out of the
                // PNG header, and without them the directory entry is written as 0x0 at 0bpp
                icons.push({ data: ResEdit.Data.RawIconItem.from(readFileSync(file), size, size, 32) });
            }

            // ImageMagick's own DIB members are well formed, so the small sizes are taken from an
            // ico it builds rather than encoded here
            const smallIco = join(workDir, 'small.ico');
            magick([SOURCE, '-background', 'none', '-define', `icon:auto-resize=${BMP_SIZES.join(',')}`, smallIco]);
            icons.push(...ResEdit.Data.IconFile.from(readFileSync(smallIco)).icons);

            const iconFile = new ResEdit.Data.IconFile();
            iconFile.icons = icons;

            const ico = Buffer.from(iconFile.generate());
            writeFileSync(TARGET, ico);

            console.log(`Wrote ${TARGET}`);
            console.log(`  ${icons.length} images: ${icons.map(icon => `${icon.data.width}x${icon.data.height}`).join(', ')}`);
            console.log(`  ${ico.length} bytes`);
        } finally {
            rmSync(workDir, { recursive: true, force: true });
        }
    })
    .catch(err => {
        console.error('Error building the icon:', err);
        process.exit(1);
    });
