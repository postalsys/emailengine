'use strict';

const { load } = require('resedit/cjs');
const PackageData = require('./package.json');

const { readFileSync, writeFileSync, renameSync, existsSync } = require('fs');

// Windows reads this as the file's "Company". Leaving it unset is not neutral: the exe then
// inherits "Node.js" from the pkg base binary the build starts from, and that is what every
// release up to 2.79.1 shipped.
const COMPANY = 'Postal Systems OÜ';

// pkg writes <name>-<target minus its node prefix>.exe into pkg.outputPath, so the file this
// script rewrites is derived from the same config pkg built it from and cannot drift out of it.
const winTarget = PackageData.pkg.targets.find(target => /-win-/.test(target));
if (!winTarget) {
    throw new Error('No Windows target found in package.json pkg.targets');
}

// The command this binary is installed as, which is what OriginalFilename and InternalName are
// supposed to name.
const binName = Object.keys(PackageData.bin)[0];

const options = {
    exe: `./${PackageData.pkg.outputPath}/${PackageData.name}-${winTarget.replace(/^node\d+-/, '')}.exe`,
    version: PackageData.version,
    properties: {
        CompanyName: COMPANY,
        LegalCopyright: `Copyright (c) ${COMPANY}`,
        FileDescription: 'EmailEngine allows access to email accounts using REST API',
        ProductName: PackageData.productTitle,
        // These describe the file as it actually ships. pkg leaves node.exe's own values here,
        // which the previous revision of this script deleted outright rather than correcting.
        OriginalFilename: `${binName}.exe`,
        InternalName: binName,
        // setProductVersion() below writes the four-part numeric form into this string as well.
        // Restating it here puts the exact package version back, which is the only place a
        // prerelease suffix can survive and the field the properties dialog shows.
        ProductVersion: PackageData.version
    },
    // Rebuilt by scripts/build-icon.js, which keeps it small enough for the check below
    icon: 'static/emailengine.ico'
};

const language = {
    lang: 1033,
    codepage: 1200
};

/**
 * Offset of the payload pkg appends after the last PE section.
 *
 * pkg addresses that payload by absolute file offset, so rewriting resources is only safe while
 * .rsrc still fits the raw allocation the linker gave it. Once it does not, the section grows,
 * every later section and the payload slide down the file, and the binary dies on startup with
 * "SyntaxError: Invalid or unexpected token" out of readPrelude. The icon is the only input here
 * big enough to cross that line - an .ico whose large members are uncompressed BMP rather than
 * PNG is several hundred KB on its own - and nothing downstream would catch it: the exe is still
 * well formed, its icons and version strings still read back correctly, and it still signs and
 * hashes like a good build.
 *
 * Reads the section table off the parsed executable, which reflects the edit as soon as
 * outputResource() has run, so the same call answers for both the before and the after image.
 */
function payloadOffset(executable) {
    return executable.getAllSections().reduce((offset, section) => Math.max(offset, section.info.pointerToRawData + section.info.sizeOfRawData), 0);
}

function resourceSection(executable) {
    return executable.getAllSections().find(section => section.info.name === '.rsrc');
}

/**
 * A Windows version resource is four 16-bit numbers, and semver does not map onto it - the
 * prerelease and build parts have nowhere to go. Take the leading integer of each of the first
 * four dot-separated components. The string overload of setFileVersion() is used rather than the
 * numeric one because a tuple shorter than four slides the language argument into the revision
 * slot, so a two-part version would be stamped as 2.79.0.1033.
 */
function toWindowsVersion(version) {
    const parts = String(version || '').split('.');

    // Indexing fixed slots rather than padding: a missing component and an unparseable one both
    // have to end up as 0, and parseInt(undefined) is NaN just like parseInt('x')
    return [0, 1, 2, 3]
        .map(index => parseInt(parts[index], 10))
        .map(value => (value >= 0 ? Math.min(value, 0xffff) : 0))
        .join('.');
}

load()
    .then(ResEdit => {
        // Both inputs checked up front, so a missing one is reported as itself rather than as
        // whatever readFileSync happens to throw further down
        if (!existsSync(options.exe)) {
            throw new Error(`Input file not found: ${options.exe}`);
        }

        if (!existsSync(options.icon)) {
            throw new Error(`Icon file not found: ${options.icon}`);
        }

        // Modify .exe w/ ResEdit
        const original = readFileSync(options.exe);
        const executable = ResEdit.NtExecutable.from(original);
        const res = ResEdit.NtExecutableResource.from(executable);
        const versionInfos = ResEdit.Resource.VersionInfo.fromEntries(res.entries);

        if (!versionInfos || versionInfos.length === 0) {
            throw new Error('No version info found in executable');
        }

        const vi = versionInfos[0];

        const fileVersion = toWindowsVersion(options.version);
        vi.setFileVersion(fileVersion, language.lang);
        vi.setProductVersion(fileVersion, language.lang);

        vi.setStringValues(language, options.properties);
        vi.outputToResourceEntries(res.entries);

        // Add icon
        const iconFile = ResEdit.Data.IconFile.from(readFileSync(options.icon));
        ResEdit.Resource.IconGroupEntry.replaceIconsForResource(
            res.entries,
            1,
            language.lang,
            iconFile.icons.map(item => item.data)
        );

        // Regenerate the .exe. The allocation is read before the edit because that is the budget
        // the linker set; once the section has grown, it has already grown to fit
        const offsetBefore = payloadOffset(executable);
        const allocated = resourceSection(executable).info.sizeOfRawData;
        res.outputResource(executable);
        const offsetAfter = payloadOffset(executable);
        const rsrc = resourceSection(executable);
        const updated = Buffer.from(executable.generate());

        // Refuse to write a binary whose payload moved - see payloadOffset() above. Checked
        // before the write so a build that would not start never reaches the disk at all
        if (offsetAfter !== offsetBefore || !original.subarray(offsetBefore).equals(updated.subarray(offsetAfter))) {
            throw new Error(
                `Rewriting the resources moved the appended pkg payload (${offsetBefore} -> ${offsetAfter}), which produces an executable that cannot start. ` +
                    `The resources need ${rsrc.info.virtualSize} bytes but only ${allocated} are allocated for .rsrc - ` +
                    `shrink ${options.icon} by at least ${rsrc.info.virtualSize - allocated} bytes, PNG-compressing its largest members.`
            );
        }

        // Written beside the target and renamed into place, as a half-written 140MB exe would
        // otherwise look like a finished build to every later step
        const tmpPath = `${options.exe}.tmp`;
        writeFileSync(tmpPath, updated);
        renameSync(tmpPath, options.exe);

        // Read back what was written. Signing, hashing and the release upload all treat this
        // file as final, so a resource edit that silently did not apply has no later chance of
        // being caught
        const writtenRes = ResEdit.NtExecutableResource.from(ResEdit.NtExecutable.from(readFileSync(options.exe)));
        const writtenInfo = ResEdit.Resource.VersionInfo.fromEntries(writtenRes.entries)[0];
        const written = writtenInfo ? writtenInfo.getStringValues(language) : {};

        const expected = Object.assign({ FileVersion: fileVersion }, options.properties);
        for (const [key, value] of Object.entries(expected)) {
            if (written[key] !== value) {
                throw new Error(`Property ${key} did not apply, expected ${JSON.stringify(value)} but found ${JSON.stringify(written[key])}`);
            }
        }

        const iconSizes = iconFile.icons.map(icon => `${icon.width || 256}x${icon.height || 256}`);

        console.log(`Successfully updated ${options.exe}`);
        console.log(`  Version: ${options.version} (resource ${fileVersion})`);
        console.log(`  Company: ${options.properties.CompanyName}`);
        console.log(`  Icon: ${options.icon} (${iconSizes.join(', ')})`);

        // The margin the payload check above depends on. Reported on every build so it is a
        // visible gauge rather than a cliff that a slightly larger icon walks off
        console.log(
            `  Resources: ${rsrc.info.virtualSize} of ${rsrc.info.sizeOfRawData} bytes allocated for .rsrc (${rsrc.info.sizeOfRawData - rsrc.info.virtualSize} spare)`
        );

        // Windows picks the closest image out of the group and scales it down. Without a small
        // one, the Explorer list view, the title bar and the taskbar all show a resampled 256px
        // image, which is visibly softer than a purpose-drawn 16x16
        if (!iconFile.icons.some(icon => (icon.width || 256) <= 48)) {
            console.log('  Note: the icon has no image at 48x48 or smaller, Windows will downscale the largest one');
        }
    })
    .catch(err => {
        console.error('Error modifying Windows executable:', err);
        process.exit(1);
    });
