'use strict';

const { load } = require('resedit/cjs');
const PackageData = require('./package.json');

const { readFileSync, writeFileSync, existsSync } = require('fs');

const options = {
    in: './ee-dist/emailengine-app-win-x64.exe',
    out: './ee-dist/emailengine-app-win-x64.exe',
    version: PackageData.version,
    properties: {
        LegalCopyright: 'Postal Systems OÜ',
        FileDescription: 'EmailEngine allows access to email accounts using REST API',
        ProductName: 'EmailEngine'
    },
    icon: 'static/emailengine.ico'
};

const language = {
    lang: 1033,
    codepage: 1200
};

load()
    .then(ResEdit => {
        // Check if input file exists
        if (!existsSync(options.in)) {
            throw new Error(`Input file not found: ${options.in}`);
        }

        // Modify .exe w/ ResEdit
        const data = readFileSync(options.in);
        const executable = ResEdit.NtExecutable.from(data);
        const res = ResEdit.NtExecutableResource.from(executable);
        const versionInfos = ResEdit.Resource.VersionInfo.fromEntries(res.entries);

        if (!versionInfos || versionInfos.length === 0) {
            throw new Error('No version info found in executable');
        }

        const vi = versionInfos[0];

        // Remove original filename
        vi.removeStringValue(language, 'OriginalFilename');
        vi.removeStringValue(language, 'InternalName');

        // Product version
        if (options.version) {
            // Convert version to tuple of 3 numbers
            const version = options.version
                .split('.')
                .map(v => Number(v) || 0)
                .slice(0, 3);

            // Update versions
            vi.setProductVersion(...version, 0, language.lang);
            vi.setFileVersion(...version, 0, language.lang);
        }

        // Add additional user specified properties
        if (options.properties) {
            vi.setStringValues(language, options.properties);
        }

        vi.outputToResourceEntries(res.entries);

        // Add icon
        if (options.icon) {
            if (!existsSync(options.icon)) {
                throw new Error(`Icon file not found: ${options.icon}`);
            }
            const iconFile = ResEdit.Data.IconFile.from(readFileSync(options.icon));
            ResEdit.Resource.IconGroupEntry.replaceIconsForResource(
                res.entries,
                1,
                language.lang,
                iconFile.icons.map(item => item.data)
            );
        }

        // Regenerate and write to .exe
        res.outputResource(executable);
        writeFileSync(options.out, Buffer.from(executable.generate()));

        console.log(`Successfully updated ${options.out}`);
        console.log(`  Version: ${options.version}`);
        console.log(`  Icon: ${options.icon || 'not set'}`);
    })
    .catch(err => {
        console.error('Error modifying Windows executable:', err.message);
        process.exit(1);
    });
