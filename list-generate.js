'use strict';

const he = require('he');
const packageData = require('./package.json');

let chunks = [];
process.stdin.on('readable', () => {
    let chunk;
    while ((chunk = process.stdin.read()) !== null) {
        chunks.push(chunk);
    }
});

process.stdin.on('end', () => {
    let list = JSON.parse(Buffer.concat(chunks));

    console.log(
        '<!doctype html><html><head><meta charset="utf-8"><title>EmailEngine Licenses</title><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.1/dist/css/bootstrap.min.css" integrity="sha384-zCbKRCUGaJDkqS1kPbPd7TveP5iyJE0EjAuZQTgFLD2ylzuqKfdKlfG/eSrtxUkn" crossorigin="anonymous"></head><body>'
    );
    console.log('<div class="container-fluid">');
    console.log(`<h1>EmailEngine v${packageData.version}</h1><p>EmailEngine includes code from the following software packages:</p>`);

    console.log('<table class="table table-sm">');
    console.log(
        '<tr><thead class="thead-dark"><th>Package</th><th>Version</th><th>License</th><th>Publisher</th><th>Publisher\'s Email</th><th>Package URL</th></tr>'
    );

    console.log('<tbody>');

    for (let key of Object.keys(list)) {
        let splitter = key.lastIndexOf('@');
        let packageName = key.substr(0, splitter);
        if (packageName === 'emailengine-app') {
            continue;
        }

        let packageVersion = key.substr(splitter + 1);
        let data = list[key];
        console.log('<tr>');

        console.log(`<td><a href="https://npmjs.com/package/${he.encode(packageName)}">${he.encode(packageName)}</a></td>`);

        [packageVersion, [].concat(data.licenses || []).join(', '), data.publisher, data.email]
            .map(entry => entry || '')
            .forEach(entry => {
                console.log('<td>' + he.encode(entry) + '</td>');
            });
        console.log('<td>');

        if (data.repository || data.url) {
            console.log(
                `<a href="${he.encode(data.repository || data.url)}">${he.encode(
                    (data.repository || data.url || '').toString().replace(/^https?:\/\//i, '')
                )}</a>`
            );
        }

        console.log('</td');
        console.log('</tr>');
    }

    console.log('</tbody></table></div></body></html>');
});
