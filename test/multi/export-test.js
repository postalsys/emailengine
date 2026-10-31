'use strict';

// An export file lives on the disk of the instance whose export worker wrote it. Any instance
// serves the download by fetching it from there, another instance starting up leaves an export it
// did not run alone, and a download whose writer is gone says so instead of failing obscurely.

const test = require('node:test');
const assert = require('node:assert').strict;
const zlib = require('node:zlib');
const fs = require('node:fs');
const path = require('node:path');
const { startScenario, waitUntil } = require('./helpers');

function exportBody() {
    return {
        startDate: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
        endDate: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
        folders: ['INBOX']
    };
}

test('exports across instances', async t => {
    const scenario = await startScenario({ instances: 2, accounts: 2 });
    t.after(() => scenario.stop());
    const [ee0, ee1] = scenario.fleet.instances;
    const account = scenario.accounts[0];

    await scenario.waitConnected();
    for (let i = 0; i < 3; i++) {
        scenario.farm.inject(account, { subject: `Export message ${i}` });
    }
    await waitUntil(
        async () => {
            const res = await ee0.request('GET', `/v1/account/${account}/messages?path=INBOX`);
            return res.status === 200 && res.body.messages.length === 3;
        },
        { timeout: 60000, label: 'three messages listed' }
    );

    let exportId;
    let writer;

    await t.test('the download is the same through either instance', async () => {
        const created = await ee0.request('POST', `/v1/account/${account}/export`, exportBody());
        assert.equal(created.status, 200, JSON.stringify(created.body));
        exportId = created.body.exportId;

        await waitUntil(
            async () => {
                const res = await ee1.request('GET', `/v1/account/${account}/export/${exportId}`);
                return res.status === 200 && res.body.status === 'completed';
            },
            { timeout: 60000, label: 'the export to complete' }
        );
        writer = await scenario.redis.hget(`exp:${account}:${exportId}`, 'instance');
        assert.ok(['ee-0', 'ee-1'].includes(writer), `written by ${writer}`);
        const filePath = await scenario.redis.hget(`exp:${account}:${exportId}`, 'filePath');
        assert.ok(filePath.includes(`${writer}-exports`), `the file is in the writer's directory: ${filePath}`);

        const downloads = [];
        for (const instance of [ee0, ee1]) {
            const res = await instance.request('GET', `/v1/account/${account}/export/${exportId}/download`, null, { raw: true });
            assert.equal(res.status, 200, `${instance.id}: ${res.body.toString().slice(0, 200)}`);
            downloads.push(res.body);
        }
        // The writer is alive, so the other instance fetched the file from it rather than its own disk
        assert.deepEqual(downloads[0], downloads[1]);
        const lines = zlib.gunzipSync(downloads[0]).toString().trim().split('\n');
        assert.equal(lines.length, 3);
        assert.ok(lines.every(line => JSON.parse(line).subject.startsWith('Export message')));
    });

    await t.test('an instance that starts does not fail an export another live instance is running', async () => {
        const reader = writer === 'ee-0' ? ee1 : ee0;
        const fakeId = 'exp_aaaaaaaaaaaaaaaaaaaaaaaa';
        await scenario.redis.hset(`exp:${account}:${fakeId}`, {
            exportId: fakeId,
            account,
            status: 'processing',
            phase: 'exporting',
            instance: writer,
            filePath: `/tmp/${fakeId}.ndjson.gz`,
            created: Date.now()
        });
        await scenario.redis.sadd('exp:active', `${account}:${fakeId}`);

        await reader.restart();
        assert.equal(await scenario.redis.hget(`exp:${account}:${fakeId}`, 'status'), 'processing');

        await scenario.redis.del(`exp:${account}:${fakeId}`);
        await scenario.redis.srem('exp:active', `${account}:${fakeId}`);
    });

    await t.test('when the writer is gone the download says so', async () => {
        const writerInstance = writer === 'ee-0' ? ee0 : ee1;
        const reader = writer === 'ee-0' ? ee1 : ee0;
        await writerInstance.kill();
        // A pod's disk goes with it; on one test machine the directory has to be removed by hand
        await fs.promises.rm(path.join(scenario.fleet.logDir, `${writer}-exports`), { recursive: true, force: true });
        // Its record expires after the heartbeat TTL
        await waitUntil(
            async () => {
                const res = await reader.request('GET', `/v1/account/${account}/export/${exportId}/download`, null, { raw: true });
                return res.status === 410;
            },
            { timeout: 30000, label: 'a 410 for the download' }
        );
    });
});
