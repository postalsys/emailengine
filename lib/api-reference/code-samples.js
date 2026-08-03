'use strict';

// Ready-to-run request samples for an operation. Generated per request because the
// base URL comes from the request the reference page was loaded with, so an instance
// behind a proxy shows the address the caller actually reaches it on.
//
// Samples are illustrative: path parameters are filled from their schema examples and
// only required query parameters are included, so the snippet is runnable after
// swapping in a real account id and access token.

// All three samples read the token from the same environment variable so the page can
// document it once and the snippets stay copy-paste runnable without editing them.
const TOKEN_ENV_VAR = 'EMAILENGINE_TOKEN';

const INDENT = '    ';

function buildUrl(baseUrl, operation) {
    let path = operation.path;

    for (const parameter of operation.pathParams) {
        path = path.replace(`{${parameter.name}}`, encodeURIComponent(parameter.sampleValue));
    }

    const query = operation.queryParams
        .filter(parameter => parameter.required)
        .map(parameter => `${encodeURIComponent(parameter.name)}=${encodeURIComponent(parameter.sampleValue)}`);

    return `${baseUrl}${path}${query.length ? `?${query.join('&')}` : ''}`;
}

// Single-quoted shell strings cannot contain a single quote, so each one closes the
// string, adds an escaped quote and reopens it.
function shellQuote(value) {
    return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function curlSample(url, operation, bodyJson) {
    const lines = [`curl -X ${operation.methodLabel} ${shellQuote(url)} \\`, `${INDENT}-H "Authorization: Bearer $${TOKEN_ENV_VAR}"`];

    if (bodyJson) {
        lines[lines.length - 1] += ' \\';
        lines.push(`${INDENT}-H "Content-Type: application/json" \\`);
        lines.push(`${INDENT}-d ${shellQuote(bodyJson)}`);
    }

    return lines.join('\n');
}

function nodeSample(url, operation, bodyJson) {
    const lines = [
        `const response = await fetch(${JSON.stringify(url)}, {`,
        `${INDENT}method: ${JSON.stringify(operation.methodLabel)},`,
        `${INDENT}headers: {`
    ];

    const headers = [`${INDENT}${INDENT}Authorization: \`Bearer \${accessToken}\``];
    if (bodyJson) {
        headers.push(`${INDENT}${INDENT}'Content-Type': 'application/json'`);
    }
    lines.push(headers.join(',\n'));
    lines.push(`${INDENT}}${bodyJson ? ',' : ''}`);

    if (bodyJson) {
        const body = bodyJson
            .split('\n')
            .map((line, index) => (index === 0 ? line : `${INDENT}${line}`))
            .join('\n');
        lines.push(`${INDENT}body: JSON.stringify(${body})`);
    }

    lines.push('});');
    lines.push('');
    lines.push('const data = await response.json();');

    return `const accessToken = process.env.${TOKEN_ENV_VAR};\n\n${lines.join('\n')}`;
}

// JSON literals do not survive a paste into Python (true/false/null), so the example
// value is re-emitted with Python literals instead of string-replacing the JSON.
function pythonLiteral(value, indent) {
    const pad = INDENT.repeat(indent);
    const padInner = INDENT.repeat(indent + 1);

    if (value === null) {
        return 'None';
    }

    if (Array.isArray(value)) {
        if (!value.length) {
            return '[]';
        }
        const items = value.map(item => `${padInner}${pythonLiteral(item, indent + 1)}`);
        return `[\n${items.join(',\n')}\n${pad}]`;
    }

    switch (typeof value) {
        case 'boolean':
            return value ? 'True' : 'False';
        case 'number':
            return String(value);
        case 'object': {
            const keys = Object.keys(value);
            if (!keys.length) {
                return '{}';
            }
            const entries = keys.map(key => `${padInner}${JSON.stringify(key)}: ${pythonLiteral(value[key], indent + 1)}`);
            return `{\n${entries.join(',\n')}\n${pad}}`;
        }
        default:
            return JSON.stringify(String(value));
    }
}

function pythonSample(url, operation, bodyValue) {
    const lines = ['import os', 'import requests', '', `access_token = os.environ["${TOKEN_ENV_VAR}"]`, ''];

    const args = [`${INDENT}${JSON.stringify(url)},`, `${INDENT}headers={"Authorization": f"Bearer {access_token}"},`];

    if (typeof bodyValue !== 'undefined') {
        args.push(`${INDENT}json=${pythonLiteral(bodyValue, 1)},`);
    }

    lines.push(`response = requests.${operation.method}(`);
    lines.push(args.join('\n'));
    lines.push(')');
    lines.push('');
    lines.push('print(response.json())');

    return lines.join('\n');
}

// A hljs class has to be a bare token, and `lang` is free text from the document. Kept to
// the characters real language names use (c++, c#, objective-c, shell-session) so nothing
// else can end up in the class attribute.
function highlightLanguage(lang) {
    return String(lang)
        .toLowerCase()
        .replace(/[^a-z0-9+#._-]/g, '');
}

// Hand-written samples from an operation's `x-codeSamples` extension - the de-facto
// standard for this, read by Redoc and Scalar too. A route declares them in its
// `plugins.openapi` block, and lib/openapi/ publishes any `x-*` key verbatim, so they reach
// every consumer of /swagger.json rather than only this page.
//
// Only the current spelling is accepted. Redoc's older `x-code-samples` exists in documents
// written by hand or by other tools; ours is generated in-house from the route table, so it
// can only ever contain what our own routes declare.
//
// Entries that are not `{ lang, source }` are dropped rather than rendered as blanks: the
// extension is free-form, and a malformed one should cost its own tab, not the page.
//
// Normalized once when the model is built, since nothing here depends on the request.
function readCodeSamples(specOperation) {
    const declared = specOperation['x-codeSamples'];

    if (!Array.isArray(declared)) {
        return [];
    }

    return declared
        .filter(sample => sample && typeof sample.lang === 'string' && typeof sample.source === 'string')
        .map((sample, index) => ({
            id: `custom-${index}`,
            label: typeof sample.label === 'string' && sample.label ? sample.label : sample.lang,
            language: highlightLanguage(sample.lang),
            code: sample.source
        }));
}

// Returns the tab set rendered under an operation. `bodyValue` is the synthesized
// request example (undefined for operations with no request body).
//
// Hand-written samples come first: someone wrote one for this operation because the
// synthesized snippets did not tell the story, which only works if it is the tab that
// opens.
function buildCodeSamples(operation, baseUrl, bodyValue, bodyJson) {
    const url = buildUrl(baseUrl, operation);

    return [
        ...(operation.codeSamples || []),
        { id: 'curl', label: 'curl', language: 'bash', code: curlSample(url, operation, bodyJson) },
        { id: 'node', label: 'Node.js', language: 'javascript', code: nodeSample(url, operation, bodyJson) },
        { id: 'python', label: 'Python', language: 'python', code: pythonSample(url, operation, bodyValue) }
        // Tab ids are composed here for the same reason as the response tabs: ui/tabs
        // neutralizes its hash params inside the partial block, so the operation id is
        // not reachable from the template
    ].map((sample, index) => Object.assign({}, sample, { tabId: `${operation.id}-sample-${sample.id}`, active: index === 0 }));
}

module.exports = {
    buildCodeSamples,
    readCodeSamples
};
