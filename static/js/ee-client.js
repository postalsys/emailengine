// Stylesheet inside the message body's shadow root (see _renderMessageBody). Host rules do not
// reach in, so this carries everything the body needs: a reset on the host, the image cap, and
// the folded-thread control. Custom properties still inherit through the boundary, which is how
// the font and the dark mode colours arrive from .ee-client / .ee-dark-mode.
const MESSAGE_BODY_STYLES = `
    :host {
        all: initial;
        display: block;
        /* Nothing the message does paints outside this box, whatever its outermost wrapper says.
           EmailEngine clips the message inside a wrapper of its own; this is the viewer's copy of
           that rule, for a body rendered by a version whose wrapper the sender could still style.
           clip, not hidden: the host must not become a scroll container of its own. */
        overflow: clip;
        color: inherit;
        font-family: var(--ee-font, sans-serif);
        font-size: 14px;
        line-height: 1.6;
        overflow-wrap: break-word;
    }

    *,
    *::before,
    *::after {
        box-sizing: border-box;
    }

    img {
        max-width: 100%;
        height: auto;
    }

    /* A message laid out wider than the viewer (a 600px newsletter on a phone) scrolls
       sideways inside the clipped host instead of losing its right edge */
    .ee-message-body-content {
        overflow-x: auto;
    }

    /* Quoted thread history, folded away by EmailEngine - see _labelCollapsedThreads() */
    .ee-collapsed-thread {
        margin-top: 12px;
    }

    .ee-collapsed-thread-toggle {
        display: inline-block;
        padding: 4px 10px;
        border: 1px solid var(--ee-toggle-border, #ddd);
        border-radius: 4px;
        background: var(--ee-toggle-bg, white);
        color: var(--ee-toggle-color, inherit);
        cursor: pointer;
        /* The message brings its own fonts along; the control keeps the client's */
        font-family: var(--ee-font, sans-serif);
        font-size: 12px;
        line-height: 1;
        user-select: none;
        list-style: none;
    }

    .ee-collapsed-thread-toggle:hover {
        background: var(--ee-toggle-hover-bg, #f0f0f0);
        border-color: var(--ee-toggle-hover-border, #ddd);
    }

    /* Same, for Safari before it supported list-style on a summary */
    .ee-collapsed-thread-toggle::-webkit-details-marker {
        display: none;
    }

    .ee-collapsed-thread[open] > .ee-collapsed-thread-toggle {
        margin-bottom: 12px;
    }
`;

// Inline SVG icons (24x24 grid, stroked with currentColor so they follow the button's text
// colour in both themes). Static markup only, nothing here is built from message data.
const ICON_PATHS = {
    back: '<path d="m15 18-6-6 6-6"/>',
    next: '<path d="m9 18 6-6-6-6"/>',
    chevronDown: '<path d="m6 9 6 6 6-6"/>',
    mail: '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>',
    mailOpen:
        '<path d="M21.2 8.4c.5.38.8.97.8 1.6v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V10a2 2 0 0 1 .8-1.6l8-6a2 2 0 0 1 2.4 0l8 6Z"/><path d="m22 10-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 10"/>',
    trash: '<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>',
    move: '<path d="M2 9V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H20a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-1"/><path d="M2 13h10"/><path d="m9 16 3-3-3-3"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
    send: '<path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>',
    compose: '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
    reply: '<polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>',
    replyAll: '<polyline points="7 17 2 12 7 7"/><polyline points="12 17 7 12 12 7"/><path d="M22 18v-2a4 4 0 0 0-4-4H7"/>',
    forward: '<polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 0 1 4-4h12"/>',
    paperclip: '<path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/>',
    close: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>',
    moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>'
};

// Default cap on the files attached in the compose form, in bytes. They travel base64 encoded
// inside one JSON request, which grows them by a third, and most providers refuse a message
// much larger than this anyway. Hosts that know their limit pass maxAttachmentSize.
const DEFAULT_MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024;

// What a compose form address has to look like before it is sent. Deliberately loose: the
// server validates properly, this only catches a name typed without its address.
const ADDRESS_PATTERN = /^[^\s@<>",;]+@[^\s@<>",;]+$/;

// Splits an address field on commas and semicolons that are not inside a quoted name or an
// angle-bracketed address, so "Doe, John" <john@example.com> stays one entry.
function splitAddressField(value) {
    const parts = [];
    let current = '';
    let quoted = false;
    let bracketed = false;
    for (let i = 0; i < value.length; i++) {
        const chr = value[i];
        if (chr === '\\' && quoted && i + 1 < value.length) {
            current += chr + value[++i];
            continue;
        }
        if (chr === '"' && !bracketed) {
            quoted = !quoted;
        } else if (chr === '<' && !quoted) {
            bracketed = true;
        } else if (chr === '>' && !quoted) {
            bracketed = false;
        } else if ((chr === ',' || chr === ';') && !quoted && !bracketed) {
            parts.push(current);
            current = '';
            continue;
        }
        current += chr;
    }
    parts.push(current);
    return parts.map(part => part.trim()).filter(Boolean);
}

function parseAddressEntry(entry) {
    const match = entry.match(/^(.*)<([^>]*)>$/);
    if (!match) {
        return { address: entry };
    }
    let name = match[1].trim();
    if (name.length > 1 && name.startsWith('"') && name.endsWith('"')) {
        name = name.slice(1, -1).replace(/\\(.)/g, '$1');
    }
    const address = match[2].trim();
    return name ? { name, address } : { address };
}

// Adds "Re: " or "Fwd: " unless the subject already starts with that prefix, so a long
// thread does not read "Re: Re: Re:"
function prefixSubject(subject, prefix) {
    const value = (subject || '').trim();
    const pattern = prefix === 'Re' ? /^re\s*:/i : /^fwd?\s*:/i;
    return pattern.test(value) ? value : `${prefix}: ${value}`.trim();
}

// Address entries that carry an address, from a list, a single entry or a bare address string.
// The server can return name-only entries and a single object where a list is expected.
function addressEntries(value) {
    return (Array.isArray(value) ? value : value ? [value] : [])
        .map(entry => (typeof entry === 'string' ? { address: entry } : entry))
        .filter(entry => entry && typeof entry.address === 'string' && entry.address);
}

// Compose form titles, by mode
const COMPOSE_TITLES = {
    new: 'New Message',
    reply: 'Reply',
    'reply-all': 'Reply All',
    forward: 'Forward'
};

// Below this container width the UI shows one pane at a time and the compose button
// drops its label. Shared by the stylesheet's container query and the compose button
// sizing, which cannot use the query because the button is not inside .ee-client.
const NARROW_WIDTH = 700;

function icon(name, size = 16) {
    return `<svg class="ee-icon" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICON_PATHS[name]}</svg>`;
}

export class EmailEngineClient {
    constructor(options = {}) {
        this.apiUrl = options.apiUrl || 'http://127.0.0.1:3000';
        this.account = options.account;
        this.accessToken = options.accessToken;
        this.container = options.container || null;
        // Resolve containerId when no element was passed directly, so
        // `new EmailEngineClient({ containerId })` renders UI too (not only the
        // factory). In a non-DOM env this stays null - an API-only client.
        if (!this.container && options.containerId && typeof document !== 'undefined') {
            this.container = document.getElementById(options.containerId);
            // A containerId that matches nothing is almost always a typo; warn
            // rather than silently degrading to a UI-less, API-only client.
            if (!this.container) {
                console.warn(`EmailEngineClient: no element found for containerId "${options.containerId}"; UI rendering disabled`);
            }
        }
        this.confirmMethod = options.confirmMethod || ((message, _title = 'Confirm', _cancelText = 'Cancel', _okText = 'OK') => confirm(message));
        this.alertMethod = options.alertMethod || ((message, _title = 'Notice', _cancelText = null, _okText = 'OK') => alert(message));

        this.currentFolder = null;
        this.currentMessage = null;
        // A message to open on startup instead of the inbox listing (a deep link). Its folder
        // is listed next to it, so the reader lands where the message lives.
        this.initialMessage = typeof options.message === 'string' && options.message ? options.message : null;
        // Told whenever the open folder or message changes, so a host page can keep its address
        // bar in step (see _notifyNavigate)
        this.onNavigate = typeof options.onNavigate === 'function' ? options.onNavigate : null;
        const maxAttachmentSize = Number(options.maxAttachmentSize);
        this.maxAttachmentSize = maxAttachmentSize > 0 ? maxAttachmentSize : DEFAULT_MAX_ATTACHMENT_SIZE;
        this.folders = [];
        this.messages = [];
        this.nextPageCursor = null;
        this.prevPageCursor = null;

        // Set once destroy() runs; guards async completions (loadFolders,
        // loadMessages, loadMessage) from re-rendering or scrolling into a
        // torn-down - or recreated - container.
        this._destroyed = false;

        // Keep-alive timer for sess_ tokens
        this.keepAliveTimer = null;
        this.lastActivity = Date.now();

        // Dark mode state. An explicit darkMode option overrides the stored
        // preference - for hosts that manage the theme themselves (usually
        // together with showDarkModeToggle: false to hide the builtin button
        // and drive the mode through setDarkMode()).
        this.darkMode = false;
        if (typeof window !== 'undefined' && window.localStorage) {
            this.darkMode = localStorage.getItem('ee-client-dark-mode') === 'true';
        }
        if (typeof options.darkMode === 'boolean') {
            this.darkMode = options.darkMode;
        }
        this.showDarkModeToggle = options.showDarkModeToggle !== false;

        // The nonce a Content-Security-Policy page hands the widget so the <style> element
        // createStyles() appends passes a style-src-elem directive without 'unsafe-inline'
        this.styleNonce = typeof options.styleNonce === 'string' && options.styleNonce ? options.styleNonce : null;

        // Get page size from localStorage or options or default
        const savedPageSize = typeof window !== 'undefined' && window.localStorage ? localStorage.getItem('ee-client-page-size') : null;
        const requestedPageSize = savedPageSize ? parseInt(savedPageSize, 10) : parseInt(options.pageSize, 10);
        this.pageSize = requestedPageSize > 0 ? requestedPageSize : 20;

        if (this.container) {
            this.init();
        }

        // Start keep-alive timer for sess_ tokens
        this._startKeepAliveTimer();
    }

    // Resolves the platform fetch (native in browsers and modern Node, node-fetch as
    // an optional fallback on older Node) and normalizes transport failures, so both
    // HTTP entry points - apiRequest and _fetchBlob - fail in the same shape.
    async _fetch(url, options) {
        // Any request counts as activity for the keep-alive timer
        this._updateActivity();

        let fetchFn = globalThis.fetch;
        if (!fetchFn) {
            // Native fetch is missing (older Node.js). Fall back to node-fetch.
            // This is a dynamic import so browsers and modern Node never load it.
            try {
                const nodeFetch = await import('node-fetch');
                fetchFn = nodeFetch.default;
            } catch {
                // node-fetch is not installed; the guard below reports it
            }
        }

        if (!fetchFn) {
            // Either node-fetch is missing or it exposed no callable default export
            throw new Error('fetch is not available. In Node.js environments, please install node-fetch: npm install node-fetch');
        }

        try {
            return await fetchFn(url, options);
        } catch (err) {
            // Mark transport level failures - an unreachable server, DNS/TLS
            // problems, a blocked CORS preflight - so callers can tell them apart
            // from an API error that carries a server message.
            const error = new Error(`Could not reach the EmailEngine server at ${this.apiUrl}`);
            error.isNetworkError = true;
            error.cause = err;
            throw error;
        }
    }

    // Turns a non-ok response into an Error carrying the server's own explanation.
    // EmailEngine answers with Boom payloads - { statusCode, error, message, code,
    // fields } - which _errorMessage() knows how to read.
    async _responseError(response) {
        let details;
        try {
            details = await response.json();
        } catch {
            // Not a JSON body - the status line is all there is to go on
            details = { message: response.statusText };
        }

        const error = new Error(`API request failed: ${response.statusText}`);
        error.statusCode = response.status;
        error.details = details;
        return error;
    }

    async apiRequest(method, endpoint, data = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...this._authHeaders()
            }
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        const response = await this._fetch(`${this.apiUrl}${endpoint}`, options);
        if (!response.ok) {
            throw await this._responseError(response);
        }

        return await response.json();
    }

    // Base path for this account's endpoints. The id is a path segment, so characters such as
    // '#', '?', '/' or '%' in it must be encoded or they cut or redirect the request.
    _accountPath() {
        return `/v1/account/${encodeURIComponent(this.account)}`;
    }

    _messagePath(messageId, suffix = '') {
        return `${this._accountPath()}/message/${encodeURIComponent(messageId)}${suffix}`;
    }

    _attachmentPath(attachmentId) {
        return `${this._accountPath()}/attachment/${encodeURIComponent(attachmentId)}`;
    }

    async loadFolders() {
        // Reset the pane to its loading state so a retry after a failure does not
        // keep showing the previous error while the new request is in flight.
        this._setPaneHtml('.ee-folder-tree', '<div class="ee-loading">Loading folders...</div>');

        try {
            const data = await this.apiRequest('GET', `${this._accountPath()}/mailboxes`);
            this.folders = data.mailboxes || [];
            this._folderTreeCache = null;
            if (this.container) {
                this.renderFolderList();
            }
            return this.folders;
        } catch (error) {
            console.error('Failed to load folders:', error);
            this._renderPaneError('.ee-folder-tree', 'Folders unavailable', error, () => this._loadInitialView());
            throw error;
        }
    }

    // Loads and renders one page of a folder's message list. The open message stays open: it is
    // the folder click (openFolder()) that closes it, while paging and refreshes keep it.
    async loadMessages(path, cursor = null) {
        this._setPaneHtml('.ee-message-list', `${this._messageListHeader(path)}<div class="ee-loading">Loading messages...</div>`);

        try {
            const params = new URLSearchParams({ path, pageSize: this.pageSize });
            if (cursor) {
                params.set('cursor', cursor);
            }

            const data = await this.apiRequest('GET', `${this._accountPath()}/messages?${params}`);
            this.messages = data.messages || [];
            this.currentFolder = path;
            this.nextPageCursor = data.nextPageCursor || null;
            this.prevPageCursor = data.prevPageCursor || null;

            if (this.container) {
                this.renderMessageList();
                this.renderFolderList(); // Re-render to update active state
            }

            this._notifyNavigate();

            return {
                messages: this.messages,
                nextPageCursor: this.nextPageCursor,
                prevPageCursor: this.prevPageCursor
            };
        } catch (error) {
            console.error('Failed to load messages:', error);
            this._renderPaneError(
                '.ee-message-list',
                'Messages unavailable',
                error,
                () => this._fireAndForget(this.loadMessages(path, cursor)),
                this._messageListHeader(path)
            );
            throw error;
        }
    }

    // Switches to another folder: closes the open message and lists the folder
    openFolder(path) {
        this.currentMessage = null;
        this.renderMessage();
        this._setView('list');
        return this.loadMessages(path);
    }

    async loadMessage(messageId) {
        this._setView('message');
        this._setPaneHtml('.ee-message-viewer', `${this._messageToolbar()}<div class="ee-loading">Loading message...</div>`);

        try {
            const params = new URLSearchParams({
                webSafeHtml: true,
                markAsSeen: true
            });
            const data = await this.apiRequest('GET', this._messagePath(messageId, `?${params}`));
            this.currentMessage = data;

            this.currentMessage.unseen = false;
            this._notifyNavigate();

            const msg = this.messages.find(m => m.id === messageId);
            if (msg) {
                msg.unseen = false;
                if (this.container) {
                    this.renderMessageList();
                }
            }

            if (this.container && !this._destroyed) {
                this.renderMessage();

                // The message opens at the top of the client: bring that into view when the
                // page is scrolled past it (a long list on a phone), and leave the page alone
                // otherwise. scrollIntoView honours the host's scroll-margin-top, which is how
                // a page with a fixed header keeps the toolbar clear of it.
                if (this.container.getBoundingClientRect().top < 0) {
                    this.container.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            }

            return this.currentMessage;
        } catch (error) {
            console.error('Failed to load message:', error);
            // A message that does not exist (deleted, moved, or a link with a mangled ID) is
            // not worth retrying, and the API's validation text means nothing to a reader
            if (error && (error.statusCode === 404 || error.statusCode === 400)) {
                this._renderPaneError(
                    '.ee-message-viewer',
                    'Message not found',
                    'It may have been moved or deleted, or the link to it is incomplete.',
                    null,
                    this._messageToolbar()
                );
            } else {
                this._renderPaneError(
                    '.ee-message-viewer',
                    'Message unavailable',
                    error,
                    () => this._fireAndForget(this.loadMessage(messageId)),
                    this._messageToolbar()
                );
            }
            throw error;
        }
    }

    async markAsRead(messageId, seen = true) {
        try {
            const flagUpdate = seen ? { flags: { add: ['\\Seen'] } } : { flags: { delete: ['\\Seen'] } };

            await this.apiRequest('PUT', this._messagePath(messageId), flagUpdate);

            const msg = this.messages.find(m => m.id === messageId);
            if (msg) {
                msg.unseen = !seen;
                if (this.container) {
                    this.renderMessageList();
                }
            }

            if (this.currentMessage && this.currentMessage.id === messageId) {
                this.currentMessage.unseen = !seen;
                if (this.container) {
                    this.renderMessage();
                }
            }

            return true;
        } catch (error) {
            console.error('Failed to update message flags:', error);
            throw error;
        }
    }

    // Takes a message that left the folder (deleted or moved) off the list, and out of the
    // viewer when it was the open one
    _dropMessage(messageId) {
        this.messages = this.messages.filter(m => m.id !== messageId);
        if (this.container) {
            this.renderMessageList();
        }

        if (this.currentMessage && this.currentMessage.id === messageId) {
            this.currentMessage = null;
            if (this.container) {
                this.renderMessage();
            }
            this._notifyNavigate();
        }
    }

    async deleteMessage(messageId) {
        try {
            const response = await this.apiRequest('DELETE', this._messagePath(messageId));

            this._dropMessage(messageId);

            // { deleted, moved: { destination, message } } - moved is set when the message went
            // to Trash instead of being removed
            return response || { deleted: true };
        } catch (error) {
            console.error('Failed to delete message:', error);
            throw error;
        }
    }

    async moveMessage(messageId, targetPath) {
        try {
            await this.apiRequest('PUT', this._messagePath(messageId, '/move'), {
                path: targetPath
            });

            this._dropMessage(messageId);

            return true;
        } catch (error) {
            console.error('Failed to move message:', error);
            throw error;
        }
    }

    // Account details (name, email address) fetched once and cached for the lifetime
    // of the instance; used as the From identity of saved drafts.
    async _getAccountInfo() {
        if (!this._accountInfo) {
            this._accountInfo = await this.apiRequest('GET', this._accountPath());
        }
        return this._accountInfo;
    }

    // The address and content fields shared by a submission and a draft upload. Empty recipient
    // lists are left out rather than sent as [].
    _messagePayload(to, subject, text, { cc, bcc, attachments, reference } = {}) {
        const data = { subject, text };
        for (const [key, value] of [
            ['to', to],
            ['cc', cc],
            ['bcc', bcc]
        ]) {
            const list = addressEntries(value);
            if (list.length) {
                data[key] = list;
            }
        }
        if (Array.isArray(attachments) && attachments.length) {
            data.attachments = attachments.map(({ filename, contentType, content }) => ({ filename, contentType, content }));
        }
        if (reference) {
            data.reference = reference;
        }
        return data;
    }

    // options: { cc, bcc, attachments: [{ filename, contentType, content (base64) }], reference }.
    // reference is EmailEngine's submit reference block ({ message, action, inline,
    // forwardAttachments }); with it the server adds the threading headers and the quote.
    async sendMessage(to, subject, text, options = {}) {
        try {
            const messageData = this._messagePayload(to, subject, text, options);

            const response = await this.apiRequest('POST', `${this._accountPath()}/submit`, messageData);
            return response;
        } catch (error) {
            console.error('Failed to send message:', error);
            throw error;
        }
    }

    async saveDraft(to, subject, text, options = {}) {
        try {
            if (!this.folders.length) {
                await this.loadFolders();
            }
            const draftsFolder = this.folders.find(f => f.specialUse === '\\Drafts');
            if (!draftsFolder) {
                throw new Error('No Drafts folder found for this account');
            }

            const messageData = {
                path: draftsFolder.path,
                flags: ['\\Draft'],
                ...this._messagePayload(to, subject, text, options)
            };

            // The upload endpoint does not add a From header on its own, but the draft
            // needs one to be deliverable later - use the account's own identity.
            try {
                const accountInfo = await this._getAccountInfo();
                if (accountInfo && accountInfo.email) {
                    messageData.from = { name: accountInfo.name || '', address: accountInfo.email };
                }
            } catch {
                // Non-fatal: the draft is saved without a From header
            }

            const response = await this.apiRequest('POST', `${this._accountPath()}/message`, messageData);
            return response;
        } catch (error) {
            console.error('Failed to save draft:', error);
            throw error;
        }
    }

    // Parses a typed address field ("Name <a@example.com>, b@example.com") into address entries
    parseAddressList(value) {
        return splitAddressField(String(value || '')).map(parseAddressEntry);
    }

    // The reverse of parseAddressList, for filling a compose field
    formatAddressList(list) {
        return addressEntries(list)
            .map(entry => {
                if (!entry.name) {
                    return entry.address;
                }
                const name = /[",;<>@\\]/.test(entry.name) ? `"${entry.name.replace(/(["\\])/g, '\\$1')}"` : entry.name;
                return `${name} <${entry.address}>`;
            })
            .join(', ');
    }

    // Recipients, subject and submit reference for a reply, reply-all or forward of msg, as the
    // compose form shows them. ownAddress (the account's) is left out of the recipients.
    //
    // Reply-all is resolved here rather than by the server: EmailEngine's reply-all merges the
    // original recipients into whatever is sent, so one the user removed from the form would be
    // put back. It goes out as a reply with every recipient spelled out instead, which the server
    // leaves alone, and what the form shows is what is sent.
    prepareResponse(msg, action, ownAddress = null) {
        if (action === 'forward') {
            return { to: [], cc: [], subject: prefixSubject(msg.subject, 'Fwd'), reference: { message: msg.id, action: 'forward', inline: true } };
        }

        const own = typeof ownAddress === 'string' ? ownAddress.toLowerCase() : '';
        const seen = new Set(own ? [own] : []);
        const take = list =>
            addressEntries(list)
                .filter(entry => {
                    const key = entry.address.toLowerCase();
                    if (seen.has(key)) {
                        return false;
                    }
                    seen.add(key);
                    return true;
                })
                .map(entry => (entry.name ? { name: entry.name, address: entry.address } : { address: entry.address }));

        // Answer the address the message nominates, otherwise its sender - or, for a message the
        // account sent itself (Sent folder), the people it went to. The account's own address is
        // never an answer, so a Reply-To naming the account falls through to the next candidate.
        const fromSelf = !!own && addressEntries(msg.from).some(entry => entry.address.toLowerCase() === own);
        let to = [];
        for (const candidate of [msg.replyTo, fromSelf ? msg.to : msg.from]) {
            to = take(candidate);
            if (to.length) {
                break;
            }
        }
        if (!to.length) {
            // A message from the account to itself: answer it anyway
            to = addressEntries(msg.from).map(entry => ({ ...entry }));
        }
        const cc = action === 'reply-all' ? take(addressEntries(msg.to).concat(addressEntries(msg.cc))) : [];

        return { to, cc, subject: prefixSubject(msg.subject, 'Re'), reference: { message: msg.id, action: 'reply', inline: true } };
    }

    // Tells the host which folder and message are open. A host error must not break the client.
    _notifyNavigate() {
        if (!this.onNavigate || this._destroyed) {
            return;
        }
        try {
            this.onNavigate({ path: this.currentFolder, messageId: this.currentMessage ? this.currentMessage.id : null });
        } catch (error) {
            console.error('onNavigate handler failed:', error);
        }
    }

    async submitDraft(messageId, options = null) {
        try {
            const response = await this.apiRequest('POST', this._messagePath(messageId, '/submit'), options);
            return response;
        } catch (error) {
            console.error('Failed to submit draft:', error);
            throw error;
        }
    }

    // A message counts as a draft when the server marks it as one (the \Draft flag on IMAP,
    // the DRAFT label on Gmail, a draft message on MS Graph) or when it sits in the Drafts
    // special-use folder.
    _isDraftMessage(msg) {
        if (!msg) {
            return false;
        }
        if (msg.draft || msg.messageSpecialUse === '\\Drafts') {
            return true;
        }
        const folder = this.folders.find(f => f.path === this.currentFolder);
        return !!(folder && folder.specialUse === '\\Drafts');
    }

    // Best-effort human readable reason for a failed request. EmailEngine returns
    // Boom style payloads - { statusCode, error, message, code, fields } - so the
    // `message` field usually carries the actual cause, e.g. "Requested account is
    // not yet initialized" when the account has not connected yet.
    _errorMessage(error, fallback = 'Unexpected error') {
        if (!error) {
            return fallback;
        }

        const details = error.details;
        const detailsMessage = details && typeof details.message === 'string' ? details.message : '';

        // Validation failures list the offending fields
        if (details && Array.isArray(details.fields)) {
            const fieldErrors = details.fields
                // Keep only entries that carry a usable message string.
                .filter(field => field && typeof field.message === 'string')
                // Map technical field names to user-friendly ones. Each replace
                // is a no-op when its pattern is absent, so no includes-guards
                // are needed - and to[N] for any index is handled, not just to[0].
                .map(field =>
                    field.message
                        .replace(/(?:to|cc|bcc)\[\d+\]\.address|"address"/g, 'email address')
                        .replace(/"subject"/g, 'subject')
                        .replace(/"text"/g, 'message')
                );

            const mainMessage = detailsMessage || fallback;
            if (fieldErrors.length > 0) {
                return `${mainMessage}:\n\n• ${fieldErrors.join('\n• ')}`;
            }
            return mainMessage;
        }

        if (detailsMessage) {
            return detailsMessage;
        }

        if (error.statusCode) {
            return `The server responded with status ${error.statusCode}`;
        }

        return error.message || fallback;
    }

    _formatSendError(error) {
        return this._errorMessage(error, 'Failed to send email. Please check your input and try again.');
    }

    // Writes markup into one of the client's panes when the UI exists and is still
    // alive, and hands the pane back so callers can wire up what they rendered.
    _setPaneHtml(selector, html) {
        if (typeof document === 'undefined' || !this.container || this._destroyed) {
            return null;
        }

        const pane = this.container.querySelector(selector);
        if (pane) {
            pane.innerHTML = html;
        }
        return pane;
    }

    // Replaces a pane's contents with an error panel explaining why its data is
    // missing, optionally with a Retry button. Without this a failed request
    // leaves the pane stuck on its "Loading..." placeholder forever, with the
    // only trace of the failure in the developer console.
    // error is the failed request's error, or a plain explanation to show instead
    _renderPaneError(selector, title, error, retry = null, header = '') {
        const detail = typeof error === 'string' ? error : this._errorMessage(error, '');
        const pane = this._setPaneHtml(
            selector,
            `
            ${header}
            <div class="ee-error">
                <div class="ee-error-title">${this.escapeHtml(title)}</div>
                ${detail ? `<div class="ee-error-detail">${this.escapeHtml(detail)}</div>` : ''}
                ${retry ? '<button type="button" class="ee-button ee-error-retry">Retry</button>' : ''}
            </div>
        `
        );

        if (pane && retry) {
            const retryButton = pane.querySelector('.ee-error-retry');
            if (retryButton) {
                retryButton.addEventListener('click', () => {
                    if (this._destroyed) {
                        return;
                    }
                    // Disable while the request is in flight so an impatient second
                    // click can not fan out a duplicate round trip. A failed retry
                    // re-renders the panel with a fresh button.
                    retryButton.disabled = true;
                    retry();
                });
            }
        }
    }

    // Loads started from a DOM handler render their own error panel, so the user
    // has already been told. Swallow the rejection rather than letting it surface
    // as an unhandled rejection in hosts with a global error reporter.
    _fireAndForget(promise) {
        promise.catch(() => {});
    }

    // A short notice at the bottom of the client that goes away on its own, for outcomes that
    // need no answer (a message queued, a draft saved). Errors keep using alertMethod.
    notify(message) {
        const toast = this.container && this.container.querySelector('.ee-toast');
        if (!toast || this._destroyed) {
            return;
        }
        toast.textContent = message;
        toast.classList.add('show');
        clearTimeout(this._toastTimer);
        this._toastTimer = setTimeout(() => toast.classList.remove('show'), 4000);
    }

    // Message actions (flag, delete, move) have no pane of their own to report into:
    // when one fails the message simply stays put, which is indistinguishable from
    // nothing having happened. Say so instead.
    _alertActionFailed(error, fallback) {
        console.error(`${fallback}:`, error);
        return this.alertMethod(this._errorMessage(error, fallback), 'Error', null, 'OK');
    }

    // The message list before any folder is opened. Shared with createLayout so the
    // pane header markup lives in one place.
    _messageListPlaceholder() {
        return `${this._messageListHeader(null)}<div class="ee-empty-state">Select a folder</div>`;
    }

    // Header for every state of the message list pane, titled with the folder
    // being shown. In the single-pane layout its back button leads to the folders.
    _messageListHeader(path, controls = '') {
        const folder = path && this.folders.find(f => f.path === path);
        return `
            <div class="ee-pane-header">
                <div class="ee-pane-heading">
                    ${this._iconButton('show-folders', 'back', 'Folders', 'ee-nav-button')}
                    <span class="ee-pane-title">${this.escapeHtml(folder ? folder.name : 'Messages')}</span>
                </div>
                ${controls}
            </div>
        `;
    }

    // The viewer's toolbar row. It stays up in the loading, empty and error states
    // too, so the header band runs unbroken across the panes and the single-pane
    // layout always has its way back to the list.
    _messageToolbar(actions = '') {
        return `
            <div class="ee-message-actions">
                ${this._iconButton('back-to-list', 'back', 'Back to messages', 'ee-nav-button')}
                ${actions}
            </div>
        `;
    }

    _messageViewerPlaceholder() {
        return `${this._messageToolbar()}<div class="ee-empty-state">Select a message to view</div>`;
    }

    // Which pane the single-pane (narrow) layout shows: folders, list or message.
    // Wider layouts show all three and ignore it.
    _getView() {
        const client = this.container && this.container.querySelector('.ee-client');
        return client ? client.dataset.view : null;
    }

    _setView(view) {
        const client = this.container && this.container.querySelector('.ee-client');
        if (client) {
            client.dataset.view = view;
        }
    }

    formatDate(dateStr) {
        const date = new Date(dateStr);
        const now = new Date();
        const diff = now - date;

        if (diff < 86400000) {
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } else if (diff < 604800000) {
            return date.toLocaleDateString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });
        } else {
            return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
        }
    }

    // The date in the message header: weekday, date and time to the minute
    formatFullDate(dateStr) {
        const date = new Date(dateStr);
        if (isNaN(date.getTime())) {
            return '';
        }
        return date.toLocaleString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    }

    // Header addresses as escaped HTML: "Name <address>" with the address muted, the bare address
    // when there is no name, and the name alone for a name-only entry
    _addressListHtml(list) {
        return (Array.isArray(list) ? list : list ? [list] : [])
            .map(entry => (typeof entry === 'string' ? { address: entry } : entry))
            .filter(entry => entry && (entry.name || entry.address))
            .map(entry => {
                if (entry.name && entry.address) {
                    return `${this.escapeHtml(entry.name)} <span class="ee-address">&lt;${this.escapeHtml(entry.address)}&gt;</span>`;
                }
                return this.escapeHtml(entry.name || entry.address);
            })
            .join(', ');
    }

    formatFileSize(bytes) {
        if (!bytes) {
            return '';
        }
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round((bytes / Math.pow(1024, i)) * 100) / 100 + ' ' + sizes[i];
    }

    /**
     * Markup for the "Code requested" box of a message that carries a one-time passcode
     * (EmailEngine's `otp` field, from the OTP-Token header). The site the code is for is named
     * only when EmailEngine reports the origin as authenticated: the header itself is not, and
     * anyone can send a message claiming a code for any site.
     *
     * @param {{code: string, origin: string, authenticated?: boolean}} [otp]
     * @returns {string} HTML, or an empty string when there is no passcode
     */
    renderOtpBox(otp) {
        if (!otp || typeof otp.code !== 'string' || !otp.code) {
            return '';
        }

        // one tile per character for a code a person reads off and types, as Gmail does
        const code = /^[A-Za-z0-9]{1,10}$/.test(otp.code)
            ? Array.from(otp.code, ch => `<span class="ee-otp-char">${this.escapeHtml(ch)}</span>`).join('')
            : `<span class="ee-otp-text">${this.escapeHtml(otp.code)}</span>`;

        let site = '';
        if (otp.authenticated) {
            try {
                site = new URL(otp.origin).host;
            } catch {
                // leave the site out rather than show a value that does not parse
            }
        }

        return `
            <div class="ee-otp" role="region" aria-label="Code requested">
                <div class="ee-otp-title">Code requested${site ? ` for <span class="ee-otp-site">${this.escapeHtml(site)}</span>` : ''}</div>
                <div class="ee-otp-code" aria-label="${this.escapeHtml(otp.code)}">${code}</div>
                <div class="ee-otp-actions">
                    <button type="button" class="ee-button ee-otp-copy" data-action="copy-otp">Copy code</button>
                    <span class="ee-otp-status" aria-live="polite"></span>
                </div>
                ${site ? '' : '<div class="ee-otp-note">The sender of this code could not be verified</div>'}
            </div>
        `;
    }

    /**
     * Copies text to the clipboard. The Clipboard API needs a secure context, so a page served
     * over plain http falls back to a selected textarea and execCommand
     *
     * @param {string} text
     * @returns {Promise<boolean>} Whether the text was copied
     */
    async copyText(text) {
        if (typeof navigator !== 'undefined' && navigator.clipboard && typeof window !== 'undefined' && window.isSecureContext) {
            try {
                await navigator.clipboard.writeText(text);
                return true;
            } catch {
                // fall through to the legacy path
            }
        }

        if (typeof document === 'undefined') {
            return false;
        }

        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.top = '-1000px';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            return document.execCommand('copy');
        } catch {
            return false;
        } finally {
            textarea.remove();
        }
    }

    escapeHtml(value) {
        if (value === null || value === undefined) {
            return '';
        }
        const htmlEscapes = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
        return String(value).replace(/[&<>"']/g, ch => htmlEscapes[ch]);
    }

    _authHeaders() {
        const headers = {};
        if (this.accessToken) {
            headers.Authorization = `Bearer ${this.accessToken}`;
        }
        return headers;
    }

    _saveBlob(blob, filename) {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    // Authenticated GET for binary payloads (attachments, message source).
    // apiRequest is not reused here - it always parses the body as JSON - but the
    // same _fetch/_responseError pair is, so a failed download reports the same
    // reason as any other request.
    async _fetchBlob(endpoint) {
        const response = await this._fetch(`${this.apiUrl}${endpoint}`, {
            headers: this._authHeaders(),
            credentials: 'include'
        });

        if (!response.ok) {
            throw await this._responseError(response);
        }

        return response;
    }

    async downloadAttachment(attachmentId, suggestedFilename = null) {
        try {
            const response = await this._fetchBlob(this._attachmentPath(attachmentId));

            // Get filename from Content-Disposition header if available
            const contentDisposition = response.headers.get('content-disposition');
            let filename = suggestedFilename || 'attachment';
            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
                if (filenameMatch && filenameMatch[1]) {
                    filename = filenameMatch[1].replace(/['"]/g, '');
                }
            }

            // Get the attachment data and trigger the download
            const blob = await response.blob();
            this._saveBlob(blob, filename);
        } catch (error) {
            console.error('Failed to download attachment:', error);
            this.alertMethod(this._errorMessage(error, 'Failed to download attachment. Please try again.'), 'Download Error', null, 'OK');
        }
    }

    async downloadOriginalMessage(messageId, subject = null) {
        try {
            const response = await this._fetchBlob(this._messagePath(messageId, '/source'));

            // Get the email data
            const blob = await response.blob();

            // Create filename based on subject and date
            const now = new Date();
            const dateStr = now.toISOString().split('T')[0];
            const safeSubject = subject ? subject.replace(/[^a-z0-9]/gi, '_').substring(0, 50) : 'email';
            const filename = `${dateStr}_${safeSubject}.eml`;

            this._saveBlob(blob, filename);
        } catch (error) {
            console.error('Failed to download original message:', error);
            this.alertMethod(this._errorMessage(error, 'Failed to download original message. Please try again.'), 'Download Error', null, 'OK');
        }
    }

    // A <style> element carrying styleNonce, for the widget stylesheet and the message body's
    // shadow root alike: a stylesheet inside a shadow root is checked against style-src-elem too.
    _createStyle(css) {
        const style = document.createElement('style');
        if (this.styleNonce) {
            // the IDL property, which is what the policy check reads on an element a script inserts
            style.nonce = this.styleNonce;
        }
        style.textContent = css;
        return style;
    }

    createStyles() {
        if (typeof document === 'undefined') {
            return;
        }

        const style = this._createStyle(`
            /* The accent comes from the host's --ee-accent, --ee-accent-hover and --ee-accent-light
               (set on the container). They are resolved into private names once per root
               element: setting --ee-accent itself here would hide the host's value. */
            .ee-client,
            .ee-compose-button,
            .ee-compose-modal,
            .ee-toast {
                --_accent: var(--ee-accent, #007bff);
                --_accent-hover: var(--ee-accent-hover, #0056b3);
                --_accent-light: var(--ee-accent-light, #66b2ff);
            }

            .ee-client {
                --ee-font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                display: flex;
                height: 100%;
                min-height: 400px;
                font-family: var(--ee-font);
                font-size: 14px;
                line-height: 1.5;
                color: #333;
                background: #fff;
                border: 1px solid #ddd;
                position: relative;
                /* Layout breakpoints follow the widget's own width, not the viewport:
                   hosts embed it in pages of any shape */
                container: ee-client / inline-size;
            }
            
            .ee-client * {
                box-sizing: border-box;
            }
            
            .ee-sidebar {
                width: clamp(160px, 18%, 220px);
                flex-shrink: 0;
                background: #ffffff;
                border-right: 1px solid #ddd;
                display: flex;
                flex-direction: column;
            }
            
            .ee-folder-list {
                list-style: none;
                margin: 0;
                padding: 0;
            }
            
            .ee-folder-item {
                cursor: pointer;
                border-bottom: 1px solid #e0e0e0;
                position: relative;
            }
            
            .ee-folder-item:hover {
                background: #e8e8e8;
            }
            
            .ee-folder-item.active {
                background: var(--_accent);
                color: white;
            }
            
            .ee-folder-item.active::before {
                content: '';
                position: absolute;
                left: 0;
                top: 0;
                bottom: 0;
                width: 3px;
                background: var(--_accent-hover);
            }
            
            .ee-folder-content {
                padding: 8px 16px 8px 0px;
                display: flex;
                align-items: center;
                position: relative;
            }
            
            .ee-folder-indent {
                color: #999;
                font-size: 12px;
                margin-right: 4px;
                font-family: monospace;
            }
            
            .ee-folder-name {
                font-weight: 500;
                flex: 1;
            }
            
            .ee-folder-name.has-children {
                font-weight: 600;
            }
            
            .ee-folder-item.active .ee-folder-indent {
                color: rgba(255, 255, 255, 0.7);
            }
            
            .ee-folder-count {
                font-size: 12px;
                opacity: 0.7;
                margin-left: 8px;
                flex-shrink: 0;
            }
            
            .ee-main {
                flex: 1;
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }
            
            .ee-message-list {
                width: clamp(260px, 32%, 380px);
                flex-shrink: 0;
                border-right: 1px solid #ddd;
                background: #ffffff;
                display: flex;
                flex-direction: column;
            }
            
            .ee-message-item {
                padding: 12px 16px;
                border-bottom: 1px solid #e0e0e0;
                cursor: pointer;
            }
            
            .ee-message-item:hover {
                background: #f8f8f8;
            }
            
            .ee-message-item.active {
                background: color-mix(in srgb, var(--_accent) 12%, white);
            }
            
            .ee-message-item.unread {
                font-weight: 600;
            }
            
            .ee-message-header {
                display: flex;
                justify-content: space-between;
                margin-bottom: 4px;
            }
            
            .ee-message-from {
                flex: 1;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            .ee-message-date {
                font-size: 12px;
                color: #666;
                flex-shrink: 0;
                margin-left: 8px;
            }
            
            .ee-message-subject {
                display: flex;
                align-items: center;
                margin-bottom: 2px;
            }
            
            .ee-message-subject-text {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                flex: 1;
                min-width: 0;
            }
            
            .ee-message-preview {
                font-size: 12px;
                color: #666;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                font-weight: normal;
            }
            
            .ee-attachment-indicator {
                display: inline-flex;
                align-items: center;
                white-space: nowrap;
                flex-shrink: 0;
                font-size: 11px;
                color: #666;
                margin-left: 8px;
            }
            
            .ee-attachment-indicator .ee-icon {
                margin-right: 2px;
            }

            /* Replied / forwarded markers, from the message flags (see _responseMarkers) */
            .ee-response-marker {
                display: inline-flex;
                align-items: center;
                gap: 4px;
                color: #666;
                margin-right: 6px;
                flex-shrink: 0;
            }

            .ee-message-title-markers {
                display: flex;
                gap: 4px;
                margin: -8px 0 12px;
                font-size: 12px;
            }

            .ee-message-title-markers:empty {
                display: none;
            }

            .ee-dark-mode .ee-response-marker {
                color: #999;
            }
            
            .ee-message-viewer {
                flex: 1;
                min-width: 0;
                display: flex;
                flex-direction: column;
                overflow: hidden;
                container: ee-viewer / inline-size;
            }
            
            .ee-message-actions {
                padding: 0 12px;
                background: #e9ecef;
                background: linear-gradient(to bottom, #f8f9fa, #e9ecef);
                border-bottom: 2px solid #dee2e6;
                display: flex;
                gap: 6px;
                height: 44px;
                align-items: center;
                flex-shrink: 0;
                box-sizing: border-box;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                overflow-x: auto;
                scrollbar-width: none;
            }
            
            .ee-button {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 6px;
                flex-shrink: 0;
                padding: 0 10px;
                border: 1px solid #d0d4d9;
                background: white;
                color: #333;
                border-radius: 6px;
                cursor: pointer;
                font-family: inherit;
                font-size: 13px;
                font-weight: 500;
                height: 30px;
                line-height: 1;
                white-space: nowrap;
                box-sizing: border-box;
            }
            
            .ee-button:hover:not(:disabled) {
                background: #f0f0f0;
            }

            .ee-button:focus-visible,
            .ee-move-button:focus-within,
            .ee-compose-button:focus-visible {
                outline: 2px solid var(--_accent);
                outline-offset: 1px;
            }

            .ee-icon {
                flex-shrink: 0;
            }

            .ee-icon-button {
                width: 30px;
                padding: 0;
            }

            .ee-nav-button {
                display: none;
            }

            /* Borderless, so a back arrow beside the title does not read as one
               of the pagination arrows */
            .ee-client .ee-button.ee-nav-button {
                background: transparent;
                border-color: transparent;
                margin-left: -6px;
            }

            .ee-toolbar-spacer {
                flex: 1;
            }

            .ee-button-primary {
                background: var(--_accent);
                border-color: var(--_accent);
                color: white;
            }

            .ee-button-primary:hover:not(:disabled) {
                background: var(--_accent-hover);
            }

            .ee-button-danger:hover:not(:disabled) {
                background: #fdecea;
                border-color: #f1b0ab;
                color: #c62828;
            }

            .ee-move-button {
                position: relative;
            }

            /* The native select covers the whole button, invisibly, so a click
               anywhere on it opens the platform folder picker */
            .ee-move-select {
                position: absolute;
                inset: 0;
                width: 100%;
                height: 100%;
                opacity: 0;
                cursor: pointer;
                font-size: 14px;
            }
            
            .ee-button:disabled {
                background: #e9ecef;
                color: #6c757d;
                cursor: not-allowed;
                opacity: 0.6;
            }
            
            .ee-message-content {
                flex: 1;
                padding: 20px;
                overflow-y: auto;
            }

            .ee-message-title {
                margin: 0 0 12px;
                font-size: 20px;
                font-weight: 600;
                line-height: 1.3;
                overflow-wrap: anywhere;
            }
            
            .ee-message-meta {
                display: grid;
                grid-template-columns: auto minmax(0, 1fr);
                gap: 2px 12px;
                margin-bottom: 16px;
                padding-bottom: 16px;
                border-bottom: 1px solid #e0e0e0;
            }
            
            .ee-message-meta-row {
                display: contents;
            }

            .ee-message-meta-value {
                overflow-wrap: anywhere;
            }

            .ee-otp {
                margin-bottom: 16px;
                padding: 14px 16px;
                background: color-mix(in srgb, var(--_accent) 7%, white);
                border-radius: 8px;
            }

            .ee-otp-title {
                font-size: 13px;
                color: #444;
                margin-bottom: 10px;
                overflow-wrap: anywhere;
            }

            .ee-otp-site {
                font-weight: 600;
            }

            .ee-otp-code {
                display: flex;
                flex-wrap: wrap;
                gap: 6px;
                margin-bottom: 12px;
                font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                font-size: 22px;
            }

            .ee-otp-char {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                min-width: 32px;
                height: 40px;
                background: white;
                border-radius: 6px;
            }

            .ee-otp-text {
                padding: 6px 10px;
                background: white;
                border-radius: 6px;
                font-size: 16px;
                overflow-wrap: anywhere;
                user-select: all;
            }

            .ee-otp-actions {
                display: flex;
                align-items: center;
                gap: 10px;
            }

            .ee-otp .ee-otp-copy {
                height: 32px;
                padding: 0 16px;
                font-size: 13px;
                background: var(--_accent);
                border-color: var(--_accent);
                color: white;
                border-radius: 16px;
            }

            .ee-otp .ee-otp-copy:hover:not(:disabled) {
                background: var(--_accent-hover);
            }

            .ee-otp-status,
            .ee-otp-note {
                font-size: 12px;
                color: #666;
            }

            .ee-otp-note {
                margin-top: 10px;
            }
            
            .ee-message-meta-label {
                color: #666;
                font-weight: 500;
            }
            
            .ee-attachments {
                margin-top: 16px;
                padding-top: 16px;
                border-top: 1px solid #e0e0e0;
            }
            
            .ee-attachments-title {
                font-weight: 500;
                margin-bottom: 8px;
                color: #333;
            }
            
            .ee-attachment-item {
                display: flex;
                align-items: center;
                padding: 8px;
                margin-bottom: 4px;
                background: #f8f8f8;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                cursor: pointer;
                transition: background 0.2s;
            }
            
            .ee-attachment-item:hover {
                background: #f0f0f0;
            }
            
            .ee-attachment-icon {
                display: flex;
                margin-right: 8px;
                color: #666;
            }
            
            .ee-attachment-info {
                flex: 1;
            }
            
            .ee-attachment-name {
                font-weight: 500;
                color: #333;
            }
            
            .ee-attachment-size {
                font-size: 12px;
                color: #666;
            }
            
            .ee-empty-state {
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100%;
                color: #999;
            }
            
            .ee-loading {
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                color: #666;
            }
            
            .ee-error {
                padding: 16px;
                background: #fee;
                color: #c00;
                border: 1px solid #fcc;
                border-radius: 4px;
                margin: 16px;
                /* Panes can be as narrow as the 200px sidebar and server
                   messages are arbitrary text, so break anywhere rather than
                   letting a long word push the layout wider. */
                overflow-wrap: anywhere;
            }

            .ee-error-title {
                font-weight: 500;
            }

            .ee-error-detail {
                margin-top: 6px;
                font-size: 12px;
                /* Field level API errors arrive as a newline separated list */
                white-space: pre-line;
            }

            .ee-error-retry {
                margin-top: 10px;
            }
            
            .ee-flag {
                display: inline-block;
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: #4CAF50;
                margin-right: 4px;
            }
            
            .ee-flag.unread {
                background: #2196F3;
            }
            
            .ee-pane-header {
                gap: 8px;
                padding: 0 12px 0 16px;
                background: #e9ecef;
                background: linear-gradient(to bottom, #f8f9fa, #e9ecef);
                border-bottom: 2px solid #dee2e6;
                display: flex;
                justify-content: space-between;
                align-items: center;
                height: 44px;
                flex-shrink: 0;
                box-sizing: border-box;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            
            .ee-pane-heading {
                display: flex;
                align-items: center;
                gap: 6px;
                min-width: 0;
            }

            .ee-pane-title {
                font-weight: 600;
                font-size: 14px;
                color: #333;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            .ee-folder-tree {
                flex: 1;
                overflow-y: auto;
            }
            
            .ee-pagination-controls {
                display: flex;
                gap: 6px;
                align-items: center;
                flex-shrink: 0;
            }
            
            .ee-page-size-selector {
                display: flex;
                gap: 6px;
                align-items: center;
                margin-left: 4px;
            }
            
            .ee-page-size-label {
                font-size: 12px;
                color: #666;
            }
            
            .ee-page-size-select {
                padding: 0 4px;
            }
            
            .ee-message-items {
                flex: 1;
                overflow-y: auto;
            }
            
            .ee-compose-button {
                position: fixed;
                bottom: 20px;
                right: 20px;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 56px;
                height: 56px;
                padding: 0;
                background: var(--_accent);
                border: none;
                border-radius: 50%;
                color: white;
                cursor: pointer;
                box-shadow: 0 4px 12px color-mix(in srgb, var(--_accent) 30%, transparent);
                z-index: 1000;
                transition: background 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
            }
            
            .ee-compose-button:hover {
                background: var(--_accent-hover);
                transform: translateY(-1px);
                box-shadow: 0 6px 16px color-mix(in srgb, var(--_accent) 40%, transparent);
            }

            /* Medium widths: the viewer is too narrow for labelled buttons, so the
               toolbar goes icon-only, as webmail toolbars usually are */
            @container ee-viewer (max-width: 699px) {
                .ee-message-actions .ee-button:not(.ee-keep-label):not(.ee-label-priority) .ee-button-label {
                    display: none;
                }

                .ee-message-actions .ee-button:not(.ee-keep-label):not(.ee-label-priority) {
                    width: 30px;
                    padding: 0;
                }

                .ee-message-actions .ee-move-button {
                    width: 44px;
                    gap: 2px;
                }
            }

            /* Below this even the reply group goes icon-only */
            @container ee-viewer (max-width: 439px) {
                .ee-message-actions .ee-label-priority .ee-button-label {
                    display: none;
                }

                .ee-message-actions .ee-label-priority {
                    width: 30px;
                    padding: 0;
                }

                .ee-toolbar-divider {
                    display: none;
                }
            }

            /* Narrow widths: one pane at a time, in the order a phone mail app uses
               (folders, list, message), with back buttons in the pane headers. The
               shown pane follows data-view on .ee-client. */
            @container ee-client (max-width: ${NARROW_WIDTH - 1}px) {
                .ee-sidebar,
                .ee-message-list,
                .ee-message-viewer {
                    display: none;
                    width: 100%;
                    flex: 1;
                    border-right: 0;
                }

                .ee-client[data-view="folders"] .ee-sidebar,
                .ee-client[data-view="list"] .ee-message-list,
                .ee-client[data-view="message"] .ee-message-viewer {
                    display: flex;
                }

                .ee-nav-button {
                    display: inline-flex;
                }

                .ee-message-content {
                    padding: 16px 16px 88px;
                }

                .ee-message-items {
                    padding-bottom: 88px;
                }

                /* the floating button is the Compose button here */
                .ee-sidebar-compose {
                    display: none;
                }
            }
            
            .ee-compose-modal {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                z-index: 2000;
            }
            
            .ee-compose-modal.show {
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .ee-compose-dialog {
                background: white;
                border-radius: 8px;
                width: 90%;
                max-width: 600px;
                max-height: 90vh;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                display: flex;
                flex-direction: column;
            }
            
            .ee-compose-header {
                padding: 16px 20px;
                border-bottom: 1px solid #e0e0e0;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-shrink: 0;
            }
            
            .ee-compose-title {
                font-size: 18px;
                font-weight: 600;
                margin: 0;
            }
            
            .ee-compose-close {
                background: none;
                border: none;
                color: #666;
                cursor: pointer;
                padding: 0;
                width: 30px;
                height: 30px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .ee-compose-close:hover {
                background: #f0f0f0;
            }
            
            .ee-compose-form {
                padding: 16px 20px;
                display: flex;
                flex-direction: column;
                gap: 10px;
                flex: 1;
                overflow-y: auto;
            }

            /* One line per header field: the label beside its input, as mail clients lay out
               their compose headers, so the text box and the quote get the height */
            .ee-compose-row {
                display: flex;
                align-items: center;
                gap: 10px;
            }

            .ee-compose-label {
                flex: 0 0 56px;
                font-size: 13px;
                font-weight: 500;
                color: #555;
            }

            .ee-compose-input {
                flex: 1;
                min-width: 0;
                padding: 8px 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
                font-family: inherit;
            }

            .ee-compose-input[aria-invalid="true"],
            .ee-compose-textarea[aria-invalid="true"] {
                border-color: #dc3545;
            }

            /* Why the form did not go out, between the form and its buttons so it is on
               screen however far the form is scrolled */
            .ee-compose-error {
                margin: 0 20px 4px;
                padding: 8px 12px;
                border: 1px solid #fcc;
                border-radius: 4px;
                background: #fee;
                color: #c00;
                font-size: 13px;
                white-space: pre-line;
                flex-shrink: 0;
            }
            
            .ee-compose-textarea {
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
                font-family: inherit;
                resize: vertical;
                min-height: 180px;
            }

            .ee-compose-input:focus,
            .ee-compose-textarea:focus {
                outline: none;
                border-color: var(--_accent);
                box-shadow: 0 0 0 2px color-mix(in srgb, var(--_accent) 12%, transparent);
            }
            
            .ee-compose-actions {
                padding: 16px 20px;
                border-top: 1px solid #e0e0e0;
                display: flex;
                gap: 12px;
                justify-content: flex-end;
                flex-shrink: 0;
            }
            
            .ee-compose-send {
                background: var(--_accent);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
            }
            
            .ee-compose-send:hover:not(:disabled) {
                background: var(--_accent-hover);
            }
            
            .ee-compose-send:disabled {
                background: #6c757d;
                cursor: not-allowed;
                opacity: 0.6;
            }
            
            /* Cancel is the quiet way out, not a third weighted button */
            .ee-compose-cancel {
                margin-right: auto;
                background: transparent;
                color: #555;
                border: none;
                padding: 10px 12px;
                border-radius: 4px;
                font-size: 14px;
                cursor: pointer;
            }

            .ee-compose-cancel:hover {
                background: #f0f0f0;
            }

            .ee-compose-save-draft {
                background: transparent;
                color: var(--_accent);
                border: 1px solid var(--_accent);
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
            }

            .ee-compose-save-draft:hover:not(:disabled) {
                background: var(--_accent);
                color: white;
            }

            .ee-compose-save-draft:disabled {
                color: #6c757d;
                border-color: #6c757d;
                cursor: not-allowed;
                opacity: 0.6;
            }

            .ee-sidebar-compose {
                padding: 12px;
                border-bottom: 1px solid #e0e0e0;
            }

            .ee-sidebar-compose-button {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                width: 100%;
                height: 38px;
                border: none;
                border-radius: 6px;
                background: var(--_accent);
                color: white;
                font: inherit;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
            }

            .ee-sidebar-compose-button:hover {
                background: var(--_accent-hover);
            }

            .ee-toolbar-divider {
                width: 1px;
                height: 20px;
                margin: 0 4px;
                background: #ddd;
                flex-shrink: 0;
            }

            .ee-address {
                color: #666;
            }

            /* A styled message on the light surface its colours were chosen for (see
               _renderMessageBody); plain messages follow the theme */
            .ee-dark-mode .ee-message-body[data-styled],
            .ee-dark-mode .ee-compose-quote-body[data-styled] {
                background: #ffffff;
                color: #222;
                padding: 12px;
                border-radius: 6px;
            }

            .ee-toast {
                position: fixed;
                left: 50%;
                bottom: 24px;
                transform: translate(-50%, 16px);
                max-width: calc(100vw - 32px);
                padding: 10px 16px;
                border-radius: 6px;
                background: #323232;
                color: #fff;
                font-family: var(--ee-font, inherit);
                font-size: 14px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
                opacity: 0;
                pointer-events: none;
                transition: opacity 0.2s ease, transform 0.2s ease;
                z-index: 2100;
            }

            .ee-toast.show {
                opacity: 1;
                transform: translate(-50%, 0);
            }

            .ee-toast.ee-dark-mode {
                background: #e0e0e0;
                color: #1a1a1a;
            }

            /* Parts of the compose form that come and go (Cc/Bcc, the forward checkbox, the
               quote) use the hidden attribute, which a display rule would otherwise override */
            .ee-compose-modal [hidden] {
                display: none !important;
            }

            .ee-compose-link {
                flex-shrink: 0;
                background: none;
                border: none;
                padding: 4px 0;
                font: inherit;
                font-size: 13px;
                color: var(--_accent);
                cursor: pointer;
            }

            .ee-compose-link:hover {
                text-decoration: underline;
            }

            .ee-compose-files {
                display: flex;
                flex-direction: column;
                gap: 8px;
            }

            .ee-compose-files-row {
                display: flex;
                flex-wrap: wrap;
                align-items: center;
                gap: 8px 16px;
            }

            .ee-compose-attach {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                background: transparent;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 6px 12px;
                font: inherit;
                font-size: 13px;
                color: inherit;
                cursor: pointer;
            }

            .ee-compose-attach:hover {
                background: #f0f0f0;
            }

            .ee-compose-forward-attachments {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                font-size: 13px;
                cursor: pointer;
            }

            .ee-compose-chips {
                display: flex;
                flex-wrap: wrap;
                gap: 6px;
            }

            .ee-compose-chips:empty {
                display: none;
            }

            .ee-compose-chip {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                max-width: 100%;
                padding: 4px 4px 4px 10px;
                border: 1px solid #ddd;
                border-radius: 16px;
                background: #f8f9fa;
                font-size: 13px;
            }

            .ee-compose-chip-name {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                min-width: 0;
            }

            .ee-compose-chip-size {
                color: #666;
                flex-shrink: 0;
            }

            .ee-compose-chip-remove {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 22px;
                height: 22px;
                padding: 0;
                border: none;
                border-radius: 50%;
                background: transparent;
                color: #666;
                cursor: pointer;
                flex-shrink: 0;
            }

            .ee-compose-chip-remove:hover {
                background: #e0e0e0;
            }

            .ee-compose-quote {
                display: flex;
                flex-direction: column;
                gap: 6px;
            }

            .ee-compose-quote-label {
                font-size: 13px;
                color: #666;
            }

            .ee-compose-quote-frame {
                max-height: 220px;
                overflow: auto;
                padding: 8px 12px;
                border-left: 3px solid #ddd;
                background: #fafafa;
                border-radius: 0 4px 4px 0;
            }

            /* Dark mode toggle button, in the Folders pane header */
            .ee-dark-mode-toggle {
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 6px;
                padding: 0;
                width: 30px;
                height: 30px;
                flex-shrink: 0;
                cursor: pointer;
                transition: all 0.2s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #495057;
            }

            .ee-dark-mode-toggle:hover {
                background: #e9ecef;
                border-color: #adb5bd;
            }

            .ee-dark-mode-icon {
                display: flex;
            }

            /* Dark mode styles */
            .ee-dark-mode {
                background: #1a1a1a;
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-dark-mode-toggle {
                background: #333;
                border-color: #444;
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-dark-mode-toggle:hover {
                background: #444;
                border-color: #555;
            }

            .ee-dark-mode .ee-sidebar {
                background: #202020;
                border-color: #333;
            }

            .ee-dark-mode .ee-folder-item {
                border-color: #333;
            }

            .ee-dark-mode .ee-folder-item:hover {
                background: #2a2a2a;
            }

            .ee-dark-mode .ee-folder-item.active {
                background: var(--_accent-hover);
            }

            .ee-dark-mode .ee-message-list {
                background: #202020;
                border-color: #333;
            }

            .ee-dark-mode .ee-message-item {
                border-color: #333;
            }

            .ee-dark-mode .ee-message-item:hover {
                background: #2a2a2a;
            }

            .ee-dark-mode .ee-message-item.active {
                background: color-mix(in srgb, var(--_accent) 35%, #1a1a1a);
            }

            .ee-dark-mode .ee-message-date,
            .ee-dark-mode .ee-message-preview,
            .ee-dark-mode .ee-attachment-indicator {
                color: #999;
            }

            .ee-dark-mode .ee-pane-header {
                background: linear-gradient(to bottom, #2a2a2a, #252525);
                border-color: #333;
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-pane-title {
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-page-size-label {
                color: #e0e0e0;
            }

            /* Read inside the message body's shadow root, where .ee-dark-mode selectors cannot reach */
            .ee-dark-mode {
                --ee-toggle-bg: #333;
                --ee-toggle-border: #444;
                --ee-toggle-color: #e0e0e0;
                --ee-toggle-hover-bg: #444;
                --ee-toggle-hover-border: #555;
            }

            .ee-dark-mode .ee-message-viewer {
                background: #1a1a1a;
            }

            .ee-dark-mode .ee-message-actions {
                background: linear-gradient(to bottom, #2a2a2a, #252525);
                border-color: #333;
            }

            .ee-dark-mode .ee-button {
                background: #333;
                border-color: #444;
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-button:hover {
                background: #444;
                border-color: #555;
            }

            .ee-dark-mode .ee-button-primary,
            .ee-dark-mode .ee-button-primary:hover:not(:disabled),
            .ee-dark-mode .ee-sidebar-compose-button {
                background: var(--_accent-hover);
                border-color: var(--_accent-hover);
                color: white;
            }

            .ee-dark-mode .ee-button-danger:hover:not(:disabled) {
                background: #4a2323;
                border-color: #7a3434;
                color: #f0a5a5;
            }

            .ee-dark-mode .ee-message-meta {
                border-color: #333;
            }

            .ee-dark-mode .ee-message-meta-label {
                color: #999;
            }

            .ee-dark-mode .ee-button:disabled {
                background: #222;
                color: #666;
            }

            .ee-dark-mode select {
                background: #2a2a2a;
                border-color: #444;
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-message-content {
                background: #1a1a1a;
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-attachments {
                border-color: #333;
            }

            .ee-dark-mode .ee-attachments-title,
            .ee-dark-mode .ee-attachment-name {
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-attachment-size {
                color: #999;
            }

            .ee-dark-mode .ee-attachment-item {
                background: #2a2a2a;
                border-color: #333;
            }

            .ee-dark-mode .ee-attachment-item:hover {
                background: #333;
            }

            .ee-dark-mode .ee-loading,
            .ee-dark-mode .ee-empty-state {
                color: #999;
            }

            .ee-dark-mode .ee-error {
                background: #3a2222;
                border-color: #5c3030;
                color: #f0a5a5;
            }

            .ee-dark-mode .ee-otp {
                background: color-mix(in srgb, var(--_accent) 18%, #1a1a1a);
            }

            .ee-dark-mode .ee-otp-title {
                color: #ccc;
            }

            .ee-dark-mode .ee-otp-char,
            .ee-dark-mode .ee-otp-text {
                background: #1a1a1a;
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-otp .ee-otp-copy {
                background: var(--_accent-hover);
                border-color: var(--_accent-hover);
                color: white;
            }

            .ee-dark-mode .ee-otp-status,
            .ee-dark-mode .ee-otp-note {
                color: #999;
            }

            .ee-dark-mode .ee-pagination {
                background: #252525;
                border-color: #333;
            }

            /* The compose button and modal sit beside .ee-client, not inside it, so
               setDarkMode puts the ee-dark-mode class on them directly */
            .ee-compose-button.ee-dark-mode {
                background: var(--_accent-hover);
                color: white;
            }

            .ee-compose-modal.ee-dark-mode {
                background: rgba(0, 0, 0, 0.7);
            }

            .ee-dark-mode .ee-compose-dialog {
                background: #202020;
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-compose-header {
                background: linear-gradient(to bottom, #2a2a2a, #252525);
                border-color: #333;
            }

            .ee-dark-mode .ee-compose-close {
                color: #999;
            }

            .ee-dark-mode .ee-compose-close:hover {
                color: #fff;
            }

            .ee-dark-mode .ee-compose-input,
            .ee-dark-mode .ee-compose-textarea {
                background: #1a1a1a;
                border-color: #444;
                color: #e0e0e0;
            }

            .ee-dark-mode .ee-compose-input:focus,
            .ee-dark-mode .ee-compose-textarea:focus {
                border-color: var(--_accent-hover);
                box-shadow: 0 0 0 2px color-mix(in srgb, var(--_accent) 25%, transparent);
            }

            .ee-dark-mode .ee-compose-actions {
                border-color: #333;
            }

            .ee-dark-mode .ee-compose-cancel {
                color: #ccc;
            }

            .ee-dark-mode .ee-compose-cancel:hover {
                background: #333;
            }

            .ee-dark-mode .ee-compose-save-draft {
                color: var(--_accent-light);
                border-color: var(--_accent-light);
            }

            .ee-dark-mode .ee-compose-save-draft:hover:not(:disabled) {
                background: var(--_accent-light);
                color: #1a1a1a;
            }

            .ee-dark-mode .ee-sidebar-compose {
                border-color: #333;
            }

            .ee-dark-mode .ee-toolbar-divider {
                background: #444;
            }

            .ee-dark-mode .ee-address,
            .ee-dark-mode .ee-compose-label {
                color: #aaa;
            }

            .ee-dark-mode .ee-compose-error {
                background: #3a2222;
                border-color: #5c3030;
                color: #f0a5a5;
            }

            .ee-dark-mode .ee-compose-link {
                color: var(--_accent-light);
            }

            .ee-dark-mode .ee-compose-attach {
                border-color: #444;
            }

            .ee-dark-mode .ee-compose-attach:hover,
            .ee-dark-mode .ee-compose-chip-remove:hover {
                background: #333;
            }

            .ee-dark-mode .ee-compose-chip {
                background: #2a2a2a;
                border-color: #444;
            }

            .ee-dark-mode .ee-compose-chip-size,
            .ee-dark-mode .ee-compose-chip-remove,
            .ee-dark-mode .ee-compose-quote-label {
                color: #999;
            }

            .ee-dark-mode .ee-compose-quote-frame {
                background: #1a1a1a;
                border-color: #444;
            }
        `);
        document.head.appendChild(style);
        this._styleElement = style;
    }

    buildFolderTree() {
        if (this._folderTreeCache) {
            return this._folderTreeCache;
        }

        const specialFolders = [];
        const regularFolders = [];

        this.folders.forEach(folder => {
            if (folder.specialUse) {
                specialFolders.push(folder);
            } else {
                regularFolders.push(folder);
            }
        });

        const specialOrder = ['\\Inbox', '\\Drafts', '\\Sent', '\\Trash', '\\Junk', '\\Archive'];
        specialFolders.sort((a, b) => {
            if (a.specialUse === '\\Inbox' || a.name.toLowerCase() === 'inbox') {
                return -1;
            }
            if (b.specialUse === '\\Inbox' || b.name.toLowerCase() === 'inbox') {
                return 1;
            }

            const aIndex = specialOrder.indexOf(a.specialUse);
            const bIndex = specialOrder.indexOf(b.specialUse);
            if (aIndex !== -1 && bIndex !== -1) {
                return aIndex - bIndex;
            }
            if (aIndex !== -1) {
                return -1;
            }
            if (bIndex !== -1) {
                return 1;
            }
            return a.name.localeCompare(b.name);
        });

        // Index children by parent in a single pass so the hierarchy walk is
        // O(n) instead of re-filtering the whole list at every level. A folder
        // whose parent is not among the regular folders (special-use parent,
        // missing parent, or no parent) is a root, keyed under null - those must
        // still surface at the top level rather than be dropped.
        const regularPaths = new Set(regularFolders.map(f => f.path));
        const childrenByParent = new Map();
        regularFolders.forEach(folder => {
            const key = regularPaths.has(folder.parentPath) ? folder.parentPath : null;
            const siblings = childrenByParent.get(key);
            if (siblings) {
                siblings.push(folder);
            } else {
                childrenByParent.set(key, [folder]);
            }
        });
        childrenByParent.forEach(siblings => siblings.sort((a, b) => a.name.localeCompare(b.name)));

        // Each entry carries its depth in the rendered tree (roots = 0). Depth
        // comes from tree position, not the path string, so a folder whose
        // parent is a special-use or missing folder renders flush at the top.
        const visited = new Set();
        const walk = (parentKey, depth) => {
            const result = [];
            const siblings = childrenByParent.get(parentKey) || [];
            siblings.forEach(folder => {
                // Guard against cyclic/self-referential parentPath values.
                if (visited.has(folder.path)) {
                    return;
                }
                visited.add(folder.path);
                result.push({ folder, depth });
                result.push(...walk(folder.path, depth + 1));
            });
            return result;
        };

        const hierarchicalRegular = walk(null, 0);

        const tree = [...specialFolders.map(folder => ({ folder, depth: 0 })), ...hierarchicalRegular];
        this._folderTreeCache = tree;
        return tree;
    }

    renderFolderList() {
        if (typeof document === 'undefined' || !this.container || this._destroyed) {
            return;
        }

        const folderTree = this.container.querySelector('.ee-folder-tree');
        if (!folderTree) {
            return;
        }

        const sortedFolders = this.buildFolderTree();
        // Precompute which paths are some folder's parent so the per-row
        // has-children check is O(1) instead of scanning this.folders each time.
        const parentPaths = new Set(this.folders.map(f => f.parentPath));

        const html = `
            <ul class="ee-folder-list">
                ${sortedFolders
                    .map(({ folder, depth }) => {
                        const hasChildren = parentPaths.has(folder.path);
                        return `
                        <li class="ee-folder-item ${folder.path === this.currentFolder ? 'active' : ''}" 
                            data-path="${this.escapeHtml(folder.path)}" 
                            data-depth="${depth}">
                            <div class="ee-folder-content" style="padding-left: ${8 + depth * 12}px;">
                                ${depth > 0 ? '<span class="ee-folder-indent">└ </span>' : ''}
                                <span class="ee-folder-name ${hasChildren ? 'has-children' : ''}">${this.escapeHtml(folder.name)}</span>
                                ${folder.status && folder.status.messages > 0 ? `<span class="ee-folder-count">${folder.status.messages}</span>` : ''}
                            </div>
                        </li>
                    `;
                    })
                    .join('')}
            </ul>
        `;
        folderTree.innerHTML = html;

        folderTree.querySelectorAll('.ee-folder-item').forEach(item => {
            item.addEventListener('click', () => {
                const path = item.getAttribute('data-path');
                this._fireAndForget(this.openFolder(path));
            });
        });
    }

    renderMessageList() {
        if (typeof document === 'undefined' || !this.container || this._destroyed) {
            return;
        }

        const messageList = this.container.querySelector('.ee-message-list');
        if (!messageList) {
            return;
        }

        if (!this.messages.length) {
            messageList.innerHTML = `${this._messageListHeader(this.currentFolder)}<div class="ee-empty-state">No messages</div>`;
            return;
        }

        const hasPagination = this.nextPageCursor || this.prevPageCursor;

        // Both arrows stay in place once there is more than one page, the unavailable
        // one disabled, so the controls do not shift under the pointer between pages
        const controls = `
                <div class="ee-pagination-controls">
                    ${
                        hasPagination
                            ? `
                        ${this._iconButton('prev-page', 'back', 'Previous page', '', !this.prevPageCursor)}
                        ${this._iconButton('next-page', 'next', 'Next page', '', !this.nextPageCursor)}
                    `
                            : ''
                    }
                    <label class="ee-page-size-selector" title="Messages per page">
                        <span class="ee-page-size-label">Show</span>
                        <select class="ee-button ee-page-size-select" data-action="page-size">
                            <option value="10" ${this.pageSize === 10 ? 'selected' : ''}>10</option>
                            <option value="20" ${this.pageSize === 20 ? 'selected' : ''}>20</option>
                            <option value="30" ${this.pageSize === 30 ? 'selected' : ''}>30</option>
                            <option value="50" ${this.pageSize === 50 ? 'selected' : ''}>50</option>
                            <option value="100" ${this.pageSize === 100 ? 'selected' : ''}>100</option>
                        </select>
                    </label>
                </div>
        `;

        const html = `
            ${this._messageListHeader(this.currentFolder, controls)}
            <div class="ee-message-items">
                ${this.messages
                    .map(
                        msg => `
                    <div class="ee-message-item ${msg.unseen ? 'unread' : ''} ${msg.id === (this.currentMessage && this.currentMessage.id) ? 'active' : ''}" data-id="${this.escapeHtml(msg.id)}">
                        <div class="ee-message-header">
                            <span class="ee-message-from">${this.escapeHtml(msg.from ? msg.from.name || msg.from.address : 'Unknown')}</span>
                            <span class="ee-message-date">${this.formatDate(msg.date)}</span>
                        </div>
                        <div class="ee-message-subject">
                            ${this._responseMarkers(msg)}
                            <span class="ee-message-subject-text">${this.escapeHtml(msg.subject || '(no subject)')}</span>
                            ${msg.attachments && msg.attachments.length > 0 ? `<span class="ee-attachment-indicator" title="Attachments">${icon('paperclip', 12)}${msg.attachments.length}</span>` : ''}
                        </div>
                        <div class="ee-message-preview">${this.escapeHtml(msg.intro || '')}</div>
                    </div>
                `
                    )
                    .join('')}
            </div>
        `;
        messageList.innerHTML = html;

        messageList.querySelectorAll('.ee-message-item').forEach(item => {
            item.addEventListener('click', () => {
                const messageId = item.getAttribute('data-id');
                this._fireAndForget(this.loadMessage(messageId));
            });
        });

        messageList.querySelectorAll('[data-action="prev-page"]').forEach(btn => {
            btn.addEventListener('click', () => {
                this._fireAndForget(this.loadMessages(this.currentFolder, this.prevPageCursor));
            });
        });

        messageList.querySelectorAll('[data-action="next-page"]').forEach(btn => {
            btn.addEventListener('click', () => {
                this._fireAndForget(this.loadMessages(this.currentFolder, this.nextPageCursor));
            });
        });

        const pageSizeSelect = messageList.querySelector('[data-action="page-size"]');
        if (pageSizeSelect) {
            pageSizeSelect.addEventListener('change', e => {
                this.pageSize = parseInt(e.target.value, 10);
                // Save to localStorage
                if (typeof window !== 'undefined' && window.localStorage) {
                    localStorage.setItem('ee-client-page-size', this.pageSize.toString());
                }
                this._fireAndForget(this.loadMessages(this.currentFolder));
            });
        }
    }

    renderMessage() {
        if (typeof document === 'undefined' || !this.container || this._destroyed) {
            return;
        }

        const viewer = this.container.querySelector('.ee-message-viewer');
        if (!viewer) {
            return;
        }

        if (!this.currentMessage) {
            viewer.innerHTML = this._messageViewerPlaceholder();
            // Nothing left to show in the single-pane layout (the message was deleted
            // or moved), so return to the list it came from
            if (this._getView() === 'message') {
                this._setView('list');
            }
            return;
        }

        const msg = this.currentMessage;
        const isUnseen = msg.unseen;
        const isDraft = this._isDraftMessage(msg);
        // Labels drop to icons when the viewer is narrow (see the ee-viewer container
        // query); aria-label and title carry the full name either way. The move control
        // is a native select laid invisibly over a button so it looks like the rest of
        // the toolbar while keeping the platform's own folder picker.
        const respond = isDraft
            ? ''
            : `${this._toolbarButton('reply', 'reply', 'Reply', 'Reply to the sender', 'ee-label-priority')}
                ${addressEntries(msg.to).length + addressEntries(msg.cc).length > 1 ? this._toolbarButton('reply-all', 'replyAll', 'Reply all', 'Reply to everyone', 'ee-label-priority') : ''}
                ${this._toolbarButton('forward', 'forward', 'Forward', 'Forward this message', 'ee-label-priority')}
                <span class="ee-toolbar-divider"></span>`;
        const actions = `
                ${isDraft ? this._toolbarButton('send-draft', 'send', 'Send draft', 'Send this draft now', 'ee-button-primary ee-keep-label') : respond}
                ${this._toolbarButton('toggle-read', isUnseen ? 'mailOpen' : 'mail', isUnseen ? 'Mark read' : 'Mark unread', isUnseen ? 'Mark as read' : 'Mark as unread')}
                <span class="ee-button ee-move-button" title="Move to folder">
                    ${icon('move')}<span class="ee-button-label">Move</span>${icon('chevronDown', 12)}
                    <select class="ee-move-select" data-action="move" aria-label="Move to folder">
                        <option value="">Move to...</option>
                        ${this.buildFolderTree()
                            .map(({ folder, depth }) => {
                                const indent = '　'.repeat(depth);
                                const prefix = depth > 0 ? '└ ' : '';
                                return `<option value="${this.escapeHtml(folder.path)}" ${folder.path === this.currentFolder ? 'disabled' : ''}>${indent}${prefix}${this.escapeHtml(folder.name)}</option>`;
                            })
                            .join('')}
                    </select>
                </span>
                ${this._toolbarButton('delete', 'trash', 'Delete', 'Delete', 'ee-button-danger')}
                <span class="ee-toolbar-spacer"></span>
                ${this._toolbarButton('download-original', 'download', 'Download', 'Download the original message (.eml)')}
        `;
        const html = `
            ${this._messageToolbar(actions)}
            <div class="ee-message-content">
                <h2 class="ee-message-title">${this.escapeHtml(msg.subject || '(no subject)')}</h2>
                <div class="ee-message-title-markers">${this._responseMarkers(msg, true)}</div>
                <div class="ee-message-meta">
                    <div class="ee-message-meta-row">
                        <span class="ee-message-meta-label">From</span>
                        <span class="ee-message-meta-value">${this._addressListHtml(msg.from) || 'Unknown'}</span>
                    </div>
                    <div class="ee-message-meta-row">
                        <span class="ee-message-meta-label">To</span>
                        <span class="ee-message-meta-value">${this._addressListHtml(msg.to)}</span>
                    </div>
                    ${
                        msg.cc && msg.cc.length
                            ? `
                        <div class="ee-message-meta-row">
                            <span class="ee-message-meta-label">Cc</span>
                            <span class="ee-message-meta-value">${this._addressListHtml(msg.cc)}</span>
                        </div>
                    `
                            : ''
                    }
                    <div class="ee-message-meta-row">
                        <span class="ee-message-meta-label">Date</span>
                        <span class="ee-message-meta-value">${this.escapeHtml(this.formatFullDate(msg.date))}</span>
                    </div>
                </div>
                ${this.renderOtpBox(msg.otp)}
                <div class="ee-message-body"></div>
                ${
                    msg.attachments && msg.attachments.length > 0
                        ? `
                    <div class="ee-attachments">
                        <div class="ee-attachments-title">Attachments (${msg.attachments.length})</div>
                        ${msg.attachments
                            .map(
                                att => `
                            <div class="ee-attachment-item" data-attachment-id="${this.escapeHtml(att.id)}">
                                <div class="ee-attachment-icon">${icon('paperclip', 18)}</div>
                                <div class="ee-attachment-info">
                                    <div class="ee-attachment-name">${this.escapeHtml(att.filename || 'Unnamed attachment')}</div>
                                    ${att.size ? `<div class="ee-attachment-size">${this.formatFileSize(att.size)}</div>` : ''}
                                </div>
                            </div>
                        `
                            )
                            .join('')}
                    </div>
                `
                        : ''
                }
            </div>
        `;
        viewer.innerHTML = html;

        const bodyRoot = this._renderMessageBody(viewer.querySelector('.ee-message-body'), msg);
        this._labelCollapsedThreads(bodyRoot);

        const sendDraftButton = viewer.querySelector('[data-action="send-draft"]');
        if (sendDraftButton) {
            sendDraftButton.addEventListener('click', async () => {
                const result = await this.confirmMethod(
                    'Send this draft to its recipients now? The draft is removed from the Drafts folder once it has been sent.',
                    'Send Draft',
                    'Cancel',
                    'Send'
                );
                if (!result) {
                    return;
                }

                // Only the label changes, the icon stays
                const label = sendDraftButton.querySelector('.ee-button-label');
                const originalText = label.textContent;
                sendDraftButton.disabled = true;
                label.textContent = 'Sending...';

                try {
                    await this.submitDraft(msg.id);
                    this.notify('Draft queued for delivery.');
                    // Refresh the folder view - the provider removes the draft once it is sent,
                    // immediately for Gmail and MS Graph, after SMTP delivery for IMAP accounts.
                    if (!this._destroyed && this.currentFolder) {
                        await this.openFolder(this.currentFolder);
                    }
                } catch (error) {
                    console.error('Failed to send draft:', error);
                    const errorMessage = this._formatSendError(error);
                    await this.alertMethod(errorMessage, 'Send Error', null, 'OK');
                    sendDraftButton.disabled = false;
                    label.textContent = originalText;
                }
            });
        }

        viewer.querySelectorAll('[data-action="reply"], [data-action="reply-all"], [data-action="forward"]').forEach(button => {
            button.addEventListener('click', () => {
                this._respond(msg.id, button.dataset.action).catch(error => this._alertActionFailed(error, 'Failed to open the compose form'));
            });
        });

        viewer.querySelector('[data-action="toggle-read"]').addEventListener('click', () => {
            const currentlyUnseen = msg.unseen;
            this.markAsRead(msg.id, currentlyUnseen).catch(error => this._alertActionFailed(error, 'Failed to update the message flags'));
        });

        viewer.querySelector('[data-action="delete"]').addEventListener('click', async () => {
            // Whether a delete moves the message to Trash or removes it depends on the backend
            // and the folder (IMAP removes it from Trash and Junk, Gmail always moves it), so the
            // question makes no promise and the notice reports what the server did
            const result = await this.confirmMethod('Delete this message?', 'Delete Message', 'Cancel', 'Delete');
            if (result) {
                this.deleteMessage(msg.id)
                    .then(response => this.notify(response && response.moved ? 'Message moved to Trash.' : 'Message deleted.'))
                    .catch(error => this._alertActionFailed(error, 'Failed to delete the message'));
            }
        });

        viewer.querySelector('[data-action="download-original"]').addEventListener('click', () => {
            this.downloadOriginalMessage(msg.id, msg.subject);
        });

        viewer.querySelector('[data-action="move"]').addEventListener('change', e => {
            const targetPath = e.target.value;
            if (targetPath) {
                this.moveMessage(msg.id, targetPath).catch(error => {
                    // The message did not move, so the select must not keep showing
                    // the target folder as though it had
                    e.target.value = '';
                    this._alertActionFailed(error, 'Failed to move the message');
                });
            }
        });

        // Add click handlers for attachments
        viewer.querySelectorAll('.ee-attachment-item').forEach(item => {
            item.addEventListener('click', () => {
                const attachmentId = item.getAttribute('data-attachment-id');
                const attachment = msg.attachments.find(a => a.id === attachmentId);
                this.downloadAttachment(attachmentId, attachment ? attachment.filename : null);
            });
        });

        const copyOtpButton = viewer.querySelector('[data-action="copy-otp"]');
        if (copyOtpButton) {
            const status = viewer.querySelector('.ee-otp-status');
            copyOtpButton.addEventListener('click', async () => {
                const copied = await this.copyText(msg.otp.code);
                copyOtpButton.textContent = copied ? 'Copied' : 'Copy code';
                status.textContent = copied ? 'Code copied to the clipboard' : 'Could not copy, select the code and copy it by hand';
                clearTimeout(this._otpCopyTimer);
                this._otpCopyTimer = setTimeout(() => {
                    copyOtpButton.textContent = 'Copy code';
                    status.textContent = '';
                }, 2500);
            });
        }

        // Message content scrolling is now handled in loadMessage method
    }

    // Replied / forwarded markers from the flags the server sets on the original once a reply or
    // forward has been delivered (IMAP accounts; Gmail API and MS Graph report neither flag).
    // labelled shows the words next to the icons, otherwise they are the accessible name only.
    //
    // EmailEngine adds \Answered to a forwarded message as well as $Forwarded, so one marker is
    // shown: Forwarded when that flag is set, Replied otherwise.
    _responseMarkers(msg, labelled = false) {
        const flags = Array.isArray(msg.flags) ? msg.flags : [];
        const marker = flags.includes('$Forwarded')
            ? { icon: 'forward', label: 'Forwarded' }
            : flags.includes('\\Answered')
              ? { icon: 'reply', label: 'Replied' }
              : null;
        if (!marker) {
            return '';
        }
        return labelled
            ? `<span class="ee-response-marker">${icon(marker.icon, 12)}<span>${marker.label}</span></span>`
            : `<span class="ee-response-marker" role="img" aria-label="${marker.label}" title="${marker.label}">${icon(marker.icon, 12)}</span>`;
    }

    // An icon-only button. Static arguments only, never message data.
    _iconButton(action, iconName, label, extraClass = '', disabled = false) {
        return `<button type="button" class="ee-button ee-icon-button ${extraClass}" data-action="${action}" aria-label="${label}" title="${label}"${disabled ? ' disabled' : ''}>${icon(iconName)}</button>`;
    }

    // A message toolbar button. Static arguments only, never message data.
    _toolbarButton(action, iconName, label, title, extraClass = '') {
        return `<button type="button" class="ee-button ${extraClass}" data-action="${action}" aria-label="${label}" title="${title}">${icon(iconName)}<span class="ee-button-label">${label}</span></button>`;
    }

    // The message body goes into a shadow root on its container. Sanitised message HTML still
    // carries class and id attributes, and in the host document those would pick up the host's
    // own stylesheet (a utility class like "fixed inset-0" could cover the whole page) or collide
    // with its ids. Inside the shadow root no host selector matches, while the message's inline
    // style attributes keep working. The host element is the same .ee-message-body as before, so
    // sizing and scrolling of the viewer are unchanged.
    _renderMessageBody(host, msg) {
        const root = host.attachShadow({ mode: 'open' });
        const style = this._createStyle(MESSAGE_BODY_STYLES);

        const content = document.createElement('div');
        content.className = 'ee-message-body-content';
        if (msg.text && msg.text.html) {
            content.innerHTML = msg.text.html;
        } else if (msg.text && msg.text.plain) {
            const pre = document.createElement('pre');
            pre.textContent = msg.text.plain;
            content.appendChild(pre);
        }

        root.replaceChildren(style, content);
        // A message that sets its own colours or backgrounds was designed for a light page;
        // in dark mode its dark text would land on a dark background, or the client's light
        // text on its white tables, so it is shown on a light surface instead (see the
        // [data-styled] rule). A plain message has none and follows the theme.
        const styled = Array.from(content.querySelectorAll('[style], [bgcolor], [color]')).some(
            el => el.hasAttribute('bgcolor') || el.hasAttribute('color') || el.style.color || el.style.backgroundColor || el.style.backgroundImage
        );
        if (styled) {
            host.dataset.styled = 'true';
        }
        return root;
    }

    // EmailEngine's web-safe HTML folds quoted thread history (reply history, forwarded content,
    // disclaimers) into a <details class="ee-collapsed-thread"> whose <summary> it leaves empty on
    // purpose, for the renderer to label. The fold is closed until the reader opens it.
    //
    // A sender can put the same markup in their own HTML - it survives sanitization - so every
    // match is relabelled rather than trusted, and the control always reads as one of these two
    // labels instead of whatever text came with the message.
    _labelCollapsedThreads(root) {
        root.querySelectorAll('details.ee-collapsed-thread > summary.ee-collapsed-thread-toggle').forEach(toggle => {
            const details = toggle.parentElement;
            const applyLabel = () => {
                toggle.textContent = details.open ? 'Hide quoted text' : 'Show quoted text';
            };

            applyLabel();
            details.addEventListener('toggle', applyLabel);
        });
    }

    createLayout() {
        if (typeof document === 'undefined' || !this.container) {
            return;
        }

        this.container.innerHTML = `
            <div class="ee-client${this.darkMode ? ' ee-dark-mode' : ''}" data-view="list">
                <div class="ee-sidebar">
                    <div class="ee-pane-header">
                        <span class="ee-pane-title">Folders</span>
                        ${
                            this.showDarkModeToggle
                                ? `<button type="button" class="ee-dark-mode-toggle" title="Toggle dark mode" aria-label="Toggle dark mode">
                            <span class="ee-dark-mode-icon">${icon(this.darkMode ? 'sun' : 'moon', 14)}</span>
                        </button>`
                                : ''
                        }
                    </div>
                    <div class="ee-sidebar-compose">
                        <button type="button" class="ee-sidebar-compose-button" data-action="compose">${icon('compose', 16)}<span>Compose</span></button>
                    </div>
                    <div class="ee-folder-tree"></div>
                </div>
                <div class="ee-message-list">${this._messageListPlaceholder()}</div>
                <div class="ee-message-viewer">${this._messageViewerPlaceholder()}</div>
            </div>
            <button type="button" class="ee-compose-button${this.darkMode ? ' ee-dark-mode' : ''}" title="Compose email" aria-label="Compose">${icon('compose', 22)}</button>
            <div class="ee-toast${this.darkMode ? ' ee-dark-mode' : ''}" role="status" aria-live="polite"></div>
            <div class="ee-compose-modal${this.darkMode ? ' ee-dark-mode' : ''}">
                <div class="ee-compose-dialog" role="dialog" aria-modal="true" aria-label="Compose">
                    <div class="ee-compose-header">
                        <h3 class="ee-compose-title">${COMPOSE_TITLES.new}</h3>
                        <button type="button" class="ee-compose-close" aria-label="Close" title="Close">${icon('close', 18)}</button>
                    </div>
                    <form class="ee-compose-form" novalidate>
                        <div class="ee-compose-row">
                            <label class="ee-compose-label" for="${this._composeId('to')}">To</label>
                            <input type="text" class="ee-compose-input" id="${this._composeId('to')}" name="to" autocomplete="off" spellcheck="false">
                            <button type="button" class="ee-compose-link" data-action="show-cc">Cc / Bcc</button>
                        </div>
                        <div class="ee-compose-row" data-field="cc" hidden>
                            <label class="ee-compose-label" for="${this._composeId('cc')}">Cc</label>
                            <input type="text" class="ee-compose-input" id="${this._composeId('cc')}" name="cc" autocomplete="off" spellcheck="false">
                        </div>
                        <div class="ee-compose-row" data-field="bcc" hidden>
                            <label class="ee-compose-label" for="${this._composeId('bcc')}">Bcc</label>
                            <input type="text" class="ee-compose-input" id="${this._composeId('bcc')}" name="bcc" autocomplete="off" spellcheck="false">
                        </div>
                        <div class="ee-compose-row">
                            <label class="ee-compose-label" for="${this._composeId('subject')}">Subject</label>
                            <input type="text" class="ee-compose-input" id="${this._composeId('subject')}" name="subject">
                        </div>
                        <textarea class="ee-compose-textarea" name="message" aria-label="Message" placeholder="Write your message"></textarea>
                        <div class="ee-compose-files">
                            <div class="ee-compose-chips"></div>
                            <div class="ee-compose-files-row">
                                <button type="button" class="ee-compose-attach" data-action="attach">${icon('paperclip', 14)}<span>Attach files</span></button>
                                <input type="file" class="ee-compose-file-input" multiple hidden>
                                <label class="ee-compose-forward-attachments" hidden>
                                    <input type="checkbox" name="forwardAttachments" checked>
                                    <span class="ee-compose-forward-attachments-label"></span>
                                </label>
                            </div>
                        </div>
                        <div class="ee-compose-quote" hidden>
                            <div class="ee-compose-quote-label"></div>
                            <div class="ee-compose-quote-frame"></div>
                        </div>
                    </form>
                    <div class="ee-compose-error" role="alert" hidden></div>
                    <div class="ee-compose-actions">
                        <button type="button" class="ee-compose-cancel">Cancel</button>
                        <button type="button" class="ee-compose-save-draft">Save Draft</button>
                        <button type="button" class="ee-compose-send">Send</button>
                    </div>
                </div>
            </div>
        `;

        // Pane navigation in the single-pane layout, delegated because the panes
        // re-render their headers on every load
        this.container.querySelector('.ee-client').addEventListener('click', e => {
            const nav = e.target.closest('[data-action="show-folders"], [data-action="back-to-list"]');
            if (nav) {
                this._setView(nav.dataset.action === 'show-folders' ? 'folders' : 'list');
            }
        });

        // Wire up compose modal events
        this.setupComposeModal();

        // Position compose button correctly
        this.positionComposeButton();
    }

    // Unique element ids for the compose form labels, so two clients on one page do not share them
    _composeId(field) {
        if (!this._composeIdPrefix) {
            EmailEngineClient._composeCounter = (EmailEngineClient._composeCounter || 0) + 1;
            this._composeIdPrefix = `ee-compose-${EmailEngineClient._composeCounter}`;
        }
        return `${this._composeIdPrefix}-${field}`;
    }

    // Opens a blank compose form, optionally prefilled: { to, cc, bcc, subject, text }. The
    // address fields take a string or address entries.
    compose(prefill = {}) {
        this._openCompose({ mode: 'new', ...prefill });
    }

    // Opens the compose form as a reply to a message (the open one when messageId is omitted)
    reply(messageId = null, { all = false } = {}) {
        return this._respond(messageId, all ? 'reply-all' : 'reply');
    }

    // Opens the compose form to forward a message (the open one when messageId is omitted)
    forward(messageId = null) {
        return this._respond(messageId, 'forward');
    }

    async _respond(messageId, action) {
        const id = messageId || (this.currentMessage && this.currentMessage.id);
        if (!id) {
            throw new Error('No message to respond to');
        }

        const [msg, ownAddress] = await Promise.all([
            this.currentMessage && this.currentMessage.id === id ? this.currentMessage : this.apiRequest('GET', this._messagePath(id, '?webSafeHtml=true')),
            // Without it the account's own address may stay among the reply-all recipients
            this._getAccountInfo().then(
                info => info && info.email,
                () => null
            )
        ]);

        this._openCompose({ mode: action, original: msg, ...this.prepareResponse(msg, action, ownAddress) });
    }

    _openCompose({ mode = 'new', to, cc, bcc, subject, text, reference = null, original = null } = {}) {
        const els = this._compose && this._compose.els;
        if (!els) {
            throw new Error('The compose form needs the client UI (a container)');
        }
        this._resetCompose();
        this._compose.reference = reference;

        const asField = value => (typeof value === 'string' ? value : this.formatAddressList(value));
        const { form } = els;
        form.elements.to.value = asField(to);
        form.elements.cc.value = asField(cc);
        form.elements.bcc.value = asField(bcc);
        form.elements.subject.value = subject || '';
        form.elements.message.value = text || '';
        this._showCopyFields({ cc: !!form.elements.cc.value, bcc: !!form.elements.bcc.value });

        els.title.textContent = COMPOSE_TITLES[mode] || COMPOSE_TITLES.new;

        // The server carries the original's attachments over on request (all or none)
        const originalAttachments = original && mode === 'forward' ? (original.attachments || []).filter(att => !att.inline && !att.embedded) : [];
        els.forwardAttachments.hidden = !originalAttachments.length;
        els.forwardAttachments.querySelector('.ee-compose-forward-attachments-label').textContent =
            `Include the original attachments (${originalAttachments.length})`;

        if (original && reference && reference.inline) {
            this._renderComposeQuote(original, mode);
        }

        els.modal.classList.add('show');
        const focusTarget = form.elements.to.value ? form.elements.message : form.elements.to;
        setTimeout(() => {
            focusTarget.focus();
            if (focusTarget === form.elements.message) {
                focusTarget.setSelectionRange(0, 0);
            }
        }, 100);
    }

    // A read-only copy of the message being answered, under the textarea. The quote that is sent
    // is built by the server from the stored original; this shows what it will contain.
    _renderComposeQuote(original, mode) {
        const { quote } = this._compose.els;
        const from = addressEntries(original.from)[0];
        const sender = from ? from.name || from.address : 'the sender';
        quote.querySelector('.ee-compose-quote-label').textContent =
            mode === 'forward' ? 'The forwarded message is added below your text:' : `${sender}'s message is quoted below your reply:`;
        // A shadow root cannot be attached twice, so each quote gets a fresh host
        const host = document.createElement('div');
        host.className = 'ee-compose-quote-body';
        quote.querySelector('.ee-compose-quote-frame').replaceChildren(host);
        this._labelCollapsedThreads(this._renderMessageBody(host, original));
        quote.hidden = false;
    }

    // Shows the Cc and Bcc fields named true and hides the rest; the link offers whichever is hidden
    _showCopyFields(show) {
        const { form } = this._compose.els;
        const hidden = [];
        for (const key of ['cc', 'bcc']) {
            form.querySelector(`[data-field="${key}"]`).hidden = !show[key];
            if (!show[key]) {
                hidden.push(key === 'cc' ? 'Cc' : 'Bcc');
            }
        }
        const link = form.querySelector('[data-action="show-cc"]');
        link.hidden = !hidden.length;
        link.textContent = hidden.join(' / ');
    }

    // Empties the form and starts a new compose state; the element references are kept
    _resetCompose() {
        const { els } = this._compose;
        els.form.reset();
        els.chips.replaceChildren();
        els.fileInput.value = '';
        els.forwardAttachments.hidden = true;
        els.quote.hidden = true;
        els.quote.querySelector('.ee-compose-quote-frame').replaceChildren();
        this._clearComposeError();
        this._compose = { els, reference: null, files: [] };
        this._showCopyFields({ cc: false, bcc: false });
    }

    _closeCompose() {
        if (this._compose && this._compose.els) {
            this._compose.els.modal.classList.remove('show');
            this._resetCompose();
        }
    }

    // Shows why the form cannot go out, inside the form itself, and marks the field it is about.
    // The message stays until the form is changed or closed.
    _showComposeError(message, field = null) {
        const { form, error } = this._compose.els;
        this._clearComposeError();
        error.textContent = message;
        error.hidden = false;
        const input = field ? form.elements[field] : null;
        if (input) {
            input.setAttribute('aria-invalid', 'true');
            input.focus();
        }
    }

    _clearComposeError() {
        const { form, error } = this._compose.els;
        error.hidden = true;
        form.querySelectorAll('[aria-invalid]').forEach(input => input.removeAttribute('aria-invalid'));
    }

    _renderComposeChips() {
        this._compose.els.chips.innerHTML = this._compose.files
            .map(
                (file, index) => `
                <span class="ee-compose-chip">
                    ${icon('paperclip', 12)}
                    <span class="ee-compose-chip-name">${this.escapeHtml(file.name)}</span>
                    <span class="ee-compose-chip-size">${this.formatFileSize(file.size)}</span>
                    <button type="button" class="ee-compose-chip-remove" data-index="${index}" aria-label="Remove ${this.escapeHtml(file.name)}" title="Remove">${icon('close', 12)}</button>
                </span>`
            )
            .join('');
    }

    _readFileAsBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => {
                const result = String(reader.result || '');
                resolve(result.slice(result.indexOf(',') + 1));
            };
            reader.onerror = () => reject(reader.error || new Error(`Could not read ${file.name}`));
            reader.readAsDataURL(file);
        });
    }

    // Takes picked files into the form within the size limit. They are kept as File objects and
    // read only when the message is sent, so a removed file is never read at all.
    _addComposeFiles(files) {
        let total = this._compose.files.reduce((sum, file) => sum + file.size, 0);
        const skipped = [];
        for (const file of files) {
            if (total + file.size > this.maxAttachmentSize) {
                skipped.push(file.name);
                continue;
            }
            total += file.size;
            this._compose.files.push(file);
        }
        this._renderComposeChips();
        if (skipped.length) {
            this._showComposeError(`Attachments are limited to ${this.formatFileSize(this.maxAttachmentSize)} in total. Not attached: ${skipped.join(', ')}`);
        }
    }

    _readComposeAttachments(files) {
        return Promise.all(
            files.map(async file => ({
                filename: file.name,
                contentType: file.type || 'application/octet-stream',
                content: await this._readFileAsBase64(file)
            }))
        );
    }

    // The form as a submission: parsed recipients, the text, the reference and the picked files,
    // plus the first reason it cannot go out as asked (null when it can). requireMessage applies
    // the send rules: a recipient, and some text unless the message is a forward.
    _readComposeForm(requireMessage) {
        const { form } = this._compose.els;
        const fields = {};
        const invalid = [];
        for (const key of ['to', 'cc', 'bcc']) {
            fields[key] = this.parseAddressList(form.elements[key].value);
            invalid.push(...fields[key].filter(entry => !ADDRESS_PATTERN.test(entry.address)).map(entry => entry.address || entry.name));
        }

        let reference = this._compose.reference;
        const isForward = !!reference && reference.action === 'forward';
        if (isForward) {
            reference = { ...reference, forwardAttachments: form.elements.forwardAttachments.checked };
        }

        const draft = {
            to: fields.to,
            subject: form.elements.subject.value.trim(),
            text: form.elements.message.value,
            files: this._compose.files,
            options: { cc: fields.cc, bcc: fields.bcc, reference }
        };

        const empty = !fields.to.length && !fields.cc.length && !fields.bcc.length && !draft.subject && !draft.text.trim() && !draft.files.length && !reference;
        if (requireMessage && !fields.to.length) {
            draft.problem = { message: 'Add at least one recipient.', field: 'to' };
        } else if (!requireMessage && empty) {
            draft.problem = { message: 'Nothing to save - fill in at least one field first.', field: 'to' };
        } else if (invalid.length) {
            draft.problem = { message: `Not a valid email address: ${invalid.join(', ')}`, field: 'to' };
        } else if (requireMessage && !draft.text.trim() && !isForward) {
            // A forward can go without a note of its own; anything else needs some text
            draft.problem = { message: 'Write a message before sending.', field: 'message' };
        }
        return draft;
    }

    // Runs a compose request with its button showing progress. The form is checked first, the
    // picked files are read, and on success the form closes and the result is returned; on any
    // failure the reason is shown over the form, kept as it was, and the result is null.
    async _runComposeAction(button, busyText, errorTitle, requireMessage, submit) {
        const draft = this._readComposeForm(requireMessage);
        if (draft.problem) {
            this._showComposeError(draft.problem.message, draft.problem.field);
            return null;
        }
        this._clearComposeError();

        const originalText = button.textContent;
        button.disabled = true;
        button.textContent = busyText;
        try {
            const attachments = await this._readComposeAttachments(draft.files);
            const result = await submit(draft.to, draft.subject, draft.text, { ...draft.options, attachments });
            this._closeCompose();
            return result || {};
        } catch (error) {
            console.error(`${errorTitle}:`, error);
            this._showComposeError(`${errorTitle}: ${this._formatSendError(error)}`);
            return null;
        } finally {
            button.disabled = false;
            button.textContent = originalText;
        }
    }

    setupComposeModal() {
        if (typeof document === 'undefined' || !this.container) {
            return;
        }

        const modal = this.container.querySelector('.ee-compose-modal');
        const els = {
            modal,
            form: modal.querySelector('.ee-compose-form'),
            title: modal.querySelector('.ee-compose-title'),
            chips: modal.querySelector('.ee-compose-chips'),
            fileInput: modal.querySelector('.ee-compose-file-input'),
            forwardAttachments: modal.querySelector('.ee-compose-forward-attachments'),
            quote: modal.querySelector('.ee-compose-quote'),
            error: modal.querySelector('.ee-compose-error')
        };
        const { form, fileInput, chips } = els;
        this._compose = { els, reference: null, files: [] };

        this.container
            .querySelectorAll('.ee-compose-button, .ee-sidebar-compose-button')
            .forEach(button => button.addEventListener('click', () => this.compose()));

        const closeCompose = () => this._closeCompose();
        modal.querySelector('.ee-compose-close').addEventListener('click', closeCompose);
        modal.querySelector('.ee-compose-cancel').addEventListener('click', closeCompose);

        // Close on backdrop click
        modal.addEventListener('click', e => {
            if (e.target === modal) {
                closeCompose();
            }
        });

        // Close on Escape key
        this._composeKeydownHandler = e => {
            if (e.key === 'Escape' && modal.classList.contains('show')) {
                closeCompose();
            }
        };
        document.addEventListener('keydown', this._composeKeydownHandler);

        form.addEventListener('input', () => {
            if (!els.error.hidden) {
                this._clearComposeError();
            }
        });

        form.querySelector('[data-action="show-cc"]').addEventListener('click', () => {
            const ccShown = !form.querySelector('[data-field="cc"]').hidden;
            this._showCopyFields({ cc: true, bcc: true });
            (ccShown ? form.elements.bcc : form.elements.cc).focus();
        });

        form.querySelector('[data-action="attach"]').addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', () => {
            const files = Array.from(fileInput.files || []);
            fileInput.value = '';
            this._addComposeFiles(files);
        });
        chips.addEventListener('click', e => {
            const remove = e.target.closest('.ee-compose-chip-remove');
            if (remove) {
                this._compose.files.splice(Number(remove.dataset.index), 1);
                this._renderComposeChips();
            }
        });

        // Save the composed message as a draft instead of sending it
        const saveDraftButton = modal.querySelector('.ee-compose-save-draft');
        saveDraftButton.addEventListener('click', async () => {
            const response = await this._runComposeAction(saveDraftButton, 'Saving...', 'Could not save the draft', false, (...args) =>
                this.saveDraft(...args)
            );
            if (!response) {
                return;
            }
            this.notify('Draft saved to the Drafts folder.');
            // Refresh the list when the user is looking at the Drafts folder
            if (!this._destroyed && response.path && this.currentFolder === response.path) {
                this._fireAndForget(this.loadMessages(this.currentFolder));
            }
        });

        // Send email
        const sendButton = modal.querySelector('.ee-compose-send');
        sendButton.addEventListener('click', async () => {
            const response = await this._runComposeAction(sendButton, 'Sending...', 'Could not send the message', true, (...args) => this.sendMessage(...args));
            if (response) {
                // Submitting only queues the message; delivery happens afterwards and can still fail
                this.notify('Message queued for delivery.');
            }
        });

        // Handle Enter key in form (Ctrl+Enter to send)
        form.addEventListener('keydown', e => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                sendButton.click();
            }
        });
    }

    positionComposeButton() {
        if (typeof document === 'undefined' || !this.container) {
            return;
        }

        const composeButton = this.container.querySelector('.ee-compose-button');
        if (!composeButton) {
            return;
        }

        const sidebarCompose = this.container.querySelector('.ee-sidebar-compose');
        const updateButtonPosition = () => {
            const containerRect = this.container.getBoundingClientRect();
            const margin = 20; // Desired margin from edges
            const buttonSize = 56;

            // The floating button is the Compose button of the one-pane layout only. Whether
            // that layout is on is the stylesheet's container query to decide, so read its
            // answer (the folder pane's own Compose button is laid out) rather than repeat
            // the breakpoint. A hidden container (display: none) reports a zero-size rect;
            // the ResizeObserver below brings the button back once the container is shown.
            const wide = sidebarCompose && sidebarCompose.offsetParent !== null;
            if (wide || (!containerRect.width && !containerRect.height)) {
                composeButton.style.display = 'none';
                return;
            }
            composeButton.style.display = '';

            // Calculate the ideal position (bottom-right of container with margin)
            const idealBottom = window.innerHeight - containerRect.bottom + margin;
            const idealRight = window.innerWidth - containerRect.right + margin;

            // Ensure button stays within viewport bounds
            const minBottom = margin;
            const minRight = margin;

            // Also ensure button stays within container horizontal bounds
            const maxRight = window.innerWidth - containerRect.left - buttonSize - margin;

            // Calculate final position
            const bottom = Math.max(minBottom, idealBottom);
            const right = Math.min(Math.max(minRight, idealRight), maxRight);

            // Apply positioning
            composeButton.style.bottom = `${bottom}px`;
            composeButton.style.right = `${right}px`;
        };

        // Initial positioning
        updateButtonPosition();

        // Update position on scroll and resize
        const updateWithThrottle = this.throttle(updateButtonPosition, 16); // ~60fps
        window.addEventListener('scroll', updateWithThrottle);
        window.addEventListener('resize', updateWithThrottle);

        // Reposition when the container itself changes size or becomes visible - window
        // scroll/resize events never fire for those. Calls the update directly instead of
        // the throttled wrapper: the throttle drops trailing calls, which would leave the
        // button hidden when the observer fires twice in quick succession (initial
        // notification followed by the container being shown). Observer callbacks are
        // already batched per frame by the browser, so there is nothing to throttle.
        let resizeObserver = null;
        if (typeof ResizeObserver !== 'undefined') {
            resizeObserver = new ResizeObserver(updateButtonPosition);
            resizeObserver.observe(this.container);
        }

        // Cleanup runs from destroy()
        this._composeButtonCleanup = () => {
            window.removeEventListener('scroll', updateWithThrottle);
            window.removeEventListener('resize', updateWithThrottle);
            if (resizeObserver) {
                resizeObserver.disconnect();
                resizeObserver = null;
            }
        };
    }

    throttle(func, limit) {
        let inThrottle;
        return function () {
            const args = arguments;
            // eslint-disable-next-line no-invalid-this -- the wrapper forwards whatever this its caller bound
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => (inThrottle = false), limit);
            }
        };
    }

    init() {
        if (typeof document === 'undefined') {
            console.warn('EmailEngineClient UI features are only available in browser environments');
            return;
        }

        this.createStyles();
        this.createLayout();

        // Set up dark mode toggle
        const toggleBtn = this.container.querySelector('.ee-dark-mode-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggleDarkMode());
        }

        this._loadInitialView();
    }

    // Load the folder list and open the account's inbox. Used on startup and by
    // the Retry button that loadFolders renders when the request fails; both
    // failure paths already put an error panel in the UI, so the rejection is
    // logged and swallowed here rather than surfacing as an unhandled rejection.
    _loadInitialView() {
        // Drop whatever a previous attempt left here; loadFolders and loadMessages
        // paint their own loading states from this point on.
        this._setPaneHtml('.ee-message-list', this._messageListPlaceholder());

        // A deep-linked message loads alongside the folders, not after them. Only the first load
        // follows the link: a Retry after a folder failure starts from the inbox as usual. A
        // message that fails has already put its error in the viewer.
        const messageId = this.initialMessage;
        this.initialMessage = null;
        const message = messageId ? this.loadMessage(messageId).catch(() => null) : Promise.resolve(null);

        return this.loadFolders()
            .catch(error => {
                // loadFolders reports into the sidebar, but the message list is the
                // larger pane and would still read "Select a folder" - a folder the
                // sidebar can no longer offer. Say what happened there too.
                this._renderPaneError('.ee-message-list', 'Folders unavailable', error, () => this._loadInitialView());
                throw error;
            })
            .then(async () => this._listFolderOf(await message))
            .catch(error => {
                // Both loadFolders and loadMessages have already rendered a panel
                console.error('Failed to load the initial view:', error);
            });
    }

    _inboxFolder() {
        return (
            this.folders.find(f => f.specialUse && f.specialUse.includes('\\Inbox')) ||
            this.folders.find(f => f.name.toLowerCase() === 'inbox') ||
            this.folders[0]
        );
    }

    // Lists the folder holding a message, or the inbox when there is no message or it reports no
    // folder (Gmail API accounts) or one that is not listed
    _listFolderOf(message) {
        const folder = (message && message.path && this.folders.find(f => f.path === message.path)) || this._inboxFolder();
        if (folder && !this._destroyed) {
            return this.loadMessages(folder.path);
        }
    }

    // Opens one message by its EmailEngine ID and lists the folder holding it. A message that
    // cannot be loaded leaves its error in the viewer and the inbox in the list, so the reader
    // still has somewhere to go.
    async openMessage(messageId) {
        const [message] = await Promise.all([this.loadMessage(messageId).catch(() => null), this.folders.length ? null : this.loadFolders()]);
        await this._listFolderOf(message);
        return message;
    }

    _updateActivity() {
        this.lastActivity = Date.now();
    }

    _startKeepAliveTimer() {
        // Only start keep-alive for sess_ tokens
        if (!this.accessToken || !this.accessToken.startsWith('sess_')) {
            return;
        }

        // Clear existing timer if any
        if (this.keepAliveTimer) {
            clearInterval(this.keepAliveTimer);
        }

        // Check every minute if we need to ping
        this.keepAliveTimer = setInterval(() => {
            const now = Date.now();
            const idleTime = now - this.lastActivity;

            // If idle for 5+ minutes, ping to keep token alive
            if (idleTime >= 5 * 60 * 1000) {
                this._keepTokenAlive();
            }
        }, 60 * 1000); // Check every minute
    }

    async _keepTokenAlive() {
        try {
            // Ping account endpoint to keep token alive
            await this.apiRequest('GET', this._accountPath());
            console.debug('Keep-alive ping sent for sess_ token');
        } catch (error) {
            console.warn('Keep-alive ping failed:', error.message);
        }
    }

    // Set dark mode from the host application (does not touch the stored
    // preference - the builtin toggle owns that)
    setDarkMode(enabled) {
        this.darkMode = !!enabled;

        // DOM updates only apply to the rendered UI; skip without a container
        if (!this.container) {
            return;
        }

        // Update UI. The compose button and modal are siblings of .ee-client, so
        // they carry the class themselves.
        this.container
            .querySelectorAll('.ee-client, .ee-compose-button, .ee-compose-modal, .ee-toast')
            .forEach(el => el.classList.toggle('ee-dark-mode', this.darkMode));

        // Update toggle button icon
        const toggleIcon = this.container.querySelector('.ee-dark-mode-icon');
        if (toggleIcon) {
            toggleIcon.innerHTML = icon(this.darkMode ? 'sun' : 'moon', 14);
        }
    }

    toggleDarkMode() {
        this.setDarkMode(!this.darkMode);

        // Save preference
        if (typeof window !== 'undefined' && window.localStorage) {
            localStorage.setItem('ee-client-dark-mode', this.darkMode.toString());
        }
    }

    destroy() {
        // Mark destroyed first so any in-flight async completion skips
        // re-rendering into a torn-down or recreated container.
        this._destroyed = true;

        // Clean up keep-alive timer
        if (this.keepAliveTimer) {
            clearInterval(this.keepAliveTimer);
            this.keepAliveTimer = null;
        }

        clearTimeout(this._toastTimer);
        clearTimeout(this._otpCopyTimer);

        // Remove the compose button's window scroll/resize listeners
        if (this._composeButtonCleanup) {
            this._composeButtonCleanup();
            this._composeButtonCleanup = null;
        }

        // Remove the document-level Escape keydown listener
        if (this._composeKeydownHandler && typeof document !== 'undefined') {
            document.removeEventListener('keydown', this._composeKeydownHandler);
            this._composeKeydownHandler = null;
        }

        // Remove the injected stylesheet
        if (this._styleElement && this._styleElement.parentNode) {
            this._styleElement.parentNode.removeChild(this._styleElement);
            this._styleElement = null;
        }
    }
}

export function createEmailEngineClient(options) {
    if (!options || typeof options !== 'object') {
        throw new Error('Invalid options: expected an options object');
    }

    if (!options.account) {
        throw new Error('Account identifier is required');
    }

    if (!options.apiUrl) {
        console.warn('No API URL specified, using default http://127.0.0.1:3000');
    }

    const client = new EmailEngineClient(options);

    // The constructor is the single place that resolves containerId to an
    // element. In a DOM environment a containerId that matches nothing is a
    // caller error, so fail loudly here - and tear down the half-built client
    // so its keep-alive timer does not leak.
    if (options.containerId && !client.container && typeof document !== 'undefined') {
        client.destroy();
        throw new Error('Container element not found');
    }

    return client;
}

export default EmailEngineClient;
