export class EmailEngineClient {
    constructor(options = {}) {
        this.apiUrl = options.apiUrl || 'http://127.0.0.1:3000';
        this.account = options.account;
        this.accessToken = options.accessToken;
        this.container = options.container;

        this.currentFolder = null;
        this.currentMessage = null;
        this.folders = [];
        this.messages = [];
        this.nextPageCursor = null;
        this.prevPageCursor = null;

        // Get page size from localStorage or options or default
        const savedPageSize =
            typeof window !== 'undefined' && window.localStorage ? localStorage.getItem('ee-client-page-size') : null;
        this.pageSize = savedPageSize ? parseInt(savedPageSize) : options.pageSize || 20;

        if (this.container) {
            this.init();
        }
    }

    async apiRequest(method, endpoint, data = null) {
        const url = `${this.apiUrl}${endpoint}`;
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        if (this.accessToken) {
            options.headers['Authorization'] = `Bearer ${this.accessToken}`;
        }

        if (data) {
            options.body = JSON.stringify(data);
        }

        let fetchFn = globalThis.fetch;
        if (!fetchFn && typeof require !== 'undefined') {
            try {
                const nodeFetch = await import('node-fetch');
                fetchFn = nodeFetch.default;
            } catch (err) {
                throw new Error(
                    'fetch is not available. In Node.js environments, please install node-fetch: npm install node-fetch'
                );
            }
        }

        if (!fetchFn) {
            throw new Error('fetch is not available');
        }

        const response = await fetchFn(url, options);
        if (!response.ok) {
            throw new Error(`API request failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async loadFolders() {
        try {
            const data = await this.apiRequest('GET', `/v1/account/${this.account}/mailboxes`);
            this.folders = data.mailboxes || [];
            if (this.container) {
                this.renderFolderList();
            }
            return this.folders;
        } catch (error) {
            console.error('Failed to load folders:', error);
            throw error;
        }
    }

    async loadMessages(path, cursor = null) {
        if (this.container) {
            const messageList = this.container.querySelector('.ee-message-list');
            if (messageList) {
                messageList.innerHTML = '<div class="ee-loading">Loading messages...</div>';
            }
        }

        try {
            const params = new URLSearchParams({ path: path, pageSize: this.pageSize });
            if (cursor) {
                params.set('cursor', cursor);
            }

            const data = await this.apiRequest('GET', `/v1/account/${this.account}/messages?${params}`);
            this.messages = data.messages || [];
            this.currentFolder = path;
            this.nextPageCursor = data.nextPageCursor || null;
            this.prevPageCursor = data.prevPageCursor || null;

            if (this.container) {
                this.renderMessageList();
                this.renderFolderList(); // Re-render to update active state
            }

            return {
                messages: this.messages,
                nextPageCursor: this.nextPageCursor,
                prevPageCursor: this.prevPageCursor
            };
        } catch (error) {
            console.error('Failed to load messages:', error);
            if (this.container) {
                const messageList = this.container.querySelector('.ee-message-list');
                if (messageList) {
                    messageList.innerHTML = '<div class="ee-error">Failed to load messages</div>';
                }
            }
            throw error;
        }
    }

    async loadMessage(messageId) {
        if (this.container) {
            const viewer = this.container.querySelector('.ee-message-viewer');
            if (viewer) {
                viewer.innerHTML = '<div class="ee-loading">Loading message...</div>';
            }
        }

        try {
            const params = new URLSearchParams({
                webSafeHtml: true,
                markAsSeen: true
            });
            const data = await this.apiRequest('GET', `/v1/account/${this.account}/message/${messageId}?${params}`);
            this.currentMessage = data;

            this.currentMessage.unseen = false;

            const msg = this.messages.find(m => m.id === messageId);
            if (msg) {
                msg.unseen = false;
                if (this.container) {
                    this.renderMessageList();
                }
            }

            if (this.container) {
                this.renderMessage();
            }

            return this.currentMessage;
        } catch (error) {
            console.error('Failed to load message:', error);
            if (this.container) {
                const viewer = this.container.querySelector('.ee-message-viewer');
                if (viewer) {
                    viewer.innerHTML = '<div class="ee-error">Failed to load message</div>';
                }
            }
            throw error;
        }
    }

    async markAsRead(messageId, seen = true) {
        try {
            const flagUpdate = seen ? { flags: { add: ['\\Seen'] } } : { flags: { delete: ['\\Seen'] } };

            await this.apiRequest('PUT', `/v1/account/${this.account}/message/${messageId}`, flagUpdate);

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

    async deleteMessage(messageId) {
        try {
            await this.apiRequest('DELETE', `/v1/account/${this.account}/message/${messageId}`);

            this.messages = this.messages.filter(m => m.id !== messageId);
            if (this.container) {
                this.renderMessageList();
            }

            if (this.currentMessage && this.currentMessage.id === messageId) {
                this.currentMessage = null;
                if (this.container) {
                    this.renderMessage();
                }
            }

            return true;
        } catch (error) {
            console.error('Failed to delete message:', error);
            throw error;
        }
    }

    async moveMessage(messageId, targetPath) {
        try {
            await this.apiRequest('PUT', `/v1/account/${this.account}/message/${messageId}/move`, {
                path: targetPath
            });

            this.messages = this.messages.filter(m => m.id !== messageId);
            if (this.container) {
                this.renderMessageList();
            }

            if (this.currentMessage && this.currentMessage.id === messageId) {
                this.currentMessage = null;
                if (this.container) {
                    this.renderMessage();
                }
            }

            return true;
        } catch (error) {
            console.error('Failed to move message:', error);
            throw error;
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

    formatFileSize(bytes) {
        if (!bytes) {
            return '';
        }
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round((bytes / Math.pow(1024, i)) * 100) / 100 + ' ' + sizes[i];
    }

    async downloadAttachment(attachmentId, suggestedFilename = null) {
        try {
            const headers = {};
            if (this.accessToken) {
                headers['Authorization'] = `Bearer ${this.accessToken}`;
            }

            const response = await fetch(`${this.apiUrl}/v1/account/${this.account}/attachment/${attachmentId}`, {
                headers,
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            // Get filename from Content-Disposition header if available
            const contentDisposition = response.headers.get('content-disposition');
            let filename = suggestedFilename || 'attachment';
            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
                if (filenameMatch && filenameMatch[1]) {
                    filename = filenameMatch[1].replace(/['"]/g, '');
                }
            }

            // Get the attachment data
            const blob = await response.blob();

            // Create a download link
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Failed to download attachment:', error);
            alert('Failed to download attachment');
        }
    }

    async downloadOriginalMessage(messageId, subject = null) {
        try {
            const headers = {};
            if (this.accessToken) {
                headers['Authorization'] = `Bearer ${this.accessToken}`;
            }

            const response = await fetch(`${this.apiUrl}/v1/account/${this.account}/message/${messageId}/source`, {
                headers,
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            // Get the email data
            const blob = await response.blob();

            // Create filename based on subject and date
            const now = new Date();
            const dateStr = now.toISOString().split('T')[0];
            const safeSubject = subject ? subject.replace(/[^a-z0-9]/gi, '_').substring(0, 50) : 'email';
            const filename = `${dateStr}_${safeSubject}.eml`;

            // Create a download link
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Failed to download original message:', error);
            alert('Failed to download original message');
        }
    }

    createStyles() {
        if (typeof document === 'undefined') {
            return;
        }

        const style = document.createElement('style');
        style.textContent = `
            .ee-client {
                display: flex;
                height: 100%;
                min-height: 400px;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                font-size: 14px;
                line-height: 1.5;
                color: #333;
                background: #fff;
                border: 1px solid #ddd;
            }
            
            .ee-client * {
                box-sizing: border-box;
            }
            
            .ee-sidebar {
                width: 200px;
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
                background: #007bff;
                color: white;
            }
            
            .ee-folder-item.active::before {
                content: '';
                position: absolute;
                left: 0;
                top: 0;
                bottom: 0;
                width: 3px;
                background: #0056b3;
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
                width: 350px;
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
                background: #e3f2fd;
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
                display: inline-block;
                font-size: 11px;
                color: #666;
                margin-left: 8px;
            }
            
            .ee-attachment-indicator::before {
                content: "📎 ";
            }
            
            .ee-message-viewer {
                flex: 1;
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }
            
            .ee-message-actions {
                padding: 10px 16px;
                background: #e9ecef;
                background: linear-gradient(to bottom, #f8f9fa, #e9ecef);
                border-bottom: 2px solid #dee2e6;
                display: flex;
                gap: 8px;
                height: 44px;
                align-items: center;
                flex-shrink: 0;
                box-sizing: border-box;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            
            .ee-button {
                padding: 4px 10px;
                border: 1px solid #ddd;
                background: white;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
                height: 24px;
                line-height: 1;
                box-sizing: border-box;
            }
            
            select.ee-button {
                padding: 3px 10px;
                height: 24px;
            }
            
            .ee-button:hover:not(:disabled) {
                background: #f0f0f0;
            }
            
            .ee-button:disabled {
                background: #e9ecef;
                color: #6c757d;
                cursor: not-allowed;
                opacity: 0.6;
            }
            
            .ee-message-content {
                flex: 1;
                padding: 16px;
                overflow-y: auto;
            }
            
            .ee-message-meta {
                margin-bottom: 16px;
                padding-bottom: 16px;
                border-bottom: 1px solid #e0e0e0;
            }
            
            .ee-message-meta-row {
                margin-bottom: 4px;
            }
            
            .ee-message-meta-label {
                display: inline-block;
                width: 60px;
                color: #666;
                font-weight: 500;
            }
            
            .ee-message-body {
                line-height: 1.6;
            }
            
            .ee-message-body img {
                max-width: 100%;
                height: auto;
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
                margin-right: 8px;
                font-size: 18px;
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
                padding: 10px 16px;
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
            
            .ee-pane-title {
                font-weight: 500;
                font-size: 14px;
                color: #333;
            }
            
            .ee-folder-tree {
                flex: 1;
                overflow-y: auto;
            }
            
            .ee-pagination-controls {
                display: flex;
                gap: 8px;
                align-items: center;
            }
            
            .ee-page-size-selector {
                display: flex;
                gap: 4px;
                align-items: center;
                margin-left: auto;
            }
            
            .ee-page-size-label {
                font-size: 12px;
                color: #666;
            }
            
            .ee-page-size-select {
                font-size: 11px;
                padding: 2px 4px;
                border: 1px solid #ddd;
                border-radius: 3px;
                background: white;
                cursor: pointer;
                height: 22px;
            }
            
            .ee-pagination-btn {
                font-size: 11px;
                padding: 3px 8px;
                height: 22px;
                line-height: 1;
            }
            
            .ee-message-items {
                flex: 1;
                overflow-y: auto;
            }
        `;
        document.head.appendChild(style);
    }

    calculateFolderDepth(folder) {
        if (!folder.parentPath || !folder.delimiter) {
            return 0;
        }

        const pathParts = folder.path.split(folder.delimiter);
        return Math.max(0, pathParts.length - 1);
    }

    buildFolderTree() {
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

        const buildHierarchy = (folders, parentPath = null, depth = 0) => {
            const result = [];

            const children = folders.filter(f => {
                if (parentPath === null) {
                    return f.parentPath === 'INBOX' || !f.parentPath || f.parentPath === '';
                } else {
                    return f.parentPath === parentPath;
                }
            });

            children.sort((a, b) => a.name.localeCompare(b.name));

            children.forEach(folder => {
                result.push(folder);
                result.push(...buildHierarchy(folders, folder.path, depth + 1));
            });

            return result;
        };

        const hierarchicalRegular = buildHierarchy(regularFolders);

        return [...specialFolders, ...hierarchicalRegular];
    }

    renderFolderList() {
        if (typeof document === 'undefined' || !this.container) {
            return;
        }

        const folderTree = this.container.querySelector('.ee-folder-tree');
        if (!folderTree) {
            return;
        }

        const sortedFolders = this.buildFolderTree();

        const html = `
            <ul class="ee-folder-list">
                ${sortedFolders
                    .map(folder => {
                        const depth = this.calculateFolderDepth(folder);
                        const hasChildren = this.folders.some(f => f.parentPath === folder.path);
                        return `
                        <li class="ee-folder-item ${folder.path === this.currentFolder ? 'active' : ''}" 
                            data-path="${folder.path}" 
                            data-depth="${depth}">
                            <div class="ee-folder-content" style="padding-left: ${8 + depth * 12}px;">
                                ${depth > 0 ? '<span class="ee-folder-indent">└ </span>' : ''}
                                <span class="ee-folder-name ${hasChildren ? 'has-children' : ''}">${folder.name}</span>
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
                this.loadMessages(path);
            });
        });
    }

    renderMessageList() {
        if (typeof document === 'undefined' || !this.container) {
            return;
        }

        const messageList = this.container.querySelector('.ee-message-list');
        if (!messageList) {
            return;
        }

        if (!this.messages.length) {
            messageList.innerHTML = `
                <div class="ee-pane-header">
                    <span class="ee-pane-title">Messages</span>
                </div>
                <div class="ee-empty-state">No messages</div>
            `;
            return;
        }

        const hasPagination = this.nextPageCursor || this.prevPageCursor;

        const html = `
            <div class="ee-pane-header">
                <span class="ee-pane-title">Messages</span>
                <div class="ee-pagination-controls">
                    ${
                        hasPagination
                            ? `
                        ${this.prevPageCursor ? `<button class="ee-button ee-pagination-btn" data-action="prev-page">← Previous</button>` : ''}
                        ${this.nextPageCursor ? `<button class="ee-button ee-pagination-btn" data-action="next-page">Next →</button>` : ''}
                    `
                            : ''
                    }
                    <div class="ee-page-size-selector">
                        <span class="ee-page-size-label">Show:</span>
                        <select class="ee-page-size-select" data-action="page-size">
                            <option value="10" ${this.pageSize === 10 ? 'selected' : ''}>10</option>
                            <option value="20" ${this.pageSize === 20 ? 'selected' : ''}>20</option>
                            <option value="30" ${this.pageSize === 30 ? 'selected' : ''}>30</option>
                            <option value="50" ${this.pageSize === 50 ? 'selected' : ''}>50</option>
                            <option value="100" ${this.pageSize === 100 ? 'selected' : ''}>100</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="ee-message-items">
                ${this.messages
                    .map(
                        msg => `
                    <div class="ee-message-item ${msg.unseen ? 'unread' : ''} ${msg.id === (this.currentMessage && this.currentMessage.id) ? 'active' : ''}" data-id="${msg.id}">
                        <div class="ee-message-header">
                            <span class="ee-message-from">${msg.from ? msg.from.name || msg.from.address : 'Unknown'}</span>
                            <span class="ee-message-date">${this.formatDate(msg.date)}</span>
                        </div>
                        <div class="ee-message-subject">
                            <span class="ee-message-subject-text">${msg.subject || '(no subject)'}</span>
                            ${msg.attachments && msg.attachments.length > 0 ? `<span class="ee-attachment-indicator">${msg.attachments.length}</span>` : ''}
                        </div>
                        <div class="ee-message-preview">${msg.intro || ''}</div>
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
                this.loadMessage(messageId);
            });
        });

        messageList.querySelectorAll('[data-action="prev-page"]').forEach(btn => {
            btn.addEventListener('click', () => {
                this.loadMessages(this.currentFolder, this.prevPageCursor);
            });
        });

        messageList.querySelectorAll('[data-action="next-page"]').forEach(btn => {
            btn.addEventListener('click', () => {
                this.loadMessages(this.currentFolder, this.nextPageCursor);
            });
        });

        const pageSizeSelect = messageList.querySelector('[data-action="page-size"]');
        if (pageSizeSelect) {
            pageSizeSelect.addEventListener('change', e => {
                this.pageSize = parseInt(e.target.value);
                // Save to localStorage
                if (typeof window !== 'undefined' && window.localStorage) {
                    localStorage.setItem('ee-client-page-size', this.pageSize.toString());
                }
                this.loadMessages(this.currentFolder);
            });
        }
    }

    renderMessage() {
        if (typeof document === 'undefined' || !this.container) {
            return;
        }

        const viewer = this.container.querySelector('.ee-message-viewer');
        if (!viewer) {
            return;
        }

        if (!this.currentMessage) {
            viewer.innerHTML = '<div class="ee-empty-state">Select a message to view</div>';
            return;
        }

        const msg = this.currentMessage;
        const isUnseen = msg.unseen;
        const html = `
            <div class="ee-message-actions">
                <button class="ee-button" data-action="toggle-read">Mark as ${isUnseen ? 'seen' : 'unseen'}</button>
                <button class="ee-button" data-action="delete">Delete</button>
                <button class="ee-button" data-action="download-original">Download Original</button>
                <select class="ee-button" data-action="move">
                    <option value="">Move to...</option>
                    ${this.buildFolderTree()
                        .map(folder => {
                            const depth = this.calculateFolderDepth(folder);
                            const indent = '　'.repeat(depth);
                            const prefix = depth > 0 ? '└ ' : '';
                            return `<option value="${folder.path}" ${folder.path === this.currentFolder ? 'disabled' : ''}>${indent}${prefix}${folder.name}</option>`;
                        })
                        .join('')}
                </select>
            </div>
            <div class="ee-message-content">
                <div class="ee-message-meta">
                    <div class="ee-message-meta-row">
                        <span class="ee-message-meta-label">From:</span>
                        ${msg.from ? `${msg.from.name || ''} &lt;${msg.from.address}&gt;` : 'Unknown'}
                    </div>
                    <div class="ee-message-meta-row">
                        <span class="ee-message-meta-label">To:</span>
                        ${msg.to ? msg.to.map(t => `${t.name || ''} &lt;${t.address}&gt;`).join(', ') : ''}
                    </div>
                    ${
                        msg.cc && msg.cc.length
                            ? `
                        <div class="ee-message-meta-row">
                            <span class="ee-message-meta-label">Cc:</span>
                            ${msg.cc.map(c => `${c.name || ''} &lt;${c.address}&gt;`).join(', ')}
                        </div>
                    `
                            : ''
                    }
                    <div class="ee-message-meta-row">
                        <span class="ee-message-meta-label">Date:</span>
                        ${new Date(msg.date).toLocaleString()}
                    </div>
                    <div class="ee-message-meta-row">
                        <span class="ee-message-meta-label">Subject:</span>
                        ${msg.subject || '(no subject)'}
                    </div>
                </div>
                <div class="ee-message-body">
                    ${msg.text && msg.text.html ? msg.text.html : msg.text && msg.text.plain ? `<pre>${msg.text.plain}</pre>` : ''}
                </div>
                ${
                    msg.attachments && msg.attachments.length > 0
                        ? `
                    <div class="ee-attachments">
                        <div class="ee-attachments-title">Attachments (${msg.attachments.length})</div>
                        ${msg.attachments
                            .map(
                                att => `
                            <div class="ee-attachment-item" data-attachment-id="${att.id}">
                                <div class="ee-attachment-icon">📎</div>
                                <div class="ee-attachment-info">
                                    <div class="ee-attachment-name">${att.filename || 'Unnamed attachment'}</div>
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

        viewer.querySelector('[data-action="toggle-read"]').addEventListener('click', () => {
            const currentlyUnseen = msg.unseen;
            this.markAsRead(msg.id, currentlyUnseen);
        });

        viewer.querySelector('[data-action="delete"]').addEventListener('click', () => {
            if (confirm('Delete this message?')) {
                this.deleteMessage(msg.id);
            }
        });

        viewer.querySelector('[data-action="download-original"]').addEventListener('click', () => {
            this.downloadOriginalMessage(msg.id, msg.subject);
        });

        viewer.querySelector('[data-action="move"]').addEventListener('change', e => {
            const targetPath = e.target.value;
            if (targetPath) {
                this.moveMessage(msg.id, targetPath);
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
    }

    createLayout() {
        if (typeof document === 'undefined' || !this.container) {
            return;
        }

        this.container.innerHTML = `
            <div class="ee-client">
                <div class="ee-sidebar">
                    <div class="ee-pane-header">
                        <span class="ee-pane-title">Folders</span>
                    </div>
                    <div class="ee-folder-tree">
                        <div class="ee-loading">Loading folders...</div>
                    </div>
                </div>
                <div class="ee-message-list">
                    <div class="ee-pane-header">
                        <span class="ee-pane-title">Messages</span>
                    </div>
                    <div class="ee-empty-state">Select a folder</div>
                </div>
                <div class="ee-message-viewer">
                    <div class="ee-empty-state">Select a message to view</div>
                </div>
            </div>
        `;
    }

    init() {
        if (typeof document === 'undefined') {
            console.warn('EmailEngineClient UI features are only available in browser environments');
            return;
        }

        this.createStyles();
        this.createLayout();
        this.loadFolders()
            .then(() => {
                const inbox =
                    this.folders.find(f => f.specialUse && f.specialUse.includes('\\Inbox')) ||
                    this.folders.find(f => f.name.toLowerCase() === 'inbox') ||
                    this.folders[0];
                if (inbox) {
                    this.loadMessages(inbox.path);
                }
            })
            .catch(error => {
                console.error('Failed to auto-select inbox:', error);
            });
    }
}

export function createEmailEngineClient(options) {
    if (typeof options === 'string') {
        options = {
            container: typeof document !== 'undefined' ? document.getElementById(options) : null
        };
    } else if (typeof HTMLElement !== 'undefined' && options instanceof HTMLElement) {
        options = {
            container: options
        };
    } else if (typeof options === 'object' && options.containerId) {
        options.container = typeof document !== 'undefined' ? document.getElementById(options.containerId) : null;
    }

    if (options.container && !options.container) {
        throw new Error('Container element not found');
    }

    if (!options.apiUrl) {
        console.warn('No API URL specified, using default http://127.0.0.1:3000');
    }

    if (!options.account) {
        throw new Error('Account identifier is required');
    }

    return new EmailEngineClient(options);
}

export default EmailEngineClient;
