export class EmailEngineClient {
    constructor(options = {}) {
        this.apiUrl = options.apiUrl || 'http://127.0.0.1:3000';
        this.account = options.account;
        this.accessToken = options.accessToken;
        this.container = options.container;
        this.confirmMethod =
            options.confirmMethod ||
            ((message, _title = 'Confirm', _cancelText = 'Cancel', _okText = 'OK') => confirm(message));
        this.alertMethod =
            options.alertMethod || ((message, _title = 'Notice', _cancelText = null, _okText = 'OK') => alert(message));

        this.currentFolder = null;
        this.currentMessage = null;
        this.folders = [];
        this.messages = [];
        this.nextPageCursor = null;
        this.prevPageCursor = null;

        // Keep-alive timer for sess_ tokens
        this.keepAliveTimer = null;
        this.lastActivity = Date.now();

        // Dark mode state
        this.darkMode = false;
        if (typeof window !== 'undefined' && window.localStorage) {
            this.darkMode = localStorage.getItem('ee-client-dark-mode') === 'true';
        }

        // Get page size from localStorage or options or default
        const savedPageSize =
            typeof window !== 'undefined' && window.localStorage ? localStorage.getItem('ee-client-page-size') : null;
        this.pageSize = savedPageSize ? parseInt(savedPageSize) : options.pageSize || 20;

        if (this.container) {
            this.init();
        }

        // Start keep-alive timer for sess_ tokens
        this._startKeepAliveTimer();
    }

    async apiRequest(method, endpoint, data = null) {
        // Update activity timestamp for keep-alive
        this._updateActivity();

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
            let errorDetails;
            try {
                errorDetails = await response.json();
            } catch (parseError) {
                // If JSON parsing fails, fall back to status text
                errorDetails = { message: response.statusText };
            }

            const error = new Error(`API request failed: ${response.statusText}`);
            error.statusCode = response.status;
            error.details = errorDetails;
            throw error;
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

            // Clear active email selection when folder changes
            this.currentMessage = null;

            if (this.container) {
                this.renderMessageList();
                this.renderFolderList(); // Re-render to update active state
                this.renderMessage(); // Clear message viewer
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

                // Scroll to top of the email client container
                this.container.scrollIntoView({ behavior: 'smooth', block: 'start' });

                // Also scroll the window to ensure visibility
                if (typeof window !== 'undefined') {
                    const containerTop = this.container.getBoundingClientRect().top + window.pageYOffset;
                    window.scrollTo({ top: containerTop, behavior: 'smooth' });
                }
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

    async sendMessage(to, subject, text) {
        try {
            const toAddresses = Array.isArray(to)
                ? to.map(addr => (typeof addr === 'string' ? { address: addr } : addr))
                : [typeof to === 'string' ? { address: to } : to];

            const messageData = {
                to: toAddresses,
                subject: subject,
                text: text
            };

            const response = await this.apiRequest('POST', `/v1/account/${this.account}/submit`, messageData);
            return response;
        } catch (error) {
            console.error('Failed to send message:', error);
            // Try to parse detailed error information
            this._parseApiError(error);
            throw error;
        }
    }

    _parseApiError(error) {
        try {
            // If error has response text, try to parse it
            if (error.message && error.message.includes('API request failed:')) {
                // This is our custom error from apiRequest, the actual response might have more details
                error.isDetailedError = false;
            }
        } catch (parseError) {
            // If parsing fails, just use the original error
            console.error('Failed to parse error details:', parseError);
        }
    }

    _formatSendError(error) {
        // If we have detailed error information from the API
        if (error.details && error.details.fields && Array.isArray(error.details.fields)) {
            const fieldErrors = error.details.fields.map(field => {
                // Try to make field errors more user-friendly
                let message = field.message;

                // Map technical field names to user-friendly names
                if (message.includes('to[0].address') || message.includes('"address"')) {
                    message = message.replace(/to\[\d+\]\.address|"address"/g, 'email address');
                }
                if (message.includes('"subject"')) {
                    message = message.replace('"subject"', 'subject');
                }
                if (message.includes('"text"')) {
                    message = message.replace('"text"', 'message');
                }

                return message;
            });

            const mainMessage = error.details.message || 'Failed to send email';
            if (fieldErrors.length > 0) {
                return `${mainMessage}:\n\n• ${fieldErrors.join('\n• ')}`;
            }
            return mainMessage;
        }

        // Fallback to generic error message
        return 'Failed to send email. Please check your input and try again.';
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
            this.alertMethod('Failed to download attachment. Please try again.', 'Download Error', null, 'OK');
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
            this.alertMethod('Failed to download original message. Please try again.', 'Download Error', null, 'OK');
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
                position: relative;
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
            
            .ee-compose-button {
                position: fixed;
                bottom: 20px;
                right: 20px;
                width: 56px;
                height: 56px;
                background: #007bff;
                border: none;
                border-radius: 50%;
                color: white;
                font-size: 24px;
                cursor: pointer;
                box-shadow: 0 4px 12px rgba(0,123,255,0.3);
                z-index: 1000;
                transition: all 0.2s ease;
            }
            
            .ee-compose-button:hover {
                background: #0056b3;
                transform: scale(1.05);
                box-shadow: 0 6px 16px rgba(0,123,255,0.4);
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
                max-height: 80vh;
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
                font-size: 24px;
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
                padding: 20px;
                display: flex;
                flex-direction: column;
                gap: 16px;
                flex: 1;
                overflow-y: auto;
            }
            
            .ee-compose-field {
                display: flex;
                flex-direction: column;
                gap: 4px;
            }
            
            .ee-compose-label {
                font-weight: 500;
                color: #333;
            }
            
            .ee-compose-input {
                padding: 8px 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
                font-family: inherit;
            }
            
            .ee-compose-input:focus {
                outline: none;
                border-color: #007bff;
                box-shadow: 0 0 0 2px rgba(0,123,255,0.1);
            }
            
            .ee-compose-textarea {
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
                font-family: inherit;
                resize: vertical;
                min-height: 200px;
            }
            
            .ee-compose-textarea:focus {
                outline: none;
                border-color: #007bff;
                box-shadow: 0 0 0 2px rgba(0,123,255,0.1);
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
                background: #007bff;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
            }
            
            .ee-compose-send:hover:not(:disabled) {
                background: #0056b3;
            }
            
            .ee-compose-send:disabled {
                background: #6c757d;
                cursor: not-allowed;
                opacity: 0.6;
            }
            
            .ee-compose-cancel {
                background: #6c757d;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 14px;
                cursor: pointer;
            }
            
            .ee-compose-cancel:hover {
                background: #545b62;
            }

            /* Dark mode toggle button */
            .ee-dark-mode-toggle {
                position: absolute;
                top: 8px;
                right: 16px;
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 3px;
                padding: 6px 10px;
                font-size: 12px;
                cursor: pointer;
                z-index: 100;
                transition: all 0.2s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #495057;
                font-weight: 500;
            }

            .ee-dark-mode-toggle:hover {
                background: #e9ecef;
                border-color: #adb5bd;
            }

            .ee-dark-mode-icon {
                font-size: 14px;
                line-height: 1;
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
                background: #0056b3;
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
                background: #1a3d5c;
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
                background: #252525;
                border-color: #333;
            }

            .ee-dark-mode .ee-attachment-item {
                background: #2a2a2a;
                border-color: #333;
            }

            .ee-dark-mode .ee-attachment-item:hover {
                background: #333;
            }

            .ee-dark-mode .ee-loading,
            .ee-dark-mode .ee-empty-state,
            .ee-dark-mode .ee-error {
                color: #999;
            }

            .ee-dark-mode .ee-pagination {
                background: #252525;
                border-color: #333;
            }

            .ee-dark-mode .ee-compose-button {
                background: #0056b3;
            }

            .ee-dark-mode .ee-compose-modal {
                background: rgba(0, 0, 0, 0.7);
            }

            .ee-dark-mode .ee-compose-content {
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
                border-color: #0056b3;
                box-shadow: 0 0 0 2px rgba(0,86,179,0.2);
            }

            .ee-dark-mode .ee-compose-actions {
                border-color: #333;
            }

            .ee-dark-mode .ee-compose-cancel {
                background: #444;
            }

            .ee-dark-mode .ee-compose-cancel:hover {
                background: #555;
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

        viewer.querySelector('[data-action="delete"]').addEventListener('click', async () => {
            const result = await this.confirmMethod(
                'Are you sure you want to delete this message? This action cannot be undone.',
                'Delete Message',
                'Cancel',
                'Delete'
            );
            if (result) {
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

        // Message content scrolling is now handled in loadMessage method
    }

    createLayout() {
        if (typeof document === 'undefined' || !this.container) {
            return;
        }

        this.container.innerHTML = `
            <div class="ee-client${this.darkMode ? ' ee-dark-mode' : ''}">
                <button class="ee-dark-mode-toggle" title="Toggle dark mode">
                    <span class="ee-dark-mode-icon">${this.darkMode ? '☀️' : '🌙'}</span>
                </button>
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
            <button class="ee-compose-button" title="Compose Email">✉</button>
            <div class="ee-compose-modal">
                <div class="ee-compose-dialog">
                    <div class="ee-compose-header">
                        <h3 class="ee-compose-title">Compose Email</h3>
                        <button class="ee-compose-close">×</button>
                    </div>
                    <form class="ee-compose-form">
                        <div class="ee-compose-field">
                            <label class="ee-compose-label">To:</label>
                            <input type="email" class="ee-compose-input" name="to" placeholder="recipient@example.com" required>
                        </div>
                        <div class="ee-compose-field">
                            <label class="ee-compose-label">Subject:</label>
                            <input type="text" class="ee-compose-input" name="subject" placeholder="Enter subject">
                        </div>
                        <div class="ee-compose-field">
                            <label class="ee-compose-label">Message:</label>
                            <textarea class="ee-compose-textarea" name="message" placeholder="Type your message here..." required></textarea>
                        </div>
                    </form>
                    <div class="ee-compose-actions">
                        <button type="button" class="ee-compose-cancel">Cancel</button>
                        <button type="button" class="ee-compose-send">Send</button>
                    </div>
                </div>
            </div>
        `;

        // Wire up compose modal events
        this.setupComposeModal();

        // Position compose button correctly
        this.positionComposeButton();
    }

    setupComposeModal() {
        if (typeof document === 'undefined' || !this.container) {
            return;
        }

        const composeButton = this.container.querySelector('.ee-compose-button');
        const modal = this.container.querySelector('.ee-compose-modal');
        const closeButton = this.container.querySelector('.ee-compose-close');
        const cancelButton = this.container.querySelector('.ee-compose-cancel');
        const sendButton = this.container.querySelector('.ee-compose-send');
        const form = this.container.querySelector('.ee-compose-form');

        // Open modal
        composeButton.addEventListener('click', () => {
            modal.classList.add('show');
            // Focus the To field
            const toField = form.querySelector('input[name="to"]');
            setTimeout(() => toField.focus(), 100);
        });

        // Close modal handlers
        const closeModal = () => {
            modal.classList.remove('show');
            form.reset();
        };

        closeButton.addEventListener('click', closeModal);
        cancelButton.addEventListener('click', closeModal);

        // Close on backdrop click
        modal.addEventListener('click', e => {
            if (e.target === modal) {
                closeModal();
            }
        });

        // Close on Escape key
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && modal.classList.contains('show')) {
                closeModal();
            }
        });

        // Send email
        sendButton.addEventListener('click', async () => {
            const formData = new FormData(form);
            const to = formData.get('to').trim();
            const subject = formData.get('subject').trim();
            const message = formData.get('message').trim();

            if (!to || !message) {
                // Close modal temporarily to show alert, then reopen
                modal.classList.remove('show');
                await this.alertMethod(
                    'Please fill in the recipient and message fields.',
                    'Validation Error',
                    null,
                    'OK'
                );
                modal.classList.add('show');
                // Re-focus the appropriate field
                const fieldToFocus = !to
                    ? form.querySelector('input[name="to"]')
                    : form.querySelector('textarea[name="message"]');
                setTimeout(() => fieldToFocus.focus(), 100);
                return;
            }

            // Disable send button and show loading state
            const originalText = sendButton.textContent;
            sendButton.disabled = true;
            sendButton.textContent = 'Sending...';

            try {
                await this.sendMessage(to, subject, message);
                // Close modal before showing success alert
                closeModal();
                await this.alertMethod('Email sent successfully!', 'Success', null, 'OK');
            } catch (error) {
                console.error('Failed to send email:', error);
                // Close modal before showing error alert
                modal.classList.remove('show');
                const errorMessage = this._formatSendError(error);
                await this.alertMethod(errorMessage, 'Send Error', null, 'OK');

                // Reopen modal with preserved values after error alert
                modal.classList.add('show');
                // Re-focus the To field to allow user to continue editing
                const toField = form.querySelector('input[name="to"]');
                setTimeout(() => toField.focus(), 100);
            } finally {
                // Re-enable send button
                sendButton.disabled = false;
                sendButton.textContent = originalText;
            }
        });

        // Handle Enter key in form (Ctrl+Enter to send)
        form.addEventListener('keydown', e => {
            if (e.key === 'Enter' && e.ctrlKey) {
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

        const updateButtonPosition = () => {
            const containerRect = this.container.getBoundingClientRect();
            const buttonSize = 56; // Button width/height
            const margin = 20; // Desired margin from edges

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

        // Store cleanup function for potential future use
        this._composeButtonCleanup = () => {
            window.removeEventListener('scroll', updateWithThrottle);
            window.removeEventListener('resize', updateWithThrottle);
        };
    }

    throttle(func, limit) {
        let inThrottle;
        return function () {
            const args = arguments;
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
            await this.apiRequest('GET', `/v1/account/${this.account}`);
            console.debug('Keep-alive ping sent for sess_ token');
        } catch (error) {
            console.warn('Keep-alive ping failed:', error.message);
        }
    }

    toggleDarkMode() {
        this.darkMode = !this.darkMode;

        // Save preference
        if (typeof window !== 'undefined' && window.localStorage) {
            localStorage.setItem('ee-client-dark-mode', this.darkMode.toString());
        }

        // Update UI
        const client = this.container.querySelector('.ee-client');
        if (client) {
            if (this.darkMode) {
                client.classList.add('ee-dark-mode');
            } else {
                client.classList.remove('ee-dark-mode');
            }
        }

        // Update toggle button icon
        const icon = this.container.querySelector('.ee-dark-mode-icon');
        if (icon) {
            icon.textContent = this.darkMode ? '☀️' : '🌙';
        }
    }

    destroy() {
        // Clean up keep-alive timer
        if (this.keepAliveTimer) {
            clearInterval(this.keepAliveTimer);
            this.keepAliveTimer = null;
        }
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
