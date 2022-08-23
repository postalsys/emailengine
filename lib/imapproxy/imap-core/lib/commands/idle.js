'use strict';

module.exports = {
    state: ['Authenticated', 'Selected'],

    handler(command, callback, next) {
        let idleTimeout = setTimeout(() => {
            if (typeof this._server.onIdleEnd === 'function') {
                this._server.onIdleEnd(this.selected && this.selected.mailbox, this.session);
            }
            this.send('* BYE IDLE terminated');
            setImmediate(() => this.close());
        }, this._server.options.idleTimeout || 30 * 60 * 1000);

        this._nextHandler = (token, next) => {
            this._nextHandler = false;
            this.idling = false;
            clearTimeout(idleTimeout);
            next(); // keep the parser flowing

            if (typeof this._server.onIdleEnd === 'function') {
                this._server.onIdleEnd(this.selected && this.selected.mailbox, this.session);
            }

            if (token.toUpperCase().trim() !== 'DONE') {
                return callback(new Error('Invalid Idle continuation (' + JSON.stringify(token) + ')'));
            }

            callback(null, {
                response: 'OK',
                message: 'IDLE terminated'
            });
        };

        this.idling = true;
        this.send('+ idling');
        this.emitNotifications(); // emit any pending notifications

        if (typeof this._server.onIdleStart === 'function') {
            this._server.onIdleStart(this.selected && this.selected.mailbox, this.session);
        }

        return next(); // resume input parser. Normally this is done by callback() but we need the next input sooner
    }
};
