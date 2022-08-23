'use strict';

const quotes = [
    'All that’s left of proud Tristram, are ghosts and ashes.',
    'I shall purge this land of the shadow.',
    'Beware! Beyond lies mortal danger for the likes of you!',
    'This monastery reeks with evil and corruption.',
    'My duty here is done.',
    'This is no place for a warrior to die.',
    'Sisters, there was no other way.',
    'I hope I never live to be that wise...',
    'Turn back! I can tell that you need more experience to fight safely in the next wilderness.',
    'Stay a while and listen!'
];

module.exports = {
    handler(command) {
        this.session.selected = this.selected = false;
        this.state = 'Logout';

        this.clearNotificationListener();
        this.send('* BYE Logout requested');
        this.send(command.tag + ' OK ' + quotes[Math.floor(Math.random() * quotes.length)]);
        setImmediate(() => this.close());
    }
};
