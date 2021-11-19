/* global document, window, $, ClipboardJS, FileReader */

'use strict';

window.showToast = (message, icon) => {
    let template = `<div class="toast-header">
    <img src="/static/icons/${icon ? icon : 'info'}.svg" class="rounded mr-2">
    <strong class="mr-auto">EmailEngine</strong>
    <button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close">
      <span aria-hidden="true">&times;</span>
    </button>
  </div>
  <div class="toast-body"></div>`;

    let toast = document.createElement('div');
    toast.classList.add('toast', 'show', 'fade');
    toast.dataset.delay = '5000';
    toast.dataset.autohide = 'true';

    toast.innerHTML = template;
    toast.querySelector('.toast-body').textContent = message;
    document.getElementById('toastContainer').appendChild(toast);

    $(toast).toast('show');
};

document.addEventListener('DOMContentLoaded', () => {
    let toggleAllElements = (allElementsElm, otherElements, direction) => {
        if (!allElementsElm || !otherElements) {
            return;
        }

        const allSelected = allElementsElm.getAttribute('type') === 'checkbox' ? allElementsElm.checked : !allElementsElm.value.trim();
        for (let elm of otherElements) {
            if (elm.classList.contains('dropdown-item')) {
                if (direction && allSelected) {
                    elm.classList.add('disabled');
                } else {
                    elm.classList.remove('disabled');
                }
            } else {
                elm.disabled = direction ? allSelected : !allSelected;
            }
        }
    };

    let allElementsElms = document.querySelectorAll('.or-else-all');
    for (let allElementsElm of allElementsElms) {
        let otherElements;
        let direction = allElementsElm && allElementsElm.dataset.reverse === 'true' ? false : true;

        if (allElementsElm && allElementsElm.dataset.target) {
            otherElements = document.querySelectorAll(`.${allElementsElm.dataset.target.trim()}`);
        }

        if (!otherElements) {
            continue;
        }

        for (let elm of [allElementsElm].concat(Array.from(otherElements))) {
            elm.addEventListener('change', () => toggleAllElements(allElementsElm, otherElements, direction));
            elm.addEventListener('click', () => toggleAllElements(allElementsElm, otherElements, direction));
        }

        if (allElementsElm) {
            toggleAllElements(allElementsElm, otherElements, direction);
        }
    }

    const formatter = new Intl.RelativeTimeFormat(undefined, {
        numeric: 'auto'
    });

    const DIVISIONS = [
        { amount: 60, name: 'seconds' },
        { amount: 60, name: 'minutes' },
        { amount: 24, name: 'hours' },
        { amount: 7, name: 'days' },
        { amount: 4.34524, name: 'weeks' },
        { amount: 12, name: 'months' },
        { amount: Number.POSITIVE_INFINITY, name: 'years' }
    ];

    function formatTimeAgo(date) {
        let duration = (date - new Date()) / 1000;

        for (let i = 0; i <= DIVISIONS.length; i++) {
            const division = DIVISIONS[i];
            if (Math.abs(duration) < division.amount) {
                return formatter.format(Math.round(duration), division.name);
            }
            duration /= division.amount;
        }
    }

    let updateRelativeTimes = () => {
        document.querySelectorAll('.relative-time').forEach(entry => {
            let time = new Date(entry.dataset.time);
            if (time) {
                entry.textContent = formatTimeAgo(time);
            }
        });
    };

    updateRelativeTimes();
    setInterval(updateRelativeTimes, 15 * 1000);

    let clip = new ClipboardJS('.copy-btn');
    if (!clip) {
        console.log('Can not set up clipboard');
    }

    // enable tooltips
    $('[data-toggle="tooltip"]').tooltip();
    $('[data-toggle="popover"]').popover();

    function dropfile(elm, file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            elm.value = (e.target.result || '').trim();
            elm.focus();
            elm.select();
        };
        reader.readAsText(file, 'UTF-8');
    }

    for (let elm of document.querySelectorAll('.droptxt')) {
        elm.addEventListener('dragenter', () => {
            elm.classList.add('dragover');
        });

        elm.addEventListener('dragleave', () => {
            elm.classList.remove('dragover');
        });

        elm.addEventListener('drop', e => {
            e.preventDefault();
            elm.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            dropfile(elm, file);
        });

        elm.addEventListener('click', () => {
            elm.focus();
            elm.select();
        });
    }

    for (let elm of document.querySelectorAll('.cur-base-url')) {
        let origin = elm.dataset.origin || window.location.origin;
        if (elm.getAttribute('type') === 'text') {
            elm.value = origin;
        } else {
            elm.textContent = origin;
        }
    }
});
