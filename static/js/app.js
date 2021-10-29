/* global document, window, $ */

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
});
