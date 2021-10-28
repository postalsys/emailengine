/* global document */

'use strict';

document.addEventListener('DOMContentLoaded', () => {
    let toggleAllElements = (allElementsElm, otherElements, direction) => {
        if (!allElementsElm || !otherElements) {
            return;
        }

        const allSelected = allElementsElm.getAttribute('type') === 'checkbox' ? allElementsElm.checked : !allElementsElm.value.trim();
        for (let elm of otherElements) {
            console.log(elm);

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
