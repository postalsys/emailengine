/* global document, window, $ */

'use strict';

/*
 * Residual Bootstrap 4 tooltip/popover shim for the Tailwind v4 + FlyonUI
 * admin theme.
 *
 * Everything else from the migration-era shim (modal, alert, collapse, tab,
 * dropdown) has been removed - all views use native FlyonUI markup now. What
 * remains is the one legacy contract that survived the reskin: the SSE-driven
 * state badges and the TLS certificate labels, whose data-title/data-content
 * hover popovers and title tooltips are repainted at runtime by
 * static/js/app.js and the smtp/imap-proxy page scripts through
 * $().popover()/$().tooltip(). The bubbles are styled by the .bs-compat-*
 * rules in static/css/src/bootstrap-compat.css.
 */

(function () {
    if (typeof $ === 'undefined' || !$.fn) {
        return;
    }

    function positionFloating(elm, anchor, placement) {
        let rect = anchor.getBoundingClientRect();
        let scrollX = window.scrollX || window.pageXOffset;
        let scrollY = window.scrollY || window.pageYOffset;

        elm.style.visibility = 'hidden';
        document.body.appendChild(elm);
        let size = elm.getBoundingClientRect();

        let top, left;
        switch (placement) {
            case 'left':
                top = scrollY + rect.top + rect.height / 2 - size.height / 2;
                left = scrollX + rect.left - size.width - 6;
                break;
            case 'right':
                top = scrollY + rect.top + rect.height / 2 - size.height / 2;
                left = scrollX + rect.right + 6;
                break;
            case 'bottom':
                top = scrollY + rect.bottom + 6;
                left = scrollX + rect.left + rect.width / 2 - size.width / 2;
                break;
            case 'top':
            default:
                top = scrollY + rect.top - size.height - 6;
                left = scrollX + rect.left + rect.width / 2 - size.width / 2;
        }

        elm.style.top = `${Math.max(0, top)}px`;
        elm.style.left = `${Math.max(0, left)}px`;
        elm.style.visibility = '';
    }

    // --- Tooltip ---------------------------------------------------------------

    let tooltipElm = null;
    let tooltipAnchor = null;

    function hideTooltip() {
        if (tooltipElm) {
            tooltipElm.remove();
            tooltipElm = null;
            tooltipAnchor = null;
        }
    }

    function showTooltip(anchor) {
        if (anchor.dataset.bsCompatTooltipDisabled === 'true') {
            return;
        }
        // stash the native title so the browser tooltip does not double up
        let title = anchor.getAttribute('title');
        if (title) {
            anchor.setAttribute('data-original-title', title);
            anchor.removeAttribute('title');
        }
        let text = anchor.getAttribute('data-original-title');
        if (!text) {
            return;
        }
        hideTooltip();
        tooltipElm = document.createElement('div');
        tooltipElm.classList.add('bs-compat-tooltip');
        tooltipElm.textContent = text;
        tooltipAnchor = anchor;
        positionFloating(tooltipElm, anchor, anchor.dataset.placement || 'top');
    }

    $.fn.tooltip = function (action) {
        return this.each(function () {
            switch (action) {
                case 'hide':
                case 'dispose':
                    hideTooltip();
                    break;
                case 'disable':
                    this.dataset.bsCompatTooltipDisabled = 'true';
                    break;
                case 'enable':
                    delete this.dataset.bsCompatTooltipDisabled;
                    break;
                default:
                // lazy init - hover delegation below handles display
            }
        });
    };

    // --- Popover ---------------------------------------------------------------

    let popoverElm = null;
    let popoverAnchor = null;

    function hidePopover() {
        if (popoverElm) {
            popoverElm.remove();
            popoverElm = null;
            popoverAnchor = null;
        }
    }

    function showPopover(anchor) {
        if (anchor.dataset.bsCompatPopoverDisabled === 'true') {
            return;
        }
        let title = anchor.dataset.title || '';
        let content = anchor.dataset.content || '';
        if (!title && !content) {
            return;
        }

        hidePopover();
        popoverElm = document.createElement('div');
        popoverElm.classList.add('bs-compat-popover');

        if (title) {
            let headerElm = document.createElement('h3');
            headerElm.classList.add('bs-compat-popover-header');
            headerElm.textContent = title;
            popoverElm.appendChild(headerElm);
        }

        let bodyElm = document.createElement('div');
        bodyElm.classList.add('bs-compat-popover-body');
        bodyElm.textContent = content;
        popoverElm.appendChild(bodyElm);

        popoverAnchor = anchor;
        positionFloating(popoverElm, anchor, anchor.dataset.placement || 'top');
    }

    $.fn.popover = function (action) {
        return this.each(function () {
            switch (action) {
                case 'hide':
                case 'dispose':
                    if (popoverAnchor === this) {
                        hidePopover();
                    }
                    break;
                case 'disable':
                    this.dataset.bsCompatPopoverDisabled = 'true';
                    if (popoverAnchor === this) {
                        hidePopover();
                    }
                    break;
                case 'enable':
                    delete this.dataset.bsCompatPopoverDisabled;
                    break;
                case 'show':
                    showPopover(this);
                    break;
                default:
                // lazy init - hover delegation below handles display
            }
        });
    };

    // --- Hover/click delegation -------------------------------------------------

    document.addEventListener('click', e => {
        let trigger = e.target.closest('[data-toggle="popover"]');
        if (trigger && trigger.dataset.trigger !== 'hover') {
            e.preventDefault();
            if (popoverAnchor === trigger) {
                hidePopover();
            } else {
                showPopover(trigger);
            }
            return;
        }

        if (popoverElm && !e.target.closest('.bs-compat-popover')) {
            hidePopover();
        }
    });

    document.addEventListener('keydown', e => {
        if (e.key !== 'Escape') {
            return;
        }
        hidePopover();
        hideTooltip();
    });

    document.addEventListener('mouseover', e => {
        let anchor = e.target.closest('[data-toggle="tooltip"]');
        if (anchor && anchor !== tooltipAnchor) {
            showTooltip(anchor);
        }

        let popAnchor = e.target.closest('[data-toggle="popover"][data-trigger="hover"]');
        if (popAnchor && popAnchor !== popoverAnchor) {
            showPopover(popAnchor);
        }
    });

    document.addEventListener('mouseout', e => {
        let anchor = e.target.closest('[data-toggle="tooltip"]');
        if (anchor && (!e.relatedTarget || !anchor.contains(e.relatedTarget))) {
            hideTooltip();
        }

        let popAnchor = e.target.closest('[data-toggle="popover"][data-trigger="hover"]');
        if (popAnchor && popAnchor === popoverAnchor && (!e.relatedTarget || !popAnchor.contains(e.relatedTarget))) {
            hidePopover();
        }
    });
})();
