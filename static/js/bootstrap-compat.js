/* global document, window, $ */

'use strict';

/*
 * Bootstrap 4 JS compatibility shim for the Tailwind v4 + FlyonUI admin theme.
 *
 * Keeps not-yet-converted views working after bootstrap.bundle.min.js was
 * removed: implements the jQuery plugin surface that the remaining inline
 * scripts actually call ($.fn.modal/tooltip/popover/dropdown) and the
 * data-toggle/data-dismiss attribute behaviors of the remaining Bootstrap
 * markup, including the jQuery event contract (shown.bs.modal,
 * closed.bs.alert, ...).
 *
 * Legacy dropdown menus are stamped with .bs-compat-dropdown-menu at
 * DOMContentLoaded; static/css/src/bootstrap-compat.css keys its legacy
 * dropdown styling on that class (plus an adjacent-sibling fallback for the
 * pre-stamp paint), so this file is the single authority on what counts as a
 * legacy dropdown.
 *
 * Both files shrink as views convert to native FlyonUI markup and are deleted
 * at the end of the migration. Converted views must NOT rely on this shim.
 */

(function () {
    if (typeof $ === 'undefined' || !$.fn) {
        return;
    }

    const TRANSITION_MS = 150;

    function resolveTarget(trigger) {
        let selector = trigger.getAttribute('data-target') || trigger.getAttribute('href');
        if (!selector || selector === '#') {
            return null;
        }
        try {
            return document.querySelector(selector);
        } catch (err) {
            return null;
        }
    }

    // --- Modal -------------------------------------------------------------

    function showModal(modal) {
        if (!modal || modal.classList.contains('show')) {
            return;
        }
        document.body.classList.add('modal-open');
        // next frame so the fade transition runs
        window.requestAnimationFrame(() => {
            modal.classList.add('show');
            window.setTimeout(() => {
                $(modal).trigger('shown.bs.modal');
            }, TRANSITION_MS);
        });
        $(modal).trigger('show.bs.modal');
    }

    function hideModal(modal) {
        if (!modal || !modal.classList.contains('show')) {
            return;
        }
        modal.classList.remove('show');
        $(modal).trigger('hide.bs.modal');
        window.setTimeout(() => {
            if (!document.querySelector('.modal.show')) {
                document.body.classList.remove('modal-open');
            }
            $(modal).trigger('hidden.bs.modal');
        }, TRANSITION_MS);
    }

    $.fn.modal = function (action) {
        return this.each(function () {
            if (action === 'hide') {
                hideModal(this);
            } else {
                // Bootstrap also treats an options object as "show"
                showModal(this);
            }
        });
    };

    // --- Alert (data-dismiss="alert" + the closed.bs.alert contract) --------

    function closeAlert(alert) {
        if (!alert) {
            return;
        }
        $(alert).trigger('close.bs.alert');
        alert.classList.remove('show');
        window.setTimeout(
            () => {
                $(alert).trigger('closed.bs.alert');
                alert.remove();
            },
            alert.classList.contains('fade') ? TRANSITION_MS : 0
        );
    }

    // --- Collapse ------------------------------------------------------------

    function setCollapsed(target, show, trigger) {
        if (!target) {
            return;
        }

        if (show) {
            // accordion behavior
            let parentSelector = target.getAttribute('data-parent');
            if (parentSelector) {
                let parent = document.querySelector(parentSelector);
                if (parent) {
                    for (let other of parent.querySelectorAll('.collapse.show')) {
                        if (other !== target) {
                            setCollapsed(other, false);
                        }
                    }
                }
            }
            target.classList.add('show');
        } else {
            target.classList.remove('show');
        }

        let triggers = trigger
            ? [trigger]
            : document.querySelectorAll(`[data-toggle="collapse"][data-target="#${target.id}"], [data-toggle="collapse"][href="#${target.id}"]`);
        for (let t of triggers) {
            t.classList.toggle('collapsed', !show);
            t.setAttribute('aria-expanded', show ? 'true' : 'false');
        }

        $(target).trigger(show ? 'shown.bs.collapse' : 'hidden.bs.collapse');
    }

    // --- Tabs ----------------------------------------------------------------

    function showTab(trigger) {
        let target = resolveTarget(trigger);
        if (!target) {
            return;
        }

        let nav = trigger.closest('.nav, .list-group');
        if (nav) {
            for (let link of nav.querySelectorAll('.nav-link, .list-group-item')) {
                link.classList.toggle('active', link === trigger);
                link.setAttribute('aria-selected', link === trigger ? 'true' : 'false');
            }
        }

        let content = target.parentElement;
        if (content) {
            for (let pane of content.children) {
                if (pane.classList.contains('tab-pane')) {
                    pane.classList.toggle('active', pane === target);
                    pane.classList.toggle('show', pane === target);
                }
            }
        }

        $(trigger).trigger('shown.bs.tab');
    }

    // --- Dropdown ------------------------------------------------------------

    // at most one legacy dropdown menu is open at a time
    let openDropdownMenu = null;

    function getDropdownMenu(trigger) {
        let parent = trigger.closest('.dropdown, .input-group-prepend, .btn-group');
        let menu = parent ? parent.querySelector('.dropdown-menu') : null;
        if (!menu && trigger.nextElementSibling && trigger.nextElementSibling.classList.contains('dropdown-menu')) {
            menu = trigger.nextElementSibling;
        }
        return menu;
    }

    function closeOpenDropdown() {
        if (openDropdownMenu) {
            openDropdownMenu.classList.remove('show');
            openDropdownMenu = null;
        }
    }

    function toggleDropdown(trigger) {
        let menu = getDropdownMenu(trigger);
        if (!menu) {
            return;
        }
        let show = !menu.classList.contains('show');
        closeOpenDropdown();
        if (show) {
            menu.classList.add('show');
            openDropdownMenu = menu;
        }
        trigger.setAttribute('aria-expanded', show ? 'true' : 'false');
    }

    $.fn.dropdown = function (action) {
        return this.each(function () {
            if (action === 'toggle' || !action) {
                toggleDropdown(this);
            }
        });
    };

    // bootstrap-autocomplete detects the Bootstrap version via
    // $.fn.button.Constructor.VERSION; nothing else uses the button plugin
    // (removed together with bootstrap-autocomplete in the datalist migration)
    $.fn.button = function () {
        return this;
    };
    $.fn.button.Constructor = { VERSION: '4.6.2' };

    // --- Tooltip ---------------------------------------------------------------

    let tooltipElm = null;
    let tooltipAnchor = null;

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
        if (anchor.dataset.html === 'true') {
            // Unlike Bootstrap 4.3+, this shim does NOT sanitize html popover
            // content. Only template-authored static markup may use
            // data-html="true"; never put dynamic data on such an anchor.
            bodyElm.innerHTML = content;
        } else {
            bodyElm.textContent = content;
        }
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
                // lazy init - click delegation below handles display
            }
        });
    };

    // --- Data-attribute delegation --------------------------------------------

    document.addEventListener('click', e => {
        // one ancestor walk for all toggle/dismiss triggers
        let trigger = e.target.closest('[data-toggle], [data-dismiss]');
        if (trigger) {
            let toggle = trigger.getAttribute('data-toggle');
            let dismiss = trigger.getAttribute('data-dismiss');

            switch (toggle) {
                case 'modal':
                    e.preventDefault();
                    showModal(resolveTarget(trigger));
                    return;
                case 'collapse': {
                    e.preventDefault();
                    let target = resolveTarget(trigger);
                    if (target) {
                        setCollapsed(target, !target.classList.contains('show'), trigger);
                    }
                    return;
                }
                case 'tab':
                case 'pill':
                    e.preventDefault();
                    showTab(trigger);
                    return;
                case 'dropdown':
                    e.preventDefault();
                    toggleDropdown(trigger);
                    return;
                case 'popover':
                    e.preventDefault();
                    if (popoverAnchor === trigger) {
                        hidePopover();
                    } else {
                        showPopover(trigger);
                    }
                    return;
            }

            switch (dismiss) {
                case 'modal':
                    e.preventDefault();
                    hideModal(trigger.closest('.modal'));
                    return;
                case 'alert':
                    e.preventDefault();
                    closeAlert(trigger.closest('.alert'));
                    return;
            }
        }

        if (popoverElm && !e.target.closest('.bs-compat-popover')) {
            hidePopover();
        }

        // outside click closes the open legacy dropdown
        if (openDropdownMenu && !e.target.closest('.dropdown-menu')) {
            closeOpenDropdown();
        }

        // clicking the modal backdrop (the .modal container itself) closes it
        if (e.target.classList && e.target.classList.contains('modal') && e.target.classList.contains('show')) {
            hideModal(e.target);
        }
    });

    document.addEventListener('keydown', e => {
        if (e.key !== 'Escape') {
            return;
        }
        hidePopover();
        hideTooltip();
        closeOpenDropdown();
        let openModal = document.querySelector('.modal.show');
        if (openModal) {
            hideModal(openModal);
        }
    });

    document.addEventListener('mouseover', e => {
        let anchor = e.target.closest('[data-toggle="tooltip"]');
        if (anchor && anchor !== tooltipAnchor) {
            showTooltip(anchor);
        }
    });

    document.addEventListener('mouseout', e => {
        let anchor = e.target.closest('[data-toggle="tooltip"]');
        if (!anchor) {
            return;
        }
        // still inside the same anchor (moving between its children) - keep it
        if (e.relatedTarget && anchor.contains(e.relatedTarget)) {
            return;
        }
        hideTooltip();
    });

    // Stamp legacy dropdown menus so the compat CSS can scope its styling to
    // them without guessing at markup shapes (see the header comment).
    document.addEventListener('DOMContentLoaded', () => {
        for (let trigger of document.querySelectorAll('[data-toggle="dropdown"]')) {
            let menu = getDropdownMenu(trigger);
            if (menu) {
                menu.classList.add('bs-compat-dropdown-menu');
            }
        }
    });
})();
