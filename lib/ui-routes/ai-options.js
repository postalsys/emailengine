'use strict';

// The choices the AI configuration page offers: the model list and the reasoning effort levels.
// Kept apart from the general route helpers because they change with the provider's catalogue,
// not with the admin UI

const settings = require('../settings');
const { DEFAULT_MODEL, REASONING_EFFORTS } = require('@postalsys/email-ai-tools');

// Fallback model list, shown until the first successful "Refresh Models" call replaces it with
// the models actually available on the configured endpoint (stored in the openAiModels
// setting). Newest first. Checked against OpenAI's catalogue on 2026-10-01
const OPEN_AI_MODELS = [
    { name: 'GPT-6 Luna', id: 'gpt-6-luna' },
    { name: 'GPT-6 Sol', id: 'gpt-6-sol' },
    { name: 'GPT-6 Astra', id: 'gpt-6-astra' },
    { name: 'GPT-5.6 Luna', id: 'gpt-5.6-luna' },
    { name: 'GPT-5.6 Terra', id: 'gpt-5.6-terra' },
    { name: 'GPT-5.4 Mini', id: 'gpt-5.4-mini' },
    { name: 'GPT-5.4 Nano', id: 'gpt-5.4-nano' },
    { name: 'GPT-5 Mini', id: 'gpt-5-mini' }
];

// Labels for the reasoning effort levels that are not just the capitalised value
const REASONING_EFFORT_LABELS = { '': 'Default', xhigh: 'Extra high', max: 'Maximum' };

/**
 * The model list for the page: the stored list from the last refresh, the fallback until then.
 * "Default" comes first, so an instance that never picked a model keeps following the library's
 * default across upgrades; a stored model the list does not carry is added after it
 *
 * @param {string} selectedModel - The stored model name, empty for the default
 * @returns {Promise<Object[]>} Entries with id, name and selected
 */
async function getOpenAiModels(selectedModel) {
    const modelList = (await settings.get('openAiModels')) || structuredClone(OPEN_AI_MODELS);

    if (selectedModel && !modelList.find(model => model.id === selectedModel)) {
        modelList.unshift({ name: selectedModel, id: selectedModel });
    }
    modelList.unshift({ name: `Default (${DEFAULT_MODEL})`, id: '' });

    return modelList.map(model => Object.assign(model, { selected: model.id === (selectedModel || '') }));
}

/**
 * The reasoning effort select, with the stored level marked. "Default" leaves the choice to the
 * library: "low" for a reasoning model, nothing for any other
 *
 * @param {string} selected - The stored level, empty for the default
 * @returns {Object[]} Entries with value, label and selected
 */
function reasoningEffortOptions(selected) {
    return ['', ...REASONING_EFFORTS].map(value => ({
        value,
        label: REASONING_EFFORT_LABELS[value] || value.charAt(0).toUpperCase() + value.slice(1),
        selected: value === (selected || '')
    }));
}

module.exports = { getOpenAiModels, reasoningEffortOptions };
