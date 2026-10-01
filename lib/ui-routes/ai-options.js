'use strict';

// The choices the AI configuration page offers: the model list and the reasoning effort levels.
// Kept apart from the general route helpers because they change with the provider's catalogue,
// not with the admin UI

const Joi = require('joi');
const settings = require('../settings');
const { settingsSchema } = require('../schemas');
const { AI_SETTING_KEYS } = require('../consts');
const { DEFAULT_MODEL, REASONING_EFFORTS, describeModel } = require('@postalsys/email-ai-tools');

// The AI page's fields, derived from the settings schema so the page, its test and the stored
// settings cannot disagree about a field. The key is handled apart: the form leaves it blank to
// keep the stored one
const aiFieldSchema = () => Object.fromEntries(AI_SETTING_KEYS.map(key => [key, settingsSchema[key].default('')]));
const aiFieldValues = payload => Object.fromEntries(AI_SETTING_KEYS.map(key => [key, payload[key]]));
// the stored values as the form shows them: strings, empty for unset
const aiFieldStrings = stored => Object.fromEntries(AI_SETTING_KEYS.map(key => [key, (stored[key] || '').toString()]));

// Everything the AI page posts: the switch and the key, the filter script as the page's own text
// field, and the request options the settings schema describes
const aiPageSchema = () =>
    Object.assign(
        {
            generateEmailSummary: settingsSchema.generateEmailSummary.default(false),
            openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
            contentFnJson: Joi.string()
                .max(1024 * 1024)
                .default('')
                .allow('')
                .trim()
                .description('Filter function')
        },
        aiFieldSchema()
    );

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
].map(model => Object.assign(model, describeModel(model.id)));

// Labels for the reasoning effort levels that are not just the capitalised value
const REASONING_EFFORT_LABELS = { '': 'Default', xhigh: 'Extra high', max: 'Maximum' };

// The entry that leaves the choice to the library, always first in the picker
const defaultModelEntry = () => ({
    id: '',
    name: `Default (${DEFAULT_MODEL})`,
    description: 'Follows the built-in default across upgrades',
    recommended: true
});

/**
 * The model list for the page: the stored list from the last refresh, the fallback until then,
 * each entry with a description and a recommended flag for the picker. "Default" comes first,
 * so an instance that never picked a model keeps following the library's default across
 * upgrades; a stored model the list does not carry is added after it, so the person sees what
 * the setting holds rather than an empty box
 *
 * @param {string} selectedModel - The stored model name, empty for the default
 * @returns {Promise<Object[]>} Entries with id, name, description and recommended
 */
async function getOpenAiModels(selectedModel) {
    const modelList = (await settings.get('openAiModels')) || OPEN_AI_MODELS;

    const entries = modelList.map(model => {
        // a list stored by an older release carries no description
        const note = typeof model.description === 'string' ? { description: model.description, recommended: !!model.recommended } : describeModel(model.id);
        return { id: model.id, name: model.name || model.id, description: note.description, recommended: note.recommended };
    });

    if (selectedModel && !entries.find(model => model.id === selectedModel)) {
        entries.unshift({ id: selectedModel, name: selectedModel, description: 'Not in the list this API key can use', recommended: false });
    }

    return [defaultModelEntry()].concat(entries);
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

module.exports = { getOpenAiModels, reasoningEffortOptions, aiPageSchema, aiFieldSchema, aiFieldValues, aiFieldStrings };
