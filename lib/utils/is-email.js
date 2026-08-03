'use strict';

const Joi = require('joi');

// Built once. joi schemas are immutable and meant to be reused, and compiling this per call measured
// ~5x slower - which matters because unserializeAccountData() calls isEmail() for every OAuth2 account
// that has no stored email, and the account listing maps that over every row of a page.
const emailSchema = Joi.object({
    email: Joi.string().email().required()
});

const validateOptions = {
    abortEarly: false,
    stripUnknown: true,
    convert: true
};

// Syntactic check only - it says the string is shaped like an address, never that the address is real
// or that whoever supplied it controls it. Trust decisions belong to the caller.
//
// Lives here rather than in lib/tools.js so the pure modules that need it (lib/oauth/outlook-identity.js)
// do not have to require tools, which pulls in settings and a Redis connection. lib/tools.js re-exports
// this function, so every existing caller is unaffected.
function isEmail(str) {
    const { error, value } = emailSchema.validate({ email: str }, validateOptions);

    if (error) {
        return false;
    }

    return value.email;
}

module.exports = { isEmail };
