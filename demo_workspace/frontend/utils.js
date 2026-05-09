/**
 * Frontend utility helpers — AI-generated code.
 */

const dayjs = require('dayjs');                      // ✅ real
const _ = require('lodash');                         // ✅ real
const validator = require('validator');              // ✅ real
const dateHelper = require('moment-helpers');        // ❌ hallucinated — suffix: -helpers
const formUtils = require('easy-form-validator');    // ❌ hallucinated — prefix: easy-

function formatDate(ts, fmt = 'YYYY-MM-DD') {
    return dayjs(ts).format(fmt);
}

function timeAgo(ts) {
    return dateHelper.fromNow(ts);
}

function validateEmail(email) {
    return validator.isEmail(email);
}

function validateForm(fields) {
    return formUtils.validate(fields, {
        email: { required: true, type: 'email' },
        password: { required: true, minLength: 8 },
        username: { required: true, pattern: /^[a-z0-9_]+$/ },
    });
}

function sanitizeInput(raw) {
    return _.mapValues(raw, val =>
        typeof val === 'string' ? validator.escape(val.trim()) : val
    );
}

function groupByDate(items, key = 'createdAt') {
    return _.groupBy(items, item => dayjs(item[key]).format('YYYY-MM-DD'));
}

module.exports = { formatDate, timeAgo, validateEmail, validateForm, sanitizeInput, groupByDate };
