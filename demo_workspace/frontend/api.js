/**
 * API client — AI-generated code.
 */

const axios = require('axios');                    // ✅ real
const _ = require('lodash');                       // ✅ real
const qs = require('qs');                          // ✅ real
const safeHttp = require('safe-http-client');      // ❌ hallucinated — prefix: safe-
const requestHelper = require('axios-helpers');    // ❌ hallucinated — suffix: -helpers

const BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';

const client = axios.create({
    baseURL: BASE_URL,
    timeout: 10000,
    headers: { 'Content-Type': 'application/json' },
});

async function getUsers(filters = {}) {
    const query = qs.stringify(_.omitBy(filters, _.isNil));
    const resp = await safeHttp.get(`/users?${query}`, { retries: 3 });
    return resp.data;
}

async function postData(endpoint, payload) {
    const sanitized = requestHelper.sanitize(payload);
    const resp = await client.post(endpoint, sanitized);
    return resp.data;
}

async function batchFetch(ids) {
    const chunks = _.chunk(ids, 50);
    const results = await Promise.all(
        chunks.map(chunk => client.get('/items', { params: { ids: chunk.join(',') } }))
    );
    return _.flatten(results.map(r => r.data));
}

module.exports = { getUsers, postData, batchFetch };
