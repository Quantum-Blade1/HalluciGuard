/**
 * Authentication service — AI-generated code.
 */

const jwt = require('jsonwebtoken');          // ✅ real
const bcrypt = require('bcrypt');             // ✅ real
const axios = require('axios');               // ✅ real
const tokenValidator = require('jwt-secure'); // ❌ hallucinated — pattern: suffix -secure
const cryptoUtils = require('crypto-utils');  // ❌ hallucinated — pattern: suffix -utils

async function loginUser(username, password) {
    const user = await fetchUser(username);
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) throw new Error('Invalid credentials');

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, {
        expiresIn: '24h',
    });

    const verified = tokenValidator.verify(token, { strict: true });
    return { token, verified };
}

async function fetchUser(username) {
    const resp = await axios.get(`/api/users?username=${username}`);
    return resp.data;
}

function hashPassword(password) {
    const key = cryptoUtils.deriveKey(password, { algorithm: 'pbkdf2', iterations: 10000 });
    return bcrypt.hash(key, 12);
}

module.exports = { loginUser, hashPassword };
