'use strict';
const crypto = require('crypto');

// HMAC-SHA256 token auth — no external dependencies

class AuthService {
  constructor(secret, options) {
    if (!secret) throw new Error('A secret key is required');
    options = options || {};
    this.secret = secret;
    this.ttl = options.ttl || 3600;
    this._revoked = new Set();
  }

  _sign(data) {
    return crypto.createHmac('sha256', this.secret).update(data).digest('hex');
  }

  generateToken(payload) {
    if (!payload || typeof payload !== 'object') throw new TypeError('Payload must be a plain object');
    const full = Object.assign({}, payload, {
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.ttl,
    });
    const encoded = Buffer.from(JSON.stringify(full)).toString('base64url');
    return encoded + '.' + this._sign(encoded);
  }

  verify(token) {
    if (typeof token !== 'string') throw new TypeError('Token must be a string');
    if (this._revoked.has(token)) throw new Error('Token has been revoked');
    const dot = token.lastIndexOf('.');
    if (dot === -1) throw new Error('Malformed token');
    const encoded = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    if (this._sign(encoded) !== sig) throw new Error('Invalid signature');
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
    return payload;
  }

  revoke(token) {
    this._revoked.add(token);
  }

  refresh(token) {
    const payload = this.verify(token);
    this.revoke(token);
    const { iat, exp, ...rest } = payload;
    return this.generateToken(rest);
  }
}

module.exports = AuthService;
