const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class JWTUtils {
  constructor() {
    this.accessTokenSecret = process.env.JWT_ACCESS_SECRET || crypto.randomBytes(64).toString('hex');
    this.refreshTokenSecret = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
    this.accessTokenExpiry = process.env.JWT_ACCESS_EXPIRY || '15m';
    this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRY || '7d';
  }

  generateAccessToken(payload) {
    return jwt.sign(payload, this.accessTokenSecret, {
      expiresIn: this.accessTokenExpiry,
      issuer: 'spectre-iam',
      audience: 'spectre-users'
    });
  }

  generateRefreshToken(payload) {
    return jwt.sign(payload, this.refreshTokenSecret, {
      expiresIn: this.refreshTokenExpiry,
      issuer: 'spectre-iam',
      audience: 'spectre-users'
    });
  }

  verifyAccessToken(token) {
    return jwt.verify(token, this.accessTokenSecret, {
      issuer: 'spectre-iam',
      audience: 'spectre-users'
    });
  }

  verifyRefreshToken(token) {
    return jwt.verify(token, this.refreshTokenSecret, {
      issuer: 'spectre-iam',
      audience: 'spectre-users'
    });
  }

  decodeToken(token) {
    return jwt.decode(token);
  }

  generateTokenPair(payload) {
    const accessToken = this.generateAccessToken(payload);
    const refreshToken = this.generateRefreshToken(payload);
    
    return {
      accessToken,
      refreshToken,
      expiresIn: this.accessTokenExpiry,
      tokenType: 'Bearer'
    };
  }
}

module.exports = new JWTUtils();
