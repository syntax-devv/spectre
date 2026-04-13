const bcrypt = require('bcryptjs');
const crypto = require('crypto');

class PasswordUtils {
  constructor() {
    this.saltRounds = 12;
  }

  async hashPassword(password) {
    return await bcrypt.hash(password, this.saltRounds);
  }

  async comparePassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
  }

  async hashToken(token) {
    return await bcrypt.hash(token, this.saltRounds);
  }

  async compareToken(token, hashedToken) {
    return await bcrypt.compare(token, hashedToken);
  }

  generateSecurePassword(length = 16) {
    return crypto.randomBytes(length).toString('hex');
  }

  validatePasswordStrength(password) {
    const errors = [];
    
    if (!password || password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }
    
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      strength: errors.length === 0 ? 'strong' : errors.length <= 2 ? 'medium' : 'weak'
    };
  }
}

module.exports = new PasswordUtils();
