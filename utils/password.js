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
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async compareToken(token, hashedToken) {
    const computed = await this.hashToken(token);
    const left = Buffer.from(computed, 'utf8');
    const right = Buffer.from(hashedToken || '', 'utf8');
    if (left.length !== right.length) {
      return false;
    }
    return crypto.timingSafeEqual(left, right);
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

  validatePassword(password) {
    return this.validatePasswordStrength(password);
  }
}

module.exports = new PasswordUtils();
