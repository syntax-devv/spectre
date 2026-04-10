class ValidationUtils {
  validateEmail(email) {
    if (!email) {
      return { isValid: false, message: 'Email is required' };
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return { isValid: false, message: 'Invalid email format' };
    }
    
    return { isValid: true };
  }

  validatePassword(password) {
    if (!password) {
      return { isValid: false, message: 'Password is required' };
    }
    
    const errors = [];
    
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }
    
    if (password.length > 128) {
      errors.push('Password must be less than 128 characters long');
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
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      message: errors.length > 0 ? errors.join(', ') : 'Password is valid'
    };
  }

  validateName(name, fieldName = 'Name') {
    if (!name) {
      return { isValid: false, message: `${fieldName} is required` };
    }
    
    if (typeof name !== 'string') {
      return { isValid: false, message: `${fieldName} must be a string` };
    }
    
    if (name.trim().length === 0) {
      return { isValid: false, message: `${fieldName} cannot be empty` };
    }
    
    if (name.length > 100) {
      return { isValid: false, message: `${fieldName} must be less than 100 characters` };
    }
    
    if (!/^[a-zA-Z\s'-]+$/.test(name)) {
      return { isValid: false, message: `${fieldName} can only contain letters, spaces, hyphens, and apostrophes` };
    }
    
    return { isValid: true };
  }

  validateRegistration(data) {
    const { email, password, firstName, lastName } = data;
    const errors = [];
    
    const emailValidation = this.validateEmail(email);
    if (!emailValidation.isValid) {
      errors.push(emailValidation.message);
    }
    
    const passwordValidation = this.validatePassword(password);
    if (!passwordValidation.isValid) {
      errors.push(...passwordValidation.errors);
    }
    
    const firstNameValidation = this.validateName(firstName, 'First name');
    if (!firstNameValidation.isValid) {
      errors.push(firstNameValidation.message);
    }
    
    const lastNameValidation = this.validateName(lastName, 'Last name');
    if (!lastNameValidation.isValid) {
      errors.push(lastNameValidation.message);
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      message: errors.length > 0 ? errors.join(', ') : 'Validation passed'
    };
  }

  validateLogin(data) {
    const { email, password } = data;
    const errors = [];
    
    const emailValidation = this.validateEmail(email);
    if (!emailValidation.isValid) {
      errors.push(emailValidation.message);
    }
    
    if (!password) {
      errors.push('Password is required');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      message: errors.length > 0 ? errors.join(', ') : 'Validation passed'
    };
  }

  validateToken(token) {
    if (!token) {
      return { isValid: false, message: 'Token is required' };
    }
    
    if (typeof token !== 'string') {
      return { isValid: false, message: 'Token must be a string' };
    }
    
    if (token.trim().length === 0) {
      return { isValid: false, message: 'Token cannot be empty' };
    }
    
    return { isValid: true };
  }

  sanitizeInput(input) {
    if (typeof input !== 'string') {
      return input;
    }
    
    return input.trim().replace(/[<>]/g, '');
  }

  validateObjectId(id) {
    if (!id) {
      return { isValid: false, message: 'ID is required' };
    }
    
    if (typeof id !== 'string') {
      return { isValid: false, message: 'ID must be a string' };
    }
    
    const objectIdRegex = /^[0-9a-fA-F]{24}$/;
    if (!objectIdRegex.test(id)) {
      return { isValid: false, message: 'Invalid ID format' };
    }
    
    return { isValid: true };
  }
}

module.exports = new ValidationUtils();
