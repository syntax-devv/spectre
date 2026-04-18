const nodemailer = require('nodemailer');
const crypto = require('crypto');
const passwordUtils = require('../utils/password');
const templateEngine = require('../utils/templateEngine');
const { logUtils } = require('../utils');
const { Resend } = require('resend');

class EmailService {
  constructor() {
    this.dryRun = process.env.EMAIL_DRY_RUN === 'true';
    this.provider = process.env.EMAIL_PROVIDER || 'smtp';
    this.outbox = [];

    if (this.dryRun) {
      return;
    }
    
    if (this.provider === 'resend') {
      const apiKey = process.env.RESEND_API_KEY || process.env.SMTP_PASS;
      if (!apiKey) {
        throw new Error('Resend API key is required');
      }
      this.resend = new Resend(apiKey);
    } else {
      this.transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
    }
  }

  async generateMagicLinkToken() {
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = await passwordUtils.hashToken(token);
    return { token, tokenHash };
  }

  createMagicLinkUrl(token) {
    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    return `${baseUrl}/auth/magic-link?token=${token}`;
  }

  async sendMagicLink(email, tokenOrUrl, firstName = null) {
    try {
      const magicLinkUrl = String(tokenOrUrl).startsWith('http')
        ? tokenOrUrl
        : this.createMagicLinkUrl(tokenOrUrl);
      
      const template = await templateEngine.render('magic-link', {
        greeting: firstName ? `Hi ${firstName},` : 'Hi there,',
        magicLinkUrl
      });

      if (this.dryRun) {
        this.outbox.push({
          type: 'magic-link',
          email,
          url: magicLinkUrl,
          createdAt: new Date().toISOString()
        });
        return true;
      }
      
      if (this.provider === 'resend') {
        const { data, error } = await this.resend.emails.send({
          from: process.env.EMAIL_FROM || 'noreply@spectre.app',
          to: [email],
          subject: 'Sign in to Spectre',
          html: template
        });

        if (error) {
          throw new Error(error.message);
        }
      } else {
        const mailOptions = {
          from: process.env.EMAIL_FROM || 'noreply@spectre.app',
          to: email,
          subject: 'Sign in to Spectre',
          html: template
        };

        await this.transporter.sendMail(mailOptions);
      }
      
      logUtils.logAuth('magic_link_sent', null, { email });
      return true;
    } catch (error) {
      logUtils.logAuthError('magic_link_send', error, { email });
      throw error;
    }
  }

  async sendPasswordReset(email, tokenOrUrl, firstName = null) {
    try {
      const resetUrl = String(tokenOrUrl).startsWith('http')
        ? tokenOrUrl
        : `${process.env.FRONTEND_URL}/auth/reset-password?token=${tokenOrUrl}`;
      
      const template = await templateEngine.render('password-reset', {
        greeting: firstName ? `Hi ${firstName},` : 'Hi there,',
        resetUrl
      });

      if (this.dryRun) {
        this.outbox.push({
          type: 'password-reset',
          email,
          url: resetUrl,
          createdAt: new Date().toISOString()
        });
        return true;
      }
      
      if (this.provider === 'resend') {
        const { data, error } = await this.resend.emails.send({
          from: process.env.EMAIL_FROM || 'noreply@spectre.app',
          to: [email],
          subject: 'Reset your Spectre password',
          html: template
        });

        if (error) {
          throw new Error(error.message);
        }
      } else {
        const mailOptions = {
          from: process.env.EMAIL_FROM || 'noreply@spectre.app',
          to: email,
          subject: 'Reset your Spectre password',
          html: template
        };

        await this.transporter.sendMail(mailOptions);
      }
      
      logUtils.logAuth('password_reset_sent', null, { email });
      return true;
    } catch (error) {
      logUtils.logAuthError('password_reset_send', error, { email });
      throw error;
    }
  }

  async verifyConnection() {
    try {
      if (this.dryRun) {
        return true;
      }

      if (this.provider === 'resend') {
        return true;
      } else {
        await this.transporter.verify();
        return true;
      }
    } catch (error) {
      logUtils.logError('Email service connection failed', error);
      return false;
    }
  }

  getOutbox() {
    return [...this.outbox];
  }

  clearOutbox() {
    this.outbox = [];
  }
}

module.exports = new EmailService();
