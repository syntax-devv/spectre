const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'spectre-iam' },
  transports: [
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880,
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 5242880,
      maxFiles: 5
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

const logUtils = {
  logAuth: (action, userId, details = {}) => {
    logger.info('Authentication event', {
      action,
      userId,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  logAuthError: (action, error, details = {}) => {
    logger.error('Authentication error', {
      action,
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  logRequest: (req, res, responseTime) => {
    logger.info('HTTP Request', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      userAgent: req.get('User-Agent'),
      ip: req.ip || req.connection.remoteAddress,
      userId: req.user?.id,
      timestamp: new Date().toISOString()
    });
  },

  logError: (error, context = {}) => {
    logger.error('Application error', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      ...context
    });
  },

  logDatabase: (operation, table, details = {}) => {
    logger.info('Database operation', {
      operation,
      table,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  logDatabaseError: (operation, error, details = {}) => {
    logger.error('Database error', {
      operation,
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  logSecurity: (event, severity = 'medium', details = {}) => {
    logger.warn('Security event', {
      event,
      severity,
      timestamp: new Date().toISOString(),
      ...details
    });
  },

  // Cache logs
  logCache: (operation, key, hit = null) => {
    logger.debug('Cache operation', {
      operation,
      key,
      hit,
      timestamp: new Date().toISOString()
    });
  },

  logPerformance: (operation, duration, details = {}) => {
    logger.info('Performance metric', {
      operation,
      duration: `${duration}ms`,
      timestamp: new Date().toISOString(),
      ...details
    });
  }
};

module.exports = { logger, logUtils };
