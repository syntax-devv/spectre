const sessionService = require('../services/sessionService');
const { logUtils } = require('../utils');

const sessionMiddleware = (options = {}) => {
  const {
    name = 'spectre-session',
    secret = process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    ttl = 30 * 60,
    rolling = true,
    httpOnly = true,
    secure = process.env.NODE_ENV === 'production',
    sameSite = 'lax'
  } = options;

  return (req, res, next) => {
    const sessionId = req.cookies?.[name];

    if (sessionId) {
      sessionService.validateSession(sessionId)
        .then(result => {
          if (result.valid) {
            req.session = result.session;
            req.sessionId = sessionId;
            
            if (rolling) {
              sessionService.updateSession(sessionId, {
                lastActivity: new Date().toISOString()
              });
            }
          } else {
            req.session = null;
            req.sessionId = null;
            res.clearCookie(name);
          }
          next();
        })
        .catch(error => {
          logUtils.logAuthError('session_middleware', error);
          req.session = null;
          req.sessionId = null;
          next();
        });
    } else {
      req.session = null;
      req.sessionId = null;
      next();
    }
  };
};

const createSessionCookie = (res, sessionId, options = {}) => {
  const cookieOptions = {
    httpOnly: options.httpOnly ?? true,
    secure: options.secure ?? (process.env.NODE_ENV === 'production'),
    sameSite: options.sameSite ?? 'lax',
    maxAge: options.maxAge ?? (30 * 60 * 1000),
    path: options.path ?? '/'
  };

  res.cookie('spectre-session', sessionId, cookieOptions);
};

const destroySessionCookie = (res) => {
  res.clearCookie('spectre-session', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/'
  });
};

module.exports = {
  sessionMiddleware,
  createSessionCookie,
  destroySessionCookie,
  sessionService
};
