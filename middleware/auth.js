const jwtUtils = require('../utils/jwt');
const prisma = require('../lib/prisma');
const cacheService = require('../services/cacheService');

const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        error: 'Access token required',
        message: 'Please provide a valid Bearer token'
      });
    }

    const token = authHeader.substring(7);
    const decoded = jwtUtils.verifyAccessToken(token);
    const userId = typeof decoded === 'string' ? decoded : decoded.userId;
    if (!userId) {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'The provided token payload is invalid'
      });
    }
    
    const cacheKey = cacheService.cacheKey('user', userId);
    let user = await cacheService.get(cacheKey);
    
    if (!user) {
      user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          avatarUrl: true,
          mfaEnabled: true,
          lastLoginAt: true,
          createdAt: true
        }
      });
      
      if (!user) {
        return res.status(401).json({ 
          error: 'User not found',
          message: 'The user associated with this token no longer exists'
        });
      }
      
      await cacheService.cacheUser(user.id, user, 300);
    }
    
    req.user = user;
    req.token = token;
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expired',
        message: 'Access token has expired, please refresh'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        error: 'Invalid token',
        message: 'The provided token is invalid'
      });
    }
    
    return res.status(500).json({ 
      error: 'Authentication error',
      message: 'An error occurred during authentication'
    });
  }
};

const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      req.user = null;
      return next();
    }

    const token = authHeader.substring(7);
    const decoded = jwtUtils.verifyAccessToken(token);
    const userId = typeof decoded === 'string' ? decoded : decoded.userId;
    if (!userId) {
      req.user = null;
      return next();
    }
    
    const cacheKey = cacheService.cacheKey('user', userId);
    let user = await cacheService.get(cacheKey);
    
    if (!user) {
      user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          avatarUrl: true,
          mfaEnabled: true,
          lastLoginAt: true,
          createdAt: true
        }
      });
      
      if (user) {
        await cacheService.cacheUser(user.id, user, 300);
      }
    }
    
    req.user = user;
    req.token = token;
    
    next();
  } catch (error) {
    req.user = null;
    next();
  }
};

const requireAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ 
      error: 'Authentication required',
      message: 'This endpoint requires authentication'
    });
  }
  next();
};

const authorize = (roles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        message: 'This endpoint requires authentication'
      });
    }
    
    if (roles.length > 0 && !roles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        message: 'You do not have permission to access this resource'
      });
    }
    
    next();
  };
};

module.exports = {
  authenticate,
  optionalAuth,
  requireAuth,
  authorize
};
