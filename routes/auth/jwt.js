const express = require('express');
const router = express.Router();
const prisma = require('../../lib/prisma');
const { supabase, supabaseAdmin } = require('../../lib/supabase');
const { logUtils } = require('../../utils');

// Helper to extract provider from Supabase user
const getAuthProvider = (user) => {
  if (!user.app_metadata?.provider) return 'email';
  return user.app_metadata.provider;
};

// Helper to format user response
const formatUserResponse = (user) => ({
  id: user.id,
  email: user.email,
  firstName: user.user_metadata?.first_name || user.user_metadata?.firstName || null,
  lastName: user.user_metadata?.last_name || user.user_metadata?.lastName || null,
  avatarUrl: user.user_metadata?.avatar_url || null,
  provider: getAuthProvider(user),
  createdAt: user.created_at,
  lastLoginAt: user.last_sign_in_at
});

// Sync Supabase auth user to Prisma database (for app-specific data)
const syncUserToDatabase = async (user, userData = {}) => {
  try {
    const email = user.email?.toLowerCase();
    if (!email) return null;

    // Check if user exists in Prisma
    const existing = await prisma.user.findUnique({ where: { email } });
    
    if (existing) {
      // Update last login and sync any new data
      return await prisma.user.update({
        where: { email },
        data: {
          lastLoginAt: new Date(),
          firstName: userData.firstName || existing.firstName,
          lastName: userData.lastName || existing.lastName,
          avatarUrl: userData.avatarUrl || user.user_metadata?.avatar_url || existing.avatarUrl
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          avatarUrl: true,
          lastLoginAt: true
        }
      });
    }

    // Create new user in Prisma
    return await prisma.user.create({
      data: {
        email,
        firstName: userData.firstName || user.user_metadata?.first_name || user.user_metadata?.firstName,
        lastName: userData.lastName || user.user_metadata?.last_name || user.user_metadata?.lastName,
        avatarUrl: userData.avatarUrl || user.user_metadata?.avatar_url,
        lastLoginAt: new Date()
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        avatarUrl: true,
        lastLoginAt: true
      }
    });
  } catch (error) {
    logUtils.logAuthError('sync_user_to_db', error, { email: user.email });
    return null;
  }
};

// Helper to get helpful error message for duplicate emails
const getDuplicateEmailMessage = async (email) => {
  try {
    // Check if user exists in Supabase
    const { data: users } = await supabaseAdmin.auth.admin.listUsers();
    const existingUser = users?.users?.find(u => u.email?.toLowerCase() === email.toLowerCase());
    
    if (!existingUser) {
      return 'An account with this email already exists. Please sign in.';
    }

    const provider = getAuthProvider(existingUser);
    
    if (provider === 'email') {
      return 'An account with this email already exists. Please sign in using email and password.';
    } else {
      return `An account with this email already exists. Please sign in using ${provider}.`;
    }
  } catch (error) {
    return 'An account with this email already exists.';
  }
};

router.post('/register', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'Email and password are required'
      });
    }

    // Register with Supabase Auth
    const { data, error } = await supabase.auth.signUp({
      email: email.toLowerCase(),
      password,
      options: {
        data: {
          first_name: firstName,
          last_name: lastName
        }
      }
    });

    if (error) {
      // Handle specific Supabase errors
      if (error.message?.toLowerCase().includes('user already registered') || 
          error.message?.toLowerCase().includes('already exists')) {
        const message = await getDuplicateEmailMessage(email);
        return res.status(409).json({
          error: 'User exists',
          message
        });
      }

      if (error.message?.toLowerCase().includes('password')) {
        return res.status(400).json({
          error: 'Weak password',
          message: error.message
        });
      }

      throw error;
    }

    if (!data.user) {
      return res.status(500).json({
        error: 'Registration failed',
        message: 'Failed to create user'
      });
    }

    // Sync to Prisma database
    await syncUserToDatabase(data.user, { firstName, lastName });

    logUtils.logAuth('user_registered_supabase', data.user.id, { email: data.user.email });

    res.status(201).json({
      message: 'User registered successfully. Please check your email to confirm your account.',
      user: formatUserResponse(data.user)
    });
  } catch (error) {
    logUtils.logAuthError('registration', error, { email });
    res.status(500).json({
      error: 'Registration failed',
      message: error.message || 'An error occurred during registration'
    });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'Email and password are required'
      });
    }

    // Sign in with Supabase Auth
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email.toLowerCase(),
      password
    });

    if (error) {
      // Check if user exists but with different provider
      if (error.message?.toLowerCase().includes('invalid login credentials')) {
        const message = await getDuplicateEmailMessage(email);
        // If message mentions a provider other than email, tell them
        if (!message.includes('email and password')) {
          return res.status(401).json({
            error: 'Authentication failed',
            message
          });
        }
      }

      return res.status(401).json({
        error: 'Authentication failed',
        message: error.message || 'Invalid email or password'
      });
    }

    if (!data.user || !data.session) {
      return res.status(500).json({
        error: 'Login failed',
        message: 'Failed to create session'
      });
    }

    // Sync to Prisma database
    await syncUserToDatabase(data.user);

    logUtils.logAuth('supabase_login_success', data.user.id, { email: data.user.email });

    res.json({
      message: 'Login successful',
      user: formatUserResponse(data.user),
      accessToken: data.session.access_token,
      refreshToken: data.session.refresh_token,
      expiresAt: data.session.expires_at
    });
  } catch (error) {
    logUtils.logAuthError('login', error, { email });
    res.status(500).json({
      error: 'Login failed',
      message: error.message || 'An error occurred during login'
    });
  }
});

router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  try {
    if (!refreshToken) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'Refresh token is required'
      });
    }

    // Use Supabase to refresh the session
    const { data, error } = await supabase.auth.refreshSession({
      refresh_token: refreshToken
    });

    if (error || !data.session) {
      return res.status(401).json({
        error: 'Token refresh failed',
        message: error?.message || 'Invalid or expired refresh token'
      });
    }

    logUtils.logAuth('token_refreshed_supabase', data.user?.id);

    res.json({
      message: 'Token refreshed successfully',
      accessToken: data.session.access_token,
      refreshToken: data.session.refresh_token,
      expiresAt: data.session.expires_at
    });
  } catch (error) {
    logUtils.logAuthError('token_refresh', error);
    res.status(401).json({
      error: 'Token refresh failed',
      message: error.message || 'Invalid or expired refresh token'
    });
  }
});

router.post('/logout', async (req, res) => {
  try {
    // Sign out from Supabase (invalidates all sessions for this user)
    const { error } = await supabase.auth.signOut();

    if (error) {
      throw error;
    }

    logUtils.logAuth('supabase_logout', null);

    res.json({
      message: 'Logout successful'
    });
  } catch (error) {
    logUtils.logAuthError('logout', error);
    res.status(500).json({
      error: 'Logout failed',
      message: error.message || 'An error occurred during logout'
    });
  }
});

module.exports = router;
