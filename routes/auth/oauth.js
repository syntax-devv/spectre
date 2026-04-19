const express = require('express');
const router = express.Router();
const { supabase, supabaseAdmin } = require('../../lib/supabase');
const prisma = require('../../lib/prisma');
const { logUtils } = require('../../utils');

function getFrontendRedirectUrl() {
  return process.env.OAUTH_REDIRECT_FRONTEND || process.env.FRONTEND_URL || 'http://localhost:3000';
}

function redirectWithStatus(res, url, { ok, provider, error, access_token, refresh_token, expires_at } = {}) {
  const target = new URL(url);
  target.searchParams.set('provider', provider);
  if (ok) {
    target.searchParams.set('ok', 'true');
    if (access_token) target.searchParams.set('access_token', access_token);
    if (refresh_token) target.searchParams.set('refresh_token', refresh_token);
    if (expires_at) target.searchParams.set('expires_at', expires_at);
  } else {
    target.searchParams.set('ok', 'false');
    if (error) target.searchParams.set('error', String(error));
  }
  res.redirect(target.toString());
}

// Sync Supabase user to Prisma database
async function syncUserToDatabase(user) {
  try {
    const email = user.email?.toLowerCase();
    if (!email) return null;

    const firstName = user.user_metadata?.full_name?.split(' ')[0] || 
                     user.user_metadata?.name?.split(' ')[0] || 
                     user.user_metadata?.given_name || null;
    const lastName = user.user_metadata?.full_name?.split(' ').slice(1).join(' ') || 
                    user.user_metadata?.name?.split(' ').slice(1).join(' ') || 
                    user.user_metadata?.family_name || null;
    const avatarUrl = user.user_metadata?.avatar_url || 
                     user.user_metadata?.picture || null;

    const existing = await prisma.user.findUnique({ where: { email } });

    if (existing) {
      return await prisma.user.update({
        where: { email },
        data: {
          lastLoginAt: new Date(),
          firstName: firstName || existing.firstName,
          lastName: lastName || existing.lastName,
          avatarUrl: avatarUrl || existing.avatarUrl
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

    return await prisma.user.create({
      data: {
        email,
        firstName,
        lastName,
        avatarUrl,
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
    logUtils.logAuthError('sync_oauth_user', error, { email: user.email });
    return null;
  }
}

// Get the backend base URL for callbacks
function getBaseUrl(req) {
  return process.env.BACKEND_URL || `${req.protocol}://${req.get('host')}`;
}

// Initiate Google OAuth via Supabase
router.get('/oauth/google', async (req, res) => {
  try {
    const baseUrl = getBaseUrl(req);
    const redirectTo = `${baseUrl}/api/auth/oauth/callback?provider=google`;

    // Get OAuth URL from Supabase
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo,
        skipBrowserRedirect: true
      }
    });

    if (error || !data?.url) {
      return res.status(500).json({
        error: 'OAuth start failed',
        message: error?.message || 'Failed to generate OAuth URL'
      });
    }

    res.redirect(data.url);
  } catch (error) {
    logUtils.logAuthError('google_oauth_start', error);
    res.status(500).json({ error: 'OAuth start failed', message: 'Failed to start Google OAuth' });
  }
});

// Initiate GitHub OAuth via Supabase
router.get('/oauth/github', async (req, res) => {
  try {
    const baseUrl = getBaseUrl(req);
    const redirectTo = `${baseUrl}/api/auth/oauth/callback?provider=github`;

    // Get OAuth URL from Supabase
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo,
        skipBrowserRedirect: true
      }
    });

    if (error || !data?.url) {
      return res.status(500).json({
        error: 'OAuth start failed',
        message: error?.message || 'Failed to generate OAuth URL'
      });
    }

    res.redirect(data.url);
  } catch (error) {
    logUtils.logAuthError('github_oauth_start', error);
    res.status(500).json({ error: 'OAuth start failed', message: 'Failed to start GitHub OAuth' });
  }
});

// Unified OAuth callback handler - receives code from Supabase after OAuth completion
router.get('/oauth/callback', async (req, res) => {
  const frontend = getFrontendRedirectUrl();
  const provider = req.query.provider || 'unknown';

  try {
    const code = req.query.code;

    if (!code) {
      return redirectWithStatus(res, frontend, { ok: false, provider, error: 'missing_code' });
    }

    // Exchange the code for a session
    const { data, error } = await supabase.auth.exchangeCodeForSession(code);

    if (error || !data.session || !data.user) {
      const errorMessage = error?.message || 'Failed to exchange code for session';
      // Check if it's an email already exists with different provider error
      if (errorMessage.toLowerCase().includes('email') && errorMessage.toLowerCase().includes('already')) {
        return redirectWithStatus(res, frontend, {
          ok: false,
          provider,
          error: 'email_already_exists_with_different_provider'
        });
      }
      return redirectWithStatus(res, frontend, { ok: false, provider, error: errorMessage });
    }

    // Sync user to Prisma database
    await syncUserToDatabase(data.user);

    logUtils.logAuth('supabase_oauth_success', data.user.id, { provider, email: data.user.email });

    // Redirect to frontend with tokens
    return redirectWithStatus(res, frontend, {
      ok: true,
      provider,
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_at: data.session.expires_at
    });
  } catch (error) {
    logUtils.logAuthError('oauth_callback', error, { provider });
    return redirectWithStatus(res, frontend, { ok: false, provider, error: 'oauth_callback_failed' });
  }
});

module.exports = router;
