const express = require('express');
const router = express.Router();

const jwtRoutes = require('./jwt');
const sessionRoutes = require('./session');
const magicLinkRoutes = require('./magic-link');
const passwordResetRoutes = require('./password-reset');
const oauthRoutes = require('./oauth');
router.use('/', jwtRoutes);
router.use('/', sessionRoutes);
router.use('/', magicLinkRoutes);
router.use('/', passwordResetRoutes);
router.use('/', oauthRoutes);

module.exports = router;
