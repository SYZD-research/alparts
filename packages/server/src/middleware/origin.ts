import type { RequestHandler } from 'express';
import { config } from '../config/index.js';
import { readCookie } from '../security/cookies.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export const enforceBrowserOrigin: RequestHandler = (req, res, next) => {
  if (SAFE_METHODS.has(req.method)) {
    next();
    return;
  }

  const origin = req.headers.origin;
  const hasSessionCookie = Boolean(readCookie(req.headers.cookie, config.auth.cookieName));
  if (hasSessionCookie && !origin) {
    res.status(403).json({ error: 'ORIGIN_REQUIRED', message: 'Authenticated browser requests require an Origin header', statusCode: 403 });
    return;
  }
  if (origin && !config.cors.origins.includes(origin)) {
    res.status(403).json({ error: 'ORIGIN_FORBIDDEN', message: 'Request origin is not allowed', statusCode: 403 });
    return;
  }

  const fetchSite = req.headers['sec-fetch-site'];
  if (fetchSite === 'cross-site') {
    res.status(403).json({ error: 'ORIGIN_FORBIDDEN', message: 'Cross-site request rejected', statusCode: 403 });
    return;
  }
  next();
};
