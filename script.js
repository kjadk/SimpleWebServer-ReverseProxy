// Reverse Proxy Plugin for Simple Web Server
const http = require('http');
const https = require('https');
const url = require('url');

let proxyRoutes = [];
let basicAuthUsers = {}; // Stores username:plaintext_password for this example
let basicAuthRealm = 'Restricted Area'; // Default realm

// Rate Limiting variables
const requestCounts = new Map(); // Stores { IP: [timestamp1, timestamp2, ...] }
let rateLimitConnections = 0;
let rateLimitTimeWindowMs = 0; // In milliseconds
let cleanupInterval = null; // To store the interval ID for clearing

// Global variable to store useXForwardedFor setting
let useXForwardedFor = false; 

function onStart(server, options) {
  if (!options.enabled1) {
    console.log('[Reverse Proxy] Plugin disabled');
    return;
  }

  try {
    proxyRoutes = JSON.parse(options.routes || '[]');
    console.log('[Reverse Proxy] Loaded routes:', proxyRoutes);
  } catch (error) {
    console.error('[Reverse Proxy] Error parsing routes configuration:', error.message);
    proxyRoutes = [];
  }

  // Load Basic Auth configuration from options
  if (options.enableBasicAuth && options.basicAuthUsers) {
    try {
      const users = JSON.parse(options.basicAuthUsers);
      for (const user in users) {
        basicAuthUsers[user] = users[user]; // Store plaintext for direct comparison
      }
      console.log('[Reverse Proxy] Basic Auth enabled and users loaded.');
    } catch (error) {
      console.error('[Reverse Proxy] Error parsing basicAuthUsers configuration:', error.message);
      basicAuthUsers = {}; // Disable Basic Auth if config is invalid
    }
  } else {
    basicAuthUsers = {}; // Ensure Basic Auth is disabled if not explicitly enabled
  }
  if (options.basicAuthRealm) {
    basicAuthRealm = options.basicAuthRealm;
  }

  // Load Rate Limiting configuration from options
  const parsedConnections = parseInt(options.rateLimitConnections, 10);
  const parsedMinutes = parseInt(options.rateLimitTimeWindowMinutes, 10);

  if (parsedConnections > 0 && parsedMinutes > 0) {
    rateLimitConnections = parsedConnections;
    rateLimitTimeWindowMs = parsedMinutes * 60 * 1000; // Convert minutes to milliseconds
    console.log(`[Reverse Proxy] Rate Limiting enabled: ${rateLimitConnections} connections per ${parsedMinutes} minutes.`);

    // Start periodic cleanup
    if (cleanupInterval) { // Clear existing interval if onStart is called again
      clearInterval(cleanupInterval);
    }
    const actualCleanupFreqMs = Math.max(rateLimitTimeWindowMs, 60 * 1000); // At least every 1 minute
    cleanupInterval = setInterval(cleanUpOldIpEntries, actualCleanupFreqMs);
    console.log(`[Reverse Proxy] Periodic IP cleanup started (every ${actualCleanupFreqMs / 1000} seconds).`);

  } else {
    rateLimitConnections = 0; // Disable if invalid or 0
    rateLimitTimeWindowMs = 0;
    console.log('[Reverse Proxy] Rate Limiting disabled.');
    // Stop periodic cleanup if rate limiting is disabled
    if (cleanupInterval) {
      clearInterval(cleanupInterval);
      cleanupInterval = null;
      console.log('[Reverse Proxy] Periodic IP cleanup stopped.');
    }
  }

  // Set useXForwardedFor global variable based on options
  useXForwardedFor = options.useXForwardedFor === true;
}

// Function to handle Basic Auth
function authenticate(req, res) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    res.statusCode = 401; // Unauthorized
    res.setHeader('WWW-Authenticate', `Basic realm="${basicAuthRealm}"`);
    res.end('Authorization Required');
    return false;
  }

  const [authType, credentials] = authHeader.split(' ');

  if (authType.toLowerCase() !== 'basic') {
    res.statusCode = 400; // Bad Request
    res.end('Only Basic Auth is supported');
    return false;
  }

  const decodedCredentials = Buffer.from(credentials, 'base64').toString();
  const [username, password] = decodedCredentials.split(':');

  if (basicAuthUsers[username] && basicAuthUsers[username] === password) {
    return true; // Authentication successful
  } else {
    res.statusCode = 401; // Unauthorized
    res.setHeader('WWW-Authenticate', `Basic realm="${basicAuthRealm}"`);
    res.end('Invalid Credentials');
    return false;
  }
}

// Function to handle Rate Limiting
function applyRateLimiting(req, res, options) { 
  if (rateLimitConnections === 0 || rateLimitTimeWindowMs === 0) {
    return true; // Rate limiting is disabled
  }

  // Determine client IP (using the new logic with useXForwardedFor)
  let clientIp = req.connection.remoteAddress || req.socket.remoteAddress;
  if (options.useXForwardedFor && req.headers['x-forwarded-for']) {
    clientIp = req.headers['x-forwarded-for'].split(',')[0].trim();
  }

  const currentTime = Date.now();

  let requests = requestCounts.get(clientIp) || [];
  
  // Filter out timestamps older than the rate limit window
  requests = requests.filter(timestamp => (currentTime - timestamp) < rateLimitTimeWindowMs);

  // --- Start NEW Log Line ---
  const formattedDate = new Date(currentTime).toLocaleDateString('no-NO', { day: '2-digit', month: '2-digit', year: 'numeric' });
  const formattedTime = new Date(currentTime).toLocaleTimeString('no-NO', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const fullUrl = `${req.connection.encrypted ? 'https' : 'http'}://${req.headers.host}${req.url}`;
  console.log(`${formattedDate} ${formattedTime}, IP: ${clientIp}, Requests: ${requests.length + 1}, ${fullUrl}`); 
  // --- End NEW Log Line ---


  if (requests.length >= rateLimitConnections) {
    console.warn(`[Reverse Proxy] Rate Limit Exceeded for IP: ${clientIp} for URL: ${req.url}`); // Adjusted warning
    res.statusCode = 429; // Too Many Requests
    res.setHeader('Retry-After', Math.ceil(rateLimitTimeWindowMs / 1000)); 
    res.end('Too Many Requests. Please try again later.');
    return false; // Request should be blocked
  }

  // Add current request timestamp and update map
  requests.push(currentTime);
  requestCounts.set(clientIp, requests);

  return true; // Request allowed
}

// Function for active periodic cleanup of old IP entries
function cleanUpOldIpEntries() {
    const currentTime = Date.now();
    let cleanedCount = 0;
    let preCleanupSize = requestCounts.size;
    
    for (const [ip, timestamps] of requestCounts.entries()) {
        const activeTimestamps = timestamps.filter(ts => (currentTime - ts) < rateLimitTimeWindowMs);
        
        if (activeTimestamps.length === 0) {
            requestCounts.delete(ip);
            cleanedCount++;
        } else {
            requestCounts.set(ip, activeTimestamps);
        }
    }

    if (cleanedCount > 0 || preCleanupSize > 0) {
        console.log(`[RateLimit Cleanup] Ran cleanup. IPs before: ${preCleanupSize}, IPs removed: ${cleanedCount}, IPs after: ${requestCounts.size}.`);
    }
}


function onRequest(req, res, options, preventDefault) {
  if (!options.enabled1 || proxyRoutes.length === 0) {
    return;
  }

  // 1. Apply Rate Limiting first, passing options
  if (!applyRateLimiting(req, res, options)) { 
    preventDefault(); 
    return; 
  }

  // 2. Apply Basic Auth if enabled and users are configured
  if (options.enableBasicAuth && Object.keys(basicAuthUsers).length > 0) {
    if (!authenticate(req, res)) {
      preventDefault(); 
      return; 
    }
  }

  // Find matching route
  const matchedRoute = proxyRoutes.find(route => {
    return req.url.startsWith(route.path);
  });

  if (!matchedRoute) {
    return; // No matching route, let the server handle normally
  }

  // Prevent default handling because we're proxying
  preventDefault();

  // Parse target URL
  const targetUrl = url.parse(matchedRoute.target);
  const isHttps = targetUrl.protocol === 'https:';
  const httpModule = isHttps ? https : http;

  // Prepare proxy request options
  const proxyPath = req.url.replace(matchedRoute.path, '') || '/';
  const proxyOptions = {
    hostname: targetUrl.hostname,
    port: targetUrl.port || (isHttps ? 443 : 80),
    path: targetUrl.pathname.replace(/\/$/, '') + proxyPath + (req.url.includes('?') ? '?' + req.url.split('?')[1] : ''),
    method: req.method,
    headers: { ...req.headers } 
  };

  // Handle host header
  if (!options.preserveHost) {
    proxyOptions.headers.host = targetUrl.host;
  }

  // Add custom headers
  try {
    const additionalHeaders = JSON.parse(options.addHeaders || '{}');
    Object.assign(proxyOptions.headers, additionalHeaders);
  } catch (error) {
    console.error('[Reverse Proxy] Error parsing additional headers:', error.message);
  }

  // Add forwarded headers
  let effectiveClientIp = req.connection.remoteAddress || req.socket.remoteAddress;
  if (options.useXForwardedFor && req.headers['x-forwarded-for']) {
    effectiveClientIp = req.headers['x-forwarded-for'].split(',')[0].trim();
  }
  proxyOptions.headers['x-forwarded-for'] = proxyOptions.headers['x-forwarded-for'] 
    ? `${proxyOptions.headers['x-forwarded-for']}, ${effectiveClientIp}`
    : effectiveClientIp;
  proxyOptions.headers['x-forwarded-proto'] = req.connection.encrypted ? 'https' : 'http';
  proxyOptions.headers['x-forwarded-host'] = req.headers.host;

  // 3. Add Security Headers to the response
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY'); 
  if (req.connection.encrypted) { 
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  res.setHeader('X-XSS-Protection', '1; mode=block'); 

  console.log(`[Reverse Proxy] Proxying ${req.method} ${req.url} -> ${matchedRoute.target}${proxyPath}`);

  // Create proxy request
  const proxyReq = httpModule.request(proxyOptions, (proxyRes) => {
    // Set response status and headers
    res.statusCode = proxyRes.statusCode;
    
    // Copy response headers, but filter out problematic ones
    Object.keys(proxyRes.headers).forEach(key => {
      if (!['connection', 'keep-alive', 'transfer-encoding'].includes(key.toLowerCase())) {
        res.setHeader(key, proxyRes.headers[key]);
      }
    });

    // Pipe response data
    proxyRes.pipe(res);
  });

  // Handle proxy request errors
  proxyReq.on('error', (error) => {
    console.error(`[Reverse Proxy] Proxy request error: ${error.message}`);
	console.error(`[Reverse Proxy] Error code: ${error.code}`);
	console.error(`[Reverse Proxy] Full error:`, error);
    if (!res.headersSent) {
      res.statusCode = 502;
      res.setHeader('Content-Type', 'text/plain');
      res.end('Bad Gateway: Unable to reach upstream server');
    }
  });

  // Set timeout
  const timeout = parseInt(options.timeout || '30000', 10);
  proxyReq.setTimeout(timeout, () => {
    console.error('[Reverse Proxy] Proxy request timeout');
    proxyReq.abort();
    if (!res.headersSent) {
      res.statusCode = 504;
      res.setHeader('Content-Type', 'text/plain');
      res.end('Gateway Timeout');
    }
  });

if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
  console.log('[Reverse Proxy] Buffering request body...');
  
  let body = [];
  
  req.on('data', (chunk) => {
    body.push(chunk);
  });
  
  req.on('end', () => {
    const fullBody = Buffer.concat(body);
    console.log(`[Reverse Proxy] Body length: ${fullBody.length}`);
    
    if (fullBody.length > 0) {
      proxyReq.write(fullBody);
    }
    proxyReq.end();
  });
  
  req.on('error', (err) => {
    console.error('[Reverse Proxy] Request error:', err);
    proxyReq.destroy();
  });
} else {
  proxyReq.end();
}
}

module.exports = { onStart, onRequest };