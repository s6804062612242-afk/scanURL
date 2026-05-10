require('dotenv').config();
const express = require('express');
const axios = require('axios');
const net = require('net');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

function normalizeInput(input) {
  if (typeof input !== 'string') throw new Error('URL must be a string');
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(input) ? input : 'http://' + input;
}

function heuristicsCheck(input) {
  try {
    const normalized = normalizeInput(input);
    const u = new URL(normalized);
    const hostname = u.hostname;
    const details = [];

    // protocol
    const okProtocols = ['http:', 'https:'];
    details.push({ check: 'protocol', suspicious: !okProtocols.includes(u.protocol), info: u.protocol });

    // ip host
    const isIp = net.isIP(hostname) !== 0;
    details.push({ check: 'ip-host', suspicious: isIp, info: hostname });

    // userinfo / @
    const hasUserinfo = u.username || u.password || normalized.includes('@');
    details.push({ check: 'userinfo-@', suspicious: !!hasUserinfo });

    // punycode
    const isPuny = /^xn--/i.test(hostname);
    details.push({ check: 'punycode', suspicious: isPuny });

    // long hostname
    details.push({ check: 'long-host', suspicious: hostname.length > 30, info: hostname.length });

    // many subdomains
    const parts = hostname.split('.').filter(Boolean);
    details.push({ check: 'many-subdomains', suspicious: parts.length > 4, info: parts.length });

    // suspicious tld
    const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq'];
    const tld = parts[parts.length - 1] ? parts[parts.length - 1].toLowerCase() : '';
    details.push({ check: 'suspicious-tld', suspicious: suspiciousTlds.includes(tld), info: tld });

    // long url
    details.push({ check: 'long-url', suspicious: normalized.length > 200, info: normalized.length });

    // many query params
    const paramsCount = Array.from(u.searchParams.keys()).length;
    details.push({ check: 'many-query-params', suspicious: paramsCount > 5, info: paramsCount });

    const score = details.reduce((s, c) => s + (c.suspicious ? 1 : 0), 0);
    const verdict = score >= 2 ? 'suspicious' : (score === 1 ? 'warning' : 'clean');

    return { ok: true, input, normalized, hostname, verdict, score, details };
  } catch (err) {
    return { ok: false, error: 'invalid_input', message: err.message };
  }
}

async function vtLookup(normalizedUrl) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY || process.env.VT_API_KEY;
  if (!apiKey) return { enabled: false, message: 'VIRUSTOTAL_API_KEY not set' };

  try {
    const encoded = Buffer.from(normalizedUrl).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const vtUrl = `https://www.virustotal.com/api/v3/urls/${encoded}`;
    try {
      const resp = await axios.get(vtUrl, { headers: { 'x-apikey': apiKey } });
      return { enabled: true, data: resp.data.data.attributes };
    } catch (err) {
      if (err.response && err.response.status === 404) {
        // submit URL for analysis
        await axios.post('https://www.virustotal.com/api/v3/urls', `url=${encodeURIComponent(normalizedUrl)}`, {
          headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' }
        });
        // wait briefly for VT to queue analysis
        await new Promise(r => setTimeout(r, 1500));
        const resp2 = await axios.get(vtUrl, { headers: { 'x-apikey': apiKey } });
        return { enabled: true, data: resp2.data.data.attributes };
      }
      throw err;
    }
  } catch (err) {
    return { enabled: true, error: err.message || String(err) };
  }
}

app.post('/check', async (req, res) => {
  const url = req.body && req.body.url;
  if (!url) return res.status(400).json({ ok: false, error: 'missing_url', message: 'POST JSON must contain { "url": "..." }' });
  const result = heuristicsCheck(url);
  try {
    const vt = await vtLookup(result.normalized);
    result.virustotal = vt;
  } catch (e) {
    result.virustotal = { error: e.message || String(e) };
  }
  res.json(result);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on port ${port}`));
