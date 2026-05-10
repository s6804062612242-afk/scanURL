require('dotenv').config();
const express = require('express');
const axios = require('axios');
const sanitizeHtml = require('sanitize-html');
const cheerio = require('cheerio');
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

// --- Sandbox preview endpoint ---

async function fetchWithRedirects(initialUrl, maxHops = 6) {
  let current = initialUrl;
  const chain = [current];
  let finalResponse = null;
  for (let i = 0; i < maxHops; i++) {
    try {
      const resp = await axios.get(current, { maxRedirects: 0, timeout: 8000, validateStatus: s => true, responseType: 'text' });
      const status = resp.status;
      if (status >= 300 && status < 400 && resp.headers && resp.headers.location) {
        const next = new URL(resp.headers.location, current).toString();
        chain.push(next);
        current = next;
        continue;
      }
      finalResponse = { url: current, status: status, headers: resp.headers, data: resp.data };
      break;
    } catch (err) {
      if (err && err.response) {
        const resp = err.response;
        const status = resp.status;
        if (status >= 300 && status < 400 && resp.headers && resp.headers.location) {
          const next = new URL(resp.headers.location, current).toString();
          chain.push(next);
          current = next;
          continue;
        } else {
          finalResponse = { url: current, status: status, headers: resp.headers || {}, data: resp.data || '' };
          break;
        }
      } else {
        throw err;
      }
    }
  }
  return { chain, finalResponse };
}

function sanitizeAndRewrite(html, baseUrl) {
  const $ = cheerio.load(html, { decodeEntities: false });
  $('script, iframe, object, embed, form, meta[http-equiv], link[rel="stylesheet"], style, noscript').remove();
  $('*').each((i, el) => {
    const attribs = el.attribs || {};
    Object.keys(attribs).forEach((a) => {
      if (/^on/i.test(a) || a === 'style' || a === 'src' || a === 'srcset' || a === 'background') {
        $(el).removeAttr(a);
      }
    });
  });
  $('a').each((i, el) => {
    const href = $(el).attr('href');
    if (!href) { $(el).removeAttr('href'); return; }
    try {
      const resolved = new URL(href, baseUrl).toString();
      $(el).attr('href', '/preview?url=' + encodeURIComponent(resolved));
      $(el).attr('rel', 'noopener noreferrer');
      $(el).attr('target','_top');
    } catch (e) {
      $(el).removeAttr('href');
    }
  });
  $('form').remove();
  const cleaned = sanitizeHtml($.html(), {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(['h1','h2','h3','h4','h5','h6','img','table','thead','tbody','tr','th','td','pre','code']),
    allowedAttributes: {
      a: ['href','rel','target'],
      img: ['alt'],
      '*': []
    },
    transformTags: {
      'img': function(tagName, attribs) { return { tagName: 'img', attribs: { alt: attribs.alt || '' } }; }
    }
  });
  return cleaned;
}

app.get('/preview', async (req, res) => {
  const urlParam = req.query.url;
  if (!urlParam) return res.status(400).send('Missing url parameter');
  let normalized;
  try { normalized = normalizeInput(urlParam); } catch(e) { return res.status(400).send('Invalid url'); }
  try {
    const { chain, finalResponse } = await fetchWithRedirects(normalized, 6);
    if (!finalResponse) {
      return res.status(502).send('Unable to fetch URL or too many redirects');
    }
    const contentType = (finalResponse.headers['content-type'] || '').toLowerCase();
    const isHtml = contentType.includes('text/html') || /<html/i.test(finalResponse.data || '');
    const finalUrl = finalResponse.url;
    const chainHtml = chain.map(u => `<li><a href="/preview?url=${encodeURIComponent(u)}">${u}</a></li>`).join('');
    let bodyHtml = '<div><em>ไม่สามารถแสดงตัวอย่าง (เนื้อหาไม่ใช่ HTML)</em></div>';
    if (isHtml) {
      const sanitized = sanitizeAndRewrite(finalResponse.data || '', finalUrl);
      bodyHtml = sanitized;
    }
    const multiWarning = chain.length > 1 ? `<div style="color:#b91c1c;font-weight:600">คำเตือน: พบการเปลี่ยนเส้นทาง ${chain.length} ชั้น</div>` : '';
    const page = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sandbox Preview</title></head><body><div style="max-width:900px;margin:0 auto;padding:1rem;font-family:system-ui,Arial,Helvetica,sans-serif"><h2>Sandbox Preview</h2>${multiWarning}<div>Redirect chain:<ul>${chainHtml}</ul></div><div style="border:1px solid #ddd;padding:1rem;margin-top:1rem;background:#fff">${bodyHtml}</div><div style="margin-top:1rem"><a href="${finalUrl}" target="_blank" rel="noopener noreferrer">Open original (external)</a></div></div></body></html>`;
    res.set('Content-Type','text/html; charset=utf-8').send(page);
  } catch (e) {
    res.status(500).send('Error fetching preview: ' + e.message);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on port ${port}`));
