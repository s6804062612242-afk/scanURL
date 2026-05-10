const express = require('express');
const path = require('path');
const net = require('net');
const app = express();

app.use(express.static(path.join(__dirname, 'frontend')));


//route 
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname,'index.html'));
});



//api
// Basic phishing heuristics endpoint
function normalizeInput(input){
  if(typeof input !== 'string') throw new Error('URL must be a string');
  if(!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(input)) return 'http://' + input;
  return input;
}

function heuristicsCheck(input){
  try{
    const normalized = normalizeInput(input);
    const u = new URL(normalized);
    const hostname = u.hostname;
    const details = [];

    // protocol
    const okProtocols = ['http:','https:'];
    details.push({check:'protocol', suspicious: !okProtocols.includes(u.protocol), info: u.protocol});

    // ip host
    const isIp = net.isIP(hostname) !== 0;
    details.push({check:'ip-host', suspicious: isIp, info: hostname});

    // userinfo / @
    const hasUserinfo = u.username || u.password || normalized.includes('@');
    details.push({check:'userinfo-@', suspicious: hasUserinfo});

    // punycode
    const isPuny = /^xn--/i.test(hostname);
    details.push({check:'punycode', suspicious: isPuny});

    // long hostname
    details.push({check:'long-host', suspicious: hostname.length > 30, info: hostname.length});

    // many subdomains
    const parts = hostname.split('.').filter(Boolean);
    details.push({check:'many-subdomains', suspicious: parts.length > 4, info: parts.length});

    // suspicious tld
    const suspiciousTlds = ['tk','ml','ga','cf','gq'];
    const tld = parts[parts.length - 1] ? parts[parts.length - 1].toLowerCase() : '';
    details.push({check:'suspicious-tld', suspicious: suspiciousTlds.includes(tld), info: tld});

    // long url
    details.push({check:'long-url', suspicious: normalized.length > 200, info: normalized.length});

    // many query params
    const paramsCount = Array.from(u.searchParams.keys()).length;
    details.push({check:'many-query-params', suspicious: paramsCount > 5, info: paramsCount});

    const score = details.reduce((s,c)=>s + (c.suspicious ? 1 : 0), 0);
    const verdict = score >= 2 ? 'suspicious' : (score === 1 ? 'warning' : 'clean');

    return { ok:true, input, normalized, hostname, verdict, score, details };
  }catch(err){
    return { ok:false, error:'invalid_input', message: err.message };
  }
}

app.post('/check', (req, res) => {
  const url = req.body && req.body.url;
  if(!url) return res.status(400).json({ ok:false, error:'missing_url', message:'POST JSON must contain { "url": "..." }' });
  const result = heuristicsCheck(url);
  res.json(result);
});


//test

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
