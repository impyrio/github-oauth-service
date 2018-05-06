'use strict';

const crypto = require('crypto');
const express = require('express');
const request = require('request');
const session = require('express-session');
const qs = require('querystring');

// Configuration
const oauth_uri = 'https://github.com/login/oauth';
const client_id = process.env.CLIENT_ID;
const client_secret = process.env.CLIENT_SECRET;
const callback_uri = process.env.CALLBACK_URI;
const scope = 'user';
const mongo_config = {
  uri: process.env.MONGO_URI,
  databaseName: process.env.MONGO_DB,
  collection: process.env.MONGO_COLLECTION
};
const cookie_maxAge = process.env.COOKIE_MAXAGE || 60 * 60 * 24 * 7; // 1 wk
const session_secret = process.env.SESSION_SECRET || 'keyboard cat';

const hashedHeaders = ['user-agent', 'forwarded', 'x-forwarded-for'];

// generate a temporary 'state' hash from the given request.
function getState(req, off = 0) {
  const hash = crypto.createHash('sha256');
  const d = Math.trunc(new Date().getTime() / 300000) - off;

  hash.update(d.toString(36));
  hashedHeaders.forEach(h => {
    if (req.headers[h]) {
      hash.update(req.headers[h]);
    }
  });
  
  return hash.digest('hex');
}

const app = express();

// session setup
const MongoDBStore = require('connect-mongodb-session')(session);
var store = new MongoDBStore(mongo_config);
store.on('error', function(error) {
  assert.ifError(error);
  assert.ok(false);
});
app.use(session({
  secret: session_secret,
  cookie: {maxAge: cookie_maxAge},
  store: store,
  resave: true,
  saveUninitialized: true
}));

// NOTE: used for isolated testing
app.get('/', (req, res) => {
  const token = req.session.access_token;
  const link = token ? 'logout' : 'login';
  res.send(`<!doctype html><head><title>github-oauth-service</title><body>
<pre><code>token: ${token || '<em>- none -</em>'}
<a href="/oauth:${link}">${link}</a></code></pre>`);
});

app.get('/oauth[:]login', (req, res) => {
  const state = getState(req);
  const return_uri = req.query.return_uri || '/';
  const redirect_uri = `${callback_uri}?${qs.stringify({return_uri})}`;
  const params = {client_id, scope, redirect_uri, state};
  res.redirect(`${oauth_uri}/authorize?${qs.stringify(params)}`);
});

app.get('/oauth[:]logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/oauth[:]authorize', (req, res) => {
  const {code, state, return_uri} = req.query;

  if (state !== getState(req) && state !== getState(req, 1)) {
    res.sendStatus(401);
    return;
  }

  const body = {client_id, client_secret, code, state};
  const uri = `${oauth_uri}/access_token`;
  request.post({uri, json: true, body}, (e, r, body) => {
    if (e || !body.access_token) {
      res.sendStatus(400);
      return;
    }

    req.session.access_token = body.access_token;
    res.redirect(return_uri || '/');
  });
});

app.listen(process.env.PORT || 8000);