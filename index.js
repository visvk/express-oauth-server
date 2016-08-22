
/**
 * Module dependencies.
 */

var InvalidArgumentError = require('oauth2-server/lib/errors/invalid-argument-error');
var NodeOAuthServer = require('oauth2-server');
var Promise = require('bluebird');
var Request = require('oauth2-server').Request;
var Response = require('oauth2-server').Response;
var UnauthorizedRequestError = require('oauth2-server/lib/errors/unauthorized-request-error');
var InvalidTokenError = require('oauth2-server/lib/errors/invalid-token-error');

/**
 * Constructor.
 */

function ExpressOAuthServer(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  this.useErrorHandler = options.useErrorHandler ? true : false;
  delete options.useErrorHandler;

  this.server = new NodeOAuthServer(options);
}

/**
 * Authentication Middleware.
 *
 * Returns a middleware that will validate a token.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-7)
 */

ExpressOAuthServer.prototype.authenticate = function(options) {
  return (function(req, res, next) {
    var request = new Request(req);
    var response = new Response(res);

    return Promise.bind(this)
      .then(function() {
        return this.server.authenticate(request, response, options);
      })
      .tap(function(token) {
        res.locals.oauth = { token: token };
        next();
      })
      .catch(function(e) {
        return handleError(e, req, res, null, next);
    });
  }).bind(this);
};

/**
 * Authorization Middleware.
 *
 * Returns a middleware that will authorize a client to request tokens.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.1)
 */

ExpressOAuthServer.prototype.authorize = function(options) {
  return (function(req, res, next) {
    var request = new Request(req);
    var response = new Response(res);

    return Promise.bind(this)
      .then(function() {
        return this.server.authorize(request, response, options);
      })
      .tap(function(code) {
        res.locals.oauth = { code: code };
      })
      .then(function() {
        return handleResponse(req, res, response);
      })
      .catch(function(e) {
        return handleError.call(this, e, req, res, response, next);
      })
      .finally(next);
  }).bind(this);
};

/**
 * Grant Middleware.
 *
 * Returns middleware that will grant tokens to valid requests.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.2)
 */

ExpressOAuthServer.prototype.token = function(options) {
  return (function(req, res, next) {
    var request = new Request(req);
    var response = new Response(res);

    return Promise.bind(this)
      .then(function() {
        return this.server.token(request, response, options);
      })
      .tap(function(token) {
        res.locals.oauth = { token: token };
      })
      .then(function() {
        return handleResponse(req, res, response);
      })
      .catch(function(e) {
        return handleError.call(this, e, req, res, response, next);
      })
      .finally(next);
  }).bind(this);
};

/**
 * Revocation Middleware.
 *
 * Returns middleware that will revoke a token.
 *
 * (See: https://tools.ietf.org/html/rfc7009#section-2)
 */

ExpressOAuthServer.prototype.revoke = function(options) {
  return (function(req, res, next) {
    var request = new Request(req);
    var response = new Response(res);

    return Promise.bind(this)
      .then(function() {
        return this.server.revoke(request, response, options);
      })
      .then(function() {
        return handleResponse(req, res, response);
      })
      .catch(function(e) {
        if (e instanceof InvalidTokenError) {
          this.invalidTokenOnRevoke = true;
        }

        return handleError.call(this, e, req, res, response, next);
      })
      .finally(next);
  }).bind(this);
};

/**
 * Handle response.
 */
var handleResponse = function(req, res, response) {

  if (response.status === 302) {
    var location = response.headers.location;
    delete response.headers.location;
    res.set(response.headers);
    res.redirect(location);
  }
  else {
    res.set(response.headers);
    res.status(response.status).send(response.body);
  }
};

/**
 * Handle error.
 */

var handleError = function(e, req, res, response, next) {
  if (this.useErrorHandler === true) {
    next(e);
  } else {
    if (response) {
      res.set(response.headers);
    }

    if (e instanceof UnauthorizedRequestError) {
      return res.status(e.code);
    }

    /**
     * All necessary information is conveyed in the response code.
     *
     * Note: invalid tokens do not cause an error response since the client
     * cannot handle such an error in a reasonable way.  Moreover, the
     * purpose of the revocation request, invalidating the particular token,
     * is already achieved.
     * @see https://tools.ietf.org/html/rfc7009#section-2.2
     */
    if (this.invalidTokenOnRevoke) {
      return res.status(200).send()
    }

    res.status(e.code).send({ error: e.name, error_description: e.message });
  }
};

/**
 * Export constructor.
 */

module.exports = ExpressOAuthServer;
