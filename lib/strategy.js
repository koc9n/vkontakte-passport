/**
 * Module dependencies.
 */
var uri = require('url')
    , crypto = require('crypto')
    , util = require('util')
    , OAuth2Strategy = require('passport-oauth2')
    , Profile = require('./profile')
    , InternalOAuthError = require('passport-oauth2').InternalOAuthError
    , VKAuthorizationError = require('./errors/vkauthorizationerror')
    , VKTokenError = require('./errors/vktokenerror')
    , VKAPIError = require('./errors/vkapierror');


/**
 * `Strategy` constructor.
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://oauth.vk.com/authorize';
    options.tokenURL = options.tokenURL || 'https://oauth.vk.com/access_token';
    options.scopeSeparator = options.scopeSeparator || ',';

    OAuth2Strategy.call(this, options, verify);

    this.name = 'vkontakte';
    this._clientSecret = options.clientSecret;
    this._enableProof = options.enableProof;
    this._profileURL = options.profileURL || 'https://api.vk.com/method/users.get';
    this._profileFields = options.profileFields || null;
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Authenticate request by delegating to VK using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {

    if (req.query && req.query.error_code && !req.query.error) {
        return this.error(new VKAuthorizationError(req.query.error_message, parseInt(req.query.error_code, 10)));
    }

    options = options || {};
    var self = this;

    if (req.query && req.query.error) {
        if (req.query.error == 'access_denied') {
            return this.fail({message: req.query.error_description});
        } else {
            return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
        }
    }

    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
        var parsed = uri.parse(callbackURL);
        if (!parsed.protocol) {
            // The callback URL is relative, resolve a fully qualified URL from the
            // URL of the originating request.
            callbackURL = uri.resolve(utils.originalURL(req, {proxy: this._trustProxy}), callbackURL);
        }
    }

    if (req.query && req.query.code) {
        var code = req.query.code;

        if (this._state) {
            if (!req.session) {
                return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
            }

            var key = this._key;
            if (!req.session[key]) {
                return this.fail({message: 'Unable to verify authorization request state.'}, 403);
            }
            var state = req.session[key].state;
            if (!state) {
                return this.fail({message: 'Unable to verify authorization request state.'}, 403);
            }

            delete req.session[key].state;
            if (Object.keys(req.session[key]).length === 0) {
                delete req.session[key];
            }

            if (state !== req.query.state) {
                return this.fail({message: 'Invalid authorization request state.'}, 403);
            }
        }

        var params = this.tokenParams(options);
        params.grant_type = 'authorization_code';
        params.redirect_uri = callbackURL;

        this._oauth2.getOAuthAccessToken(code, params,
            function (err, accessToken, refreshToken, params) {
                if (err) {
                    return self.error(self._createOAuthError('Failed to obtain access token', err));
                }
                /**
                 * added params after getting acces_code to load to profile
                 */
                self._loadUserProfile(params, accessToken, function (err, profile) {
                    if (err) {
                        return self.error(err);
                    }

                    function verified(err, user, info) {
                        if (err) {
                            return self.error(err);
                        }
                        if (!user) {
                            return self.fail(info);
                        }
                        self.success(user, info);
                    }

                    try {
                        if (self._passReqToCallback) {
                            var arity = self._verify.length;
                            if (arity == 6) {
                                self._verify(req, accessToken, refreshToken, params, profile, verified);
                            } else { // arity == 5
                                self._verify(req, accessToken, refreshToken, profile, verified);
                            }
                        } else {
                            var arity = self._verify.length;
                            if (arity == 5) {
                                self._verify(accessToken, refreshToken, params, profile, verified);
                            } else { // arity == 4
                                self._verify(accessToken, refreshToken, profile, verified);
                            }
                        }
                    } catch (ex) {
                        return self.error(ex);
                    }
                });
            }
        );
    } else {
        var params = this.authorizationParams(options);
        params.response_type = 'code';
        params.redirect_uri = callbackURL;
        var scope = options.scope || this._scope;
        if (scope) {
            if (Array.isArray(scope)) {
                scope = scope.join(this._scopeSeparator);
            }
            params.scope = scope;
        }
        var state = options.state;
        if (state) {
            params.state = state;
        } else if (this._state) {
            if (!req.session) {
                return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
            }

            var key = this._key;
            state = uid(24);
            if (!req.session[key]) {
                req.session[key] = {};
            }
            req.session[key].state = state;
            params.state = state;
        }

        var location = this._oauth2.getAuthorizeUrl(params);
        this.redirect(location);
    }
};

Strategy.prototype._loadUserProfile = function (params, accessToken, done) {
    var self = this;

    function loadIt() {
        return self.userProfile(params, accessToken, done);
    }

    function skipIt() {
        return done(null);
    }

    if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
        // async
        this._skipUserProfile(accessToken, function (err, skip) {
            if (err) {
                return done(err);
            }
            if (!skip) {
                return loadIt();
            }
            return skipIt();
        });
    } else {
        var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
        if (!skip) {
            return loadIt();
        }
        return skipIt();
    }
};

/**
 * Retrieve user profile from VK.
 *
 * set up _profileFields to get that information from profile what you need
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (params, accessToken, done) {
    var url = uri.parse(this._profileURL);
    if (this._enableProof) {
        // Secure API call by adding proof of the app secret.  This is required when
        // the "Require AppSecret Proof for Server API calls" setting has been
        // enabled.  The proof is a SHA256 hash of the access token, using the app
        // secret as the key.

        var proof = crypto.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
        url.search = (url.search ? url.search + '&' : '') + 'appsecret_proof=' + encodeURIComponent(proof);
    }
    if (this._profileFields) {
        var fields = this._convertProfileFields(this._profileFields);
        if (fields !== '') {
            url.search = (url.search ? url.search + '&' : '') + 'fields=' + fields;
        }
    }
    url = uri.format(url);

    this._oauth2.get(url, accessToken, function (err, body, res) {
        var json;

        if (err) {
            if (err.data) {
                try {
                    json = JSON.parse(err.data);
                } catch (_) {
                }
            }

            if (json && json.error && typeof json.error == 'object') {
                return done(new VKAPIError(json.error.message, json.error.type, json.error.code, json.error.error_subcode));
            }
            return done(new InternalOAuthError('Failed to fetch user profile', err));
        }

        try {
            json = JSON.parse(body);
        } catch (ex) {
            return done(new Error('Failed to parse user profile'));
        }
        json = json.response[0];
        /**
         * add properties from params to profile json obj
         */

        var paramsKeys = Object.keys(params);
        for (var key in paramsKeys) {
            json[paramsKeys[key]] = params[paramsKeys[key]];
        }

        var profile = Profile.parse(json);
        profile.provider = 'vkontakte';
        profile._raw = body;
        profile._json = json;

        done(null, profile);
    });
};

/**
 * Return extra VK-specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `display`  Display mode to render dialog, { `page`, `popup`, `touch` }.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (options) {
    var params = {};

    if (options.display) {
        params.display = options.display;
    }

    if (options.authType) {
        params.auth_type = options.authType;
    }
    if (options.authNonce) {
        params.auth_nonce = options.authNonce;
    }

    return params;
};


/**
 * Parse error response from VK OAuth 2.0 token endpoint.
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
Strategy.prototype.parseErrorResponse = function (body, status) {
    var json = JSON.parse(body);
    if (json.error && typeof json.error == 'object') {
        return new VKTokenError(json.error.message, json.error.type, json.error.code, json.error.error_subcode);
    }
    return OAuth2Strategy.prototype.parseErrorResponse.call(this, body, status);
};

Strategy.prototype._convertProfileFields = function (profileFields) {
    var map = {
        'id': 'id',
        'username': 'username',
        'displayName': 'name',
        'name': ['last_name', 'first_name', 'middle_name'],
        'gender': 'gender',
        'birthday': 'birthday',
        'profileUrl': 'link',
        'emails': 'email',
        'photos': 'picture'
    };

    var fields = [];

    profileFields.forEach(function (f) {
        // return raw VK profile field to support the many fields that don't
        // map cleanly to Portable Contacts
        if (typeof map[f] === 'undefined') {
            return fields.push(f);
        }
        ;

        if (Array.isArray(map[f])) {
            Array.prototype.push.apply(fields, map[f]);
        } else {
            fields.push(map[f]);
        }
    });

    return fields.join(',');
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
