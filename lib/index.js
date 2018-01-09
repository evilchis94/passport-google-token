'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _passportOauth = require('passport-oauth');

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; } /**
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                * Module dependencies.
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                */


/**
 * `Strategy` constructor.
 *
 * The Google authentication strategy authenticates requests by delegating to
 * Google using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Google application's client id
 *   - `clientSecret`  your Google application's client secret
 *   - `callbackURL`   URL to which Google will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new GoogleStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/google/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
var GoogleTokenStrategy = function (_OAuth2Strategy) {
    _inherits(GoogleTokenStrategy, _OAuth2Strategy);

    function GoogleTokenStrategy(_options, _verify) {
        _classCallCheck(this, GoogleTokenStrategy);

        var options = _options || {};
        var verify = _verify;

        options.authorizationURL = options.authorizationURL || 'https://accounts.google.com/o/oauth2/auth';
        options.tokenURL = options.tokenURL || 'https://accounts.google.com/o/oauth2/token';

        var _this = _possibleConstructorReturn(this, (GoogleTokenStrategy.__proto__ || Object.getPrototypeOf(GoogleTokenStrategy)).call(this, options, verify));

        _this.name = 'google-token';
        _this._accessTokenField = options.accessTokenField || 'access_token';
        _this._refreshTokenField = options.refreshTokenField || 'refresh_token';
        return _this;
    }

    /**
    * Authenticate request by delegating to a service provider using OAuth 2.0.
    *
    * @param {Object} req
    * @api protected
    */


    _createClass(GoogleTokenStrategy, [{
        key: 'authenticate',
        value: function authenticate(req, options) {
            var _this2 = this;

            var accessToken = this.lookup(req, this._accessTokenField);
            var refreshToken = this.lookup(req, this._refreshTokenField);

            if (!accessToken) return this.fail({ message: 'You should provide ' + this._accessTokenField });

            this._loadUserProfile(accessToken, function (error, profile) {
                if (error) return _this2.error(error);

                var verified = function verified(error, user, info) {
                    if (error) return _this2.error(error);
                    if (!user) return _this2.fail(info);

                    return _this2.success(user, info);
                };

                if (_this2._passReqToCallback) {
                    _this2._verify(req, accessToken, refreshToken, profile, verified);
                } else {
                    _this2._verify(accessToken, refreshToken, profile, verified);
                }
            });
        }

        /**
        * Retrieve user profile from Google.
        *
        * This function constructs a normalized profile, with the following properties:
        *
        *   - `provider`         always set to `google`
        *   - `id`
        *   - `username`
        *   - `displayName`
        *
        * @param {String} accessToken
        * @param {Function} done
        * @api protected
        */

    }, {
        key: 'userProfile',
        value: function userProfile(accessToken, done) {
            this._oauth2.get('https://www.googleapis.com/oauth2/v1/userinfo', accessToken, function (err, body, res) {
                if (err) {
                    return done(new _passportOauth.InternalOAuthError('Failed to fetch user profile', err));
                }

                try {
                    var json = JSON.parse(body);

                    var profile = {
                        provider: 'google'
                    };
                    profile.id = json.id;
                    profile.displayName = json.name;
                    profile.name = {
                        familyName: json.family_name,
                        givenName: json.given_name
                    };
                    profile.emails = [{
                        value: json.email
                    }];

                    profile._raw = body;
                    profile._json = json;

                    done(null, profile);
                } catch (e) {
                    done(e);
                }
            });
        }
    }, {
        key: 'parseOAuth2Token',
        value: function parseOAuth2Token(req) {
            var OAuth2AuthorizationField = 'Authorization';
            var headerValue = req.headers && (req.headers[OAuth2AuthorizationField] || req.headers[OAuth2AuthorizationField.toLowerCase()]);

            return headerValue && function () {
                var bearerRE = /Bearer\ (.*)/;
                var match = bearerRE.exec(headerValue);
                return match && match[1];
            }();
        }
    }, {
        key: 'lookup',
        value: function lookup(req, field) {
            return req.body && req.body[field] || req.query && req.query[field] || req.headers && (req.headers[field] || req.headers[field.toLowerCase()]) || this.parseOAuth2Token(req);
        }
    }]);

    return GoogleTokenStrategy;
}(_passportOauth.OAuth2Strategy);

exports.default = GoogleTokenStrategy;
module.exports = exports['default'];