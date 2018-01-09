/**
 * Module dependencies.
 */
import {OAuth2Strategy, InternalOAuthError} from 'passport-oauth';
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
export default class GoogleTokenStrategy extends OAuth2Strategy {
    constructor(_options, _verify) {
        const options = _options || {};
        const verify = _verify;

        options.authorizationURL = options.authorizationURL || 'https://accounts.google.com/o/oauth2/auth';
        options.tokenURL = options.tokenURL || 'https://accounts.google.com/o/oauth2/token';

        super(options, verify);

        this.name = 'google-token';
        this._accessTokenField = options.accessTokenField || 'access_token';
        this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    }

    /**
   * Authenticate request by delegating to a service provider using OAuth 2.0.
   *
   * @param {Object} req
   * @api protected
   */
    authenticate(req, options) {
        const accessToken = this.lookup(req, this._accessTokenField);
        const refreshToken = this.lookup(req, this._refreshTokenField);

        if (!accessToken) 
            return this.fail({message: `You should provide ${this._accessTokenField}`});
        
        this._loadUserProfile(accessToken, (error, profile) => {
            if (error) 
                return this.error(error);
            
            const verified = (error, user, info) => {
                if (error) 
                    return this.error(error);
                if (!user) 
                    return this.fail(info);
                
                return this.success(user, info);
            };

            if (this._passReqToCallback) {
                this._verify(req, accessToken, refreshToken, profile, verified);
            } else {
                this._verify(accessToken, refreshToken, profile, verified);
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
    userProfile(accessToken, done) {
        this
            ._oauth2
            .get('https://www.googleapis.com/oauth2/v1/userinfo', accessToken, (err, body, res) => {
                if (err) {
                    return done(new InternalOAuthError('Failed to fetch user profile', err));
                }

                try {
                    const json = JSON.parse(body);

                    const profile = {
                        provider: 'google'
                    };
                    profile.id = json.id;
                    profile.displayName = json.name;
                    profile.name = {
                        familyName: json.family_name,
                        givenName: json.given_name
                    };
                    profile.emails = [
                        {
                            value: json.email
                        }
                    ];

                    profile._raw = body;
                    profile._json = json;

                    done(null, profile);
                } catch (e) {
                    done(e);
                }
            });
    }

    parseOAuth2Token(req) {
        const OAuth2AuthorizationField = 'Authorization';
        const headerValue = (req.headers && (req.headers[OAuth2AuthorizationField] || req.headers[OAuth2AuthorizationField.toLowerCase()]));

        return (headerValue && (() => {
            const bearerRE = /Bearer\ (.*)/;
            let match = bearerRE.exec(headerValue);
            return (match && match[1]);
        })());
    }

    lookup(req, field) {
        return (req.body && req.body[field] || req.query && req.query[field] || req.headers && (req.headers[field] || req.headers[field.toLowerCase()]) || this.parseOAuth2Token(req));
    }
}
