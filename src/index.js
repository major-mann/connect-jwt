module.exports = createJwtValidator;

const SESSION_COOKIE = 'session';
const QUERY_NAME = 'token';
const HEADER_NAME = 'authorization';
const BEARER_TOKEN = 'bearer';
const MAX_TOKEN_AGE = "14d";

const jwt = require('jsonwebtoken');

function createJwtValidator({
    fetchIssuerData,
    cookieName = SESSION_COOKIE,
    queryName = QUERY_NAME,
    headerName = HEADER_NAME,
    tokenType = BEARER_TOKEN,
    strictTokenType = false,
    maxAge = MAX_TOKEN_AGE,
    completeToken = false
}) {
    return async function validateJwt(request, response, next) {
        const token = userToken(request);
        if (token) {
            try {
                request.user = await verifyToken(token);
                next();
            } catch (ex) {
                next(ex);
            }
        } else {
            next(new VerificationError('No token supplied', 'no-token'));
        }
    }

    function userToken(request) {
        if (headerName && request.headers[headerName]) {
            return bearerToken(request.headers[headerName]);
        } else if (cookieName && request.headers.cookie) {
            return cookieValue(request.headers.cookie, cookieName);
        } else if (queryName && request.query && request.query[queryName]) {
            return req.query[queryName];
        } else {
            return undefined;
        }
    }

    function bearerToken(authorization) {
        const [type, data] = authorization.trim().split(' ');
        if (data && type.toLowerCase() === tokenType) {
            return data;
        } else if (type && !strictTokenType) {
            return type;
        } else {
            return undefined;
        }
    }

    function cookieValue(cookie, name) {
        const cookies = cookie
            .split(';')
            .map(cookie => cookie.split('='));

        const tokenData = cookies
            .find(([key]) => key === name);
        return tokenData && tokenData[1];
    }

    async function verifyToken(token) {
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.iss || !decoded.aud || !decoded.sub) {
            throw new VerificationError(`Supplied token requires the "iss", "aud" and "sub" claims. ` +
                `Got ${decoded && Object.keys(decoded)}`, 'missing-claims');
        }

        const issuerData = await fetchIssuerData(decoded.iss, decoded);
        if (!issuerData) {
            throw new VerificationError(`Unable to process tokens from "${decoded.iss}"`, 'no-issuer-data');
        }

        try {
            const claims = await verifyJwt(token, issuerData.key, {
                algorithms: issuerData.algorithms,
                audience: issuerData.audience,
                clockTolerance: issuerData.clockTolerance,
                maxAge: issuerData.maxAge || maxAge,
                complete: completeToken,
                ignoreExpiration: issuerData.ignoreExpiration,
                ignoreNotBefore: issuerData.ignoreNotBefore,
                subject: issuerData.subject
            });
            return claims;
        } catch (ex) {
            console.debug('Unable to verify jwt', ex);
            throw new VerificationError('Token signature validation failed', 'invalid-signature');
        }
    }

    function verifyJwt(token, key, options) {
        return new Promise(function promiseHandler(resolve, reject) {
            jwt.verify(token, key, options, function onVerified(err, decoded) {
                if (err) {
                    reject(err);
                } else {
                    resolve(decoded);
                }
            });
        });
    }
}

class VerificationError extends Error {
    constructor(message, code) {
        super(message);
        this.code = code;
    }
}
