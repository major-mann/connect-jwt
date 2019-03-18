# Connect JWT
A connect handler for validating a JWT that can come from header, cookie or query string. Supports validation of multiple concurrent issuers. Uses [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) to perform the actual token validation.

## Usage

    const jwt = require('@major-mann/connect-jwt');
    app.use(jwt({
        cookieName = 'session',
        queryName = 'token',
        headerName = 'authorization',
        tokenType = 'bearer',
        strictTokenType = false,
        maxAge = '14d',
        completeToken = false,
        fetchIssuerData: () => ({
            // All of the following is passed to jsonwebtoken
            key, // Required
            algorithms, // Supported algorithm
            maxAge,
            subject,
            audience,
            clockTolerance,
            ignoreNotBefore,
            ignoreExpiration
        })
    }));
