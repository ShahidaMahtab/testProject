const CustomError = require('../errors');
const { isTokenValid } = require('../utils');

// user will be authenticated using token and req will be customized adding user property
const authenticateUser = (req, res, next) => {
    const token = req.signedCookies.token;

    if(!token) {
        throw new CustomError.UnauthenticatedError('Authentication Invalid');
    };

    try {
        const payload = isTokenValid({ token });
        const { name, userId, role } = payload;
        req.user = { name, userId, role };
        next();
    } catch (error) {
        throw new CustomError.UnauthenticatedError('Authentication Invalid'); 
    };
};

// to check multiple role based authentication
const authorizePermissions = (...roles) => { // ... rest operator
    return (req, res, next) => {
        if(!roles.includes(req.user.role)) {
            throw new CustomError.UnauthorizedError('Unauthorized to access this route'); 
        }
        next();
    }
}

module.exports = {
    authenticateUser,
    authorizePermissions
};