const jwt = require('jsonwebtoken');

const verifyJWT = async (req, res, next) => {

    const authHeader = req.headers.authorization || req.headers.Authorization;

    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No token provided || UnAuthorized' });
    }
    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.JWT_SECRET_ACCESS_TOKEN, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token || forbidden' });
        }
        req.decoded = decoded;
        next();
    });
};

module.exports = verifyJWT;