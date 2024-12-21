const jwt = require("jsonwebtoken");
const User = require("../models/userSchema");

const authenticateUser = async (req, res, next) => {
    try {
        const token = req.cookies.token || req.headers.authorization?.split(" ")[1];

        if (!token) {
            return res.status(401).json({error: "Authentication required"});
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (!user || !user.isVerified) {
            return res.status(401).json({error: "Invalid token. Or Account not verified. Please verify your email."});
        }

        req.user = user;
        next();
    } catch (error) {
        console.error("Authentication error", error);
        res.status(401).json({error: "Authentication failed"});
    }
};

module.exports = authenticateUser;