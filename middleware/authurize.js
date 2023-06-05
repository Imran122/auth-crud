const jsonwebtoken = require("jsonwebtoken");
require("dotenv").config();
const User = require("../models/user");
const { expressjwt: expressJwt } = require("express-jwt");
var jwks = require("jwks-rsa");

const jwks = JWKS({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
});

// Create the Express JWT middleware
const jwtCheck = expressJwt({
  secret: jwks.expressJwtSecret({
    jwksUri: 'your-jwks-uri', // Provide the URL to your JWKS endpoint
  }),
  algorithms: ['RS256'],
});
exports.authenticate = (req, res, next) => {
  let token = req.header('Authorization');

  if (!token) return res.status(404).json({ msg: 'Token not found!' });

  token = token.replace('Bearer ', '');

  jwtCheck(req, res, async function (err, success) {
    if (err) {
      try {
        const vrfy = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Ver', vrfy);
        req.ID = vrfy._id;
        next();
      } catch (_) {
        return res.status(401).json({ msg: 'Invalid Token' });
      }
    } else {
      const { useremail } = jwt.decode(token);
      console.log('useremail....', useremail);
      try {
        const user = await User.findOne({ email: useremail });
        const { _id } = user;
        console.log('_id....', _id);
        req.ID = _id;
      } catch (error) {
        console.log(error);
      }

      next();
    }
  });
};
exports.checkSenderUserId = (req, res, next) => {
  const { sender_userId } = req.body;

  console.log("fisrt ", sender_userId);
  if (sender_userId && sender_userId === req.ID) {
    next();
  } else {
    const { sender_userId } = req.query;
    console.log("second ", sender_userId);
    console.log("req.ID ", req.ID);

    if (sender_userId && sender_userId == req.ID) {
      next();
    } else {
      return res
        .status(404)
        .json({ msg: "You are not authorized to send this request" });
    }
  }
};

exports.resetToken = (req, res, next) => {
  const token = req.header("auth-Token");
  // console.log(token);
  if (!token) return res.status(404).json({ msg: "Token not found!" });
  try {
    const vrfy = jsonwebtoken.verify(token, process.env.PASSWORD_RESET_TOKEN);
    req.ID = vrfy.ID;
    next();
  } catch (_) {
    res.status(401).json({ msg: "Invalid Token" });
  }
};
