const jsonwebtoken = require("jsonwebtoken");
require("dotenv").config();
const User = require("../models/user");





// Create the Express JWT middleware
const jwt = require('jsonwebtoken');

exports.authenticate = async (req, res, next) => {
  let token = req.header('Authorization');

  if (!token) return res.status(404).json({ msg: 'Token not found!' });

  token = token.replace('Bearer ', '');

  try {
    const vrfy = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Ver', vrfy);
    req.ID = vrfy._id;
    next();
  } catch (err) {
    return res.status(401).json({ msg: 'Invalid Token' });
  }
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
