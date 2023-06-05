const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { v4: uuid } = require('uuid');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

exports.signup = async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    const user = await User.findOne({ email }).exec();
    if (user) {
      return res.status(400).json({
        error: "Email is taken",
      });
    }

    const verificationCode = crypto.randomBytes(3).toString('hex').toUpperCase();

    const newUser = new User({
      name,
      role,
      email,
      password,
      verificationCode,
    });

    await newUser.save();

    res.json({
      message: "Signup success! Please verify your email with the verification code",
      verificationCode,
    });
  } catch (error) {
    return res.status(400).json(error);
  }
};




//verify code
exports.verifyCode = async (req, res) => {
  const { email, verificationCode } = req.body;

  try {
    const user = await User.findOne({ email }).exec();
    if (!user) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    if (user.verified) {
      return res.status(400).json({
        error: "User is already verified",
      });
    }

    if (user.verificationCode !== verificationCode) {
      return res.status(400).json({
        error: "Invalid verification code",
      });
    }

    user.verified = true;
    user.verificationCode = null;
    await user.save();

    res.json({
      message: "Verification successful. You can now login.",
    });
  } catch (error) {
    return res.status(400).json(error);
  }
};



exports.signin = (req, res) => {
  const { email, password } = req.body;

  // check if user exists
  User.findOne({ email }).exec((err, user) => {
    console.log(user);
    if (err || !user) {
      return res.status(400).json({
        error: "User with that email does not exist. Please signup",
      });
    }

    // authenticate
    if (!user.authenticate(password)) {
      return res.status(400).json({
        error: "Email and password do not match",
      });
    }
  // Check if the user is verified
  if (!user.verified) {
    return res.status(400).json({
      error: "User is not verified. Please verify after signup",
    });
  }
    if (
      user.role === "admin" ||
      user.role === "support" ||
      user.role === "user"
    ) {
      // Set the user object in the session
      req.session.user = {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      };

      // Generate a JWT token
      const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });

      // Set the JWT token as a cookie
      res.cookie("token", token, {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        
      });

      // Return the user details and token
      return res.json({
        token,
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    } else {
      return res.status(400).json({
        error: "User not found",
      });
    }
  });
};

// create reusable transporter object using the default SMTP transport
exports.forgotPasswordSentLinkToEmail = async (req, res) => {
  try {
    const email = req.body.email;
    const token = uuid();

    let transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: "itechverser22@gmail.com",
        pass: "utypznwxwgxzzbkv",
      },
    });

    let mailOptions = {
      from: "itechverser22@gmail.com",
      to: email,
      subject: "Password reset",
      text: "Hello,\n\nPlease click the following link to reset your password:",
      html: `<p>Hello,</p><p>Please click the following link to reset your password:</p><a href=${process.env.CLIENT_URL}/change-password?token=${token}>${process.env.CLIENT_URL}/change-password?token=${token}</a>`,
    };

    await new Promise((resolve, reject) => {
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });

    res.json({ message: `Message sent to ${email}` });
  } catch (error) {
    res.json({ message: error.message });
  }
};

//reset password api by the token
exports.updatePassword = async (req, res) => {
  try {
    const { token, password, email } = req.body;
    const user = await User.findOne({
      email: email,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ error: "User Not Found.Give Valid User Email." });
    }
    user.password = password; // Set the new password
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    user.salt = user.makeSalt(); // Generate a new salt for the user
    user.hashed_password = user.encryptPassword(password); // Encrypt the new password
    await user.save();
    // send email to the user to confirm that their password has been changed
    res.status(200).json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
};
