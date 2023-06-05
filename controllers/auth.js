const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { json } = require("body-parser");

exports.signup = (req, res) => {
  const { name, email, password, role } = req.body;
  //const profile = req.files.profileImage;

  //console.log("file", profile);

  //const encodeedPic = picData.toString("base64");
  //const profileImage = Buffer.from(encodeedPic, "base64");
  //console.log(profileImage);

  try {
    User.findOne({ email }).exec((err, user) => {
      if (user) {
        return res.status(400).json({
          error: "Email is taken",
        });
      } else {
        let newUser = new User({
          name,
          role,
          email,
          password,
        });

        newUser.save();
        res.json({
          message: "Signup success! Please signin",
        });
      }
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
        secure: process.env.NODE_ENV === "production", // Set "secure" option based on the environment
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
    const token = uuid.v4();
    console.log(email);
    let transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: "itechverser@gmail.com",
        pass: "ihbjuqfkwjqqbhny",
      },
    });
    let mailOptions = {
      from: "itechverser@gmail.com", // sender address
      to: email, // list of receivers

      subject: "Password reset", // Subject line
      text: "Hello,\n\nPlease click the following link to reset your password:", // plain text body
      html: `<p>Hello,</p><p>Please click the following link to reset your password:</p><a href=${process.env.CLIENT_URL}/change-password?token=${token}>${process.env.CLIENT_URL}/change-password?token=${token}</a>`, // html body
    };
    // send mail with defined transport object
    await transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return console.log(error);
      }
      return res.json({ message: `Message sent to ${email} ` });
    });
  } catch (error) {
    res.json({ message: error });
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
