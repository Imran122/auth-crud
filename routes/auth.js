const express = require("express");
const router = express.Router();

// import controller
const {
  signup,
  signin,

  forgotPasswordSentLinkToEmail,
  updatePassword,
} = require("../controllers/auth");
const { authenticate } = require("../middleware/authurize");
// import validators
const {
  userSignupValidator,
  userSigninValidator,
} = require("../validators/auth");
const { runValidation } = require("../validators");

router.post("/signup", userSignupValidator, runValidation, signup);
router.post("/signin", userSigninValidator, runValidation, signin);

router.put("/forgot-password-sys-to-sent-email", forgotPasswordSentLinkToEmail);
router.put("/update-password", updatePassword);
module.exports = router;
