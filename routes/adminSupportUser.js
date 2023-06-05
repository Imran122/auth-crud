const express = require("express");
const router = express.Router();

// import controller
const {
  createUser,
  userListData,
  userDelete,
  read,
  userUpdateData,
} = require("../controllers/adminSupportUser");
const { authenticate } = require("../middleware/authurize");
// import validators

router.post("/create-user", authenticate, createUser);
router.get("/user-list", authenticate, userListData);
router.delete("/user-delete", authenticate, userDelete);
router.get("/user-details", authenticate, read);
router.patch("/user-update", authenticate, userUpdateData);
module.exports = router;
