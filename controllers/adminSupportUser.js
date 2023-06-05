const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { json } = require("body-parser");

function createUserWithRole(name, email, password, role, res) {
  User.findOne({ email }).exec((err, existingUser) => {
    if (existingUser) {
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
        message: "Account created successfully!",
      });
    }
  });
}

exports.createUser = (req, res) => {
  const { name, email, password, role } = req.body;
  const requestingUserId = req.ID;

  try {
    User.findById(requestingUserId).exec((err, user) => {
      if (user.role === "admin") {
        createUserWithRole(name, email, password, role, res);
      } else if (user.role === "support") {
        if (role !== "admin") {
          createUserWithRole(name, email, password, role, res);
        } else {
          return res.status(400).json({
            error: "Support role can not create admin users",
          });
        }
      } else if (user.role === "normal") {
        return res.status(400).json({
          error: "Normal users are not allowed to create new users",
        });
      } else {
        return res.status(400).json({
          error: "You are not allowed",
        });
      }
    });
  } catch (error) {
    return res.status(400).json(error);
  }
};

//show user list
exports.userListData = async (req, res) => {
  try {
    const user = await User.findById(req.ID).exec();

    if (user.role === "admin") {
      const userList = await User.find();
      res.json(userList);
    } else if (user.role === "support") {
      const userList = await User.find({
        $or: [{ role: "user" }, { role: "support" }],
        _id: { $ne: req.ID },
      });
      res.json(userList);
    } else {
      return res.status(400).json({
        error: "You are not allowed",
      });
    }
  } catch (error) {
    res.json({ message: error });
  }
};

//read user
exports.read = async (req, res) => {
  const _id = req.query.id;
  try {
    const requestingUser = await User.findById(req.ID).exec();

    if (requestingUser.role === "admin") {
      try {
        const user = await User.findById(_id).exec();
        if (!user) {
          return res.status(400).json({
            error: "User not found",
          });
        }
        res.json(user);
      } catch (error) {
        return res.status(400).json({
          error: "Error retrieving user",
        });
      }
    } else if (requestingUser.role === "support") {
      const user = await User.findById(_id).exec();
      if (!user) {
        return res.status(400).json({
          error: "User not found",
        });
      } else if (user.role === "admin") {
        return res.status(400).json({
          error: "You are not allowed to access this user",
        });
      }
      res.json(user);
    } else if (requestingUser.role === "normal-user") {
      if (_id !== req.ID) {
        return res.status(400).json({
          error: "You are not allowed to access this user",
        });
      }
      try {
        const user = await User.findById(_id).exec();
        if (!user) {
          return res.status(400).json({
            error: "User not found",
          });
        }
        res.json(user);
      } catch (error) {
        return res.status(400).json({
          error: "Error retrieving user",
        });
      }
    } else {
      return res.status(400).json({
        error: "You are not allowed",
      });
    }
  } catch (error) {
    res.json({ message: error });
  }
};

//update list
exports.userUpdateData = async (req, res) => {
  const { name, email, _id } = req.body;
  try {
    const requestingUser = await User.findById(req.ID).exec();

    if (requestingUser.role === "admin") {
      try {
        await User.findByIdAndUpdate(_id, {
          $set: {
            name: name,
            email: email,
          },
        });

        return res.json({
          name: name,
          email: email,
        });
      } catch (error) {
        return res.status(400).json({
          error: "Error updating user",
        });
      }
    } else if (requestingUser.role === "support") {
      const userToUpdate = await User.findById(_id).exec();
      if (!userToUpdate) {
        return res.status(400).json({
          error: "User not found",
        });
      } else if (userToUpdate.role === "admin") {
        return res.status(400).json({
          error: "You are not allowed to update this user",
        });
      }
      try {
        await User.findByIdAndUpdate(_id, {
          $set: {
            name: name,
            email: email,
          },
        });

        return res.json({
          name: name,
          email: email,
        });
      } catch (error) {
        return res.status(400).json({
          error: "Error updating user",
        });
      }
    } else if (requestingUser.role === "normal-user") {
      if (_id !== req.ID) {
        return res.status(400).json({
          error: "You are not allowed to update this user",
        });
      }
      try {
        await User.findByIdAndUpdate(_id, {
          $set: {
            name: name,
            email: email,
          },
        });

        return res.json({
          name: name,
          email: email,
        });
      } catch (error) {
        return res.status(400).json({
          error: "Error updating user",
        });
      }
    } else {
      return res.status(400).json({
        error: "You are not allowed",
      });
    }
  } catch (error) {
    res.json({ message: error });
  }
};

//delete user
exports.userDelete = async (req, res) => {
  try {
    const requestingUser = await User.findById(req.ID).exec();
    const id = req.query.id;

    if (requestingUser.role === "admin") {
      try {
        await User.deleteOne({ _id: id });

        return res.json({ message: "Successfully deleted" });
      } catch (error) {
        return res.status(400).json({
          error: "Error deleting user",
        });
      }
    } else if (requestingUser.role === "support") {
      const userToDelete = await User.findById(id).exec();
      if (!userToDelete) {
        return res.status(400).json({
          error: "User not found",
        });
      } else if (userToDelete.role === "admin") {
        return res.status(400).json({
          error: "You are not allowed to delete this user",
        });
      }
      try {
        await User.deleteOne({ _id: id });

        return res.json({ message: "Successfully deleted" });
      } catch (error) {
        return res.status(400).json({
          error: "Error deleting user",
        });
      }
    } else if (requestingUser.role === "normal-user") {
      return res.status(400).json({
        error: "You are not allowed to delete users",
      });
    } else {
      return res.status(400).json({
        error: "You are not allowed",
      });
    }
  } catch (error) {
    res.json({ message: error });
  }
};
