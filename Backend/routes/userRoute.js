const express = require("express");
const { 
    registerUser, 
    loginUser, 
    logoutUser, 
    updateUser, 
    deleteUser 
} = require("../controllers/userController");
const authenticateUser = require("../utils/authenticateUser")

const router = express.Router();

// User Registration
router.post("/register", registerUser);

// User Login
router.post("/login", loginUser);

// User Logout
router.post("/logout", logoutUser);

// Update User Information, protected route with authenticateUser 
router.put("/update",authenticateUser, updateUser);

// Delete User Account, protected route with authenticateUser 
router.delete("/delete", authenticateUser, deleteUser);

module.exports = router;
