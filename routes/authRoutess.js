const express = require("express");
const router = express.Router();
const authContrroler = require("../controller/authController");

router.route("/register").post(authContrroler.register);
router.route("/login").post(authContrroler.login);
router.route("/refrsh").get(authContrroler.refrsh);
router.route("/logout").post(authContrroler.logout);

module.exports = router;
