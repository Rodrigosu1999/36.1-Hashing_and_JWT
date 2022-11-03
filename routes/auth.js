const jwt = require("jsonwebtoken");
const express = require("express");
const router = new express.Router();

const User = require("../models/user");
const {SECRET_KEY} = require("../config");
const ExpressError = require("../expressError");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
    try {
        const {username, password} = req.body;
        const isAuth = await User.authenticate(username, password);
        if (isAuth) {
            const payload = {username};
            const _token = jwt.sign(payload, SECRET_KEY);
            User.updateLoginTimestamp(username);
            return res.json({_token});
        } else {
            throw new ExpressError("Invalid username/password", 400);
        }
    } catch (e) {
        return next(e);
    }
});


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async (req, res, next) => {
    try {
        const {username} = await User.register(req.body);
        const payload = {username};
        const _token = jwt.sign(payload, SECRET_KEY); 
        return res.json({_token})
    } catch (e) {
        if (e.code === "23505") {
            return next(new ExpressError("Username is already taken", 400));
        } 
        return next(e);
    }
});

module.exports = router;