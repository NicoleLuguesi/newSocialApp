const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const brcypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const isEmpty = require("../../utils/isEmpty");
const config = require('config');
const { check, validationResult } = require('express-validator/check');

const User = require('../../models/User');

//@route POST api/users
// @desc Register user
// @access Public
router.post('/', [
  check('name', 'Name is required').notEmpty(),
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
],
 async (req, res) => { 
  const errors = validationResult(req);
  if(!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, password } = req.body;

  try {
    let user = await User.findOne({ email });

    // See if user exists
    if(user) {
      return res
      .status(400)
      .json({ errors: [ { msg: 'User already exists'}]});
    }

    // Get users gravatar
    const avatar = gravatar.url(email, {
      s:'200',
      r: 'pg',
      d: 'mm'
    })

    user = new User({
      name,
      email,
      avatar,
      password
    });
    // Encrypt password - bcrypt
    const salt = await brcypt.genSalt(10);

    user.password = await brcypt.hash(password, salt);

    await user.save();
    
    // Return jsonwebtoken
    const payload = {
      user: {
        id: user.id
      }
    }
      jwt.sign(
      payload, 
      config.get('jwtSecret'),
      { expiresIn: 3600000 },
      (err, token) => {
        if(err) throw err;
        res.json({ token });
      });
    } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error')
  }
});

// @route		PUT api/users
// @desc		login route
// @access	public
router.put(
  "/",
[
  check("email", "Email Required").notEmpty(),
  check("email", "Valid Email Required").isEmail(),
  check("password", "Password Required").notEmpty(),
],
async (req, res) => {
  const errors = validationResult(req);
  if(!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array()});
  }

  try {
    const user = await User.findOne({ email: req.body.email });

    if(isEmpty(user)) {
      return res.status(400).json({ errors: {message: "Invalid Login"}});
    }

    User.findOneAndUpdate(user._id, { lastLogin: Date.now() });
    
    const payload = {
      id: user._id,
      email: user.email,
    };

    const token = jwt.sign(payload, config.jwtSecret, {});

    res.json(token)

  } catch (err) {
    console.error(err);
    return res.status(500).json(err );
  }
 }
);

module.exports = router;
