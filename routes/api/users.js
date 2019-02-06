const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const keys = require('../../config/keys');

// Load Input Validation
const validateRegisterInput = require('../../validation/register');
const validateLoginInput = require('../../validation/login');

// Load user model
const User = require('../../models/User');

// @route   GET api/users/test
// @desc    Tests users route
// @access  Public
router.get('/test', (req, res) => res.json({ msg: 'Users Works' }));

// @route   POST api/users/register
// @desc    Register user
// @access  Public
router.post('/register', (req, res) => {
  const { errors, isValid } = validateRegisterInput(req.body);
  // Check validation
  if (!isValid) {
    return res.status(400).json(errors);
  }
  // check if user exisrs
  User.findOne({ email: req.body.email }).then(user => {
    if (user) {
      errors.email = 'Email already exists';
      return res.status(400).json(errors);
    } else {
      const avatar = gravatar.url(req.body.email, {
        s: '200', // size
        r: 'pg', // Rating
        d: 'mm' // Default
      });
      const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        avatar,
        password: req.body.password
      });

      // generating salt
      bcrypt.genSalt(10, (err, salt) => {
        //hash the password with salt
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) {
            throw err;
          }
          // setting user's password to generared hash
          newUser.password = hash;
          // save ==> mongoose method
          newUser
            .save()
            .then(user => res.json(user))
            .catch(err => console.log(err));
        });
      });
    }
  });
});

// @route   GET api/users/login
// @desc    Login user /  Returning JWT token
// @access  Public
router.post('/login', (req, res) => {
  const { errors, isValid } = validateLoginInput(req.body);
  // Check validation
  if (!isValid) {
    return res.status(400).json(errors);
  }

  const email = req.body.email;
  const password = req.body.password;

  // Find user by email
  User.findOne({ email }).then(user => {
    // Check for user
    if (!user) {
      errors.email = 'User not found';
      return res.status(404).json(errors);
    }

    // Check password
    // user.password ==> pass from database
    // password ==> entered to form password (req)
    bcrypt.compare(password, user.password).then(isMatch => {
      if (isMatch) {
        // User matched

        // create JWT payload
        const payload = { id: user.id, name: user.name, avatar: user.avatar };

        // Sign Token

        // arguments ==> (payload, secret, options )
        jwt.sign(
          payload,
          keys.secretOrKey,
          { expiresIn: '2000 days' },
          (err, token) => {
            // Bearer ==> type of the token
            res.json({ success: true, token: 'Bearer ' + token });
          }
        );
      } else {
        errors.password = 'Password incorrect';
        // gonna use these names ('msg' and 'password') on frontend
        return res.status(404).json(errors);
        // return res.status(404).json({ password: 'Password incorrect' });
      }
    });
  });
});

// @route   GET api/users/current
// @desc    Return current user
// @access  Private
router.get(
  '/current',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    // res.json(req.user);
    res.json({
      id: req.user.id,
      name: req.user.name,
      password: req.user.password
    });
  }
);

module.exports = router;
