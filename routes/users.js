const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const User = require('../models/User');

// @route POST api/users
// @desc Register a user
// @access Public

router.post(
	'/',
	[
		check('name', 'please add name')
			.not()
			.isEmpty(),
		check('email', 'please include a valid email').isEmail(),
		check(
			'password',
			'please enter a password with 6 or more characters'
		).isLength({ min: 6 })
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}
		const { name, email, password } = req.body;

		try {
			let user = await User.findOne({ email: email });
			if (user) {
				return res.status(400).json({ msg: 'User already exists' });
			}
			user = new User({
				name,
				email,
				password
			});
			// encrypt password -> hash version
			const salt = await bcrypt.genSalt(10);

			user.password = await bcrypt.hash(password, salt);

			await user.save();
			// object to send in token
			const payload = {
				user: {
					id: user.id
				}
			};

			// generate a token (payload, secret) expires in an hour (production time)
			jwt.sign(
				payload,
				config.get('jwtSecret'),
				{
					expiresIn: 3600
				},
				(err, token) => {
					if (err) throw err;
					res.json({ token });
				}
			);
		} catch (err) {
			console.error(err.message);
			res.status(500).send('Server Error');
		}
	}
);

module.exports = router;
