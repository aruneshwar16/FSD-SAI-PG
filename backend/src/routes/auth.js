const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Register
router.post('/register', async (req, res) => {
  try {
    console.log('Registration request received:', req.body); // Debug log
    const { username, name, email, password } = req.body;
    const finalUsername = username || name; // Use username if provided, otherwise use name

    if (!finalUsername || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username: finalUsername }] });
    if (existingUser) {
      console.log('User already exists:', email); // Debug log
      return res.status(400).json({ message: 'User already exists' });
    }

    // Create new user
    const user = new User({
      username: finalUsername,
      email,
      password
    });
    console.log('Attempting to save user:', { username: finalUsername, email }); // Debug log
    await user.save();
    console.log('User saved successfully:', user._id); // Debug log

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({
      token,
      userId: user._id,
      username: user.username,
      message: 'Registration successful'
    });
  } catch (error) {
    console.error('Registration error:', error); // Debug log
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    res.json({ token, userId: user._id, username: user.username });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

module.exports = router; 