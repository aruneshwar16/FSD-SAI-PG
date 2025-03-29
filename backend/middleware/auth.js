const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
  try {
    let token;
    
    // Check for Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
      console.log('Received token:', token); // Debug log
    }

    if (!token) {
      console.log('No token provided'); // Debug log
      return res.status(401).json({ message: 'Not authorized, no token' });
    }

    try {
      // Check for admin token
      if (token === 'adminToken') {
        console.log('Admin token detected'); // Debug log
        req.user = { _id: 'admin', role: 'admin' };
        return next();
      }

      // Verify JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log('Decoded token:', decoded); // Debug log
      
      const user = await User.findById(decoded.id).select('-password');
      
      if (!user) {
        console.log('User not found for token'); // Debug log
        return res.status(401).json({ message: 'User not found' });
      }

      req.user = user;
      next();
    } catch (error) {
      console.error('Token verification error:', error); // Debug log
      return res.status(401).json({ message: 'Not authorized, token failed' });
    }
  } catch (error) {
    console.error('Auth middleware error:', error); // Debug log
    res.status(500).json({ message: 'Server error in authentication' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    console.log('User role:', req.user.role); // Debug log
    console.log('Required roles:', roles); // Debug log
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        message: `User role ${req.user.role} is not authorized to access this route`
      });
    }
    next();
  };
};

module.exports = { protect, authorize }; 