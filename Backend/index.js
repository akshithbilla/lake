// server.js
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import dotenv from "dotenv";
import cors from "cors";
import crypto from "crypto";
import nodemailer from "nodemailer";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import MongoStore from 'connect-mongo';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware ---------------------------------------------------------------------
app.use(cookieParser());

const allowedOrigins = [
  'https://lake-pi.vercel.app',
  'http://localhost:5173' // For development
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Enhanced session configuration
app.use(session({
  secret: process.env.JWT_SECRET || 'default-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    ttl: 14 * 24 * 60 * 60 // 14 days
  }),
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 14, // 14 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection with enhanced options
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.error("Mongo connection error:", err));

// Enhanced User Schema with indexes
const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
  },
  password: { 
    type: String, 
    required: function() { return !this.googleId; } // Not required for Google auth
  },
  googleId: String,
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetTokenExpiry: Date,
  loginCount: { type: Number, default: 0 },
  lastLogin: Date
}, { timestamps: true });

// Indexes
userSchema.index({ email: 1 });
userSchema.index({ verificationToken: 1 });
userSchema.index({ resetToken: 1 });

// Add methods to user schema
userSchema.methods.generateVerificationToken = function() {
  this.verificationToken = crypto.randomBytes(32).toString('hex');
  return this.verificationToken;
};

userSchema.methods.generatePasswordResetToken = function() {
  this.resetToken = crypto.randomBytes(32).toString('hex');
  this.resetTokenExpiry = Date.now() + 3600000; // 1 hour
  return this.resetToken;
};

const User = mongoose.model("User", userSchema);

// Enhanced Project Schema
const projectSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    required: true,
    index: true
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores and hyphens']
  },
  projects: [{
    title: { type: String, required: true, maxlength: 100 },
    description: { type: String, maxlength: 500 },
    techStack: [{ type: String, maxlength: 30 }],
    images: [{ type: String }],
    liveUrl: { type: String, match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Please use a valid URL'] },
    githubUrl: { type: String, match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Please use a valid URL'] },
    category: { type: String, enum: ['web', 'mobile', 'desktop', 'other'], default: 'web' },
    featured: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  profile: {
    name: { type: String, maxlength: 100 },
    passionateText: { type: String, maxlength: 200 },
    bio: { type: String, maxlength: 1000 },
    avatar: { type: String },
    socialLinks: {
      github: { type: String, match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Please use a valid URL'] },
      linkedin: { type: String, match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Please use a valid URL'] },
      twitter: { type: String, match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Please use a valid URL'] },
      personalWebsite: { type: String, match: [/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/, 'Please use a valid URL'] }
    },
    skills: [{
      techName: { type: String, maxlength: 50 },
      skillsUsed: [{ type: String, maxlength: 50 }]
    }],
    education: [{
      collegeName: { type: String, maxlength: 200 },
      branch: { type: String, maxlength: 100 },
      course: { type: String, maxlength: 100 },
      yearOfPassout: { type: Number, min: 1900, max: new Date().getFullYear() + 10 }
    }],
    workExperience: [{
      companyName: { type: String, maxlength: 200 },
      position: { type: String, maxlength: 100 },
      duration: { type: String, maxlength: 50 },
      description: { type: String, maxlength: 500 },
      currentlyWorking: { type: Boolean, default: false }
    }]
  },
  template: { 
    type: String, 
    default: 'default',
    enum: ['default', 'minimal', 'professional', 'creative']
  }
}, { timestamps: true });

const Project = mongoose.model('Project', projectSchema);

// Passport Configuration --------------------------------------------------------

// Local Strategy
passport.use(new LocalStrategy({ 
  usernameField: "email",
  passwordField: "password"
}, async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return done(null, false, { message: "User not found" });
    }

    // For Google-authenticated users without a password
    if (user.googleId && !user.password) {
      return done(null, false, { message: "Please login with Google" });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return done(null, false, { message: "Invalid credentials" });
    }

    if (!user.isVerified) {
      return done(null, false, { message: "Please verify your email first" });
    }

    // Update login stats
    user.loginCount += 1;
    user.lastLogin = new Date();
    await user.save();

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
  passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    let user = await User.findOne({ email });

    if (!user) {
      // Create new user with Google auth
      user = new User({
        email,
        googleId: profile.id,
        isVerified: true
      });
      await user.save();
    } else if (!user.googleId) {
      // Existing user without Google auth - add Google ID
      user.googleId = profile.id;
      user.isVerified = true;
      await user.save();
    }

    // Update login stats
    user.loginCount += 1;
    user.lastLogin = new Date();
    await user.save();

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Email Transport Configuration --------------------------------------------------
const transporter = nodemailer.createTransport({
  service: "Gmail",
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false // For local testing only, remove in production
  }
});

// Verify email transport
transporter.verify((error, success) => {
  if (error) {
    console.error('Error verifying email transporter:', error);
  } else {
    console.log('Email transporter is ready to send messages');
  }
});

// Utility Functions -------------------------------------------------------------
const sendVerificationEmail = async (email, token) => {
  const verifyLink = `${process.env.FRONTEND_URL}/verify-email/${token}`;
  
  const mailOptions = {
    from: `"MyPortfolify" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Verify Your Email Address",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2d3748;">Welcome to MyPortfolify!</h2>
        <p>Please click the button below to verify your email address:</p>
        <a href="${verifyLink}" 
           style="display: inline-block; padding: 10px 20px; background-color: #4299e1; 
                  color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">
          Verify Email
        </a>
        <p>If you didn't create an account with MyPortfolify, please ignore this email.</p>
        <p style="font-size: 12px; color: #718096;">This link will expire in 24 hours.</p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
  } catch (err) {
    console.error(`Error sending verification email to ${email}:`, err);
    throw err;
  }
};

const sendPasswordResetEmail = async (email, token) => {
  const resetLink = `${process.env.FRONTEND_URL}/reset-password/${token}`;

  const mailOptions = {
    from: `"MyPortfolify Security" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Password Reset Request",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2d3748;">Password Reset Request</h2>
        <p>We received a request to reset your password. Click the button below to proceed:</p>
        <a href="${resetLink}" 
           style="display: inline-block; padding: 10px 20px; background-color: #4299e1; 
                  color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">
          Reset Password
        </a>
        <p>If you didn't request a password reset, please ignore this email or contact support.</p>
        <p style="font-size: 12px; color: #718096;">This link will expire in 1 hour.</p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Password reset email sent to ${email}`);
  } catch (err) {
    console.error(`Error sending password reset email to ${email}:`, err);
    throw err;
  }
};

// JWT Middleware
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: 'Unauthorized: No token provided' 
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ 
        success: false,
        message: 'Forbidden: Invalid token',
        error: err.message 
      });
    }
    
    req.user = decoded;
    next();
  });
};

// Routes ------------------------------------------------------------------------

// Health Check
app.get('/', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    message: 'MyPortfolify API is running',
    timestamp: new Date().toISOString()
  });
});

// Authentication Routes ---------------------------------------------------------

// Register
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Email and password are required' 
      });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        message: 'User already exists' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const newUser = new User({
      email,
      password: hashedPassword,
      isVerified: false
    });

    // Generate verification token
    const verificationToken = newUser.generateVerificationToken();
    await newUser.save();

    // Send verification email
    await sendVerificationEmail(email, verificationToken);

    res.status(201).json({ 
      success: true,
      message: 'User registered successfully. Please check your email for verification.' 
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error during registration',
      error: err.message 
    });
  }
});

// Verify Email
app.get('/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired verification token' 
      });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    // Redirect to frontend with success message
    res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`);
  } catch (err) {
    console.error('Email verification error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error during email verification',
      error: err.message 
    });
  }
});

// Login
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: info.message || 'Authentication failed' 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        _id: user._id, 
        email: user.email, 
        isVerified: user.isVerified 
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 3600000 // 1 hour
    });

    res.status(200).json({ 
      success: true,
      message: 'Login successful',
      user: {
        _id: user._id,
        email: user.email,
        isVerified: user.isVerified
      }
    });
  })(req, res, next);
});

// Google Auth
app.get('/auth/google', 
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    prompt: 'select_account' // Force account selection
  })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { 
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=google-auth-failed`,
    session: false 
  }),
  (req, res) => {
    // Generate JWT token for Google auth
    const token = jwt.sign(
      { 
        _id: req.user._id, 
        email: req.user.email, 
        isVerified: req.user.isVerified 
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 3600000 // 1 hour
    });

    // Redirect to frontend
    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  }
);

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  });
  
  res.status(200).json({ 
    success: true,
    message: 'Logged out successfully' 
  });
});

// Check Auth Status
app.get('/check-auth', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password -verificationToken');
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      user 
    });
  } catch (err) {
    console.error('Check auth error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error checking auth status',
      error: err.message 
    });
  }
});

// Forgot Password
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required' 
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal if user doesn't exist for security
      return res.status(200).json({ 
        success: true,
        message: 'If an account with that email exists, a reset link has been sent' 
      });
    }

    // Generate and save reset token
    const resetToken = user.generatePasswordResetToken();
    await user.save();

    // Send reset email
    await sendPasswordResetEmail(email, resetToken);

    res.status(200).json({ 
      success: true,
      message: 'Password reset link sent to your email' 
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error processing password reset',
      error: err.message 
    });
  }
});

// Reset Password
app.post('/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password || password.length < 8) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must be at least 8 characters' 
      });
    }

    const user = await User.findOne({ 
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired reset token' 
      });
    }

    // Update password and clear reset token
    user.password = await bcrypt.hash(password, 12);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.status(200).json({ 
      success: true,
      message: 'Password updated successfully' 
    });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error resetting password',
      error: err.message 
    });
  }
});

// Profile Routes ----------------------------------------------------------------

// Create or get user profile
app.post('/api/profiles', authMiddleware, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ 
        success: false,
        message: 'Username is required' 
      });
    }

    // Check if username is taken
    const existingProfile = await Project.findOne({ username });
    if (existingProfile) {
      return res.status(400).json({ 
        success: false,
        message: 'Username already taken' 
      });
    }

    // Create new profile
    const newProfile = await Project.create({
      userId: req.user._id,
      username,
      projects: [],
      profile: {
        name: req.user.email.split('@')[0],
        passionateText: '',
        bio: '',
        avatar: '',
        socialLinks: {
          github: '',
          linkedin: '',
          twitter: '',
          personalWebsite: ''
        },
        skills: [],
        education: [],
        workExperience: []
      }
    });

    res.status(201).json({ 
      success: true,
      profile: newProfile 
    });
  } catch (err) {
    console.error('Create profile error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error creating profile',
      error: err.message 
    });
  }
});

// Get current user's profile
app.get('/api/profiles/me', authMiddleware, async (req, res) => {
  try {
    const profile = await Project.findOne({ userId: req.user._id });
    if (!profile) {
      return res.status(404).json({ 
        success: false,
        message: 'Profile not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      profile 
    });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error fetching profile',
      error: err.message 
    });
  }
});

// Update profile
app.put('/api/profiles/me/profile', authMiddleware, async (req, res) => {
  try {
    const { profile } = req.body;
    
    if (!profile) {
      return res.status(400).json({ 
        success: false,
        message: 'Profile data is required' 
      });
    }

    const updatedProfile = await Project.findOneAndUpdate(
      { userId: req.user._id },
      { $set: { profile } },
      { new: true, runValidators: true }
    );

    if (!updatedProfile) {
      return res.status(404).json({ 
        success: false,
        message: 'Profile not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      profile: updatedProfile 
    });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error updating profile',
      error: err.message 
    });
  }
});

// Update template
app.put('/api/profiles/me/template', authMiddleware, async (req, res) => {
  try {
    const { template } = req.body;
    
    if (!template) {
      return res.status(400).json({ 
        success: false,
        message: 'Template is required' 
      });
    }

    const updatedProfile = await Project.findOneAndUpdate(
      { userId: req.user._id },
      { $set: { template } },
      { new: true }
    );

    if (!updatedProfile) {
      return res.status(404).json({ 
        success: false,
        message: 'Profile not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      profile: updatedProfile 
    });
  } catch (err) {
    console.error('Update template error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error updating template',
      error: err.message 
    });
  }
});

// Get public profile by username
app.get('/api/profiles/:username', async (req, res) => {
  try {
    const profile = await Project.findOne({ username: req.params.username });
    if (!profile) {
      return res.status(404).json({ 
        success: false,
        message: 'Profile not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      profile 
    });
  } catch (err) {
    console.error('Get public profile error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error fetching public profile',
      error: err.message 
    });
  }
});

// Project CRUD Routes -----------------------------------------------------------

// Create project
app.post('/api/profiles/me/projects', authMiddleware, async (req, res) => {
  try {
    const projectData = req.body;
    
    if (!projectData || !projectData.title) {
      return res.status(400).json({ 
        success: false,
        message: 'Project title is required' 
      });
    }

    const profile = await Project.findOne({ userId: req.user._id });
    if (!profile) {
      return res.status(404).json({ 
        success: false,
        message: 'Profile not found' 
      });
    }

    profile.projects.push(projectData);
    await profile.save();

    res.status(201).json({ 
      success: true,
      profile 
    });
  } catch (err) {
    console.error('Create project error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error creating project',
      error: err.message 
    });
  }
});

// Update project
app.put('/api/profiles/me/projects/:projectId', authMiddleware, async (req, res) => {
  try {
    const { projectId } = req.params;
    const projectData = req.body;
    
    if (!projectData) {
      return res.status(400).json({ 
        success: false,
        message: 'Project data is required' 
      });
    }

    const profile = await Project.findOne({ userId: req.user._id });
    if (!profile) {
      return res.status(404).json({ 
        success: false,
        message: 'Profile not found' 
      });
    }

    const projectIndex = profile.projects.findIndex(
      p => p._id.toString() === projectId
    );

    if (projectIndex === -1) {
      return res.status(404).json({ 
        success: false,
        message: 'Project not found' 
      });
    }

    profile.projects[projectIndex] = {
      ...profile.projects[projectIndex].toObject(),
      ...projectData
    };

    await profile.save();

    res.status(200).json({ 
      success: true,
      profile 
    });
  } catch (err) {
    console.error('Update project error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error updating project',
      error: err.message 
    });
  }
});

// Delete project
app.delete('/api/profiles/me/projects/:projectId', authMiddleware, async (req, res) => {
  try {
    const { projectId } = req.params;

    const profile = await Project.findOne({ userId: req.user._id });
    if (!profile) {
      return res.status(404).json({ 
        success: false,
        message: 'Profile not found' 
      });
    }

    const initialLength = profile.projects.length;
    profile.projects = profile.projects.filter(
      p => p._id.toString() !== projectId
    );

    if (profile.projects.length === initialLength) {
      return res.status(404).json({ 
        success: false,
        message: 'Project not found' 
      });
    }

    await profile.save();

    res.status(200).json({ 
      success: true,
      profile 
    });
  } catch (err) {
    console.error('Delete project error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Server error deleting project',
      error: err.message 
    });
  }
});

// Error Handling Middleware ------------------------------------------------------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false,
    message: 'Endpoint not found' 
  });
});

// Start Server -------------------------------------------------------------------
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});