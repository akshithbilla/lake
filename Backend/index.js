// server.js
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import dotenv from "dotenv";
import cors from "cors";
import crypto from "crypto";
import nodemailer from "nodemailer";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware ---------------------------------------------------------------------
app.use(cors({ 
  origin: process.env.FRONTEND_URL || "http://localhost:5173", 
  credentials: true 
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Remove session middleware since we're using JWT
app.use(passport.initialize());

const isAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const adminEmails = process.env.ADMIN_EMAILS.split(",");
    if (adminEmails.includes(decoded.email)) {
      req.user = decoded;
      return next();
    }
    res.status(403).send("Access denied. Admins only.");
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// JWT Helper Functions
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      isVerified: user.isVerified
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

// Mongoose Setup -----------------------------------------------------------------
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.error("Mongo connection error:", err));

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetTokenExpiry: Date,
  lastLogin: Date,
  loginCount: { type: Number, default: 0 },
  refreshToken: String
});

const User = mongoose.model("User", userSchema);

const projectSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  projects: [{
    title: String,
    description: String,
    techStack: [String],
    images: [String],
    liveUrl: String,
    githubUrl: String,
    category: String,
    featured: Boolean,
    createdAt: { type: Date, default: Date.now }
  }],
  profile: {
    name: String,
    passionateText: String,
    bio: String,
    avatar: String,
    socialLinks: {
      github: String,
      linkedin: String,
      twitter: String,
      personalWebsite: String
    },
    skills: [{
      techName: String,
      skillsUsed: [String]
    }],
    education: [{
      collegeName: String,
      branch: String,
      course: String,
      yearOfPassout: Number
    }],
    workExperience: [{
      companyName: String,
      position: String,
      duration: String,
      description: String,
      currentlyWorking: Boolean
    }]
  },
  template: { type: String, default: 'default' }
});

const Project = mongoose.model('Project', projectSchema);

// Passport Config ----------------------------------------------------------------
passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) return done(null, false, { message: "User not found" });

    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? done(null, user) : done(null, false, { message: "Invalid credentials" });
  } catch (err) {
    return done(err);
  }
}));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/callback",
  passReqToCallback: true,
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ email: profile.email });
    if (!user) {
      user = await User.create({ 
        email: profile.email, 
        password: "google", 
        isVerified: true 
      });
    }
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

// Email Transport ----------------------------------------------------------------
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Routes -------------------------------------------------------------------------

// Authentication Routes ----------------------------------------------------------
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    const newUser = await User.create({
      email,
      password: hashedPassword,
      verificationToken,
    });

    const verifyLink = `${process.env.BACKEND_URL || 'http://localhost:3000'}/verify-email/${verificationToken}`;
    await transporter.sendMail({
      from: `"MyPortfolify" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Complete Your MyPortfolify Registration",
      html: `
        <div style="font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
          <div style="background-color: #f8f9fa; padding: 30px; border-radius: 8px;">
            <div style="text-align: center; margin-bottom: 25px;">
              <h1 style="color: #2c3e50; font-size: 24px; margin: 0;">MyPortfolify</h1>
            </div>
            <div style="background-color: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
              <h2 style="color: #2c3e50; font-size: 20px; margin-top: 0;">Welcome to MyPortfolify!</h2>
              <p style="line-height: 1.6;">Hi ${email.split('@')[0]},</p>
              <p style="line-height: 1.6;">Thank you for creating an account. Please verify your email address to complete your registration.</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${verifyLink}" style="display: inline-block; padding: 12px 24px; background-color: #4f46e5; color: white; text-decoration: none; border-radius: 4px; font-weight: 500; font-size: 16px;">Verify Email Address</a>
              </div>
            </div>
          </div>
        </div>
      `,
    });

    res.status(200).json({ message: "Registered, verify email sent" });
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/verify-email/:token", async (req, res) => {
  const { token } = req.params;
  try {
    const user = await User.findOneAndUpdate(
      { verificationToken: token },
      { isVerified: true, verificationToken: null },
      { new: true }
    );
    if (!user) return res.status(400).send("Invalid or expired token");
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?verified=true`);
  } catch (err) {
    res.status(500).send("Server error");
  }
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ message: info.message });
    if (!user.isVerified) return res.status(403).json({ message: "Please verify your email first" });

    // Update login info
    User.findByIdAndUpdate(user._id, { 
      $set: { lastLogin: new Date() },
      $inc: { loginCount: 1 }
    }).exec();

    // Generate tokens
    const accessToken = generateToken(user);
    const refreshToken = jwt.sign(
      { id: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '30d' }
    );

    // Save refresh token to DB
    User.findByIdAndUpdate(user._id, { refreshToken }).exec();

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });

    res.json({
      accessToken,
      user: {
        _id: user._id,
        email: user.email,
        isVerified: user.isVerified
      }
    });
  })(req, res, next);
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    // Generate tokens for Google auth
    const accessToken = generateToken(req.user);
    const refreshToken = jwt.sign(
      { id: req.user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '30d' }
    );

    // Save refresh token to DB
    await User.findByIdAndUpdate(req.user._id, { refreshToken });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });

    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/auth-success?token=${accessToken}`);
  }
);

app.post("/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ message: "No refresh token" });

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const newAccessToken = generateToken(user);
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(32).toString("hex");
  const expiry = Date.now() + 3600000;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    user.resetToken = token;
    user.resetTokenExpiry = expiry;
    await user.save();

    const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password/${token}`;
    await transporter.sendMail({
      from: `"MyPortfolify Security" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset Request",
      html: `
        <div style="font-family: 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
          <div style="background-color: #f8fafc; padding: 30px; border-radius: 8px;">
            <h2 style="color: #1e293b; font-size: 18px; margin-top: 0;">Password Reset Request</h2>
            <p style="line-height: 1.6;">We received a request to reset the password for your account.</p>
            <div style="text-align: center; margin: 25px 0;">
              <a href="${resetLink}" style="display: inline-block; padding: 12px 24px; background-color: #6366f1; color: white; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 15px;">Reset Password</a>
            </div>
          </div>
        </div>
      `,
    });

    res.status(200).json({ message: "Reset link sent" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    user.password = await bcrypt.hash(password, 10);
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    res.status(200).json({ message: "Password updated" });
  } catch (err) {
    res.status(500).json({ message: "Error resetting password" });
  }
});

app.post("/logout", verifyToken, async (req, res) => {
  try {
    // Clear refresh token from DB
    await User.findByIdAndUpdate(req.user.id, { refreshToken: null });
    
    // Clear cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    res.status(500).json({ message: "Logout error" });
  }
});

app.get("/check-auth", verifyToken, (req, res) => {
  res.status(200).json({
    authenticated: true,
    user: req.user
  });
});

// Profile Routes -----------------------------------------------------------------
app.get('/api/profiles/check-username', async (req, res) => {
  const { username } = req.query;
  if (!username) {
    return res.status(400).json({ message: "Username is required" });
  }

  try {
    const profile = await Project.findOne({ username });
    res.json({ exists: !!profile });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Create or get user profile
app.post('/api/profiles', verifyToken, async (req, res) => {
  try {
    const { username } = req.body;
    
    // Check if username is available
    const existingProfile = await Project.findOne({ username });
    if (existingProfile) {
      return res.status(400).json({ message: "Username already taken" });
    }

    // Create new profile with all fields
    const newProfile = await Project.create({
      userId: req.user.id,
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

    res.status(201).json(newProfile);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get current user's profile
app.get('/api/profiles/me', verifyToken, async (req, res) => {
  try {
    const profile = await Project.findOne({ userId: req.user.id });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }
    res.json(profile);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Update profile information
app.put('/api/profiles/me/profile', verifyToken, async (req, res) => {
  try {
    const { profile } = req.body;
    
    const updatedProfile = await Project.findOneAndUpdate(
      { userId: req.user.id },
      { $set: { profile } },
      { new: true }
    );

    if (!updatedProfile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    res.json(updatedProfile);
  } catch (err) {
    console.error("Error updating profile:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Update template preference
app.put('/api/profiles/me/template', verifyToken, async (req, res) => {
  try {
    const validTemplates = ['default', 'minimal', 'professional'];
    const { template } = req.body;

    if (template && !validTemplates.includes(template)) {
      return res.status(400).json({ message: "Invalid template" });
    }

    const updatedProfile = await Project.findOneAndUpdate(
      { userId: req.user.id },
      { $set: { template } },
      { new: true }
    );

    if (!updatedProfile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    res.json(updatedProfile);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Public profile route
app.get('/api/profiles/:username', async (req, res) => {
  try {
    const profile = await Project.findOne({ username: req.params.username });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }
    res.json(profile);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Project CRUD Routes ------------------------------------------------------------
app.post('/api/profiles/me/projects', verifyToken, async (req, res) => {
  try {
    const profile = await Project.findOne({ userId: req.user.id });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    profile.projects.push(req.body);
    await profile.save();
    res.status(201).json(profile);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.put('/api/profiles/me/projects/:projectId', verifyToken, async (req, res) => {
  try {
    const profile = await Project.findOne({ userId: req.user.id });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    const projectIndex = profile.projects.findIndex(
      p => p._id.toString() === req.params.projectId
    );

    if (projectIndex === -1) {
      return res.status(404).json({ message: "Project not found" });
    }

    profile.projects[projectIndex] = {
      ...profile.projects[projectIndex].toObject(),
      ...req.body
    };

    await profile.save();
    res.json(profile);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.delete('/api/profiles/me/projects/:projectId', verifyToken, async (req, res) => {
  try {
    const profile = await Project.findOne({ userId: req.user.id });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    profile.projects = profile.projects.filter(
      p => p._id.toString() !== req.params.projectId
    );

    await profile.save();
    res.json(profile);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Admin Routes -------------------------------------------------------------------
app.get("/admin", isAdmin, async (req, res) => {
  try {
    const users = await User.find().lean();
    const profiles = await Project.find().lean();
    
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const usersWithProfiles = await Project.countDocuments();
    const totalProjects = await Project.aggregate([
      { $unwind: "$projects" },
      { $count: "total" }
    ]);
    
    const userData = users.map(user => {
      const userProfile = profiles.find(p => p.userId && p.userId.toString() === user._id.toString());
      return {
        ...user,
        hasProfile: !!userProfile,
        username: userProfile?.username || 'N/A',
        projectCount: userProfile?.projects?.length || 0
      };
    });

    res.json({
      users: userData,
      stats: {
        totalUsers,
        verifiedUsers,
        usersWithProfiles: usersWithProfiles || 0,
        totalProjects: totalProjects[0]?.total || 0
      }
    });
  } catch (err) {
    console.error("Admin error:", err);
    res.status(500).json({ message: "Error loading admin data" });
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});