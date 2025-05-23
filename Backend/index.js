// server.js
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import dotenv from "dotenv";
import cors from "cors";
import crypto from "crypto";
import nodemailer from "nodemailer";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";
//import nodemailer from "nodemailer";
import cookieParser from "cookie-parser";
import MongoStore from 'connect-mongo';
dotenv.config();

const app = express();
const port = 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware ---------------------------------------------------------------------


 
app.use(cookieParser());
const allowedOrigins = ['https://lake-pi.vercel.app'];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (e.g. mobile apps, curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true // Allow cookies / credentials
}));

 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false,
   store: MongoStore.create({
  mongoUrl: process.env.MONGO_URI,
})

}));
app.use(passport.initialize());
app.use(passport.session());

 


// MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.error("Mongo connection error:", err));

  const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  loginCount: { type: Number, default: 0 }
});
// JWT Middleware
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden' });
    req.user = user;
    next();
  });
};


const User = mongoose.model("User", userSchema);

// Updated Project Schema with new fields
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
 
{/**
// Passport Config (unchanged) ----------------------------------------------------
passport.use(new LocalStrategy({ usernameField: "username" }, async (username, password, done) => {
  try {
    const user = await User.findOne({ email: username });
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
  callbackURL:`${process.env.BACKEND_URL}/auth/google/callback`,
  passReqToCallback: true,
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ email: profile.email });
    if (!user) {
      user = await User.create({ email: profile.email, password: "google", isVerified: true });
    }
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});*/}

// Email Transport (unchanged) ----------------------------------------------------
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    let user = await User.findOne({ email });

    if (!user) {
      user = new User({
        email,
        password: "google",
        isVerified: true
      });
      await user.save();
    }

    done(null, user);
  } catch (err) {
    done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// Routes -------------------------------------------------------------------------

// Authentication Routes (unchanged) ----------------------------------------------
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const existingUser = await User.findOne({ email });

  if (existingUser) return res.status(400).json({ message: 'User already exists' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = crypto.randomBytes(32).toString("hex");

  const newUser = new User({
    email,
    password: hashedPassword,
    isVerified: false,
    verificationToken
  });
  await newUser.save();

  const verifyLink = `${process.env.BACKEND_URL}/verify-email/${verificationToken}`;
  await transporter.sendMail({
    from: '"MyPortfolify" <myportfolify@gmail.com>',
    to: email,
    subject: "Verify your email",
    html: `<p>Click <a href="${verifyLink}">here</a> to verify your email.</p>`
  });

  res.status(201).json({ message: 'User registered. Verification email sent.' });
});

app.get("/verify-email/:token", async (req, res) => {
  const user = await User.findOne({ verificationToken: req.params.token });

  if (!user) return res.status(400).json({ message: "Invalid or expired token." });

  user.isVerified = true;
  user.verificationToken = undefined;
  await user.save();

  res.status(200).json({ message: "Email verified successfully!" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(400).json({ message: "Invalid credentials" });

  if (!user.isVerified)
    return res.status(401).json({ message: "Please verify your email first" });

  const token = jwt.sign(
    { _id: user._id, email: user.email, isVerified: user.isVerified },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 3600000,
  });

  res.status(200).json({ message: "Login successful" });
});
app.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "None"
  });
  res.status(200).json({ message: "Logged out" });
});

app.get("/check-auth", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user._id).select("-password");
  if (!user) return res.status(401).json({ message: "User not found" });

  res.status(200).json({ user });
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/" }),
  (req, res) => {
    const token = jwt.sign(
      { _id: req.user._id, email: req.user.email, isVerified: req.user.isVerified },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 3600000
    });

    res.redirect(`${process.env.FRONTEND_URL}/`);
  }
);

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

    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${token}`;

await transporter.sendMail({
  from: '"MyPortfolify Security" <security@myportfolify.com>', // Professional sender
  to: email,
  subject: "Password Reset Request for Your MyPortfolify Account",
  text: `Hi there,\n\nWe received a request to reset your MyPortfolify password. Click the link below to proceed:\n\n${resetLink}\n\nThis link expires in 1 hour for security reasons.\n\nIf you didn't request this, please ignore this email or contact support.\n\n- The MyPortfolify Team`,
  html: `
    <div style="font-family: 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
      <div style="background-color: #f8fafc; padding: 30px; border-radius: 8px;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #2c3e50; margin: 0; font-size: 22px;">MyPortfolify</h1>
          <p style="color: #64748b; font-size: 14px; margin-top: 5px;">Portfolio Management</p>
        </div>

        <div style="background: white; padding: 30px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
          <h2 style="color: #1e293b; font-size: 18px; margin-top: 0;">Password Reset Request</h2>
          <p style="line-height: 1.6;">We received a request to reset the password for your account.</p>
          
          <div style="text-align: center; margin: 25px 0;">
            <a href="${resetLink}" 
               style="display: inline-block; padding: 12px 24px; background-color: #6366f1; color: white; 
                      text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 15px;
                      transition: background-color 0.3s ease;"
               onMouseOver="this.style.backgroundColor='#4f46e5'" 
               onMouseOut="this.style.backgroundColor='#6366f1'">
              Reset Password
            </a>
          </div>

          <p style="font-size: 14px; color: #64748b; line-height: 1.5;">
            <strong>Important:</strong> This link will expire in 1 hour for security reasons. 
            If you didn't request a password reset, please secure your account by 
            <a href="mailto:support@myportfolify.com" style="color: #6366f1;">contacting support</a>.
          </p>
        </div>

        <div style="margin-top: 30px; text-align: center; font-size: 12px; color: #94a3b8;">
          <p>© ${new Date().getFullYear()} MyPortfolify. All rights reserved.</p>
          <p style="margin: 5px 0;">For your security, do not share this email with anyone.</p>
          <p>If the button doesn't work, copy this URL to your browser:<br>
            <span style="word-break: break-all; color: #475569;">${resetLink}</span>
          </p>
        </div>
      </div>
    </div>
  `
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

 
 
app.get('/', (req, res) => {
  res.send('✅ Server is working!');
});
// Profile Routes -----------------------------------------------------------------
app.get("/api/profiles/me", authMiddleware, async (req, res) => {
  const profile = await Profile.findOne({ userId: req.user._id });
  if (!profile) return res.status(404).json({ message: "Profile not found" });

  res.status(200).json(profile);
});


// Create or get user profile
app.post('/api/profiles', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    const { username } = req.body;
    
    // Check if username is available
    const existingProfile = await Project.findOne({ username });
    if (existingProfile) {
      return res.status(400).json({ message: "Username already taken" });
    }

    // Create new profile with all fields
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

    res.status(201).json(newProfile);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get current user's profile
app.get("/api/profiles/:userId", async (req, res) => {
  const profile = await Profile.findOne({ userId: req.params.userId });
  if (!profile) return res.status(404).json({ message: "Profile not found" });

  res.status(200).json(profile);
});

// Update profile information
// Update profile information
app.put('/api/profiles/me/profile', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    const { profile } = req.body;
    
    const updatedProfile = await Project.findOneAndUpdate(
      { userId: req.user._id },
      { $set: { profile } },
      { new: true }
    );

    if (!updatedProfile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    res.status(200).json(updatedProfile);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});


// Update template preference
app.put('/api/profiles/me/template', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    const validTemplates = ['default', 'minimal', 'professional'];
    const { template } = req.body;

    if (template && !validTemplates.includes(template)) {
      return res.status(400).json({ message: "Invalid template" });
    }

    const updatedProfile = await Project.findOneAndUpdate(
      { userId: req.user._id },
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

// Project CRUD Routes (unchanged) ------------------------------------------------
app.post('/api/profiles/me/projects', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    const profile = await Project.findOne({ userId: req.user._id });
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

app.put('/api/profiles/me/projects/:projectId', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    const profile = await Project.findOne({ userId: req.user._id });
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

app.delete('/api/profiles/me/projects/:projectId', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    const profile = await Project.findOne({ userId: req.user._id });
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

// Admin Routes (unchanged) -------------------------------------------------------

// Start Server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});