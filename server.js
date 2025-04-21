require('dotenv').config();
const mongoose = require("mongoose");
const path = require("path");
const express = require("express");
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const schedule = require('node-schedule');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const sanitize = require('express-mongo-sanitize');

const app = express();

// Database connection
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/time_capsule", {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  age: Number,
  mobile: Number,
  gender: String,
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  email: { type: String, required: true },
  message: { type: String, required: true },
  sendTime: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  sent: { type: Boolean, default: false }
});

// Add indexes
userSchema.index({ email: 1 });
messageSchema.index({ sendTime: 1 });
messageSchema.index({ email: 1 });

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

// Middleware
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(sanitize());
app.use(csrf({ cookie: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many attempts, please try again later'
});

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Routes
app.post("/store", async (req, res) => {
  try {
    const { name, email, password, age, mobile, gender } = req.body;
    
    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({ 
      name, 
      email, 
      password: hashedPassword, 
      age, 
      mobile, 
      gender 
    });
    
    await user.save();
    
    // Verification email
    const verificationLink = `http://${req.headers.host}/verify-email?token=${encodeURIComponent(email)}`;
    
    await transporter.sendMail({
      from: `Time Capsule <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Verify Your Time Capsule Account',
      html: `
        <h2>Welcome to Time Capsule!</h2>
        <p>Please click the link below to verify your email:</p>
        <a href="${verificationLink}">Verify Email</a>
        <p>If you didn't create an account, please ignore this email.</p>
      `
    });
    
    res.status(201).json({ message: "User created. Please check your email for verification." });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/check_user", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (!user.verified) {
      return res.status(403).json({ error: "Please verify your email first" });
    }

    res.json({ message: "Login successful", user: { email: user.email, name: user.name } });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/schedule_message", async (req, res) => {
  try {
    const { email, message, sendTime } = req.body;
    
    if (!email || !message || !sendTime) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const sendDate = new Date(sendTime);
    if (sendDate <= new Date()) {
      return res.status(400).json({ error: "Send time must be in the future" });
    }

    const newMessage = new Message({ email, message, sendTime: sendDate });
    await newMessage.save();

    // Schedule the email
    schedule.scheduleJob(sendDate, async () => {
      try {
        await transporter.sendMail({
          from: `Time Capsule <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Your Time Capsule Message Has Arrived!',
          html: `
            <h2>Your Time Capsule Has Been Opened!</h2>
            <div style="background:#f8f9fa;padding:20px;border-radius:8px;">
              ${message.replace(/\n/g, '<br>')}
            </div>
            <p>This message was scheduled on ${newMessage.createdAt.toDateString()}</p>
          `
        });

        await Message.findByIdAndUpdate(newMessage._id, { sent: true });
      } catch (err) {
        console.error(`Failed to send message to ${email}:`, err);
      }
    });

    res.status(201).json({ 
      message: "Message scheduled successfully",
      scheduledTime: sendDate.toISOString()
    });
  } catch (err) {
    console.error("Message scheduling error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/verify-email", async (req, res) => {
  try {
    const email = decodeURIComponent(req.query.token);
    await User.findOneAndUpdate({ email }, { verified: true });
    res.sendFile(path.join(__dirname, 'public', 'email-verified.html'));
  } catch (err) {
    console.error("Email verification error:", err);
    res.status(400).send('Verification failed');
  }
});

// Serve HTML files
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "home.html")));
app.get("/signup", (req, res) => res.sendFile(path.join(__dirname, "public", "Signup.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "LogIn.html")));
app.get("/time_capsule", (req, res) => res.sendFile(path.join(__dirname, "public", "time_capsule.html")));

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).sendFile(path.join(__dirname, 'public', 'error.html'));
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});