const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();
app.use(express.json());

// Allow requests from your custom domain
app.use(cors({ 
  origin: ['https://grasoncountrymusic.com', 'https://www.grasoncountrymusic.com', 'http://localhost:3000'],
  credentials: true 
}));

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-grason-country';
const ADMIN_EMAIL = 'grasoncountrymusic@gmail.com';
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

// Connect to Cloud Database
if (MONGO_URI) {
  mongoose.connect(MONGO_URI)
    .then(() => console.log(' Connected to MongoDB Atlas!'))
    .catch(err => console.error(' Database Connection Error:', err));
}

// Database Schemas
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  passwordHash: String,
  isArtist: { type: Boolean, default: false },
  twoFactorCode: String,
  twoFactorExpires: Date
});

const PostSchema = new mongoose.Schema({
  authorName: String,
  authorEmail: String,
  isArtist: Boolean,
  caption: String,
  firewood: { type: Number, default: 0 },
  comments: [{ author: String, text: String, createdAt: { type: Date, default: Date.now } }],
  createdAt: { type: Date, default: Date.now }
});

const PollSchema = new mongoose.Schema({
  question: String,
  options: [{ text: String, votes: { type: Number, default: 0 } }],
  active: { type: Boolean, default: true }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Poll = mongoose.model('Poll', PollSchema);

// Email Transporter for 2FA Verification
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // App Password from Google Account
  }
});

// Middleware: Authenticate Token
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized access' });
  try {
    req.user = jwt.decode(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Middleware: Require Artist Admin
const requireArtist = (req, res, next) => {
  if (!req.user || !req.user.isArtist) {
    return res.status(403).json({ error: 'Forbidden: Artist privileges required' });
  }
  next();
};

/* --- AUTHENTICATION & 2FA --- */
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const lowerEmail = email.toLowerCase();
    
    const existing = await User.findOne({ email: lowerEmail });
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 10);
    const isArtist = lowerEmail === ADMIN_EMAIL;

    const newUser = new User({ name, email: lowerEmail, passwordHash, isArtist });
    await newUser.save();

    const token = jwt.encode({ id: newUser._id, name: newUser.name, email: newUser.email, isArtist }, JWT_SECRET);
    res.json({ token, user: { name: newUser.name, email: newUser.email, isArtist } });
  } catch (err) {
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const lowerEmail = email.toLowerCase();
    const user = await User.findOne({ email: lowerEmail });

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Trigger 2FA Email Code for Artist Account
    if (user.email === ADMIN_EMAIL) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      user.twoFactorCode = code;
      user.twoFactorExpires = Date.now() + 10 * 60 * 1000; // Code expires in 10 minutes
      await user.save();

      await transporter.sendMail({
        from: '"Grason Powell Security" <grasoncountrymusic@gmail.com>',
        to: ADMIN_EMAIL,
        subject: '🔑 Your Artist Security Verification Code',
        text: `Your 2FA login verification code is: ${code}`
      });

      return res.json({ require2FA: true, email: user.email });
    }

    const token = jwt.encode({ id: user._id, name: user.name, email: user.email, isArtist: user.isArtist }, JWT_SECRET);
    res.json({ token, user: { name: user.name, email: user.email, isArtist: user.isArtist } });
  } catch (err) {
    res.status(500).json({ error: 'Login error' });
  }
});

app.post('/api/auth/verify-2fa', async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user || user.twoFactorCode !== code || Date.now() > user.twoFactorExpires) {
      return res.status(400).json({ error: 'Invalid or expired 2FA code' });
    }

    user.twoFactorCode = null;
    user.twoFactorExpires = null;
    await user.save();

    const token = jwt.encode({ id: user._id, name: user.name, email: user.email, isArtist: true }, JWT_SECRET);
    res.json({ token, user: { name: user.name, email: user.email, isArtist: true } });
  } catch (err) {
    res.status(500).json({ error: '2FA Verification failed' });
  }
});

/* --- DYNAMIC POLL ENGINE --- */
app.get('/api/poll', async (req, res) => {
  try {
    let poll = await Poll.findOne({ active: true });
    if (!poll) {
      poll = new Poll({
        question: "Which kind of song should Grason Powell make next?",
        options: [
          { text: "🎸 Heavy Acoustic Storytelling Ballad", votes: 0 },
          { text: "⚡ Upbeat Outlaw Country Rock", votes: 0 },
          { text: "🌙 Late Night Porch Jam", votes: 0 }
        ],
        active: true
      });
      await poll.save();
    }
    res.json(poll);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching poll' });
  }
});

app.post('/api/poll/update', requireAuth, requireArtist, async (req, res) => {
  try {
    const { question, options } = req.body;
    await Poll.updateMany({}, { active: false });

    const newPoll = new Poll({
      question,
      options: options.map(opt => ({ text: opt, votes: 0 })),
      active: true
    });
    await newPoll.save();
    res.json({ success: true, poll: newPoll });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update poll' });
  }
});

app.post('/api/poll/vote', async (req, res) => {
  try {
    const { pollId, optionIndex } = req.body;
    const poll = await Poll.findById(pollId);
    if (poll && poll.options[optionIndex]) {
      poll.options[optionIndex].votes += 1;
      await poll.save();
    }
    res.json(poll);
  } catch (err) {
    res.status(500).json({ error: 'Failed to record vote' });
  }
});

/* --- SOCIAL MEDIA FEED API --- */
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find().sort({ createdAt: -1 });
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching posts' });
  }
});

app.post('/api/posts', requireAuth, async (req, res) => {
  try {
    const { caption } = req.body;
    const post = new Post({
      authorName: req.user.name,
      authorEmail: req.user.email,
      isArtist: req.user.isArtist,
      caption
    });
    await post.save();
    res.json(post);
  } catch (err) {
    res.status(500).json({ error: 'Error creating post' });
  }
});

app.post('/api/posts/:id/firewood', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (post) {
      post.firewood += 1;
      await post.save();
    }
    res.json(post);
  } catch (err) {
    res.status(500).json({ error: 'Error adding firewood' });
  }
});

app.listen(PORT, () => console.log(` Security Server active on port ${PORT}`));