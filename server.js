// server.js - Node.js + Express Backend with MongoDB
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/cipherotto', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['student', 'moderator', 'admin'], default: 'student' },
  score: { type: Number, default: 0 },
  completedChallenges: [{ type: String }],
  createdAt: { type: Date, default: Date.now }
});

// Cipher Schema
const cipherSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  type: { type: String, enum: ['builtin', 'community'], default: 'community' },
  algorithm: { type: String },
  example: { type: String },
  difficulty: { type: String, enum: ['easy', 'medium', 'hard'], default: 'medium' },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  moderatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  moderationNotes: { type: String },
  encryptFunction: { type: String },
  decryptFunction: { type: String },
  parameters: [{ name: String, type: String, default: mongoose.Schema.Types.Mixed }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Challenge Schema
const challengeSchema = new mongoose.Schema({
  cipher: { type: mongoose.Schema.Types.ObjectId, ref: 'Cipher' },
  encryptedText: { type: String, required: true },
  plainText: { type: String, required: true },
  difficulty: { type: String, enum: ['easy', 'medium', 'hard'] },
  points: { type: Number, default: 10 },
  hints: [{ text: String, pointDeduction: Number }],
  createdAt: { type: Date, default: Date.now }
});

// User Progress Schema
const progressSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  challenge: { type: mongoose.Schema.Types.ObjectId, ref: 'Challenge' },
  completed: { type: Boolean, default: false },
  attempts: { type: Number, default: 0 },
  hintsUsed: { type: Number, default: 0 },
  timeSpent: { type: Number },
  completedAt: { type: Date }
});

const User = mongoose.model('User', userSchema);
const Cipher = mongoose.model('Cipher', cipherSchema);
const Challenge = mongoose.model('Challenge', challengeSchema);
const Progress = mongoose.model('Progress', progressSchema);

// Middleware for authentication
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    
    const decoded = jwt.verify(token, 'your-secret-key');
    const user = await User.findById(decoded.userId);
    
    if (!user) throw new Error();
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

// Middleware for moderator role
const moderatorMiddleware = (req, res, next) => {
  if (req.user.role !== 'moderator' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Moderator role required.' });
  }
  next();
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, 'your-secret-key');
    res.status(201).json({ user: { id: user._id, username, email, role: user.role }, token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, 'your-secret-key');
    res.json({ 
      user: { id: user._id, username: user.username, email: user.email, role: user.role, score: user.score }, 
      token 
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============ CIPHER ROUTES ============

// Get all approved ciphers
app.get('/api/ciphers', async (req, res) => {
  try {
    const ciphers = await Cipher.find({ 
      $or: [{ type: 'builtin' }, { status: 'approved' }] 
    }).populate('submittedBy', 'username');
    res.json(ciphers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get cipher by ID
app.get('/api/ciphers/:id', async (req, res) => {
  try {
    const cipher = await Cipher.findById(req.params.id).populate('submittedBy', 'username');
    if (!cipher) {
      return res.status(404).json({ error: 'Cipher not found' });
    }
    res.json(cipher);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Submit new cipher (requires authentication)
app.post('/api/ciphers', authMiddleware, async (req, res) => {
  try {
    const { name, description, algorithm, example, difficulty, encryptFunction, decryptFunction, parameters } = req.body;
    
    const cipher = new Cipher({
      name,
      description,
      algorithm,
      example,
      difficulty,
      encryptFunction,
      decryptFunction,
      parameters,
      type: 'community',
      status: 'pending',
      submittedBy: req.user._id
    });
    
    await cipher.save();
    res.status(201).json({ message: 'Cipher submitted for moderation', cipher });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============ MODERATION ROUTES ============

// Get pending ciphers (moderators only)
app.get('/api/moderation/ciphers', authMiddleware, moderatorMiddleware, async (req, res) => {
  try {
    const pendingCiphers = await Cipher.find({ status: 'pending' })
      .populate('submittedBy', 'username email')
      .sort({ createdAt: -1 });
    res.json(pendingCiphers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve cipher (moderators only)
app.put('/api/moderation/ciphers/:id/approve', authMiddleware, moderatorMiddleware, async (req, res) => {
  try {
    const { moderationNotes } = req.body;
    const cipher = await Cipher.findByIdAndUpdate(
      req.params.id,
      { 
        status: 'approved',
        moderatedBy: req.user._id,
        moderationNotes,
        updatedAt: new Date()
      },
      { new: true }
    );
    
    if (!cipher) {
      return res.status(404).json({ error: 'Cipher not found' });
    }
    
    res.json({ message: 'Cipher approved', cipher });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Reject cipher (moderators only)
app.put('/api/moderation/ciphers/:id/reject', authMiddleware, moderatorMiddleware, async (req, res) => {
  try {
    const { moderationNotes } = req.body;
    const cipher = await Cipher.findByIdAndUpdate(
      req.params.id,
      { 
        status: 'rejected',
        moderatedBy: req.user._id,
        moderationNotes: moderationNotes || 'Does not meet quality standards',
        updatedAt: new Date()
      },
      { new: true }
    );
    
    if (!cipher) {
      return res.status(404).json({ error: 'Cipher not found' });
    }
    
    res.json({ message: 'Cipher rejected', cipher });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get all moderation history (moderators only)
app.get('/api/moderation/history', authMiddleware, moderatorMiddleware, async (req, res) => {
  try {
    const history = await Cipher.find({ 
      status: { $in: ['approved', 'rejected'] } 
    })
      .populate('submittedBy', 'username')
      .populate('moderatedBy', 'username')
      .sort({ updatedAt: -1 });
    res.json(history);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ CHALLENGE ROUTES ============

// Get challenges
app.get('/api/challenges', async (req, res) => {
  try {
    const { difficulty, cipherId } = req.query;
    const filter = {};
    
    if (difficulty) filter.difficulty = difficulty;
    if (cipherId) filter.cipher = cipherId;
    
    const challenges = await Challenge.find(filter)
      .populate('cipher', 'name description')
      .limit(10);
    res.json(challenges);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create challenge (authenticated users)
app.post('/api/challenges', authMiddleware, async (req, res) => {
  try {
    const { cipherId, encryptedText, plainText, difficulty, points, hints } = req.body;
    
    const cipher = await Cipher.findById(cipherId);
    if (!cipher) {
      return res.status(404).json({ error: 'Cipher not found' });
    }
    
    const challenge = new Challenge({
      cipher: cipherId,
      encryptedText,
      plainText,
      difficulty: difficulty || 'medium',
      points: points || 10,
      hints: hints || []
    });
    
    await challenge.save();
    res.status(201).json(challenge);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Submit challenge answer
app.post('/api/challenges/:id/submit', authMiddleware, async (req, res) => {
  try {
    const { answer } = req.body;
    const challenge = await Challenge.findById(req.params.id);
    
    if (!challenge) {
      return res.status(404).json({ error: 'Challenge not found' });
    }
    
    // Find or create progress record
    let progress = await Progress.findOne({ 
      user: req.user._id, 
      challenge: challenge._id 
    });
    
    if (!progress) {
      progress = new Progress({
        user: req.user._id,
        challenge: challenge._id
      });
    }
    
    progress.attempts += 1;
    
    // Check answer (case-insensitive, remove spaces)
    const normalizedAnswer = answer.toUpperCase().replace(/\s/g, '');
    const normalizedCorrect = challenge.plainText.toUpperCase().replace(/\s/g, '');
    
    if (normalizedAnswer === normalizedCorrect) {
      progress.completed = true;
      progress.completedAt = new Date();
      
      // Award points (deduct for hints used)
      const pointDeduction = progress.hintsUsed * 2;
      const earnedPoints = Math.max(1, challenge.points - pointDeduction);
      
      req.user.score += earnedPoints;
      req.user.completedChallenges.push(challenge._id);
      await req.user.save();
      await progress.save();
      
      res.json({ 
        correct: true, 
        pointsEarned: earnedPoints,
        totalScore: req.user.score,
        message: 'Correct! Challenge completed!'
      });
    } else {
      await progress.save();
      res.json({ 
        correct: false, 
        attempts: progress.attempts,
        message: 'Incorrect. Try again!'
      });
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get hint for challenge
app.post('/api/challenges/:id/hint', authMiddleware, async (req, res) => {
  try {
    const challenge = await Challenge.findById(req.params.id);
    
    if (!challenge || !challenge.hints || challenge.hints.length === 0) {
      return res.status(404).json({ error: 'No hints available' });
    }
    
    let progress = await Progress.findOne({ 
      user: req.user._id, 
      challenge: challenge._id 
    });
    
    if (!progress) {
      progress = new Progress({
        user: req.user._id,
        challenge: challenge._id
      });
    }
    
    if (progress.hintsUsed >= challenge.hints.length) {
      return res.status(400).json({ error: 'All hints already used' });
    }
    
    const hint = challenge.hints[progress.hintsUsed];
    progress.hintsUsed += 1;
    await progress.save();
    
    res.json({ hint: hint.text, hintsRemaining: challenge.hints.length - progress.hintsUsed });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============ USER ROUTES ============

// Get user profile
app.get('/api/users/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    const progress = await Progress.find({ user: user._id })
      .populate('challenge', 'difficulty points');
    
    res.json({ user, progress });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get leaderboard
app.get('/api/users/leaderboard', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const leaderboard = await User.find()
      .select('username score completedChallenges')
      .sort({ score: -1 })
      .limit(limit);
    
    res.json(leaderboard);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update user profile
app.put('/api/users/me', authMiddleware, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (username) {
      const existingUser = await User.findOne({ username, _id: { $ne: req.user._id } });
      if (existingUser) {
        return res.status(400).json({ error: 'Username already taken' });
      }
      req.user.username = username;
    }
    
    await req.user.save();
    res.json({ user: req.user });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============ STATS ROUTES ============

// Get global statistics
app.get('/api/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalCiphers = await Cipher.countDocuments({ status: 'approved' });
    const totalChallenges = await Challenge.countDocuments();
    const pendingModeration = await Cipher.countDocuments({ status: 'pending' });
    
    res.json({
      totalUsers,
      totalCiphers,
      totalChallenges,
      pendingModeration
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ SEED DATA ============

// Seed built-in ciphers
app.post('/api/seed', async (req, res) => {
  try {
    const builtInCiphers = [
      {
        name: 'Aristocrat Cipher',
        description: 'Monoalphabetic substitution cipher that preserves word spaces',
        type: 'builtin',
        status: 'approved',
        difficulty: 'medium',
        algorithm: 'Random substitution alphabet with preserved spacing',
        example: 'HELLO WORLD → SVOOL DORLW (with substitution key)'
      },
      {
        name: 'Nihilist Cipher',
        description: 'Uses Polybius square coordinates with numerical key addition',
        type: 'builtin',
        status: 'approved',
        difficulty: 'hard',
        algorithm: 'Polybius square encoding with key stream addition',
        example: 'HELLO → 23 33 34 34 42 (coordinates + key)'
      },
      {
        name: 'Affine Cipher',
        description: 'Uses mathematical formula E(x) = (ax + b) mod 26',
        type: 'builtin',
        status: 'approved',
        difficulty: 'medium',
        algorithm: 'Linear mathematical transformation',
        example: 'HELLO → RCLLA (a=5, b=8)'
      },
      {
        name: 'Baconian Cipher',
        description: 'Encodes each letter as a sequence of A and B',
        type: 'builtin',
        status: 'approved',
        difficulty: 'medium',
        algorithm: 'Binary encoding using two symbols',
        example: 'H → AABBB'
      }
    ];
    
    await Cipher.insertMany(builtInCiphers);
    res.json({ message: 'Built-in ciphers seeded successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Cipher Otto API running on port ${PORT}`);
});
