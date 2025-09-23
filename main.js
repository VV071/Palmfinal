require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const tf = require("@tensorflow/tfjs");
const Razorpay = require("razorpay");
const multer = require("multer");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const upload = multer({ dest: "uploads/" });
const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key';

// ------------------ FIREBASE ------------------
const serviceAccount = require("./firebase-service-account.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET
});
const db = admin.firestore();
const bucket = admin.storage().bucket();

// ------------------ RAZORPAY ------------------
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ------------------ COSINE SIMILARITY ------------------
function cosineSimilarity(a, b) {
  const aTensor = tf.tensor1d(a);
  const bTensor = tf.tensor1d(b);
  const dot = tf.sum(tf.mul(aTensor, bTensor));
  const normA = tf.norm(aTensor);
  const normB = tf.norm(bTensor);
  return dot.div(normA.mul(normB)).dataSync()[0];
}

// ------------------ UTILITY FUNCTIONS ------------------
const generateToken = (email, userId) => {
  return jwt.sign({ email, userId, iat: Date.now() }, JWT_SECRET, { expiresIn: '24h' });
};

const hashPassword = async (password) => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

const verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

const generateUserId = () => {
  return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
};

// ------------------ MIDDLEWARE ------------------
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && (authHeader.startsWith('Bearer ') 
    ? authHeader.split(' ')[1] 
    : authHeader);

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      error: 'Access token required',
      code: 'TOKEN_MISSING' 
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Check if user still exists in Firebase
    const userDoc = await db.collection('users').doc(decoded.userId).get();
    if (!userDoc.exists) {
      return res.status(403).json({ 
        success: false, 
        error: 'User not found',
        code: 'USER_NOT_FOUND' 
      });
    }

    req.user = decoded;
    req.userData = userDoc.data();
    next();
  } catch (err) {
    return res.status(403).json({ 
      success: false, 
      error: 'Invalid or expired token',
      code: 'TOKEN_INVALID' 
    });
  }
};

const validateInput = (requiredFields) => {
  return (req, res, next) => {
    const missing = requiredFields.filter(field => !req.body[field]);
    if (missing.length > 0) {
      return res.status(400).json({
        success: false,
        error: `Missing required fields: ${missing.join(', ')}`,
        code: 'VALIDATION_ERROR'
      });
    }
    next();
  };
};

// ------------------ AUTHENTICATION APIS ------------------

// User Signup
app.post('/auth/signup', validateInput(['email', 'password']), async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format',
        code: 'INVALID_EMAIL'
      });
    }

    // Validate password strength
    if (!password || password.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 6 characters long',
        code: 'WEAK_PASSWORD'
      });
    }

    // Check if user already exists
    const existingUser = await db.collection('users').where('email', '==', email).limit(1).get();
    if (!existingUser.empty) {
      return res.status(409).json({
        success: false,
        error: 'User with this email already exists',
        code: 'USER_EXISTS'
      });
    }

    // Create new user
    const userId = generateUserId();
    const hashedPassword = await hashPassword(password);

    const userData = {
      userId,
      email,
      name: name || '',
      password: hashedPassword,
      balance: 0,
      kycStatus: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      isActive: true
    };

    await db.collection('users').doc(userId).set(userData);

    const token = generateToken(email, userId);

    res.status(201).json({
      success: true,
      message: 'User account created successfully',
      data: {
        token,
        user: {
          userId,
          email,
          name: name || '',
          balance: 0,
          kycStatus: 'pending'
        }
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
});

// User Login
app.post('/auth/login', validateInput(['email', 'password']), async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const userQuery = await db.collection('users').where('email', '==', email).limit(1).get();

    if (userQuery.empty) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const userDoc = userQuery.docs[0];
    const userData = userDoc.data();

    // Check if account is active
    if (!userData.isActive) {
      return res.status(401).json({
        success: false,
        error: 'Account is deactivated',
        code: 'ACCOUNT_INACTIVE'
      });
    }

    // Verify password
    const isPasswordValid = await verifyPassword(password, userData.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const token = generateToken(email, userData.userId);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          userId: userData.userId,
          email: userData.email,
          name: userData.name,
          balance: userData.balance,
          kycStatus: userData.kycStatus
        }
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
});

// Password Reset Request
app.post('/auth/reset', validateInput(['email']), async (req, res) => {
  try {
    const { email } = req.body;

    // Check if user exists (but don't reveal if email exists for security)
    const userQuery = await db.collection('users').where('email', '==', email).limit(1).get();

    // Always return success to prevent email enumeration
    res.json({
      success: true,
      message: 'If the email exists in our system, a password reset link has been sent'
    });

    // Only process reset if user actually exists
    if (!userQuery.empty) {
      // In production, implement actual email sending logic here
      console.log(`Password reset requested for: ${email}`);
      // You would integrate with email service like SendGrid, AWS SES, etc.
    }

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
});

// ------------------ WALLET APIS ------------------

// Get Wallet Information
app.get('/wallet', authenticateToken, async (req, res) => {
  try {
    // Get recent transactions
    const transactionsSnapshot = await db
      .collection('transactions')
      .where('userId', '==', req.user.userId)
      .orderBy('timestamp', 'desc')
      .limit(10)
      .get();

    const transactions = [];
    transactionsSnapshot.forEach(doc => {
      transactions.push({ id: doc.id, ...doc.data() });
    });

    res.json({
      success: true,
      data: {
        balance: req.userData.balance || 0,
        currency: 'INR',
        transactions: transactions,
        totalTransactions: transactions.length
      }
    });

  } catch (error) {
    console.error('Get wallet error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      code: 'SERVER_ERROR'
    });
  }
});

// Razorpay Payment Verification and Wallet Top-up
app.post('/wallet/razorpay/verify', authenticateToken, validateInput(['paymentId', 'orderId', 'signature']), async (req, res) => {
  try {
    const { paymentId, orderId, signature } = req.body;

    // Verify Razorpay signature
    const generatedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(orderId + '|' + paymentId)
      .digest('hex');

    if (generatedSignature !== signature) {
      return res.status(400).json({
        success: false,
        error: 'Payment verification failed - Invalid signature',
        code: 'INVALID_SIGNATURE'
      });
    }

    // Get transaction details from pending transactions
    const transactionQuery = await db
      .collection('transactions')
      .where('razorpayOrderId', '==', orderId)
      .where('status', '==', 'pending')
      .limit(1)
      .get();

    if (transactionQuery.empty) {
      return res.status(404).json({
        success: false,
        error: 'Transaction not found',
        code: 'TRANSACTION_NOT_FOUND'
      });
    }

    const transactionDoc = transactionQuery.docs[0];
    const transactionData = transactionDoc.data();
    const topupAmount = transactionData.amount;

    // Update user balance
    const userRef = db.collection('users').doc(req.user.userId);
    await userRef.update({
      balance: admin.firestore.FieldValue.increment(topupAmount)
    });

    // Update transaction status
    await transactionDoc.ref.update({
      status: 'completed',
      paymentId: paymentId,
      completedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Get updated balance
    const updatedUser = await userRef.get();
    const newBalance = updatedUser.data().balance;

    res.json({
      success: true,
      message: 'Payment verified and wallet topped up successfully',
      data: {
        transactionId: transactionDoc.id,
        newBalance: newBalance,
        amountAdded: topupAmount,
        currency: 'INR'
      }
    });

  } catch (error) {
    console.error('Razorpay verification error:', error);
    res.status(500).json({
      success: false,
      error: 'Payment verification failed',
      code: 'VERIFICATION_ERROR'
    });
  }
});

// ------------------ PALM VERIFICATION APIS ------------------

// Verify Palm for Payment (Updated from original /pay endpoint)
app.post('/palm/verify', authenticateToken, validateInput(['landmarks', 'amount']), async (req, res) => {
  try {
    const { landmarks, amount, merchantId, description } = req.body;

    // Validate amount
    if (typeof amount !== 'number' || amount <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid payment amount',
        code: 'INVALID_AMOUNT'
      });
    }

    // Find matching palm from all registered palms
    const palmSnapshot = await db.collection('palmIndex').get();
    let matchedUserId = null;
    let highestSimilarity = 0;

    palmSnapshot.forEach(doc => {
      const stored = doc.data().landmarks;
      const similarity = cosineSimilarity(landmarks, stored);
      if (similarity > 0.95 && similarity > highestSimilarity) {
        matchedUserId = doc.id;
        highestSimilarity = similarity;
      }
    });

    if (!matchedUserId) {
      return res.status(401).json({
        success: false,
        error: 'Palm verification failed. Please try again.',
        code: 'VERIFICATION_FAILED'
      });
    }

    // Verify the matched user is the authenticated user
    if (matchedUserId !== req.user.userId) {
      return res.status(403).json({
        success: false,
        error: 'Palm does not match authenticated user',
        code: 'USER_MISMATCH'
      });
    }

    // Check wallet balance
    if (req.userData.balance < amount) {
      return res.status(400).json({
        success: false,
        error: 'Insufficient wallet balance',
        code: 'INSUFFICIENT_BALANCE',
        data: {
          currentBalance: req.userData.balance,
          requiredAmount: amount
        }
      });
    }

    // Process payment
    const userRef = db.collection('users').doc(req.user.userId);
    await userRef.update({
      balance: admin.firestore.FieldValue.increment(-amount)
    });

    // Update merchant balance if merchant exists
    if (merchantId) {
      const merchantRef = db.collection('merchants').doc(merchantId);
      const merchantDoc = await merchantRef.get();

      if (merchantDoc.exists) {
        await merchantRef.update({
          balance: admin.firestore.FieldValue.increment(amount)
        });
      }
    }

    // Record transaction
    const transactionRef = await db.collection('transactions').add({
      userId: req.user.userId,
      type: 'payment',
      amount: amount,
      merchantId: merchantId || 'unknown',
      description: description || 'Palm payment',
      status: 'completed',
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      paymentMethod: 'palm_verification',
      similarity: highestSimilarity
    });

    // Get updated balance
    const updatedUser = await userRef.get();
    const newBalance = updatedUser.data().balance;

    res.json({
      success: true,
      message: 'Payment completed successfully',
      data: {
        transactionId: transactionRef.id,
        amountPaid: amount,
        newBalance: newBalance,
        currency: 'INR',
        merchantId: merchantId
      }
    });

  } catch (error) {
    console.error('Palm verification payment error:', error);
    res.status(500).json({
      success: false,
      error: 'Payment processing failed',
      code: 'PAYMENT_ERROR'
    });
  }
});

// ------------------ ORIGINAL ENDPOINTS (Updated) ------------------

// Mobile Login (Updated with JWT)
app.post("/login", async (req, res) => {
  const { userId, name } = req.body;
  if (!userId || !name) return res.status(400).json({ success: false, error: "Missing params" });

  try {
    const userRef = db.collection("users").doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      await userRef.set({ 
        userId,
        name, 
        balance: 0, 
        kycStatus: "pending",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        isActive: true
      });
    }

    const user = await userRef.get();
    const userData = user.data();

    // Generate token for this legacy login
    const token = generateToken(userData.email || userId, userId);

    res.json({ 
      success: true, 
      user: userData,
      token: token
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Login failed" });
  }
});

// Register Palm (Updated)
app.post("/registerPalm", authenticateToken, async (req, res) => {
  const { landmarks } = req.body;
  if (!landmarks) return res.status(400).json({ success: false, error: "Missing landmarks" });

  try {
    await db.collection("palmIndex").doc(req.user.userId).set({ 
      landmarks,
      registeredAt: admin.firestore.FieldValue.serverTimestamp()
    });
    res.json({ success: true, message: "Palm template registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Palm registration failed" });
  }
});

// Wallet Top-up (Updated)
app.post("/wallet/topup", authenticateToken, async (req, res) => {
  const { amount } = req.body;
  if (!amount) return res.status(400).json({ success: false, error: "Missing amount" });

  try {
    const order = await razorpay.orders.create({
      amount: amount * 100,
      currency: "INR",
      receipt: "wallet_topup_" + Date.now()
    });

    await db.collection("transactions").add({
      userId: req.user.userId,
      type: "wallet_topup",
      amount,
      razorpayOrderId: order.id,
      status: "pending",
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true, order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Wallet top-up failed" });
  }
});

// Razorpay Webhook (Updated)
app.post("/wallet/verify", bodyParser.json({ type: "application/json" }), async (req, res) => {
  const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
  const signature = req.headers["x-razorpay-signature"];
  const body = JSON.stringify(req.body);

  const expectedSignature = crypto
    .createHmac("sha256", webhookSecret)
    .update(body)
    .digest("hex");

  if (signature !== expectedSignature) return res.status(400).json({ success: false, error: "Invalid signature" });

  try {
    const event = req.body;
    if (event.event === "payment.captured") {
      const razorpayOrderId = event.payload.payment.entity.order_id;
      const amount = event.payload.payment.entity.amount / 100;

      const snapshot = await db
        .collection("transactions")
        .where("razorpayOrderId", "==", razorpayOrderId)
        .limit(1)
        .get();

      if (!snapshot.empty) {
        const doc = snapshot.docs[0];
        const data = doc.data();
        const userRef = db.collection("users").doc(data.userId);

        await userRef.update({ 
          balance: admin.firestore.FieldValue.increment(amount) 
        });

        await doc.ref.update({ 
          status: "completed",
          completedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
    }

    res.json({ status: "ok" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Webhook processing failed" });
  }
});

// Get User Transactions (Updated)
app.get("/transactions/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;

  // Verify user can only access their own transactions
  if (userId !== req.user.userId) {
    return res.status(403).json({ 
      success: false, 
      error: "Access denied" 
    });
  }

  try {
    const snapshot = await db
      .collection("transactions")
      .where("userId", "==", userId)
      .orderBy("timestamp", "desc")
      .get();

    const transactions = [];
    snapshot.forEach(doc => transactions.push({ id: doc.id, ...doc.data() }));

    res.json({ success: true, transactions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Failed to fetch transactions" });
  }
});

// KYC Verification (Updated)
app.post("/kyc/verify", authenticateToken, upload.single("document"), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ success: false, error: "Missing document" });

  try {
    const destination = `kyc/${req.user.userId}/${file.originalname}`;
    await bucket.upload(file.path, { destination });
    const fileUrl = `gs://${bucket.name}/${destination}`;

    const verificationResult = { status: "pending" }; // Replace with real API call

    await db.collection("users").doc(req.user.userId).update({
      kycStatus: verificationResult.status,
      kycDocumentUrl: fileUrl,
      kycSubmittedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true, status: verificationResult.status });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "KYC verification failed" });
  }
});

// ------------------ UTILITY ROUTES ------------------

// Health Check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'PalmPay backend is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Get User Profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    // Get palm registration status
    const palmDoc = await db.collection('palmIndex').doc(req.user.userId).get();
    const isPalmRegistered = palmDoc.exists;

    res.json({
      success: true,
      data: {
        user: {
          userId: req.userData.userId,
          email: req.userData.email,
          name: req.userData.name,
          balance: req.userData.balance,
          kycStatus: req.userData.kycStatus,
          createdAt: req.userData.createdAt
        },
        palm: {
          isRegistered: isPalmRegistered,
          registeredAt: isPalmRegistered ? palmDoc.data().registeredAt : null
        }
      }
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get profile',
      code: 'PROFILE_ERROR'
    });
  }
});

// ------------------ ERROR HANDLING ------------------

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'NOT_FOUND'
  });
});


// Global Error Handler
app.use((error, req, res, next) => {
  console.error('Global error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'SERVER_ERROR'
  });
});

// ------------------ START SERVER ------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 PalmPay backend running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

module.exports = app;