require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const tf = require("@tensorflow/tfjs");
const Razorpay = require("razorpay");
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");

const upload = multer({ dest: "uploads/" });
const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:8080'],
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

// Stricter rate limiting for password reset endpoints
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 reset attempts per hour
  message: {
    success: false,
    error: 'Too many password reset attempts, please try again later',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key';
const RESET_TOKEN_SECRET = process.env.RESET_TOKEN_SECRET || 'your_reset_token_secret';
const EMAIL_FROM = process.env.EMAIL_FROM || 'noreply@palmpay.com';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Email transporter configuration
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_APP_PASSWORD
  }
});

// Verify email transporter
emailTransporter.verify()
  .then(() => console.log('✅ Email transporter ready'))
  .catch(err => console.log('❌ Email transporter error:', err));

// ------------------ FIREBASE ------------------
// Allow FIREBASE_SERVICE_ACCOUNT to be either raw JSON or a path to a JSON file
let serviceAccount;
const serviceAccountEnv = process.env.FIREBASE_SERVICE_ACCOUNT || "";
try {
  if (serviceAccountEnv.trim().startsWith("{")) {
    serviceAccount = JSON.parse(serviceAccountEnv);
  } else if (serviceAccountEnv.trim().length > 0) {
    const resolvedPath = path.isAbsolute(serviceAccountEnv)
      ? serviceAccountEnv
      : path.resolve(__dirname, serviceAccountEnv);
    const fileContents = fs.readFileSync(resolvedPath, "utf8");
    serviceAccount = JSON.parse(fileContents);
  } else {
    // Fallback to local serviceAccount.json if env not provided
    const fallbackPath = path.resolve(__dirname, "serviceAccount.json");
    const fileContents = fs.readFileSync(fallbackPath, "utf8");
    serviceAccount = JSON.parse(fileContents);
  }
} catch (err) {
  console.error("❌ Failed to load Firebase service account:", err.message);
  process.exit(1);
}
const firebaseOptions = {
  credential: admin.credential.cert(serviceAccount)
};
if (process.env.FIREBASE_STORAGE_BUCKET) {
  firebaseOptions.storageBucket = process.env.FIREBASE_STORAGE_BUCKET;
}
admin.initializeApp(firebaseOptions);
const db = admin.firestore();
let bucket = null;
if (process.env.FIREBASE_STORAGE_BUCKET) {
  bucket = admin.storage().bucket();
} else {
  console.warn('⚠️ FIREBASE_STORAGE_BUCKET not set. Firebase Storage features are disabled.');
}

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

const generateResetToken = (email, userId) => {
  return jwt.sign(
    { email, userId, type: 'password_reset', iat: Date.now() },
    RESET_TOKEN_SECRET,
    { expiresIn: '1h' } // Reset tokens expire in 1 hour
  );
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

// NEW: Platform detection middleware
const detectPlatform = (req, res, next) => {
  const userAgent = req.get('User-Agent') || '';
  const clientType = req.get('X-Client-Type') || '';
  
  // Determine platform based on user agent or custom header
  let platform = 'web'; // default
  
  if (clientType.toLowerCase().includes('flutter') || 
      clientType.toLowerCase().includes('mobile') ||
      clientType.toLowerCase().includes('android') ||
      clientType.toLowerCase().includes('ios')) {
    platform = 'mobile';
  } else if (userAgent.includes('Flutter') || 
             userAgent.includes('Dart') ||
             userAgent.includes('Mobile') ||
             userAgent.includes('Android') ||
             userAgent.includes('iPhone') ||
             userAgent.includes('iPad')) {
    platform = 'mobile';
  }
  
  req.platform = platform;
  console.log(`🔍 Detected platform: ${platform} for ${req.method} ${req.path}`);
  next();
};

// Apply platform detection to all routes
app.use(detectPlatform);

// Enhanced email sending function
const sendEmail = async (to, subject, htmlContent, textContent = null) => {
  try {
    const mailOptions = {
      from: EMAIL_FROM,
      to,
      subject,
      html: htmlContent,
      text: textContent || htmlContent.replace(/<[^>]*>/g, '') // Strip HTML for text version
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log(`✅ Email sent successfully to ${to}:`, result.messageId);
    return { success: true, messageId: result.messageId };
  } catch (error) {
    console.error(`❌ Email sending failed to ${to}:`, error);
    return { success: false, error: error.message };
  }
};

// Generate password reset email HTML
const generateResetEmailHTML = (name, resetToken, resetUrl) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset - PalmPay</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
            .content { padding: 30px; }
            .button { display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
            .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #eee; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🖐️ PalmPay</h1>
                <h2>Password Reset Request</h2>
            </div>
            <div class="content">
                <p>Hello ${name},</p>
                <p>We received a request to reset your password for your PalmPay account. If you made this request, click the button below to reset your password:</p>
                
                <div style="text-align: center;">
                    <a href="${resetUrl}" class="button">Reset Password</a>
                </div>
                
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong>
                    <ul>
                        <li>This link will expire in 1 hour</li>
                        <li>If you didn't request this reset, please ignore this email</li>
                        <li>Never share this link with anyone</li>
                    </ul>
                </div>
                
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #667eea;">${resetUrl}</p>
                
                <p>If you didn't request this password reset, please ignore this email or contact our support team if you have concerns.</p>
                
                <p>Best regards,<br>The PalmPay Team</p>
            </div>
            <div class="footer">
                <p>© 2024 PalmPay. All rights reserved.</p>
                <p>This email was sent to ${to}. If you have questions, contact support.</p>
            </div>
        </div>
    </body>
    </html>
  `;
};

// ------------------ PLATFORM-AWARE USER DATA CREATION ------------------

// Create platform-specific user data
const createUserData = (platform, userData) => {
  const baseData = {
    userId: userData.userId,
    email: userData.email,
    name: userData.name || '',
    password: userData.password,
    platform: platform,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    isActive: true
  };

  if (platform === 'mobile') {
    // Mobile app specific fields
    return {
      ...baseData,
      balance: 0,
      kycStatus: 'pending',
      isKycVerified: false,
      isPalmRegistered: false,
      deviceInfo: {
        platform: 'mobile',
        registeredDevices: []
      }
    };
  } else {
    // Web app specific fields
    return {
      ...baseData,
      profile: {
        preferences: {},
        settings: {}
      },
      webAccess: {
        lastLoginDevice: null,
        browserInfo: null
      }
    };
  }
};

// Get platform-specific user response
const getUserResponse = (platform, userData) => {
  const baseResponse = {
    userId: userData.userId,
    email: userData.email,
    name: userData.name,
    platform: userData.platform
  };

  if (platform === 'mobile') {
    return {
      ...baseResponse,
      balance: userData.balance || 0,
      kycStatus: userData.kycStatus || 'pending',
      isKycVerified: userData.isKycVerified || false,
      isPalmRegistered: userData.isPalmRegistered || false
    };
  } else {
    return {
      ...baseResponse,
      profile: userData.profile || {},
      webAccess: userData.webAccess || {}
    };
  }
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

// Verify reset token middleware
const verifyResetToken = (req, res, next) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({
      success: false,
      error: 'Reset token is required',
      code: 'TOKEN_MISSING'
    });
  }

  try {
    const decoded = jwt.verify(token, RESET_TOKEN_SECRET);
    
    if (decoded.type !== 'password_reset') {
      return res.status(403).json({
        success: false,
        error: 'Invalid token type',
        code: 'INVALID_TOKEN_TYPE'
      });
    }

    req.resetData = decoded;
    next();
  } catch (err) {
    return res.status(403).json({
      success: false,
      error: 'Invalid or expired reset token',
      code: 'TOKEN_INVALID'
    });
  }
};

// ------------------ AUTHENTICATION APIS ------------------

// Enhanced User Signup with Platform Detection
app.post('/auth/signup', validateInput(['email', 'password']), async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const platform = req.platform;

    console.log(`📱 Signup request from ${platform} platform`);

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

    // Create new user with platform-specific data
    const userId = generateUserId();
    const hashedPassword = await hashPassword(password);

    const userData = createUserData(platform, {
      userId,
      email,
      name,
      password: hashedPassword
    });

    await db.collection('users').doc(userId).set(userData);

    const token = generateToken(email, userId);

    res.status(201).json({
      success: true,
      message: `User account created successfully for ${platform} platform`,
      data: {
        token,
        user: getUserResponse(platform, userData)
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

// Enhanced User Login with Platform Validation
app.post('/auth/login', validateInput(['email', 'password']), async (req, res) => {
  try {
    const { email, password } = req.body;
    const platform = req.platform;

    console.log(`🔐 Login request from ${platform} platform`);

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

    // Platform access control (OPTIONAL - commented out to allow cross-platform access)
    /*
    if (userData.platform && userData.platform !== platform) {
      return res.status(403).json({
        success: false,
        error: `This account was registered for ${userData.platform} platform. Please use the correct platform to login.`,
        code: 'PLATFORM_MISMATCH'
      });
    }
    */

    // Verify password
    const isPasswordValid = await verifyPassword(password, userData.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Update last login info based on platform
    const updateData = {
      lastLoginAt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (platform === 'web') {
      updateData['webAccess.lastLoginDevice'] = req.get('User-Agent');
    }

    await userDoc.ref.update(updateData);

    const token = generateToken(email, userData.userId);

    res.json({
      success: true,
      message: `Login successful from ${platform} platform`,
      data: {
        token,
        user: getUserResponse(userData.platform || platform, userData)
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

// ------------------ PASSWORD RESET APIS (Cross-Platform) ------------------

// Request Password Reset
app.post('/auth/forgot-password', resetLimiter, validateInput(['email']), async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format',
        code: 'INVALID_EMAIL'
      });
    }

    // Always return success to prevent email enumeration
    res.json({
      success: true,
      message: 'If the email exists in our system, a password reset link has been sent',
      data: {
        emailSent: true,
        expiresIn: '1 hour'
      }
    });

    // Check if user exists (but don't reveal this in response)
    const userQuery = await db.collection('users').where('email', '==', email).limit(1).get();
    
    if (!userQuery.empty) {
      const userDoc = userQuery.docs[0];
      const userData = userDoc.data();

      // Generate reset token
      const resetToken = generateResetToken(email, userData.userId);
      
      // Create reset URL based on platform
      let resetUrl;
      if (userData.platform === 'mobile') {
        resetUrl = `palmpay://reset-password?token=${resetToken}`;
      } else {
        resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
      }
      
      // Store reset token in user's document with expiry
      await userDoc.ref.update({
        resetToken,
        resetTokenExpiry: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 60 * 60 * 1000)), // 1 hour
        resetTokenCreatedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      // Send password reset email
      const emailHTML = generateResetEmailHTML(
        userData.name || 'User',
        resetToken,
        resetUrl
      );

      const emailResult = await sendEmail(
        email,
        'Reset Your PalmPay Password',
        emailHTML
      );

      // Log email result but don't expose it to client
      if (!emailResult.success) {
        console.error('Failed to send reset email:', emailResult.error);
      }
    }

  } catch (error) {
    console.error('Password reset request error:', error);
    // Still return success to prevent information leakage
    res.json({
      success: true,
      message: 'If the email exists in our system, a password reset link has been sent'
    });
  }
});

// Verify Reset Token (Cross-Platform)
app.post('/auth/verify-reset-token', validateInput(['token']), async (req, res) => {
  try {
    const { token } = req.body;

    const decoded = jwt.verify(token, RESET_TOKEN_SECRET);
    
    if (decoded.type !== 'password_reset') {
      return res.status(403).json({
        success: false,
        error: 'Invalid token type',
        code: 'INVALID_TOKEN_TYPE'
      });
    }

    // Check if user still exists and token hasn't been used
    const userDoc = await db.collection('users').doc(decoded.userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const userData = userDoc.data();
    
    // Check if token matches stored token and hasn't expired
    if (userData.resetToken !== token) {
      return res.status(403).json({
        success: false,
        error: 'Invalid reset token',
        code: 'TOKEN_INVALID'
      });
    }

    if (userData.resetTokenExpiry && userData.resetTokenExpiry.toDate() < new Date()) {
      return res.status(403).json({
        success: false,
        error: 'Reset token has expired',
        code: 'TOKEN_EXPIRED'
      });
    }

    res.json({
      success: true,
      message: 'Reset token is valid',
      data: {
        email: userData.email,
        platform: userData.platform,
        expiresAt: userData.resetTokenExpiry.toDate().toISOString()
      }
    });

  } catch (err) {
    return res.status(403).json({
      success: false,
      error: 'Invalid or expired reset token',
      code: 'TOKEN_INVALID'
    });
  }
});

// Reset Password with Token (Cross-Platform)
app.post('/auth/reset-password', validateInput(['token', 'newPassword']), verifyResetToken, async (req, res) => {
  try {
    const { newPassword } = req.body;
    const { userId, email } = req.resetData;

    // Validate new password strength
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 6 characters long',
        code: 'WEAK_PASSWORD'
      });
    }

    // Find user document
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const userData = userDoc.data();
    const { token } = req.body;

    // Double-check token validity and expiry
    if (userData.resetToken !== token) {
      return res.status(403).json({
        success: false,
        error: 'Invalid reset token',
        code: 'TOKEN_INVALID'
      });
    }

    if (userData.resetTokenExpiry && userData.resetTokenExpiry.toDate() < new Date()) {
      return res.status(403).json({
        success: false,
        error: 'Reset token has expired',
        code: 'TOKEN_EXPIRED'
      });
    }

    // Hash new password
    const hashedPassword = await hashPassword(newPassword);

    // Update user's password and clear reset token
    await userDoc.ref.update({
      password: hashedPassword,
      resetToken: admin.firestore.FieldValue.delete(),
      resetTokenExpiry: admin.firestore.FieldValue.delete(),
      resetTokenCreatedAt: admin.firestore.FieldValue.delete(),
      passwordUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Send confirmation email
    const confirmationHTML = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center;">
          <h1>🖐️ PalmPay</h1>
          <h2>Password Updated Successfully</h2>
        </div>
        <div style="padding: 30px;">
          <p>Hello ${userData.name || 'User'},</p>
          <p>Your PalmPay account password has been successfully updated.</p>
          <p>Platform: ${userData.platform}</p>
          <p>If you didn't make this change, please contact our support team immediately.</p>
          <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <strong>✅ Security Tip:</strong> Always use a strong, unique password for your account.
          </div>
          <p>Best regards,<br>The PalmPay Team</p>
        </div>
        <div style="padding: 20px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #eee;">
          <p>© 2024 PalmPay. All rights reserved.</p>
        </div>
      </div>
    `;

    await sendEmail(
      email,
      'PalmPay Password Updated Successfully',
      confirmationHTML
    );

    res.json({
      success: true,
      message: 'Password has been reset successfully',
      data: {
        passwordUpdated: true,
        confirmationEmailSent: true,
        platform: userData.platform
      }
    });

  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reset password',
      code: 'RESET_FAILED'
    });
  }
});

// Change Password (Cross-Platform)
app.post('/auth/change-password', authenticateToken, validateInput(['currentPassword', 'newPassword']), async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const { userId } = req.user;

    // Validate new password strength
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'New password must be at least 6 characters long',
        code: 'WEAK_PASSWORD'
      });
    }

    // Get user document
    const userDoc = await db.collection('users').doc(userId).get();
    const userData = userDoc.data();

    // Verify current password
    const isCurrentPasswordValid = await verifyPassword(currentPassword, userData.password);
    if (!isCurrentPasswordValid) {
      return res.status(401).json({
        success: false,
        error: 'Current password is incorrect',
        code: 'INVALID_CURRENT_PASSWORD'
      });
    }

    // Check if new password is different from current
    const isSamePassword = await verifyPassword(newPassword, userData.password);
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        error: 'New password must be different from current password',
        code: 'SAME_PASSWORD'
      });
    }

    // Hash new password and update
    const hashedPassword = await hashPassword(newPassword);
    await userDoc.ref.update({
      password: hashedPassword,
      passwordUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      message: 'Password changed successfully',
      data: {
        passwordUpdated: true
      }
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to change password',
      code: 'CHANGE_PASSWORD_FAILED'
    });
  }
});

// ------------------ MOBILE-ONLY ENDPOINTS ------------------

// Palm Registration - Mobile Only
app.post("/registerPalm", authenticateToken, async (req, res) => {
  if (req.platform !== 'mobile' && req.userData.platform !== 'mobile') {
    return res.status(403).json({ 
      success: false, 
      error: "Palm registration is only available on mobile app",
      code: 'MOBILE_ONLY_FEATURE'
    });
  }

  const { landmarks } = req.body;
  if (!landmarks) return res.status(400).json({ success: false, error: "Missing landmarks" });

  try {
    await db.collection("palmIndex").doc(req.user.userId).set({ 
      landmarks,
      registeredAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Update user's palm registration status
    await db.collection('users').doc(req.user.userId).update({
      isPalmRegistered: true
    });
    
    res.json({ success: true, message: "Palm template registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Palm registration failed" });
  }
});

// Palm Verification Payment - Mobile Only
app.post('/palm/verify', authenticateToken, validateInput(['landmarks', 'amount']), async (req, res) => {
  if (req.platform !== 'mobile' && req.userData.platform !== 'mobile') {
    return res.status(403).json({ 
      success: false, 
      error: "Palm verification is only available on mobile app",
      code: 'MOBILE_ONLY_FEATURE'
    });
  }

  try {
    const { landmarks, amount, merchantId, description } = req.body;

    if (typeof amount !== 'number' || amount <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid payment amount',
        code: 'INVALID_AMOUNT'
      });
    }

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

    if (matchedUserId !== req.user.userId) {
      return res.status(403).json({
        success: false,
        error: 'Palm does not match authenticated user',
        code: 'USER_MISMATCH'
      });
    }

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

    const userRef = db.collection('users').doc(req.user.userId);
    await userRef.update({
      balance: admin.firestore.FieldValue.increment(-amount)
    });

    if (merchantId) {
      const merchantRef = db.collection('merchants').doc(merchantId);
      const merchantDoc = await merchantRef.get();

      if (merchantDoc.exists) {
        await merchantRef.update({
          balance: admin.firestore.FieldValue.increment(amount)
        });
      }
    }

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

// KYC Verification - Mobile Only
app.post("/kyc/verify", authenticateToken, upload.single("document"), async (req, res) => {
  if (req.platform !== 'mobile' && req.userData.platform !== 'mobile') {
    return res.status(403).json({ 
      success: false, 
      error: "KYC verification is only available on mobile app",
      code: 'MOBILE_ONLY_FEATURE'
    });
  }

  const file = req.file;
  if (!file) return res.status(400).json({ success: false, error: "Missing document" });

  try {
    const destination = `kyc/${req.user.userId}/${file.originalname}`;
    await bucket.upload(file.path, { destination });
    const fileUrl = `gs://${bucket.name}/${destination}`;

    const verificationResult = { status: "pending" };

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

// ------------------ WALLET APIS (Mobile Only) ------------------

app.get('/wallet', authenticateToken, async (req, res) => {
  if (req.platform !== 'mobile' && req.userData.platform !== 'mobile') {
    return res.status(403).json({ 
      success: false, 
      error: "Wallet features are only available on mobile app",
      code: 'MOBILE_ONLY_FEATURE'
    });
  }

  try {
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

app.post("/wallet/topup", authenticateToken, async (req, res) => {
  if (req.platform !== 'mobile' && req.userData.platform !== 'mobile') {
    return res.status(403).json({ 
      success: false, 
      error: "Wallet top-up is only available on mobile app",
      code: 'MOBILE_ONLY_FEATURE'
    });
  }

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

app.post('/wallet/razorpay/verify', authenticateToken, validateInput(['paymentId', 'orderId', 'signature']), async (req, res) => {
  if (req.platform !== 'mobile' && req.userData.platform !== 'mobile') {
    return res.status(403).json({ 
      success: false, 
      error: "Payment verification is only available on mobile app",
      code: 'MOBILE_ONLY_FEATURE'
    });
  }

  try {
    const { paymentId, orderId, signature } = req.body;

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

    const userRef = db.collection('users').doc(req.user.userId);
    await userRef.update({
      balance: admin.firestore.FieldValue.increment(topupAmount)
    });

    await transactionDoc.ref.update({
      status: 'completed',
      paymentId: paymentId,
      completedAt: admin.firestore.FieldValue.serverTimestamp()
    });

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

app.get("/transactions/:userId", authenticateToken, async (req, res) => {
  if (req.platform !== 'mobile' && req.userData.platform !== 'mobile') {
    return res.status(403).json({ 
      success: false, 
      error: "Transaction history is only available on mobile app",
      code: 'MOBILE_ONLY_FEATURE'
    });
  }

  const { userId } = req.params;

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

// ------------------ LEGACY ENDPOINTS (for backward compatibility) ------------------

// Legacy login endpoint (keeping for compatibility)
app.post("/login", async (req, res) => {
  const { userId, name } = req.body;
  if (!userId || !name) return res.status(400).json({ success: false, error: "Missing params" });

  try {
    const userRef = db.collection("users").doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      // Create legacy user with mobile platform
      await userRef.set(createUserData('mobile', {
        userId,
        name, 
        email: userId, // using userId as email for legacy users
        password: await hashPassword('legacy_password') // placeholder password
      }));
    }

    const user = await userRef.get();
    const userData = user.data();

    const token = generateToken(userData.email || userId, userId);

    res.json({ 
      success: true, 
      user: getUserResponse('mobile', userData),
      token: token
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Login failed" });
  }
});

// ------------------ COMMON ENDPOINTS ------------------

// Health Check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'PalmPay backend is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    platform: req.platform,
    features: {
      passwordReset: true,
      emailService: !!process.env.EMAIL_USERNAME,
      platformDetection: true
    }
  });
});

// Get User Profile (Platform-aware)
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const platform = req.userData.platform || req.platform;
    
    let responseData = {
      user: getUserResponse(platform, req.userData)
    };

    // Add mobile-specific data if mobile user
    if (platform === 'mobile') {
      const palmDoc = await db.collection('palmIndex').doc(req.user.userId).get();
      const isPalmRegistered = palmDoc.exists;

      responseData.palm = {
        isRegistered: isPalmRegistered,
        registeredAt: isPalmRegistered ? palmDoc.data().registeredAt : null
      };
    }

    res.json({
      success: true,
      data: responseData
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

// Webhook verification (platform-agnostic)
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

// Error handling
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
    platform: req.platform
  });
});

app.use((error, req, res, next) => {
  console.error('Global error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'SERVER_ERROR',
    platform: req.platform
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 PalmPay backend running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`📧 Email service: ${process.env.EMAIL_USERNAME ? 'Configured' : 'Not configured'}`);
  console.log(`🔐 Password reset: Enabled`);
  console.log(`📱 Platform detection: Enabled`);
  console.log(`✨ Features:`);
  console.log(`  - Web app: Authentication, Password reset`);
  console.log(`  - Mobile app: Full PalmPay features + Wallet + Palm verification`);
});

module.exports = app;
