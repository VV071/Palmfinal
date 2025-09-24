/**
 * main.js
 *
 * Fully integrated backend implementing:
 * - Palm-only payments (one-to-many) with encrypted embeddings
 * - JWT access + refresh tokens (HttpOnly cookie)
 * - Payment intents + cancel (optional)
 * - Automatic Razorpay Contact & Fund Account creation on vendor UPI registration
 * - Razorpay Payouts using fund_account_id (idempotent) and refund-on-failure
 * - Razorpay webhook verification & reconciliation
 * - Rate limiting, Joi validation, Firestore transactions, lockout, audit logs
 *
 * Required npm packages:
 * npm i express cookie-parser helmet cors express-rate-limit joi jsonwebtoken bcryptjs firebase-admin dotenv axios
 *
 * Set environment variables as per README at the bottom of this file.
 */

require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const admin = require('firebase-admin');
const axios = require('axios');

const app = express();

/* -----------------------
   Middleware
   ----------------------- */
app.use(helmet());
app.use(express.json({ limit: '300kb' }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));

/* -----------------------
   Env vars and sanity checks
   ----------------------- */
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET;
const EMBEDDING_KEY = process.env.EMBEDDING_KEY; // 64 hex chars
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;

if (!JWT_SECRET) {
  console.error('JWT_SECRET not set. Exiting.');
  process.exit(1);
}
if (!EMBEDDING_KEY || EMBEDDING_KEY.length !== 64) {
  console.warn('EMBEDDING_KEY missing or wrong length. Generate 32 bytes hex and set EMBEDDING_KEY.');
}
if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
  console.warn('RAZORPAY keys not set; payouts will fail until provided.');
}

/* -----------------------
   Initialize Firebase Admin
   ----------------------- */
try {
  admin.initializeApp();
} catch (e) {
  // ignore if already initialized
}
const db = admin.firestore();

/* -----------------------
   Crypto / embedding helpers
   ----------------------- */
const EMB_KEY = Buffer.from(EMBEDDING_KEY || '0'.repeat(64), 'hex'); // fallback zero key (WARNING)

function encryptEmbedding(embeddingArray) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', EMB_KEY, iv);
  const serialized = Buffer.from(JSON.stringify(embeddingArray));
  const encrypted = Buffer.concat([cipher.update(serialized), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    data: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64')
  };
}

function decryptEmbedding({ data, iv, tag }) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', EMB_KEY, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]);
  return JSON.parse(decrypted.toString());
}

/* -----------------------
   Token helpers
   ----------------------- */
const ACCESS_EXPIRES = '15m';
const REFRESH_EXPIRES_SECONDS = 60 * 60 * 24 * 30; // 30 days

function generateAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
}
function generateRefreshToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: `${REFRESH_EXPIRES_SECONDS}s` });
}
function hashToken(token) {
  return crypto.createHmac('sha256', JWT_SECRET).update(token).digest('hex');
}

/* -----------------------
   Cosine similarity (digit-by-digit)
   ----------------------- */
function cosineSimilarity(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return 0;
  let dot = 0.0;
  let magA = 0.0;
  let magB = 0.0;
  for (let i = 0; i < a.length; i++) {
    const ai = Number(a[i]) || 0;
    const bi = Number(b[i]) || 0;
    dot += ai * bi;
    magA += ai * ai;
    magB += bi * bi;
  }
  magA = Math.sqrt(magA);
  magB = Math.sqrt(magB);
  if (magA === 0 || magB === 0) return 0;
  return dot / (magA * magB);
}

/* -----------------------
   Joi schemas
   ----------------------- */
const registerPalmSchema = Joi.object({ landmarks: Joi.array().items(Joi.number()).min(10).max(5000).required() });
const palmVerifySchema = Joi.object({
  landmarks: Joi.array().items(Joi.number()).min(10).max(5000).required(),
  merchantId: Joi.string().required(),
  amount: Joi.number().positive().required()
});
const createPaymentIntentSchema = Joi.object({ merchantId: Joi.string().required(), amount: Joi.number().positive().required() });
const merchantUpiSchema = Joi.object({
  name: Joi.string().required(),
  contact: Joi.string().optional().allow(''), // phone
  email: Joi.string().optional().allow(''),
  upi: Joi.string().required()
});

/* -----------------------
   Rate limiting
   ----------------------- */
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { success: false, error: 'Too many requests' }});
app.use('/auth', authLimiter);

const palmLimiter = rateLimit({ windowMs: 60 * 1000, max: 8, message: { success: false, error: 'Too many palm attempts — try again later' }});
app.use('/palm', palmLimiter);

/* -----------------------
   Auth middleware
   ----------------------- */
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token) return res.status(401).json({ success: false, error: 'Access token required' });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { userId: decoded.userId, email: decoded.email };
    next();
  } catch (e) {
    return res.status(403).json({ success: false, error: 'Invalid or expired token' });
  }
}

/* -----------------------
   Simple auth endpoints
   ----------------------- */
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password, displayName } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email & password required' });

    const usersRef = db.collection('users');
    const existing = await usersRef.where('email', '==', email).limit(1).get();
    if (!existing.empty) return res.status(400).json({ success: false, error: 'User exists' });

    const hashed = await bcrypt.hash(password, 10);
    const userDoc = { email, passwordHash: hashed, displayName: displayName || '', balance: 0, createdAt: admin.firestore.FieldValue.serverTimestamp() };
    const userRef = await usersRef.add(userDoc);

    const payload = { userId: userRef.id, email };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);
    await db.collection('refreshTokens').doc(userRef.id).set({ tokenHash: hashToken(refreshToken), createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt: admin.firestore.Timestamp.fromDate(new Date(Date.now() + REFRESH_EXPIRES_SECONDS * 1000)) });

    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: NODE_ENV === 'production', sameSite: 'Strict', maxAge: REFRESH_EXPIRES_SECONDS * 1000 });
    return res.json({ success: true, accessToken, userId: userRef.id });
  } catch (err) {
    console.error('signup err', err);
    return res.status(500).json({ success: false, error: 'Signup failed' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email & password required' });

    const usersRef = db.collection('users');
    const snap = await usersRef.where('email', '==', email).limit(1).get();
    if (snap.empty) return res.status(401).json({ success: false, error: 'Invalid credentials' });

    const doc = snap.docs[0];
    const user = doc.data();
    const match = await bcrypt.compare(password, user.passwordHash || '');
    if (!match) return res.status(401).json({ success: false, error: 'Invalid credentials' });

    const payload = { userId: doc.id, email };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);
    await db.collection('refreshTokens').doc(doc.id).set({ tokenHash: hashToken(refreshToken), createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt: admin.firestore.Timestamp.fromDate(new Date(Date.now() + REFRESH_EXPIRES_SECONDS * 1000)) });

    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: NODE_ENV === 'production', sameSite: 'Strict', maxAge: REFRESH_EXPIRES_SECONDS * 1000 });
    return res.json({ success: true, accessToken, userId: doc.id });
  } catch (err) {
    console.error('login err', err);
    return res.status(500).json({ success: false, error: 'Login failed' });
  }
});

app.post('/auth/refresh', async (req, res) => {
  try {
    const rt = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!rt) return res.status(401).json({ success: false, error: 'Refresh token missing' });
    let decoded;
    try { decoded = jwt.verify(rt, JWT_SECRET); } catch (e) { return res.status(401).json({ success: false, error: 'Invalid refresh token' }); }
    const stored = await db.collection('refreshTokens').doc(decoded.userId).get();
    if (!stored.exists) return res.status(401).json({ success: false, error: 'Refresh token not found' });
    if (stored.data().tokenHash !== hashToken(rt)) return res.status(401).json({ success: false, error: 'Refresh token revoked' });
    const accessToken = generateAccessToken({ userId: decoded.userId, email: decoded.email });
    return res.json({ success: true, accessToken });
  } catch (err) {
    console.error('refresh err', err);
    return res.status(500).json({ success: false, error: 'Refresh failed' });
  }
});

/* -----------------------
   Register palm (encrypted) - used during mobile registration flow
   ----------------------- */
app.post('/palm/register', authenticateToken, async (req, res) => {
  try {
    const { error, value } = registerPalmSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, error: 'Invalid landmarks' });
    const { landmarks } = value;
    const encrypted = encryptEmbedding(landmarks);
    await db.collection('palmIndex').doc(req.user.userId).set({ encrypted, registeredAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return res.json({ success: true, message: 'Palm registered' });
  } catch (err) {
    console.error('register palm', err);
    return res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

/* -----------------------
   Payment intent (optional)
   ----------------------- */
app.post('/payment/create', authenticateToken, async (req, res) => {
  try {
    const { error, value } = createPaymentIntentSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, error: 'Invalid input' });
    const { merchantId, amount } = value;
    const TTL_SECONDS = 30;
    const nonce = crypto.randomBytes(12).toString('hex');
    const intent = { payerId: req.user.userId, merchantId, amount, nonce, status: 'pending', createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt: admin.firestore.Timestamp.fromDate(new Date(Date.now() + TTL_SECONDS * 1000)) };
    const ref = await db.collection('paymentIntents').add(intent);
    return res.json({ success: true, paymentIntentId: ref.id, expiresIn: TTL_SECONDS });
  } catch (err) {
    console.error('create intent', err);
    return res.status(500).json({ success: false, error: 'Failed to create intent' });
  }
});

app.post('/payment/cancel', authenticateToken, async (req, res) => {
  try {
    const { paymentIntentId } = req.body;
    if (!paymentIntentId) return res.status(400).json({ success: false, error: 'paymentIntentId required' });
    const piRef = db.collection('paymentIntents').doc(paymentIntentId);
    const piDoc = await piRef.get();
    if (!piDoc.exists) return res.status(404).json({ success: false, error: 'Intent not found' });
    const pi = piDoc.data();
    if (req.user.userId !== pi.payerId && req.user.userId !== pi.merchantId) return res.status(403).json({ success: false, error: 'Not authorized to cancel' });
    if (pi.status !== 'pending') return res.status(400).json({ success: false, error: 'Only pending intents can be cancelled' });
    await piRef.update({ status: 'cancelled', cancelledAt: admin.firestore.FieldValue.serverTimestamp() });
    return res.json({ success: true, message: 'Intent cancelled' });
  } catch (err) {
    console.error('cancel intent', err);
    return res.status(500).json({ success: false, error: 'Cancel failed' });
  }
});

/* -----------------------
   Razorpay helper functions
   ----------------------- */
async function createRazorpayContact({ name, contact = '', email = '', type = 'vendor', reference_id }) {
  // returns { success: true, data } or { success: false, error }
  const url = 'https://api.razorpay.com/v1/contacts';
  try {
    const resp = await axios.post(url, { name, contact, email, type, reference_id }, {
      auth: { username: RAZORPAY_KEY_ID, password: RAZORPAY_KEY_SECRET },
      headers: { 'Content-Type': 'application/json' },
      timeout: 15000
    });
    return { success: true, data: resp.data };
  } catch (err) {
    return { success: false, error: err.response?.data || err.message };
  }
}

async function createRazorpayFundAccount({ contact_id, account_type = 'vpa', vpa_address }) {
  // Returns fund_account object on success
  const url = 'https://api.razorpay.com/v1/fund_accounts';
  const payload = {
    contact_id,
    account_type,
    [account_type === 'vpa' ? 'vpa' : 'bank_account']: account_type === 'vpa' ? { address: vpa_address } : {}
  };
  try {
    const resp = await axios.post(url, payload, {
      auth: { username: RAZORPAY_KEY_ID, password: RAZORPAY_KEY_SECRET },
      headers: { 'Content-Type': 'application/json' },
      timeout: 15000
    });
    return { success: true, data: resp.data };
  } catch (err) {
    return { success: false, error: err.response?.data || err.message };
  }
}

async function createRazorpayPayout({ amountInPaise, fund_account_id, idempotencyKey, purpose = 'payout', queue_if_low_balance = false, notes = {} }) {
  // Use fund_account_id (preferred) to initiate payout in Razorpay
  const url = 'https://api.razorpay.com/v1/payouts';
  const payload = {
    account_number: undefined, // optional depending on account setup
    amount: amountInPaise,
    currency: 'INR',
    mode: 'upi',
    purpose,
    fund_account_id,
    queue_if_low_balance,
    notes
  };
  try {
    const resp = await axios.post(url, payload, {
      auth: { username: RAZORPAY_KEY_ID, password: RAZORPAY_KEY_SECRET },
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      timeout: 20000
    });
    return { success: true, data: resp.data };
  } catch (err) {
    return { success: false, error: err.response?.data || err.message };
  }
}

/* -----------------------
   Merchant: register UPI (creates Razorpay contact + fund account automatically)
   - Requires merchant to be authenticated (you can use merchant account or admin flow)
   - Saves contactId and fundAccountId on merchants/{merchantId}
   ----------------------- */
app.post('/merchant/registerUpi', authenticateToken, async (req, res) => {
  try {
    const { error, value } = merchantUpiSchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, error: 'Invalid input' });
    const { name, contact, email, upi } = value;

    // Merchant doc id: use authenticated userId as merchantId or allow admin to pass merchantId.
    const merchantId = req.user.userId;
    const merchantRef = db.collection('merchants').doc(merchantId);

    // Create contact in Razorpay (if not already)
    const existing = await merchantRef.get();
    const existingData = existing.exists ? existing.data() : {};
    if (existingData.contactId && existingData.fundAccountId) {
      return res.json({ success: true, message: 'Merchant already registered for payouts', contactId: existingData.contactId, fundAccountId: existingData.fundAccountId });
    }

    // create contact
    const contactResp = await createRazorpayContact({ name, contact, email, type: 'vendor', reference_id: merchantId });
    if (!contactResp.success) {
      console.error('create contact failed', contactResp.error);
      return res.status(500).json({ success: false, error: 'Failed to create contact' });
    }
    const contactId = contactResp.data.id;

    // create fund account for UPI
    const fundResp = await createRazorpayFundAccount({ contact_id: contactId, account_type: 'vpa', vpa_address: upi });
    if (!fundResp.success) {
      console.error('create fund account failed', fundResp.error);
      // optionally delete contact to avoid orphaned contact, but keep it for manual reconciliation
      return res.status(500).json({ success: false, error: 'Failed to create fund account' });
    }
    const fundAccountId = fundResp.data.id;

    // store merchant info
    await merchantRef.set({ name, contact, email, contactId, fundAccountId, upi, createdAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

    return res.json({ success: true, message: 'Merchant payout setup complete', contactId, fundAccountId });
  } catch (err) {
    console.error('merchant.registerUpi err', err);
    return res.status(500).json({ success: false, error: 'Merchant registration failed' });
  }
});

/* -----------------------
   Account lockout helper
   ----------------------- */
async function registerFailure(userId) {
  const metaRef = db.collection('palmMeta').doc(userId);
  await metaRef.set({ failures: admin.firestore.FieldValue.increment(1), lastFailureAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
  const snap = await metaRef.get();
  const meta = snap.data() || {};
  const failCount = meta.failures || 0;
  if (failCount >= 10) {
    const lockMinutes = 30;
    await metaRef.update({ lockUntil: admin.firestore.Timestamp.fromDate(new Date(Date.now() + lockMinutes * 60 * 1000)) });
  }
}

/* -----------------------
   PALM-ONLY verify (one-to-many) with Razorpay payout integration
   - Accepts landmarks, merchantId, amount
   - Finds best matching user by comparing decrypted embeddings server-side
   - Deducts payer, creates transaction (processing), invokes Razorpay payout using fund_account_id
   - On payout success -> mark completed; on payout failure -> refund payer
   ----------------------- */
app.post('/palm/verify', palmLimiter, async (req, res) => {
  try {
    const { error, value } = palmVerifySchema.validate(req.body);
    if (error) return res.status(400).json({ success: false, error: 'Invalid payload' });
    const { landmarks, merchantId, amount } = value;

    // merchant existence check
    const merchantRef = db.collection('merchants').doc(merchantId);
    const merchantSnap = await merchantRef.get();
    if (!merchantSnap.exists) return res.status(400).json({ success: false, error: 'Unknown merchant' });
    const merchantData = merchantSnap.data();

    // Read all palms (small scale). For scale, move to vector DB.
    const palmSnap = await db.collection('palmIndex').get();
    if (palmSnap.empty) return res.status(404).json({ success: false, error: 'No palms registered' });

    let bestScore = -1;
    let bestUserId = null;

    for (const doc of palmSnap.docs) {
      const docData = doc.data();
      if (!docData?.encrypted) continue;
      let stored;
      try {
        stored = decryptEmbedding(docData.encrypted);
      } catch (e) {
        console.warn('decrypt fail for', doc.id);
        continue;
      }
      const score = cosineSimilarity(landmarks, stored);
      if (score > bestScore) {
        bestScore = score;
        bestUserId = doc.id;
      }
    }

    const THRESH = 0.94;
    if (!bestUserId || bestScore < THRESH) {
      await db.collection('palmAttempts').add({ merchantId, attemptedAt: admin.firestore.FieldValue.serverTimestamp(), passed: false, bestScore, candidateFound: !!bestUserId });
      // Optionally register failure on bestUserId if present
      if (bestUserId) await registerFailure(bestUserId);
      return res.status(401).json({ success: false, error: 'No matching palm found', bestScore });
    }

    // Check lockout
    const metaRef = db.collection('palmMeta').doc(bestUserId);
    const metaSnap = await metaRef.get();
    if (metaSnap.exists) {
      const meta = metaSnap.data();
      if (meta.lockUntil && meta.lockUntil.toMillis() > Date.now()) return res.status(403).json({ success: false, error: 'Account locked due to repeated failed attempts' });
    }

    // Atomic: deduct payer and create transaction (processing)
    const payerRef = db.collection('users').doc(bestUserId);
    let transactionId;
    try {
      const trx = await db.runTransaction(async (t) => {
        const payerSnap = await t.get(payerRef);
        if (!payerSnap.exists) throw { code: 'NO_PAYER' };
        const payer = payerSnap.data();
        if (payer.balance < amount) throw { code: 'INSUFFICIENT_BALANCE' };

        t.update(payerRef, { balance: admin.firestore.FieldValue.increment(-amount) });

        const trxRef = db.collection('transactions').doc();
        const trxObj = { payerId: bestUserId, merchantId, amount, currency: 'INR', status: 'processing', similarity: bestScore, createdAt: admin.firestore.FieldValue.serverTimestamp() };
        t.set(trxRef, trxObj);

        return { transactionId: trxRef.id };
      });
      transactionId = trx.transactionId;
    } catch (err) {
      if (err.code === 'INSUFFICIENT_BALANCE') return res.status(400).json({ success: false, error: 'Insufficient balance' });
      console.error('transaction create error', err);
      return res.status(500).json({ success: false, error: 'Failed to create transaction' });
    }

    // Initiate payout using pre-created fundAccountId
    const fundAccountId = merchantData.fundAccountId;
    if (!fundAccountId) {
      // If fundAccountId missing, mark transaction failed and refund immediately
      await db.collection('transactions').doc(transactionId).update({ status: 'failed', failedAt: admin.firestore.FieldValue.serverTimestamp(), failReason: 'merchant_missing_fund_account' });
      // refund payer
      await db.collection('users').doc(bestUserId).update({ balance: admin.firestore.FieldValue.increment(amount) });
      return res.status(500).json({ success: false, error: 'Merchant payout setup incomplete. Refunded payer.' });
    }

    const idempotencyKey = `payout_${transactionId}`;
    const amountInPaise = Math.round(amount * 100);
    const notes = { internal_txn: transactionId, merchantId };

    const payoutResp = await createRazorpayPayout({ amountInPaise, fund_account_id: fundAccountId, idempotencyKey, notes });

    if (payoutResp.success) {
      // success path
      const payoutData = payoutResp.data;
      await db.collection('transactions').doc(transactionId).update({ status: 'completed', completedAt: admin.firestore.FieldValue.serverTimestamp(), payoutProvider: 'razorpay', payoutId: payoutData.id || null, payoutResponse: payoutData });
      await db.collection('merchantSettlements').doc(payoutData.id || transactionId).set({ transactionId, merchantId, amount, provider: 'razorpay', payoutId: payoutData.id || null, status: 'initiated', createdAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

      await db.collection('palmAttempts').add({ merchantId, attemptedAt: admin.firestore.FieldValue.serverTimestamp(), passed: true, userId: bestUserId, similarity: bestScore });

      return res.json({ success: true, message: 'Payment completed and payout initiated', transactionId, payerId: bestUserId, merchantId, amount, similarity: bestScore });
    } else {
      // payout failed -> refund payer and mark failed
      const payoutError = payoutResp.error || payoutResp.raw || 'payout_failed';
      await db.runTransaction(async (t) => {
        t.update(db.collection('users').doc(bestUserId), { balance: admin.firestore.FieldValue.increment(amount) });
        t.update(db.collection('transactions').doc(transactionId), { status: 'failed', failedAt: admin.firestore.FieldValue.serverTimestamp(), failReason: payoutError });
        const revRef = db.collection('transactions').doc();
        t.set(revRef, { type: 'refund', originalTransactionId: transactionId, payerId: bestUserId, merchantId, amount, status: 'completed', createdAt: admin.firestore.FieldValue.serverTimestamp() });
      });

      await db.collection('merchantSettlements').doc(transactionId).set({ transactionId, merchantId, amount, provider: 'razorpay', status: 'failed', error: payoutError, createdAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

      return res.status(500).json({ success: false, error: 'Payout failed, payer refunded', details: payoutError });
    }

  } catch (err) {
    console.error('palm.verify err', err);
    return res.status(500).json({ success: false, error: 'Verification failed' });
  }
});

/* -----------------------
   Razorpay webhook endpoint (raw body required)
   ----------------------- */
// Use express.raw for this specific route to preserve body for signature verification
app.post('/webhook/razorpay', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    if (!signature) {
      console.warn('Missing razorpay signature');
      return res.status(400).send('missing signature');
    }
    const bodyBuffer = req.body; // Buffer
    const expected = crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET || '').update(bodyBuffer).digest('hex');
    if (expected !== signature) {
      console.warn('Invalid razorpay webhook signature');
      return res.status(400).send('invalid signature');
    }

    const body = JSON.parse(bodyBuffer.toString('utf8'));
    const event = body.event;

    // Example handling: payout.processed, payout.failed, payout.processed
    if (event && event.startsWith('payout.')) {
      const payoutEntity = body.payload?.payout?.entity;
      if (!payoutEntity) {
        console.warn('No payout entity in webhook');
        return res.status(200).json({ success: true });
      }

      const payoutId = payoutEntity.id;
      const status = payoutEntity.status; // processed, failed, initiated, etc.
      const amount = (payoutEntity.amount || 0) / 100;
      const notes = payoutEntity.notes || {};
      const transactionId = notes.internal_txn || null;

      // Update merchantSettlements and transactions accordingly
      await db.collection('merchantSettlements').doc(payoutId).set({
        payoutId,
        status,
        amount,
        raw: payoutEntity,
        receivedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      if (transactionId) {
        if (status === 'processed' || status === 'paid') {
          await db.collection('transactions').doc(transactionId).update({ payoutStatus: status, payoutId, payoutConfirmedAt: admin.firestore.FieldValue.serverTimestamp() });
        } else if (status === 'failed') {
          await db.collection('transactions').doc(transactionId).update({ payoutStatus: status, payoutFailedAt: admin.firestore.FieldValue.serverTimestamp(), payoutFailReason: payoutEntity.failure_reason || null });
          // optionally: create reversal flow if not already done
        }
      }
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('webhook err', err);
    return res.status(500).send('webhook error');
  }
});

/* -----------------------
   Admin metadata endpoint (debug only)
   ----------------------- */
app.get('/admin/palmmeta/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const doc = await db.collection('palmIndex').doc(userId).get();
    if (!doc.exists) return res.status(404).json({ success: false, error: 'not found' });
    return res.json({ success: true, meta: { registeredAt: doc.data().registeredAt } });
  } catch (e) {
    return res.status(500).json({ success: false, error: 'admin error' });
  }
});

/* -----------------------
   Server start
   ----------------------- */
app.listen(PORT, () => {
  console.log(`Secure palm backend listening on ${PORT}`);
});

/* -----------------------
   README / ENV checklist (IMPORTANT)
   -----------------------
Required environment variables:

- JWT_SECRET (string) - strong secret for signing tokens.
- EMBEDDING_KEY (64 hex chars) - 32 bytes hex for AES-256-GCM encryption of embeddings.
    Generate example: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
- GOOGLE_APPLICATION_CREDENTIALS pointing to your Firebase service account JSON (or configure firebase-admin another way).
- RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET (test keys for dev).
- RAZORPAY_WEBHOOK_SECRET (set in Razorpay dashboard for webhooks).

NPM packages:
  express cookie-parser helmet cors express-rate-limit joi jsonwebtoken bcryptjs firebase-admin dotenv axios

Production hardening suggestions (must before going live):
1. Use Cloud KMS or similar to store/decrypt EMBEDDING_KEY — do not keep long-term plaintext in environment variables for production.
2. Enforce HTTPS and set secure cookies in production.
3. Harden CORS to allow only your scanner and mobile origins.
4. Use Redis-based rate limiter if you run multiple server instances.
5. Move one-to-many search into a private vector DB (FAISS/Milvus/Pinecone) when user-base grows; keep vector DB private to backend.
6. Monitor/pipeline logs (Sentry / Cloud Logging) and add alerts for many failed attempts or mass payouts.
7. Do not log raw embeddings or PII anywhere.
8. Test Razorpay payout flows in sandbox and ensure Idempotency keys and IP allowlist are configured in Razorpay dashboard.

Quick scanner call (palm-only flow):
POST /palm/verify
Body:
{
  "landmarks": [...],   // embedding or landmark vector
  "merchantId": "merchant_doc_id",
  "amount": 120.5
}

Response:
- success true + transactionId on success
- success false + error on failure

-----------------------------------------------------------------------
End of file
-----------------------------------------------------------------------*/
