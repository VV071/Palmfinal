require('dotenv').config();
const express = require('express'); // Express server
const cookieParser = require('cookie-parser'); // Cookie parser
const helmet = require('helmet'); // Security headers
const cors = require('cors'); // CORS
const rateLimit = require('express-rate-limit'); // Rate limiting
const Joi = require('joi'); // Validation
const jwt = require('jsonwebtoken'); // JWT
const bcrypt = require('bcryptjs'); // Password hashing
const crypto = require('crypto'); // AES encryption
const admin = require('firebase-admin'); // Firebase Admin
const axios = require('axios'); // HTTP requests

const app = express();

// ---------- Middleware ----------
app.use(helmet());
app.use(express.json({ limit: '300kb' }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));

// ---------- Env vars ----------
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET;
const EMBEDDING_KEY = process.env.EMBEDDING_KEY;
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;

if (!JWT_SECRET) { console.error('JWT_SECRET missing'); process.exit(1); }
if (!EMBEDDING_KEY || EMBEDDING_KEY.length !== 64) console.warn('EMBEDDING_KEY missing or invalid length');
if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) console.warn('Razorpay keys missing');

// ---------- Firebase Init ----------
try { admin.initializeApp(); } catch(e){} 
const db = admin.firestore();

// ---------- Crypto helpers ----------
const EMB_KEY = Buffer.from(EMBEDDING_KEY || '0'.repeat(64), 'hex');
function encryptEmbedding(arr){ // Encrypt landmarks
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', EMB_KEY, iv);
    const serialized = Buffer.from(JSON.stringify(arr));
    const encrypted = Buffer.concat([cipher.update(serialized), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { data: encrypted.toString('base64'), iv: iv.toString('base64'), tag: tag.toString('base64') };
}
function decryptEmbedding({data, iv, tag}){ // Decrypt landmarks
    const decipher = crypto.createDecipheriv('aes-256-gcm', EMB_KEY, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]);
    return JSON.parse(decrypted.toString());
}

// ---------- Token helpers ----------
const ACCESS_EXPIRES = '15m';
const REFRESH_EXPIRES_SECONDS = 60*60*24*30;
function generateAccessToken(payload){ return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_EXPIRES }); }
function generateRefreshToken(payload){ return jwt.sign(payload, JWT_SECRET, { expiresIn: `${REFRESH_EXPIRES_SECONDS}s` }); }
function hashToken(token){ return crypto.createHmac('sha256', JWT_SECRET).update(token).digest('hex'); }

// ---------- Cosine similarity ----------
function cosineSimilarity(a,b){
    if(!Array.isArray(a)||!Array.isArray(b)||a.length!==b.length)return 0;
    let dot=0, magA=0, magB=0;
    for(let i=0;i<a.length;i++){ const ai=Number(a[i])||0; const bi=Number(b[i])||0; dot+=ai*bi; magA+=ai*ai; magB+=bi*bi; }
    magA=Math.sqrt(magA); magB=Math.sqrt(magB);
    if(magA===0||magB===0)return 0;
    return dot/(magA*magB);
}

// ---------- Joi schemas ----------
const registerPalmSchema = Joi.object({ landmarks: Joi.array().items(Joi.number()).min(10).max(5000).required() });
const palmVerifySchema = Joi.object({ landmarks:Joi.array().items(Joi.number()).min(10).max(5000).required(), merchantId:Joi.string().required(), amount:Joi.number().positive().required() });
const createPaymentIntentSchema = Joi.object({ merchantId:Joi.string().required(), amount:Joi.number().positive().required() });
const merchantUpiSchema = Joi.object({ name:Joi.string().required(), contact:Joi.string().optional().allow(''), email:Joi.string().optional().allow(''), upi:Joi.string().required() });

// ---------- Rate limiting ----------
const authLimiter = rateLimit({ windowMs:15*60*1000,max:20,message:{success:false,error:'Too many requests'}});
app.use('/auth', authLimiter);
const palmLimiter = rateLimit({ windowMs:60*1000,max:8,message:{success:false,error:'Too many palm attempts'}});
app.use('/palm', palmLimiter);

// ---------- Auth middleware ----------
async function authenticateToken(req,res,next){
    try{
        const authHeader=req.headers['authorization'];
        const token=authHeader&&authHeader.startsWith('Bearer ')?authHeader.split(' ')[1]:null;
        if(!token)return res.status(401).json({success:false,error:'Access token required'});
        const decoded=jwt.verify(token,JWT_SECRET);
        req.user={userId:decoded.userId,email:decoded.email};
        next();
    }catch(e){ return res.status(403).json({success:false,error:'Invalid or expired token'}); }
}

// ---------- Auth endpoints ----------
app.post('/auth/signup', async(req,res)=>{
    try{
        const {email,password,displayName}=req.body;
        if(!email||!password)return res.status(400).json({success:false,error:'Email & password required'});
        const usersRef=db.collection('users');
        const existing=await usersRef.where('email','==',email).limit(1).get();
        if(!existing.empty)return res.status(400).json({success:false,error:'User exists'});
        const hashed=await bcrypt.hash(password,10);
        const userDoc={email,passwordHash:hashed,displayName:displayName||'',balance:0,createdAt:admin.firestore.FieldValue.serverTimestamp()};
        const userRef=await usersRef.add(userDoc);
        const payload={userId:userRef.id,email};
        const accessToken=generateAccessToken(payload);
        const refreshToken=generateRefreshToken(payload);
        await db.collection('refreshTokens').doc(userRef.id).set({ tokenHash:hashToken(refreshToken), createdAt:admin.firestore.FieldValue.serverTimestamp(), expiresAt:admin.firestore.Timestamp.fromDate(new Date(Date.now()+REFRESH_EXPIRES_SECONDS*1000)) });
        res.cookie('refreshToken',refreshToken,{httpOnly:true,secure:NODE_ENV==='production',sameSite:'Strict',maxAge:REFRESH_EXPIRES_SECONDS*1000});
        return res.json({success:true,accessToken,userId:userRef.id});
    }catch(err){ console.error('signup err',err); return res.status(500).json({success:false,error:'Signup failed'}); }
});

app.post('/auth/login', async(req,res)=>{
    try{
        const {email,password}=req.body;
        if(!email||!password)return res.status(400).json({success:false,error:'Email & password required'});
        const usersRef=db.collection('users');
        const snap=await usersRef.where('email','==',email).limit(1).get();
        if(snap.empty)return res.status(401).json({success:false,error:'Invalid credentials'});
        const doc=snap.docs[0]; const user=doc.data();
        const match=await bcrypt.compare(password,user.passwordHash||'');
        if(!match)return res.status(401).json({success:false,error:'Invalid credentials'});
        const payload={userId:doc.id,email};
        const accessToken=generateAccessToken(payload);
        const refreshToken=generateRefreshToken(payload);
        await db.collection('refreshTokens').doc(doc.id).set({ tokenHash:hashToken(refreshToken), createdAt:admin.firestore.FieldValue.serverTimestamp(), expiresAt:admin.firestore.Timestamp.fromDate(new Date(Date.now()+REFRESH_EXPIRES_SECONDS*1000)) });
        res.cookie('refreshToken',refreshToken,{httpOnly:true,secure:NODE_ENV==='production',sameSite:'Strict',maxAge:REFRESH_EXPIRES_SECONDS*1000});
        return res.json({success:true,accessToken,userId:doc.id});
    }catch(err){ console.error('login err',err); return res.status(500).json({success:false,error:'Login failed'}); }
});

app.post('/auth/refresh', async(req,res)=>{
    try{
        const rt=req.cookies?.refreshToken||req.body?.refreshToken;
        if(!rt)return res.status(401).json({success:false,error:'Refresh token missing'});
        let decoded; try{decoded=jwt.verify(rt,JWT_SECRET);}catch(e){return res.status(401).json({success:false,error:'Invalid refresh token'});}
        const stored=await db.collection('refreshTokens').doc(decoded.userId).get();
        if(!stored.exists)return res.status(401).json({success:false,error:'Refresh token not found'});
        if(stored.data().tokenHash!==hashToken(rt))return res.status(401).json({success:false,error:'Refresh token revoked'});
        const accessToken=generateAccessToken({userId:decoded.userId,email:decoded.email});
        return res.json({success:true,accessToken});
    }catch(err){ console.error('refresh err',err); return res.status(500).json({success:false,error:'Refresh failed'}); }
});

// ---------- Palm registration ----------
app.post('/palm/register', authenticateToken, async(req,res)=>{
    try{
        const {error,value}=registerPalmSchema.validate(req.body);
        if(error)return res.status(400).json({success:false,error:'Invalid landmarks'});
        const encrypted=encryptEmbedding(value.landmarks);
        await db.collection('palmIndex').doc(req.user.userId).set({encrypted,registeredAt:admin.firestore.FieldValue.serverTimestamp()},{merge:true});
        return res.json({success:true,message:'Palm registered'});
    }catch(err){ console.error('register palm',err); return res.status(500).json({success:false,error:'Registration failed'}); }
});

// ---------- Payment intent ----------
app.post('/payment/create', authenticateToken, async(req,res)=>{
    try{
        const {error,value}=createPaymentIntentSchema.validate(req.body);
        if(error)return res.status(400).json({success:false,error:'Invalid input'});
        const {merchantId,amount}=value;
        const TTL_SECONDS=30; const nonce=crypto.randomBytes(12).toString('hex');
        const intent={payerId:req.user.userId,merchantId,amount,nonce,status:'pending',createdAt:admin.firestore.FieldValue.serverTimestamp(),expiresAt:admin.firestore.Timestamp.fromDate(new Date(Date.now()+TTL_SECONDS*1000))};
        const ref=await db.collection('paymentIntents').add(intent);
        return res.json({success:true,paymentIntentId:ref.id,expiresIn:TTL_SECONDS});
    }catch(err){ console.error('create intent',err); return res.status(500).json({success:false,error:'Failed to create intent'}); }
});

app.post('/payment/cancel', authenticateToken, async(req,res)=>{
    try{
        const {paymentIntentId}=req.body;
        if(!paymentIntentId)return res.status(400).json({success:false,error:'paymentIntentId required'});
        const piRef=db.collection('paymentIntents').doc(paymentIntentId);
        const piDoc=await piRef.get();
        if(!piDoc.exists)return res.status(404).json({success:false,error:'Intent not found'});
        const pi=piDoc.data();
        if(req.user.userId!==pi.payerId&&req.user.userId!==pi.merchantId)return res.status(403).json({success:false,error:'Not authorized'});
        if(pi.status!=='pending')return res.status(400).json({success:false,error:'Only pending intents can be cancelled'});
        await piRef.update({status:'cancelled',cancelledAt:admin.firestore.FieldValue.serverTimestamp()});
        return res.json({success:true,message:'Intent cancelled'});
    }catch(err){ console.error('cancel intent',err); return res.status(500).json({success:false,error:'Cancel failed'}); }
});

// ---------- Razorpay helper functions ----------
async function createRazorpayContact({name,contact='',email='',type='vendor',reference_id}){ try{const resp=await axios.post('https://api.razorpay.com/v1/contacts',{name,contact,email,type,reference_id},{auth:{username:RAZORPAY_KEY_ID,password:RAZORPAY_KEY_SECRET},headers:{'Content-Type':'application/json'},timeout:15000});return{success:true,data:resp.data};}catch(err){return{success:false,error:err.response?.data||err.message}} }
async function createRazorpayFundAccount({contact_id,account_type='vpa',vpa_address}){ try{const payload={contact_id,account_type,[account_type==='vpa'?'vpa':'bank_account']:account_type==='vpa'?{address:vpa_address}:{}}; const resp=await axios.post('https://api.razorpay.com/v1/fund_accounts',payload,{auth:{username:RAZORPAY_KEY_ID,password:RAZORPAY_KEY_SECRET},headers:{'Content-Type':'application/json'},timeout:15000}); return{success:true,data:resp.data};}catch(err){return{success:false,error:err.response?.data||err.message}} }
async function createRazorpayPayout({amountInPaise,fund_account_id,idempotencyKey,purpose='payout',queue_if_low_balance=false,notes={}}){ try{const resp=await axios.post('https://api.razorpay.com/v1/payouts',{amount:amountInPaise,currency:'INR',mode:'upi',purpose,fund_account_id,queue_if_low_balance,notes},{auth:{username:RAZORPAY_KEY_ID,password:RAZORPAY_KEY_SECRET},headers:{'Content-Type':'application/json','Idempotency-Key':idempotencyKey},timeout:20000});return{success:true,data:resp.data};}catch(err){return{success:false,error:err.response?.data||err.message}} }

// ---------- Merchant UPI registration ----------
app.post('/merchant/registerUpi', authenticateToken, async(req,res)=>{
    try{
        const {error,value}=merchantUpiSchema.validate(req.body);
        if(error)return res.status(400).json({success:false,error:'Invalid input'});
        const {name,contact,email,upi}=value;
        const merchantId=req.user.userId;
        const merchantRef=db.collection('merchants').doc(merchantId);
        const existing=await merchantRef.get(); const existingData=existing.exists?existing.data():{};
        if(existingData.contactId&&existingData.fundAccountId)return res.json({success:true,message:'Merchant already registered',contactId:existingData.contactId,fundAccountId:existingData.fundAccountId});
        const contactResp=await createRazorpayContact({name,contact,email,type:'vendor',reference_id:merchantId});
        if(!contactResp.success){ console.error('create contact failed',contactResp.error); return res.status(500).json({success:false,error:'Failed to create contact'}); }
        const contactId=contactResp.data.id;
        const fundResp=await createRazorpayFundAccount({contact_id:contactId,account_type:'vpa',vpa_address:upi});
        if(!fundResp.success){ console.error('create fund account failed',fundResp.error); return res.status(500).json({success:false,error:'Failed to create fund account'}); }
        const fundAccountId=fundResp.data.id;
        await merchantRef.set({name,contact,email,contactId,fundAccountId,upi,createdAt:admin.firestore.FieldValue.serverTimestamp()},{merge:true});
        return res.json({success:true,message:'Merchant payout setup complete',contactId,fundAccountId});
    }catch(err){ console.error('merchant.registerUpi err',err); return res.status(500).json({success:false,error:'Merchant registration failed'}); }
});

// ---------- Palm verification ----------
async function registerFailure(userId){ const metaRef=db.collection('palmMeta').doc(userId); await metaRef.set({failures:admin.firestore.FieldValue.increment(1),lastFailureAt:admin.firestore.FieldValue.serverTimestamp()},{merge:true}); const snap=await metaRef.get(); const meta=snap.data()||{}; const failCount=meta.failures||0; if(failCount>=10){ await metaRef.update({lockUntil:admin.firestore.Timestamp.fromDate(new Date(Date.now()+30*60*1000))}); } }

app.post('/palm/verify', palmLimiter, async(req,res)=>{
    try{
        const {error,value}=palmVerifySchema.validate(req.body);
        if(error)return res.status(400).json({success:false,error:'Invalid payload'});
        const {landmarks,merchantId,amount}=value;
        const merchantRef=db.collection('merchants').doc(merchantId);
        const merchantSnap=await merchantRef.get();
        if(!merchantSnap.exists)return res.status(400).json({success:false,error:'Unknown merchant'});
        const merchantData=merchantSnap.data();
        const palmSnap=await db.collection('palmIndex').get();
        if(palmSnap.empty)return res.status(404).json({success:false,error:'No palms registered'});

        let bestScore=-1,bestUserId=null;
        for(const doc of palmSnap.docs){
            const docData=doc.data();
            if(!docData?.encrypted)continue;
            let stored; try{stored=decryptEmbedding(docData.encrypted);}catch(e){continue;}
            const score=cosineSimilarity(landmarks,stored);
            if(score>bestScore){bestScore=score;bestUserId=doc.id;}
        }

        const THRESH=0.94;
        if(!bestUserId||bestScore<THRESH){ if(bestUserId) await registerFailure(bestUserId); return res.status(401).json({success:false,error:'No matching palm found',bestScore}); }

        const metaRef=db.collection('palmMeta').doc(bestUserId);
        const metaSnap=await metaRef.get();
        if(metaSnap.exists){ const meta=metaSnap.data(); if(meta.lockUntil && meta.lockUntil.toMillis()>Date.now()) return res.status(403).json({success:false,error:'Account locked due to repeated failed attempts'}); }

        const payerRef=db.collection('users').doc(bestUserId);
        let transactionId;
        try{
            const trx=await db.runTransaction(async(t)=>{
                const payerSnap=await t.get(payerRef);
                if(!payerSnap.exists)throw{code:'NO_PAYER'};
                const payer=payerSnap.data();
                if(payer.balance<amount)throw{code:'INSUFFICIENT'};
                t.update(payerRef,{balance:admin.firestore.FieldValue.increment(-amount)});
                const merchantUserRef=db.collection('users').doc(merchantId);
                const merchantSnap2=await t.get(merchantUserRef);
                if(!merchantSnap2.exists)throw{code:'NO_MERCHANT'};
                t.update(merchantUserRef,{balance:admin.firestore.FieldValue.increment(amount)});
                const trxRef=db.collection('transactions').doc();
                transactionId=trxRef.id;
                t.set(trxRef,{from:bestUserId,to:merchantId,amount,status:'success',createdAt:admin.firestore.FieldValue.serverTimestamp()});
            });
        }catch(e){ console.error('palm pay trx err',e); if(e.code==='INSUFFICIENT') return res.status(400).json({success:false,error:'Insufficient balance'}); else return res.status(500).json({success:false,error:'Transaction failed'}); }

        return res.json({success:true,message:'Payment successful',transactionId,userId:bestUserId});
    }catch(err){ console.error('verify palm err',err); return res.status(500).json({success:false,error:'Verification failed'}); }
});

// ---------- Razorpay webhook ----------
app.post('/webhook/razorpay', express.raw({type:'application/json'}), async(req,res)=>{
    const sig=req.headers['x-razorpay-signature'];
    const body=req.body;
    const cryptoLocal=require('crypto');
    const hmac=cryptoLocal.createHmac('sha256',RAZORPAY_WEBHOOK_SECRET).update(body).digest('hex');
    if(hmac!==sig)return res.status(400).json({success:false,error:'Invalid signature'});
    console.log('Webhook received',body.toString());
    res.json({success:true});
});

// ---------- Admin debug ----------
app.get('/admin/palmmeta', async(req,res)=>{ const snap=await db.collection('palmMeta').get(); const result=snap.docs.map(d=>({id:d.id,...d.data()})); res.json({success:true,result}); });

// ---------- Server listen ----------
app.listen(PORT,()=>console.log(`Server running on port ${PORT}`));

/* -----------------------
   Wallet top-up (Razorpay)
   ----------------------- */

// Create a top-up order
app.post('/wallet/topup', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ success: false, error: 'Invalid amount' });

    const amountInPaise = Math.round(amount * 100);
    const idempotencyKey = `topup_${req.user.userId}_${Date.now()}`;

    // Create Razorpay order
    const orderResp = await axios.post('https://api.razorpay.com/v1/orders', {
      amount: amountInPaise,
      currency: 'INR',
      receipt: `topup_${req.user.userId}_${Date.now()}`,
      payment_capture: 1,
      notes: { userId: req.user.userId }
    }, {
      auth: { username: RAZORPAY_KEY_ID, password: RAZORPAY_KEY_SECRET },
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      timeout: 15000
    });

    if (!orderResp.data || !orderResp.data.id) throw new Error('Razorpay order creation failed');

    // Store top-up transaction as pending
    await db.collection('walletTopups').doc(orderResp.data.id).set({
      userId: req.user.userId,
      amount,
      amountInPaise,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      razorpayOrderId: orderResp.data.id
    });

    return res.json({ success: true, orderId: orderResp.data.id, amount, currency: 'INR' });
  } catch (err) {
    console.error('wallet topup err', err);
    return res.status(500).json({ success: false, error: 'Failed to create top-up order' });
  }
});

// Handle Razorpay payment webhook for wallet top-up
app.post('/webhook/razorpay-topup', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    if (!signature) return res.status(400).send('missing signature');

    const expected = crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET || '').update(req.body).digest('hex');
    if (expected !== signature) return res.status(400).send('invalid signature');

    const body = JSON.parse(req.body.toString('utf8'));
    const event = body.event;

    if (event === 'payment.captured') {
      const payment = body.payload?.payment?.entity;
      if (!payment) return res.status(200).json({ success: true });

      const orderId = payment.order_id;
      const topupRef = db.collection('walletTopups').doc(orderId);
      const topupSnap = await topupRef.get();
      if (!topupSnap.exists) return res.status(404).send('top-up not found');

      const topup = topupSnap.data();
      if (topup.status === 'completed') return res.status(200).json({ success: true }); // already processed

      // Increment user balance and mark top-up as completed
      await db.runTransaction(async (t) => {
        const userRef = db.collection('users').doc(topup.userId);
        t.update(userRef, { balance: admin.firestore.FieldValue.increment(topup.amount) });
        t.update(topupRef, { status: 'completed', razorpayPaymentId: payment.id, completedAt: admin.firestore.FieldValue.serverTimestamp() });
      });

      console.log(`Wallet top-up completed: user=${topup.userId}, amount=${topup.amount}`);
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('wallet topup webhook err', err);
    return res.status(500).send('webhook error');
  }
});
// ---------- KYC Endpoints ----------

// Endpoint: Get DigiLocker OAuth URL
app.get('/kyc/digilocker/url', authenticateToken, async (req, res) => {
  try {
    // Your backend should generate DigiLocker OAuth URL here
    // For example, redirect_uri points back to your backend callback
    const clientId = process.env.DIGILOCKER_CLIENT_ID;
    const redirectUri = process.env.DIGILOCKER_REDIRECT_URI;
    const state = req.user.userId; // use userId as state
    const authUrl = `https://digilocker.gov.in/public/oauth2/1/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=org.gov.digilocker.userprofile&state=${state}`;
    return res.json({ success: true, authUrl });
  } catch (err) {
    console.error('digilocker url err', err);
    return res.status(500).json({ success: false, error: 'Failed to generate DigiLocker URL' });
  }
});

// Endpoint: Submit KYC documents (PAN/Aadhaar images)
app.post('/kyc/submit', authenticateToken, async (req, res) => {
  try {
    if (!req.files?.pan || !req.files?.aadhaar) {
      return res.status(400).json({ success: false, error: 'PAN and Aadhaar images required' });
    }

    const panFile = req.files.pan;
    const aadhaarFile = req.files.aadhaar;

    // RazorpayX KYC API endpoint: POST /v1/kyc
    const razorpayResp = await axios.post(
      'https://api.razorpay.com/v1/kyc',
      {
        name: req.user.email, // or full name from your users collection
        kyc_type: 'individual',
        document: [
          { type: 'pan', file: panFile.data.toString('base64') },
          { type: 'aadhaar', file: aadhaarFile.data.toString('base64') }
        ]
      },
      {
        auth: { username: RAZORPAY_KEY_ID, password: RAZORPAY_KEY_SECRET },
        headers: { 'Content-Type': 'application/json' },
        timeout: 20000
      }
    );

    // Save RazorpayX KYC ID in Firestore
    await db.collection('kyc').doc(req.user.userId).set({
      kycId: razorpayResp.data.id,
      status: razorpayResp.data.status || 'pending',
      submittedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ success: true, status: razorpayResp.data.status || 'pending' });
  } catch (err) {
    console.error('kyc submit err', err.response?.data || err.message);
    return res.status(500).json({ success: false, error: 'KYC submission failed' });
  }
});

// Endpoint: Get KYC status
app.get('/kyc/status', authenticateToken, async (req, res) => {
  try {
    const kycDoc = await db.collection('kyc').doc(req.user.userId).get();
    if (!kycDoc.exists) return res.json({ success: true, status: 'not_submitted' });

    const kycData = kycDoc.data();
    const kycId = kycData ? kycData.kycId : null;

    if (!kycId) return res.json({ success: true, status: 'not_submitted' });

    // Fetch status from RazorpayX
    const razorpayResp = await axios.get(`https://api.razorpay.com/v1/kyc/${kycId}`, {
      auth: { username: RAZORPAY_KEY_ID, password: RAZORPAY_KEY_SECRET },
      timeout: 15000,
    });

    // Update Firestore with latest status
    await db.collection('kyc').doc(req.user.userId).update({
      status: razorpayResp.data.status,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ success: true, status: razorpayResp.data.status });
  } catch (err) {
    console.error('kyc status err', err.response?.data || err.message);
    return res.status(500).json({ success: false, error: 'Failed to fetch KYC status' });
  }
});
