require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const csrf = require('csurf');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './uploads');
const IS_PROD = process.env.NODE_ENV === 'production';
for (const dir of [DATA_DIR, UPLOAD_DIR]) fs.mkdirSync(dir, { recursive: true });
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  if (IS_PROD) throw new Error('SESSION_SECRET must be at least 32 characters in production.');
  process.env.SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
  console.warn('Using a temporary development session secret. Configure SESSION_SECRET before deployment.');
}

const db = new Database(path.join(DATA_DIR, 'wealth-go.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, balance INTEGER NOT NULL DEFAULT 0, bank_account_name TEXT DEFAULT '',
 bank_account_number TEXT DEFAULT '', bank_name TEXT DEFAULT '', referral_code TEXT UNIQUE NOT NULL,
 referred_by INTEGER REFERENCES users(id), role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS deposits (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), amount INTEGER NOT NULL,
 sender_name TEXT NOT NULL, proof_file TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 admin_note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS withdrawals (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), amount INTEGER NOT NULL,
 account_name TEXT NOT NULL, account_number TEXT NOT NULL, bank_name TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', admin_note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS investments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), plan_name TEXT NOT NULL,
 principal INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL,
 amount INTEGER NOT NULL, status TEXT NOT NULL, description TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const defaults = {
 site_name: process.env.SITE_NAME || 'Wealth Go', deposit_bank_name: 'PalmPay', deposit_account_name: 'John Olumide', deposit_account_number: '8111556330',
 deposit_instructions: 'Transfer only to this Wealth Go receiving account. After payment, enter the amount and payer name and upload your receipt. Your balance is credited only after an administrator verifies the transfer.',
 withdrawals_open: '1', minimum_withdrawal: '2000', referral_reward: '0', welcome_bonus: '600'
};
const setDefault = db.prepare('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)');
for (const [k,v] of Object.entries(defaults)) setDefault.run(k, String(v));
const getSetting = db.prepare('SELECT value FROM settings WHERE key=?');
const setSetting = db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
const setting = key => getSetting.get(key)?.value ?? '';
const addTransaction = db.prepare('INSERT INTO transactions(user_id,kind,amount,status,description) VALUES(?,?,?,?,?)');

async function seedAdmin() {
  const username = process.env.ADMIN_USERNAME || 'ADMIN';
  const password = process.env.ADMIN_PASSWORD;
  if (!password && IS_PROD) throw new Error('Set ADMIN_PASSWORD in production.');
  if (!password) console.warn('No ADMIN_PASSWORD set. Admin account will not be seeded until configured.');
  if (!password) return;
  const existing = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  const hash = await bcrypt.hash(password, 12);
  if (existing) db.prepare("UPDATE users SET password_hash=?, role='admin' WHERE id=?").run(hash, existing.id);
  else db.prepare("INSERT INTO users(username,email,password_hash,referral_code,role) VALUES(?,?,?,?, 'admin')")
    .run(username, `${username.toLowerCase().replace(/[^a-z0-9]/g,'')}@wealthgo.local`, hash, 'WGADMIN');
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'], scriptSrc: ["'self'", "'unsafe-inline'"] } }}));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }), secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false, name: 'wealthgo.sid',
  cookie: { httpOnly: true, sameSite: 'lax', secure: IS_PROD, maxAge: 1000 * 60 * 60 * 8 }
}));
app.use(csrf());
app.use((req,res,next) => {
  res.locals.csrfToken = req.csrfToken();
  res.locals.currentUser = req.session.user || null;
  res.locals.siteName = setting('site_name') || 'Wealth Go';
  res.locals.publicBaseUrl = process.env.PUBLIC_BASE_URL || '';
  res.locals.notice = req.session.notice || null; delete req.session.notice;
  res.locals.formatNaira = n => '₦' + Number(n || 0).toLocaleString('en-NG');
  next();
});
app.use((err,req,res,next) => {
  if (err.code === 'EBADCSRFTOKEN') return res.status(403).render('error', { title: 'Session expired', message: 'This form expired. Go back, refresh the page, and try again.' });
  next(err);
});
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false, message: 'Too many attempts. Please wait and try again.' });
const upload = multer({
  storage: multer.diskStorage({ destination: UPLOAD_DIR, filename: (req,file,cb) => cb(null, `${Date.now()}-${crypto.randomBytes(10).toString('hex')}${path.extname(file.originalname).toLowerCase()}`) }),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req,file,cb) => cb(null, ['image/jpeg','image/png','image/webp','application/pdf'].includes(file.mimetype))
});
function requireAuth(req,res,next) { if (!req.session.user) return res.redirect('/login'); next(); }
function requireAdmin(req,res,next) { if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).render('error',{title:'Access denied',message:'This area is restricted to administrators.'}); next(); }
function notice(req,text,type='success') { req.session.notice = { text, type }; }
function page(res, view, title, data={}) { return res.render(view, { title, ...data }); }
function userById(id) { return db.prepare('SELECT * FROM users WHERE id=?').get(id); }
function refreshUser(req) { const u = userById(req.session.user.id); if (u) req.session.user = {id:u.id, username:u.username, email:u.email, role:u.role, balance:u.balance}; }

app.get('/', (req,res) => page(res,'home','Home',{plans:[['VIP 1',3000,750],['VIP 2',5000,1250],['VIP 3',10000,2500],['VIP 4',20000,5000],['VIP 5',50000,12500],['VIP 6',100000,25000],['VIP 7',200000,50000]]}));
app.get('/register',(req,res)=>page(res,'auth','Create account',{mode:'register',ref:req.query.ref||''}));
app.post('/register',authLimiter,async(req,res)=>{
  const username=String(req.body.username||'').trim(); const email=String(req.body.email||'').trim().toLowerCase(); const password=String(req.body.password||'');
  const ref=String(req.body.ref||'').trim();
  if(!/^[a-zA-Z0-9_]{3,24}$/.test(username)||!/^\S+@\S+\.\S+$/.test(email)||password.length<10){notice(req,'Use a 3–24 character username, a valid email, and a password of at least 10 characters.','error');return res.redirect('/register');}
  try {
    const referrer=ref?db.prepare('SELECT id FROM users WHERE referral_code=?').get(ref):null;
    const code=crypto.randomBytes(5).toString('hex').toUpperCase();
    const bonus=Math.max(0,Math.floor(Number(setting('welcome_bonus')||600)));
    const passwordHash=await bcrypt.hash(password,12);
    const createUser=db.transaction(()=>{
      const result=db.prepare("INSERT INTO users(username,email,password_hash,referral_code,referred_by,balance) VALUES(?,?,?,?,?,?)").run(username,email,passwordHash,code,referrer?.id||null,bonus);
      if(bonus>0) addTransaction.run(Number(result.lastInsertRowid),'welcome_bonus',bonus,'approved','Welcome bonus credited at registration');
      return Number(result.lastInsertRowid);
    });
    const newId=createUser();
    req.session.user={id:newId,username,email,role:'user',balance:bonus};
    notice(req,bonus>0?`Account created. Your ₦${bonus.toLocaleString('en-NG')} welcome bonus has been credited.`:'Account created. Add your bank details and submit a deposit proof when ready.');res.redirect('/dashboard');
  }catch(e){notice(req,'That username or email is already in use.','error');res.redirect('/register');}
});
app.get('/login',(req,res)=>page(res,'auth','Login',{mode:'login'}));
app.post('/login',authLimiter,async(req,res)=>{
  const username=String(req.body.username||'').trim(); const password=String(req.body.password||'');
  const u=db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username,username.toLowerCase());
  if(!u||!(await bcrypt.compare(password,u.password_hash))){notice(req,'Invalid login details.','error');return res.redirect('/login');}
  req.session.regenerate(err=>{if(err)return res.status(500).send('Could not start session.');req.session.user={id:u.id,username:u.username,email:u.email,role:u.role,balance:u.balance};res.redirect(u.role==='admin'?'/admin':'/dashboard');});
});
app.post('/logout',requireAuth,(req,res)=>req.session.destroy(()=>res.redirect('/')));
app.get('/dashboard',requireAuth,(req,res)=>{
  refreshUser(req);const u=userById(req.session.user.id);
  const investments=db.prepare('SELECT * FROM investments WHERE user_id=? ORDER BY id DESC LIMIT 6').all(u.id);
  const transactions=db.prepare('SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 8').all(u.id);
  const referrals=db.prepare('SELECT COUNT(*) count FROM users WHERE referred_by=?').get(u.id).count;
  page(res,'dashboard','Dashboard',{u,investments,transactions,referrals});
});
app.get('/products',requireAuth,(req,res)=>page(res,'products','Investment products',{plans:[['VIP 1',3000,750],['VIP 2',5000,1250],['VIP 3',10000,2500],['VIP 4',20000,5000],['VIP 5',50000,12500],['VIP 6',100000,25000],['VIP 7',200000,50000]]}));
app.post('/invest',requireAuth,(req,res)=>{
  const plans={'VIP 1':3000,'VIP 2':5000,'VIP 3':10000,'VIP 4':20000,'VIP 5':50000,'VIP 6':100000,'VIP 7':200000};const name=String(req.body.plan||'');const amount=plans[name];
  const u=userById(req.session.user.id);if(!amount)return res.redirect('/products');
  if(u.balance<amount){notice(req,'Your available balance is too low. Deposit funds first.','error');return res.redirect('/products');}
  const run=db.transaction(()=>{db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(amount,u.id);db.prepare('INSERT INTO investments(user_id,plan_name,principal) VALUES(?,?,?)').run(u.id,name,amount);addTransaction.run(u.id,'investment',amount,'active',`${name} package purchased`);});run();refreshUser(req);notice(req,`${name} package purchased. No profit is credited automatically; any return terms must be verified and disclosed.`);res.redirect('/dashboard');
});
app.get('/deposit',requireAuth,(req,res)=>page(res,'deposit','Deposit',{settings:{bank:setting('deposit_bank_name'),name:setting('deposit_account_name'),number:setting('deposit_account_number'),instructions:setting('deposit_instructions')}}));
app.post('/deposit',requireAuth,(req,res,next)=>upload.single('proof')(req,res,err=>{
  if(err){notice(req,'Upload failed. Use a JPG, PNG, WEBP, or PDF no larger than 5 MB.','error');return res.redirect('/deposit');}
  const amount=Number(req.body.amount);const sender=String(req.body.sender_name||'').trim();
  if(!Number.isSafeInteger(amount)||amount<1000||!sender||!req.file){if(req.file)fs.unlink(req.file.path,()=>{});notice(req,'Enter an amount of at least ₦1,000, the payer name, and upload payment proof.','error');return res.redirect('/deposit');}
  db.prepare('INSERT INTO deposits(user_id,amount,sender_name,proof_file) VALUES(?,?,?,?)').run(req.session.user.id,amount,sender,path.basename(req.file.path));
  addTransaction.run(req.session.user.id,'deposit',amount,'pending','Deposit submitted for manual review');notice(req,'Deposit proof submitted. Your balance will update only after admin approval.');res.redirect('/history');
}));
app.get('/withdraw',requireAuth,(req,res)=>page(res,'withdraw','Withdraw',{u:userById(req.session.user.id),open:setting('withdrawals_open')==='1',min:Number(setting('minimum_withdrawal')||2000)}));
app.post('/withdraw',requireAuth,(req,res)=>{
  if(setting('withdrawals_open')!=='1'){notice(req,'The withdrawal portal is currently closed.','error');return res.redirect('/withdraw');}
  const amount=Number(req.body.amount);const u=userById(req.session.user.id);
  const account_name=String(req.body.account_name||'').trim();const account_number=String(req.body.account_number||'').trim();const bank_name=String(req.body.bank_name||'').trim();
  const min=Math.max(2000,Number(setting('minimum_withdrawal')||2000));
  if(!Number.isSafeInteger(amount)||amount<min||amount>u.balance||!account_name||!/^\d{8,20}$/.test(account_number)||!bank_name){notice(req,'Check the amount and complete all bank details. The amount must be within your available balance.','error');return res.redirect('/withdraw');}
  const run=db.transaction(()=>{db.prepare('UPDATE users SET balance=balance-?,bank_account_name=?,bank_account_number=?,bank_name=? WHERE id=?').run(amount,account_name,account_number,bank_name,u.id);db.prepare('INSERT INTO withdrawals(user_id,amount,account_name,account_number,bank_name) VALUES(?,?,?,?,?)').run(u.id,amount,account_name,account_number,bank_name);addTransaction.run(u.id,'withdrawal',amount,'pending','Withdrawal reserved pending admin approval');});run();refreshUser(req);notice(req,'Withdrawal request submitted for admin approval. The amount is reserved while pending.');res.redirect('/history');
});
app.get('/profile',requireAuth,(req,res)=>page(res,'profile','Profile',{u:userById(req.session.user.id)}));
app.post('/profile',requireAuth,(req,res)=>{
 const name=String(req.body.account_name||'').trim(),number=String(req.body.account_number||'').trim(),bank=String(req.body.bank_name||'').trim();
 if(!name||!/^\d{8,20}$/.test(number)||!bank){notice(req,'Enter a valid account name, account number (8–20 digits), and bank name.','error');return res.redirect('/profile');}
 db.prepare('UPDATE users SET bank_account_name=?,bank_account_number=?,bank_name=? WHERE id=?').run(name,number,bank,req.session.user.id);notice(req,'Bank details saved. Verify them carefully before requesting a withdrawal.');res.redirect('/profile');
});
app.get('/history',requireAuth,(req,res)=>{
 const id=req.session.user.id;page(res,'history','History',{
 deposits:db.prepare('SELECT * FROM deposits WHERE user_id=? ORDER BY id DESC').all(id),
 withdrawals:db.prepare('SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC').all(id),
 transactions:db.prepare('SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC').all(id)
 });
});
app.get('/proof/:id',requireAuth,(req,res)=>{
 const d=db.prepare('SELECT * FROM deposits WHERE id=?').get(Number(req.params.id));if(!d)return res.sendStatus(404);
 if(req.session.user.role!=='admin'&&d.user_id!==req.session.user.id)return res.sendStatus(403);
 const file=path.join(UPLOAD_DIR,path.basename(d.proof_file));if(!fs.existsSync(file))return res.sendStatus(404);res.sendFile(file);
});
app.get('/admin',requireAdmin,(req,res)=>{
 const stats={users:db.prepare("SELECT COUNT(*) n FROM users WHERE role='user'").get().n,pendingDeposits:db.prepare("SELECT COUNT(*) n FROM deposits WHERE status='pending'").get().n,pendingWithdrawals:db.prepare("SELECT COUNT(*) n FROM withdrawals WHERE status='pending'").get().n,totalBalance:db.prepare("SELECT COALESCE(SUM(balance),0) n FROM users WHERE role='user'").get().n};
 page(res,'admin','Admin panel',{stats,settings:{bank:setting('deposit_bank_name'),name:setting('deposit_account_name'),number:setting('deposit_account_number'),instructions:setting('deposit_instructions'),withdrawalsOpen:setting('withdrawals_open')==='1',minimum:setting('minimum_withdrawal'),referralReward:setting('referral_reward'),siteName:setting('site_name')},deposits:db.prepare("SELECT d.*,u.username FROM deposits d JOIN users u ON u.id=d.user_id WHERE d.status='pending' ORDER BY d.id ASC").all(),withdrawals:db.prepare("SELECT w.*,u.username FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.status='pending' ORDER BY w.id ASC").all(),users:db.prepare('SELECT id,username,email,balance,role,created_at FROM users ORDER BY id DESC LIMIT 100').all()});
});
app.post('/admin/settings',requireAdmin,(req,res)=>{
 const fields={site_name:req.body.site_name,deposit_bank_name:req.body.bank_name,deposit_account_name:req.body.account_name,deposit_account_number:req.body.account_number,deposit_instructions:req.body.instructions,withdrawals_open:req.body.withdrawals_open==='on'?'1':'0',minimum_withdrawal:String(Math.max(2000,Math.floor(Number(req.body.minimum_withdrawal)||2000))),referral_reward:'0'};
 if(fields.deposit_account_number && !/^\d{8,20}$/.test(fields.deposit_account_number)){notice(req,'Deposit account number must contain 8–20 digits.','error');return res.redirect('/admin');}
 for(const [k,v] of Object.entries(fields))setSetting.run(k,String(v??''));notice(req,'Settings saved. Deposit account details are now shown to users.');res.redirect('/admin');
});
app.post('/admin/deposit/:id',requireAdmin,(req,res)=>{
 const id=Number(req.params.id),action=String(req.body.action),note=String(req.body.note||'').slice(0,500);const d=db.prepare("SELECT * FROM deposits WHERE id=? AND status='pending'").get(id);if(!d){notice(req,'Deposit was already reviewed or does not exist.','error');return res.redirect('/admin');}
 const run=db.transaction(()=>{db.prepare('UPDATE deposits SET status=?,admin_note=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?').run(action==='approve'?'approved':'rejected',note,id);if(action==='approve'){db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(d.amount,d.user_id);addTransaction.run(d.user_id,'deposit',d.amount,'approved','Deposit approved by admin');}else addTransaction.run(d.user_id,'deposit',d.amount,'rejected','Deposit rejected by admin');});run();notice(req,action==='approve'?'Deposit approved and user balance credited.':'Deposit rejected.');res.redirect('/admin');
});
app.post('/admin/withdrawal/:id',requireAdmin,(req,res)=>{
 const id=Number(req.params.id),action=String(req.body.action),note=String(req.body.note||'').slice(0,500);const w=db.prepare("SELECT * FROM withdrawals WHERE id=? AND status='pending'").get(id);if(!w){notice(req,'Withdrawal was already reviewed or does not exist.','error');return res.redirect('/admin');}
 const run=db.transaction(()=>{db.prepare('UPDATE withdrawals SET status=?,admin_note=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?').run(action==='approve'?'approved':'rejected',note,id);if(action!=='approve')db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(w.amount,w.user_id);addTransaction.run(w.user_id,'withdrawal',w.amount,action==='approve'?'approved':'rejected',action==='approve'?'Withdrawal marked paid by admin':'Withdrawal rejected; reserved balance refunded');});run();notice(req,action==='approve'?'Withdrawal approved. Complete the bank transfer separately and mark it paid only after sending.':'Withdrawal rejected and funds refunded to user balance.');res.redirect('/admin');
});
app.post('/admin/user/:id/balance',requireAdmin,(req,res)=>{
 const id=Number(req.params.id),amount=Number(req.body.amount),direction=String(req.body.direction);if(!Number.isSafeInteger(amount)||amount<=0||amount>100000000){notice(req,'Enter a valid positive amount.','error');return res.redirect('/admin');}
 const u=userById(id);if(!u||u.role==='admin'){notice(req,'User not found.','error');return res.redirect('/admin');}
 if(direction==='credit'){db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(amount,id);addTransaction.run(id,'adjustment',amount,'approved','Admin balance adjustment (credit)');}else{if(u.balance<amount){notice(req,'User balance is too low for that debit.','error');return res.redirect('/admin');}db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(amount,id);addTransaction.run(id,'adjustment',amount,'approved','Admin balance adjustment (debit)');}
 notice(req,'User balance updated.');res.redirect('/admin');
});
app.use((req,res)=>res.status(404).render('error',{title:'Page not found',message:'That page does not exist.'}));
app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).render('error',{title:'Something went wrong',message:'The request could not be completed. Check the server logs for details.'});});
seedAdmin().then(()=>app.listen(PORT,()=>console.log(`Wealth Go listening on port ${PORT}`))).catch(err=>{console.error(err);process.exit(1);});
