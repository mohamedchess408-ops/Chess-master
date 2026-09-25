require('dotenv').config();
const express=require('express');
const session=require('express-session');
const Database=require('better-sqlite3');
const crypto=require('crypto');
const path=require('path');
const app=express();
const db=new Database(process.env.DB_FILE||path.join(__dirname,'chess-mastery.db'));
const PORT=process.env.PORT||3000;
function ensureAuthTokenColumn(){const cols=db.prepare('PRAGMA table_info(users)').all();if(!cols.some(x=>x.name==='auth_token'))db.exec('ALTER TABLE users ADD COLUMN auth_token TEXT');}

app.set('trust proxy',1);

app.use(express.json({limit:'5mb'}));
app.use(session({secret:process.env.SESSION_SECRET||'chess-mastery-secret',resave:false,saveUninitialized:false,proxy:true,cookie:{httpOnly:true,sameSite:'lax',secure:true}}));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,
 chess_username TEXT DEFAULT '',contact TEXT DEFAULT '',
 role TEXT DEFAULT 'customer',created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS courses(
 id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,description TEXT DEFAULT '',
 price_cents INTEGER DEFAULT 0,free_chapters INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS chapters(
 id INTEGER PRIMARY KEY AUTOINCREMENT,course_id INTEGER,chapter_number INTEGER,
 title TEXT,pgn TEXT,start_fen TEXT DEFAULT 'start'
);
CREATE TABLE IF NOT EXISTS purchases(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,course_id INTEGER,
 paypal_order_id TEXT UNIQUE,amount_cents INTEGER,status TEXT DEFAULT 'pending',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS paypal_settings(
 id INTEGER PRIMARY KEY CHECK(id=1),client_id TEXT,client_secret TEXT,env TEXT DEFAULT 'sandbox'
);`);

const email=x=>String(x||'').trim().toLowerCase();
const hash=p=>{const s=crypto.randomBytes(16);return s.toString('hex')+':'+crypto.scryptSync(String(p),s,64).toString('hex')};
const verify=(p,x)=>{try{const [a,b]=String(x).split(':');return crypto.timingSafeEqual(crypto.scryptSync(String(p),Buffer.from(a,'hex'),64),Buffer.from(b,'hex'))}catch{return false}};
const pub=u=>u&&({id:u.id,name:u.name,email:u.email,chess_username:u.chess_username,contact:u.contact,role:u.role,created_at:u.created_at});
const current=req=>{if(req.session.userId){const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);if(u)return u;}const h=String(req.headers.authorization||'');if(h.startsWith('Bearer '))return db.prepare('SELECT * FROM users WHERE auth_token=?').get(h.slice(7));return null;};
const makeToken=()=>crypto.randomBytes(32).toString('hex');
const auth=(req,res,next)=>{if(!current(req))return res.status(401).json({error:'Please log in first'});next()};
const admin=(req,res,next)=>{const u=current(req);if(!u||u.role!=='admin')return res.status(403).json({error:'Admin only'});req.user=u;next()};

db.prepare("UPDATE users SET role='admin' WHERE email=?").run('topkatlop@gmail.com');
if(process.env.ADMIN_EMAIL&&process.env.ADMIN_PASSWORD){
 const e=email(process.env.ADMIN_EMAIL),u=db.prepare('SELECT id FROM users WHERE email=?').get(e);
 if(!u)db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')").run('Chess Mastery Admin',e,hash(process.env.ADMIN_PASSWORD));
 else db.prepare("UPDATE users SET role='admin' WHERE email=?").run(e);
}

function pgnTokens(pgn){
 return String(pgn||'')
 .replace(/\[[^\]]*\]/g,' ')
 .replace(/\{[^}]*\}/gs,' ')
 .replace(/;[^\n]*/g,' ')
 .replace(/\([^()]*\)/g,' ')
 .replace(/\$\d+/g,' ')
 .replace(/\b(1-0|0-1|1\/2-1\/2|\*)\b/g,' ')
 .split(/\s+/).filter(Boolean).filter(x=>!/^\d+\.(\.\.)?$/.test(x));
}
function splitPgn(pgn){
 const t=pgnTokens(pgn),out=[];
 for(let i=0,n=1;i<t.length;i+=40,n++)out.push({number:n,pgn:t.slice(i,i+40).join(' ')});
 return out;
}

app.get('/api/me',(req,res)=>res.json({user:pub(current(req))}));

app.post('/api/auth/register',(req,res)=>{
 const {name,email:e,password,chess_username='',contact=''}=req.body||{};
 if(!String(name||'').trim()||!e||String(password||'').length<8)return res.status(400).json({error:'Enter a name, email and password of at least 8 characters.'});
 try{
  const role=db.prepare('SELECT id FROM users LIMIT 1').get()?'customer':'admin';
  const token=makeToken();
  const id=db.prepare('INSERT INTO users(name,email,password_hash,chess_username,contact,role,auth_token) VALUES(?,?,?,?,?,?,?)')
   .run(String(name).trim(),email(e),hash(password),String(chess_username).trim(),String(contact).trim(),role,token).lastInsertRowid;
  req.session.userId=id;req.session.save(err=>{if(err)return res.status(500).json({error:'Could not save login session.'});res.json({user:pub(current(req)),token})});
 }catch{res.status(400).json({error:'This email is already registered.'})}
});
app.post('/api/auth/login',(req,res)=>{
 const u=db.prepare('SELECT * FROM users WHERE email=?').get(email(req.body?.email));
 if(!u||!verify(req.body?.password,u.password_hash))return res.status(401).json({error:'Invalid email or password.'});
 const token=makeToken();db.prepare('UPDATE users SET auth_token=? WHERE id=?').run(token,u.id);req.session.userId=u.id;req.session.save(err=>{if(err)return res.status(500).json({error:'Could not save login session.'});res.json({user:pub(u),token})});
});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.put('/api/profile',auth,(req,res)=>{
 const {name,chess_username='',contact=''}=req.body||{};
 if(!String(name||'').trim())return res.status(400).json({error:'Name is required.'});
 db.prepare('UPDATE users SET name=?,chess_username=?,contact=? WHERE id=?').run(String(name).trim(),String(chess_username).trim(),String(contact).trim(),req.session.userId);
 res.json({user:pub(current(req))});
});

app.get('/api/courses',(req,res)=>{
 const rows=db.prepare('SELECT * FROM courses ORDER BY id DESC').all().map(c=>({...c,chapter_count:db.prepare('SELECT COUNT(*) n FROM chapters WHERE course_id=?').get(c.id).n}));
 res.json(rows);
});
app.get('/api/courses/:id',(req,res)=>{
 const c=db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id);
 if(!c)return res.status(404).json({error:'Course not found'});
 const u=current(req);
 const paid=!!(u&&db.prepare("SELECT id FROM purchases WHERE user_id=? AND course_id=? AND status='completed'").get(u.id,c.id));
 const freeChapters=1;
 const chapters=db.prepare('SELECT id,chapter_number,title,pgn,start_fen FROM chapters WHERE course_id=? ORDER BY chapter_number').all(c.id)
 .map(ch=>({...ch,locked:!(u?.role==='admin'||paid||ch.chapter_number<=freeChapters),pgn:(u?.role==='admin'||paid||ch.chapter_number<=freeChapters)?ch.pgn:null}));
 res.json({...c,purchased:paid,chapters});
});

app.post('/api/admin/courses',admin,(req,res)=>{
 const {title,description='',price_cents=0,free_chapters=1,pgn=''}=req.body||{};
 if(!String(title||'').trim()||!String(pgn||'').trim())return res.status(400).json({error:'Course title and PGN are required.'});
 const parts=splitPgn(pgn);
 if(!parts.length)return res.status(400).json({error:'No chess moves were found in the PGN.'});
 const tx=db.transaction(()=>{
  const id=db.prepare('INSERT INTO courses(title,description,price_cents,free_chapters) VALUES(?,?,?,?)')
   .run(String(title).trim(),String(description).trim(),Math.max(0,Math.round(Number(price_cents)*100)),Math.max(0,Math.floor(Number(free_chapters)))).lastInsertRowid;
  const ins=db.prepare('INSERT INTO chapters(course_id,chapter_number,title,pgn) VALUES(?,?,?,?)');
  parts.forEach(x=>ins.run(id,x.number,'Chapter '+x.number,x.pgn));
  return id;
 });
 res.json({ok:true,id:tx(),chapters:parts.length});
});
app.delete('/api/admin/courses/:id',admin,(req,res)=>{db.prepare('DELETE FROM chapters WHERE course_id=?').run(req.params.id);db.prepare('DELETE FROM courses WHERE id=?').run(req.params.id);res.json({ok:true})});
app.get('/api/admin/users',admin,(req,res)=>res.json({
 users:db.prepare('SELECT id,name,email,chess_username,contact,role,created_at FROM users ORDER BY id DESC').all(),
 purchases:db.prepare('SELECT p.*,c.title FROM purchases p LEFT JOIN courses c ON c.id=p.course_id ORDER BY p.id DESC').all()
}));
app.post('/api/admin/users/:id/role',admin,(req,res)=>{
 const role=req.body?.role==='admin'?'admin':'customer';
 db.prepare('UPDATE users SET role=? WHERE id=?').run(role,req.params.id);
 res.json({ok:true,role});
});

app.get('/api/paypal/config',(req,res)=>{const p=db.prepare('SELECT client_id,env FROM paypal_settings WHERE id=1').get();res.json({configured:!!p?.client_id,client_id:p?.client_id||'',env:p?.env||'sandbox'});});
app.get('/api/admin/paypal',admin,(req,res)=>{
 const p=db.prepare('SELECT client_id,env FROM paypal_settings WHERE id=1').get();
 res.json({configured:!!p?.client_id,client_id:p?.client_id||'',env:p?.env||'sandbox'});
});
app.post('/api/admin/paypal',admin,(req,res)=>{
 const {client_id,client_secret,env='sandbox'}=req.body||{};
 if(!client_id||!client_secret)return res.status(400).json({error:'PayPal Client ID and Secret are required.'});
 if(!['sandbox','live'].includes(env))return res.status(400).json({error:'Invalid PayPal environment.'});
 db.prepare("INSERT INTO paypal_settings(id,client_id,client_secret,env) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET client_id=excluded.client_id,client_secret=excluded.client_secret,env=excluded.env").run(String(client_id).trim(),String(client_secret).trim(),env);
 res.json({ok:true});
});

async function paypalToken(){
 const p=db.prepare('SELECT * FROM paypal_settings WHERE id=1').get();
 const client=p?.client_id||process.env.PAYPAL_CLIENT_ID,secret=p?.client_secret||process.env.PAYPAL_CLIENT_SECRET,env=p?.env||process.env.PAYPAL_ENV||'sandbox';
 if(!client||!secret)throw Error('PayPal is not configured by the admin.');
 const base=env==='live'?'https://api-m.paypal.com':'https://api-m.sandbox.paypal.com';
 const r=await fetch(base+'/v1/oauth2/token',{method:'POST',headers:{Authorization:'Basic '+Buffer.from(client+':'+secret).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type=client_credentials'});
 const j=await r.json();if(!r.ok)throw Error('PayPal authentication failed.');
 return {base,token:j.access_token};
}
app.post('/api/paypal/create-order',auth,async(req,res)=>{
 try{
  const c=db.prepare('SELECT * FROM courses WHERE id=?').get(req.body?.course_id);
  if(!c||c.price_cents<=0)return res.status(400).json({error:'This course is free.'});
  const {base,token}=await paypalToken();
  const r=await fetch(base+'/v2/checkout/orders',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({intent:'CAPTURE',purchase_units:[{reference_id:String(c.id),description:c.title,amount:{currency_code:'USD',value:(c.price_cents/100).toFixed(2)}}]})});
  const j=await r.json();if(!r.ok)throw Error(j.message||'Could not create PayPal order.');
  db.prepare('INSERT INTO purchases(user_id,course_id,paypal_order_id,amount_cents,status) VALUES(?,?,?,?,?)').run(req.session.userId,c.id,j.id,c.price_cents,'pending');
  res.json({id:j.id});
 }catch(e){res.status(500).json({error:e.message})}
});
app.post('/api/paypal/capture-order',auth,async(req,res)=>{
 try{
  const p=db.prepare('SELECT * FROM purchases WHERE paypal_order_id=? AND user_id=?').get(req.body?.order_id,req.session.userId);
  if(!p)return res.status(404).json({error:'Purchase not found.'});
  const {base,token}=await paypalToken();
  const r=await fetch(base+'/v2/checkout/orders/'+encodeURIComponent(p.paypal_order_id)+'/capture',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:'{}'});
  const j=await r.json();if(!r.ok)throw Error(j.message||'Payment capture failed.');
  const ok=j.status==='COMPLETED';db.prepare('UPDATE purchases SET status=? WHERE id=?').run(ok?'completed':'failed',p.id);
  res.json({ok,status:j.status});
 }catch(e){res.status(500).json({error:e.message})}
});

app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log('Chess Mastery running on port '+PORT));