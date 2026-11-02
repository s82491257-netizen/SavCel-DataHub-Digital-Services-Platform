require('dotenv').config();
const express=require('express');
const {Pool}=require('pg');
const cors=require('cors');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const axios=require('axios');
const path=require('path');
const app=express();
const PORT=process.env.PORT||10000;
app.use(cors()); app.use(express.json()); app.use(express.static(__dirname));
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false}});
pool.connect().then(()=>console.log("DB Connected")).catch(e=>console.log("DB error",e.message));
const JWT=process.env.JWT_SECRET||'SAVCEL_PURPLE_2024';
const sign=p=>jwt.sign(p,JWT,{expiresIn:'7d'});
const auth=(req,res,next)=>{const h=req.headers.authorization; if(!h) return res.status(401).json({error:'Login needed'}); try{req.user=jwt.verify(h.split(' ')[1],JWT); next();}catch{return res.status(401).json({error:'Invalid token'});}};
const adminOnly=(req,res,next)=>{if(req.user.role!=='admin') return res.status(403).json({error:'Admin only'}); next();};

async function init(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name VARCHAR(100), email VARCHAR(100) UNIQUE, phone VARCHAR(20), password VARCHAR(200), role VARCHAR(20) DEFAULT 'user', balance DECIMAL(10,2) DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS admins (id SERIAL PRIMARY KEY, email VARCHAR(100) UNIQUE, password VARCHAR(200));
 CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name VARCHAR(150), category VARCHAR(50), network VARCHAR(50), size_gb VARCHAR(50), price_ghs DECIMAL(10,2), cost_price DECIMAL(10,2), description TEXT, available BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS orders (id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id), product_id INT REFERENCES products(id), product_name VARCHAR(150), category VARCHAR(50), phone_number VARCHAR(50), quantity INT DEFAULT 1, amount_ghs DECIMAL(10,2), status VARCHAR(20) DEFAULT 'pending', paystack_ref VARCHAR(100) UNIQUE, result TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS payments (id SERIAL PRIMARY KEY, order_id INT REFERENCES orders(id), user_id INT, reference VARCHAR(100) UNIQUE, amount_ghs DECIMAL(10,2), status VARCHAR(20) DEFAULT 'pending', verified_at TIMESTAMP);
 CREATE TABLE IF NOT EXISTS agents (id SERIAL PRIMARY KEY, user_id INT UNIQUE REFERENCES users(id), commission_rate DECIMAL(5,2) DEFAULT 5.00, total_earnings DECIMAL(10,2) DEFAULT 0, status VARCHAR(20) DEFAULT 'approved');
 `);
 const a=await pool.query("SELECT * FROM admins WHERE email='admin@savcel.com'");
 if(a.rows.length===0){const h=await bcrypt.hash('Admin@123',10); await pool.query("INSERT INTO admins (email,password) VALUES ($1,$2)",['admin@savcel.com',h]);}
 const p=await pool.query("SELECT COUNT(*) FROM products");
 if(p.rows[0].count==0){
  await pool.query(`INSERT INTO products (name,category,network,size_gb,price_ghs,cost_price,description) VALUES 
  ('MTN 1GB','data','MTN','1GB',6.00,5.00,'MTN Data - Instant'),
  ('MTN 5GB','data','MTN','5GB',27.00,25.00,'MTN Data - 5GB'),
  ('Telecel 10GB','data','Telecel','10GB',45.00,42.00,'Telecel Data Bundle'),
  ('AT iShare 5GB','data','AT','5GB',26.00,24.00,'AT iShare Data'),
  ('WAEC Checker','waec','WAEC','1 PIN',16.00,14.00,'WAEC Results Checker PIN - Instant'),
  ('BECE Checker','bece','BECE','1 PIN',16.00,14.00,'BECE Placement Checker'),
  ('ChatGPT Plus 1 Month','ai_tool','AI','1 Month',120.00,100.00,'AI Tools Subscription'),
  ('Canva Pro 1 Month','ai_tool','AI','1 Month',35.00,30.00,'Canva Pro Account')
  `);
 }
}
init();

// PUBLIC
app.get('/api/paystack/key',(req,res)=>res.json({publicKey:process.env.PAYSTACK_PUBLIC_KEY||''}));
app.get('/api/products',async(req,res)=>{
 let q="SELECT * FROM products WHERE available=true"; let params=[]; let i=1;
 if(req.query.category){q+=` AND category=$${i++}`; params.push(req.query.category);}
 if(req.query.network){q+=` AND network=$${i++}`; params.push(req.query.network);}
 q+=" ORDER BY price_ghs ASC";
 const r=await pool.query(q,params); res.json(r.rows);
});
app.get('/api/categories',(req,res)=>res.json(['data','waec','bece','ai_tool']));

// AUTH
app.post('/api/register',async(req,res)=>{
 const {name,email,phone,password}=req.body; if(!name||!email||!password) return res.status(400).json({error:'All fields required'});
 try{
  const ex=await pool.query("SELECT id FROM users WHERE email=$1",[email.toLowerCase()]);
  if(ex.rows.length>0) return res.status(400).json({error:'Email exists'});
  const h=await bcrypt.hash(password,10);
  const r=await pool.query("INSERT INTO users (name,email,phone,password) VALUES ($1,$2,$3,$4) RETURNING id,name,email",[name,email.toLowerCase(),phone||'',h]);
  const token=sign({id:r.rows[0].id,email:r.rows[0].email,role:'user'}); res.json({token,user:r.rows[0]});
 }catch(e){res.status(500).json({error:e.message});}
});
app.post('/api/login',async(req,res)=>{
 const {email,password}=req.body;
 const r=await pool.query("SELECT * FROM users WHERE email=$1",[email.toLowerCase()]);
 if(!r.rows.length) return res.status(400).json({error:'Invalid login'});
 const ok=await bcrypt.compare(password,r.rows[0].password); if(!ok) return res.status(400).json({error:'Invalid login'});
 const token=sign({id:r.rows[0].id,email:r.rows[0].email,role:'user'}); res.json({token,user:{id:r.rows[0].id,name:r.rows[0].name,email:r.rows[0].email}});
});
app.post('/api/admin/login',async(req,res)=>{
 const {email,password}=req.body; const r=await pool.query("SELECT * FROM admins WHERE email=$1",[email.toLowerCase()]);
 if(!r.rows.length) return res.status(400).json({error:'Invalid admin'}); const ok=await bcrypt.compare(password,r.rows[0].password); if(!ok) return res.status(400).json({error:'Invalid admin'});
 const token=sign({id:r.rows[0].id,email:r.rows[0].email,role:'admin'}); res.json({token});
});
app.post('/api/agent/apply',auth,async(req,res)=>{
 try{ await pool.query("INSERT INTO agents (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING",[req.user.id]); res.json({message:'Agent application received - Approved'});}catch(e){res.status(500).json({error:e.message});}
});

// ORDERS
app.post('/api/orders',auth,async(req,res)=>{
 const {product_id,phone_number,quantity}=req.body;
 try{
  const prod=await pool.query("SELECT * FROM products WHERE id=$1 AND available=true",[product_id]);
  if(!prod.rows.length) return res.status(404).json({error:'Product not available'});
  const p=prod.rows[0]; const qty=quantity||1; const amount=Number(p.price_ghs)*qty;
  const ref='SAVCEL_'+Date.now()+'_'+Math.floor(Math.random()*1000);
  const order=await pool.query("INSERT INTO orders (user_id,product_id,product_name,category,phone_number,quantity,amount_ghs,status,paystack_ref) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8) RETURNING *",[req.user.id,p.id,p.name,p.category,phone_number||'',qty,amount,ref]);
  await pool.query("INSERT INTO payments (order_id,user_id,reference,amount_ghs) VALUES ($1,$2,$3,$4)",[order.rows[0].id,req.user.id,ref,amount]);
  res.json({order:order.rows[0],reference:ref,amount});
 }catch(e){res.status(500).json({error:e.message});}
});
app.post('/api/paystack/verify',auth,async(req,res)=>{
 const {reference}=req.body; const secret=process.env.PAYSTACK_SECRET_KEY; if(!secret) return res.status(500).json({error:'Paystack not configured'});
 try{
  const ps=await axios.get(`https://api.paystack.co/transaction/verify/${reference}`,{headers:{Authorization:`Bearer ${secret}`}});
  if(ps.data.data.status!=='success'){ await pool.query("UPDATE payments SET status='failed' WHERE reference=$1",[reference]); await pool.query("UPDATE orders SET status='failed' WHERE paystack_ref=$1",[reference]); return res.status(400).json({error:'Payment not successful'});}
  await pool.query("UPDATE payments SET status='success', verified_at=NOW() WHERE reference=$1",[reference]);
  const ord=await pool.query("UPDATE orders SET status='completed', result=$1 WHERE paystack_ref=$2 RETURNING *",['Delivered - Check SMS / Email',reference]);
  // agent commission
  const ag=await pool.query("SELECT * FROM agents WHERE user_id=$1",[req.user.id]); 
  if(ag.rows.length>0){ const earn=Number(ord.rows[0].amount_ghs)*(Number(ag.rows[0].commission_rate)/100); await pool.query("UPDATE agents SET total_earnings=total_earnings+$1 WHERE user_id=$2",[earn,req.user.id]);}
  res.json({message:'Payment verified & delivered',order:ord.rows[0]});
 }catch(e){res.status(500).json({error:'Verify failed',details:e.response?.data||e.message});}
});
app.get('/api/my/orders',auth,async(req,res)=>{const r=await pool.query("SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC",[req.user.id]); res.json(r.rows);});
app.get('/api/my/agent',auth,async(req,res)=>{const r=await pool.query("SELECT * FROM agents WHERE user_id=$1",[req.user.id]); res.json(r.rows[0]||null);});

// ADMIN
app.get('/api/admin/stats',auth,adminOnly,async(req,res)=>{
 const u=await pool.query("SELECT COUNT(*) FROM users"); const pr=await pool.query("SELECT COUNT(*) FROM products");
 const o=await pool.query("SELECT COUNT(*) FROM orders WHERE status='completed'"); const rev=await pool.query("SELECT COALESCE(SUM(amount_ghs),0) as total FROM orders WHERE status='completed'");
 res.json({users:u.rows[0].count,products:pr.rows[0].count,orders:o.rows[0].count,revenue:rev.rows[0].total});
});
app.get('/api/admin/products',auth,adminOnly,async(req,res)=>{const r=await pool.query("SELECT * FROM products ORDER BY id DESC"); res.json(r.rows);});
app.post('/api/admin/products',auth,adminOnly,async(req,res)=>{
 const {name,category,network,size_gb,price_ghs,cost_price,description}=req.body;
 const r=await pool.query("INSERT INTO products (name,category,network,size_gb,price_ghs,cost_price,description) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *",[name,category,network,size_gb,price_ghs,cost_price,description]); res.json(r.rows[0]);
});
app.delete('/api/admin/products/:id',auth,adminOnly,async(req,res)=>{await pool.query("DELETE FROM products WHERE id=$1",[req.params.id]); res.json({ok:true});});
app.get('/api/admin/orders',auth,adminOnly,async(req,res)=>{const r=await pool.query("SELECT o.*, u.email as user_email FROM orders o LEFT JOIN users u ON o.user_id=u.id ORDER BY o.created_at DESC"); res.json(r.rows);});
app.get('/api/admin/users',auth,adminOnly,async(req,res)=>{const r=await pool.query("SELECT id,name,email,phone,created_at FROM users ORDER BY id DESC"); res.json(r.rows);});
app.get('/api/admin/agents',auth,adminOnly,async(req,res)=>{const r=await pool.query("SELECT a.*, u.name, u.email FROM agents a JOIN users u ON a.user_id=u.id"); res.json(r.rows);});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.listen(PORT,()=>console.log('SavCel DataHub running on '+PORT));