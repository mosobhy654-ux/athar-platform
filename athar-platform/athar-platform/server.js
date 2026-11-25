'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-this-admin-key';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const STORAGE_DIR = path.resolve(process.env.STORAGE_DIR || path.join(__dirname, 'storage'));
const UPLOAD_DIR = path.join(STORAGE_DIR, 'uploads');
const DB_FILE = path.join(STORAGE_DIR, 'data.json');
const BACKUP_DIR = path.join(STORAGE_DIR, 'backups');
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY = 25 * 1024 * 1024;
const MAX_FILE = 8 * 1024 * 1024;
const ALLOWED_IMAGE = new Set(['.png', '.jpg', '.jpeg', '.webp']);
const ALLOWED_DOC = new Set(['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.txt', '.zip', '.ino', '.py', '.js', '.html', '.css', '.json', '.md', '.csv']);
const BLOCKED = new Set(['.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.ps1', '.sh', '.dll', '.jar', '.apk', '.app']);
const MIME = {
  '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8',
  '.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg',
  '.webp':'image/webp','.pdf':'application/pdf','.txt':'text/plain; charset=utf-8','.csv':'text/csv; charset=utf-8',
  '.svg':'image/svg+xml','.ico':'image/x-icon'
};

for (const d of [STORAGE_DIR, UPLOAD_DIR, BACKUP_DIR]) fs.mkdirSync(d, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ projects: [], inquiries: [], surveys: [], officers: [{id:'staff-1',name:'Faculty Officer',title:'Dr.',department:'Administration'}] }, null, 2));

let db = readDb();
const rate = new Map();

function readDb() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { projects: [], inquiries: [], surveys: [], officers: [] }; }
}
function saveDb() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
function backupDb() {
  try {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    fs.copyFileSync(DB_FILE, path.join(BACKUP_DIR, `data-${stamp}.json`));
    const backups = fs.readdirSync(BACKUP_DIR).filter(x => x.endsWith('.json')).sort();
    while (backups.length > 20) fs.unlinkSync(path.join(BACKUP_DIR, backups.shift()));
  } catch (e) { console.error('Backup error:', e.message); }
}
setInterval(backupDb, 24 * 60 * 60 * 1000).unref();

function send(res, status, data, headers={}) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': typeof data === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'strict-origin-when-cross-origin',
    'X-Frame-Options':'DENY', 'Content-Security-Policy':"default-src 'self' https: data:; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; connect-src 'self';",
    ...headers });
  res.end(body);
}
function fail(res, status, message) { send(res, status, { error: message }); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0, chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(new Error('حجم الطلب أكبر من المسموح')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch { reject(new Error('صيغة البيانات غير صحيحة')); }
    });
    req.on('error', reject);
  });
}
function clean(v, max=5000) { return String(v ?? '').trim().slice(0, max); }
function id() { return crypto.randomUUID(); }
function hash(v) { return crypto.createHash('sha256').update(v).digest('hex'); }
function privateProject(p) {
  const { editKeyHash, email, age, gender, ...safe } = p;
  return safe;
}
function admin(req) {
  const key = req.headers['x-admin-key'] || '';
  return key.length > 0 && crypto.timingSafeEqual(Buffer.from(hash(key)), Buffer.from(hash(ADMIN_KEY)));
}
function owner(req, p) {
  const key = req.headers['x-edit-key'] || '';
  return !!key && !!p && hash(key) === p.editKeyHash;
}
function rateLimit(req, res, limit=60) {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now(), arr = (rate.get(ip) || []).filter(t => now - t < 60000);
  if (arr.length >= limit) { fail(res, 429, 'طلبات كثيرة. حاول مرة أخرى بعد دقيقة.'); return false; }
  arr.push(now); rate.set(ip, arr); return true;
}
function validateProject(body) {
  const required = ['name','team','year','dept','problem','desc','email'];
  for (const k of required) if (!clean(body[k], 5000)) return `الحقل مطلوب: ${k}`;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean(body.email, 200))) return 'البريد الإلكتروني غير صحيح';
  if (![1,2,3,4].includes(Number(body.year))) return 'الفرقة يجب أن تكون من 1 إلى 4';
  if (clean(body.name).length < 3) return 'اسم المشروع قصير جداً';
  if (Array.isArray(body.files) && body.files.length > 12) return 'الحد الأقصى 12 ملفاً';
  for (const f of (body.files || [])) {
    if (!f || typeof f.data !== 'string' || !f.name) return 'بيانات ملف غير صحيحة';
    const ext = path.extname(f.name).toLowerCase();
    if (BLOCKED.has(ext)) return `نوع الملف غير مسموح: ${ext}`;
    if (!(ALLOWED_IMAGE.has(ext) || ALLOWED_DOC.has(ext))) return `نوع الملف غير مدعوم: ${ext}`;
    const raw = f.data.replace(/^data:[^;]+;base64,/, '');
    if (Buffer.from(raw, 'base64').length > MAX_FILE) return 'حجم الملف يتجاوز 8MB';
  }
  return null;
}
function saveFiles(files, projectId) {
  const saved = [];
  for (const f of (files || [])) {
    const ext = path.extname(f.name).toLowerCase();
    const raw = f.data.replace(/^data:[^;]+;base64,/, '');
    const buf = Buffer.from(raw, 'base64');
    const filename = `${projectId}-${crypto.randomBytes(5).toString('hex')}${ext}`;
    fs.writeFileSync(path.join(UPLOAD_DIR, filename), buf);
    saved.push({ name: clean(f.name, 180), stored: filename, kind: f.kind === 'code' ? 'code' : (ALLOWED_IMAGE.has(ext) ? 'image' : 'file'), size: buf.length });
  }
  return saved;
}
function publicProject(p) {
  const x = privateProject(p);
  return { ...x, files: (x.files || []).map(f => ({ name:f.name, kind:f.kind, size:f.size, url:`/uploads/${encodeURIComponent(f.stored)}` })) };
}
async function route(req, res) {
  const url = new URL(req.url, BASE_URL);
  const pathname = decodeURIComponent(url.pathname);
  if (req.method === 'GET' && pathname === '/health') return send(res, 200, { status:'ok', service:'Athar', time:new Date().toISOString() });
  if (req.method === 'GET' && pathname === '/api/staff') return send(res, 200, db.officers || []);
  if (req.method === 'GET' && pathname === '/api/projects') {
    const q = clean(url.searchParams.get('q'), 200).toLowerCase();
    const dept = clean(url.searchParams.get('dept'), 100);
    const year = clean(url.searchParams.get('year'), 10);
    const need = clean(url.searchParams.get('need'), 100);
    let items = db.projects.filter(p => p.status === 'approved');
    if (q) items = items.filter(p => [p.name,p.problem,p.desc,p.team,p.dept].join(' ').toLowerCase().includes(q));
    if (dept) items = items.filter(p => p.dept === dept);
    if (year) items = items.filter(p => String(p.year) === year);
    if (need) items = items.filter(p => (p.seeking || []).includes(need));
    items.sort((a,b) => Number(b.featured)-Number(a.featured) || new Date(b.created)-new Date(a.created));
    return send(res, 200, items.map(publicProject));
  }
  if (req.method === 'GET' && pathname.startsWith('/api/projects/')) {
    const pid = pathname.split('/').pop();
    const p = db.projects.find(x => x.id === pid && x.status === 'approved');
    if (!p) return fail(res, 404, 'المشروع غير موجود أو لم تتم الموافقة عليه');
    p.views = (p.views || 0) + 1; saveDb();
    return send(res, 200, publicProject(p));
  }
  if (req.method === 'POST' && pathname === '/api/projects') {
    if (!rateLimit(req,res,12)) return;
    const b = await readBody(req);
    const err = validateProject(b); if (err) return fail(res, 400, err);
    const pid = id(), editKey = crypto.randomBytes(24).toString('hex');
    const files = saveFiles(b.files || [], pid);
    const p = {
      id:pid,status:'pending',created:new Date().toISOString(),
      name:clean(b.name,180),team:clean(b.team,180),members:clean(b.members,1000),skills:clean(b.skills,1000),
      year:Number(b.year),dept:clean(b.dept,100),section:clean(b.section,50),email:clean(b.email,200),
      age:clean(b.age,10),gender:clean(b.gender,30),problem:clean(b.problem,3000),desc:clean(b.desc,5000),
      field:clean(b.field,300),audience:clean(b.audience,500),cost:clean(b.cost,200),stage:clean(b.stage,50),
      ask:clean(b.ask,500),useFunds:clean(b.useFunds,1000),model:clean(b.model,1000),
      obstacles:clean(b.obstacles,2000),solutions:clean(b.solutions,2000),
      github:clean(b.github,500),demo:clean(b.demo,500),video:clean(b.video,500),linkedin:clean(b.linkedin,500),
      links:clean(b.links,2000),photo:clean(b.photo,500),files,seeking:Array.isArray(b.seeking)?b.seeking.map(x=>clean(x,80)).slice(0,8):[],
      views:0,likes:0,featured:false,approvedBy:'',editKeyHash:hash(editKey)
    };
    db.projects.push(p); saveDb();
    return send(res, 201, { message:'تم استلام المشروع وهو الآن قيد المراجعة', id:pid, editKey, editUrl:`${BASE_URL}/?edit=${pid}&key=${editKey}`, status:'pending' });
  }
  if (pathname.startsWith('/api/projects/') && req.method === 'PUT') {
    const pid = pathname.split('/').pop(), p = db.projects.find(x=>x.id===pid);
    if (!p) return fail(res,404,'المشروع غير موجود');
    if (!owner(req,p)) return fail(res,403,'رابط التعديل غير صالح');
    const b = await readBody(req), err = validateProject({...p,...b, files:b.files || []});
    if (err) return fail(res,400,err);
    Object.assign(p, {
      name:clean(b.name,180),team:clean(b.team,180),members:clean(b.members,1000),skills:clean(b.skills,1000),
      year:Number(b.year),dept:clean(b.dept,100),section:clean(b.section,50),email:clean(b.email,200),
      problem:clean(b.problem,3000),desc:clean(b.desc,5000),field:clean(b.field,300),audience:clean(b.audience,500),
      cost:clean(b.cost,200),stage:clean(b.stage,50),ask:clean(b.ask,500),useFunds:clean(b.useFunds,1000),
      model:clean(b.model,1000),obstacles:clean(b.obstacles,2000),solutions:clean(b.solutions,2000),
      github:clean(b.github,500),demo:clean(b.demo,500),video:clean(b.video,500),linkedin:clean(b.linkedin,500),
      links:clean(b.links,2000),seeking:Array.isArray(b.seeking)?b.seeking:[],status:'pending',approvedBy:''
    });
    if (Array.isArray(b.files) && b.files.length) p.files = [...(p.files||[]), ...saveFiles(b.files,pid)];
    saveDb(); return send(res,200,{message:'تم حفظ التعديلات وإعادة المشروع للمراجعة',status:p.status});
  }
  if (pathname.startsWith('/api/projects/') && req.method === 'DELETE') {
    const pid = pathname.split('/').pop(), p = db.projects.find(x=>x.id===pid);
    if (!p) return fail(res,404,'المشروع غير موجود');
    if (!owner(req,p)) return fail(res,403,'رابط التعديل غير صالح');
    db.projects = db.projects.filter(x=>x.id!==pid); saveDb(); return send(res,200,{message:'تم حذف المشروع'});
  }
  if (req.method === 'POST' && pathname === '/api/react') {
    const b = await readBody(req), p = db.projects.find(x=>x.id===clean(b.id) && x.status==='approved');
    if (!p) return fail(res,404,'المشروع غير موجود');
    if (b.type==='like') p.likes=(p.likes||0)+1;
    saveDb(); return send(res,200,{views:p.views||0,likes:p.likes||0});
  }
  if (req.method === 'POST' && pathname === '/api/inquiries') {
    if (!rateLimit(req,res,10)) return;
    const b = await readBody(req);
    if (!clean(b.projectId) || !clean(b.message,3000)) return fail(res,400,'اختر مشروعاً واكتب الرسالة');
    const p = db.projects.find(x=>x.id===b.projectId && x.status==='approved');
    if (!p) return fail(res,404,'المشروع غير موجود');
    const inquiry={id:id(),projectId:p.id,projectName:p.name,name:clean(b.name,150),company:clean(b.company,180),email:clean(b.email,200),message:clean(b.message,3000),created:new Date().toISOString()};
    db.inquiries.push(inquiry); saveDb(); return send(res,201,{message:'تم إرسال رسالتك إلى إدارة المنصة'});
  }
  if (req.method === 'POST' && pathname === '/api/survey') {
    if (!rateLimit(req,res,8)) return;
    const b=await readBody(req);
    const answers=b.answers && typeof b.answers==='object' ? b.answers : {};
    if (Object.keys(answers).length < 5) return fail(res,400,'أجب عن الأسئلة الخمسة على الأقل');
    db.surveys.push({id:id(),answers,created:new Date().toISOString()}); saveDb();
    return send(res,201,{message:'شكراً لمشاركتك. تم تسجيل إجابتك بشكل مجهول.'});
  }
  if (pathname.startsWith('/api/admin/')) {
    if (!admin(req)) return fail(res,401,'مفتاح الإدارة غير صحيح');
    if (req.method==='GET' && pathname==='/api/admin/projects') return send(res,200,db.projects.map(p=>({...p,editKeyHash:undefined})));
    if (req.method==='POST' && pathname==='/api/admin/review') {
      const b=await readBody(req), p=db.projects.find(x=>x.id===b.id);
      if (!p) return fail(res,404,'المشروع غير موجود');
      p.status=b.action==='approve'?'approved':'rejected'; p.featured=!!b.featured;
      p.approvedBy=clean(b.approvedBy,150); saveDb(); return send(res,200,{message:'تم تحديث حالة المشروع'});
    }
    if (req.method==='GET' && pathname==='/api/admin/inquiries') return send(res,200,db.inquiries);
    if (req.method==='GET' && pathname==='/api/admin/survey') {
      const counts={}; for(let i=1;i<=12;i++) counts[i]={yes:0,maybe:0,no:0};
      for(const s of db.surveys) for(const [k,v] of Object.entries(s.answers)) if(counts[k] && counts[k][v]!==undefined) counts[k][v]++;
      return send(res,200,{total:db.surveys.length,counts});
    }
    if (req.method==='GET' && pathname==='/api/admin/officers') return send(res,200,db.officers||[]);
    if (req.method==='POST' && pathname==='/api/admin/officers') {
      const b=await readBody(req); if(!clean(b.name)) return fail(res,400,'اسم المسؤول مطلوب');
      db.officers.push({id:id(),name:clean(b.name,150),title:clean(b.title,30),department:clean(b.department,100)});
      saveDb(); return send(res,201,{message:'تمت إضافة المسؤول'});
    }
    if (req.method==='GET' && pathname==='/api/admin/export.csv') {
      const rows=[['id','name','team','year','department','status','created','problem','cost','email']];
      for(const p of db.projects) rows.push([p.id,p.name,p.team,p.year,p.dept,p.status,p.created,p.problem,p.cost,p.email]);
      const csv=rows.map(r=>r.map(v=>`"${String(v??'').replace(/"/g,'""')}"`).join(',')).join('\r\n');
      return send(res,200,csv,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="athar-projects.csv"'});
    }
  }
  if (req.method==='GET' && pathname.startsWith('/uploads/')) {
    const filename=path.basename(pathname.slice('/uploads/'.length));
    const file=path.join(UPLOAD_DIR,filename);
    if(!fs.existsSync(file)) return fail(res,404,'الملف غير موجود');
    const ext=path.extname(file).toLowerCase();
    if(BLOCKED.has(ext)) return fail(res,403,'هذا النوع من الملفات غير مسموح');
    res.writeHead(200,{'Content-Type':MIME[ext]||'application/octet-stream','Content-Disposition':`attachment; filename*=UTF-8''${encodeURIComponent(filename)}`,'X-Content-Type-Options':'nosniff'});
    return fs.createReadStream(file).pipe(res);
  }
  if (req.method==='GET' && pathname==='/sitemap.xml') {
    const urls=db.projects.filter(p=>p.status==='approved').map(p=>`<url><loc>${BASE_URL}/p/${p.id}</loc></url>`).join('');
    res.writeHead(200,{'Content-Type':'application/xml; charset=utf-8'}); return res.end(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`);
  }
  if (req.method==='GET' && pathname.startsWith('/p/')) {
    const pid=pathname.split('/').pop(), p=db.projects.find(x=>x.id===pid&&x.status==='approved');
    if(!p) return fail(res,404,'المشروع غير موجود');
    const html=`<!doctype html><html><head><meta charset="utf-8"><meta property="og:title" content="${escapeHtml(p.name)} - Athar"><meta property="og:description" content="${escapeHtml(p.problem)}"><meta property="og:type" content="website"><meta property="og:url" content="${BASE_URL}/p/${p.id}"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(p.name)} - Athar</title></head><body><h1>${escapeHtml(p.name)}</h1><p>${escapeHtml(p.problem)}</p><a href="/?project=${p.id}">Open on Athar</a></body></html>`;
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'}); return res.end(html);
  }
  if (req.method==='GET') {
    const rel=pathname==='/'?'index.html':pathname.replace(/^\/+/,'');
    const file=path.resolve(PUBLIC_DIR,rel);
    if(!file.startsWith(PUBLIC_DIR+path.sep) && file!==path.join(PUBLIC_DIR,'index.html')) return fail(res,403,'Forbidden');
    if(!fs.existsSync(file) || !fs.statSync(file).isFile()) return fail(res,404,'Not found');
    const ext=path.extname(file).toLowerCase();
    res.writeHead(200,{'Content-Type':MIME[ext]||'application/octet-stream','Cache-Control':'no-cache'});
    return fs.createReadStream(file).pipe(res);
  }
  fail(res,404,'Not found');
}
function escapeHtml(s) { return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

const server=http.createServer((req,res)=>{ route(req,res).catch(e=>{console.error(e); if(!res.headersSent) fail(res,500,e.message||'حدث خطأ داخلي'); else res.destroy(); }); });
server.listen(PORT,()=>console.log(`Athar running at ${BASE_URL} (port ${PORT})`));
