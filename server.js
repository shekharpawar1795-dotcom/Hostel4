import express from 'express';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import {
  db,
  CATEGORIES,
  PRIORITIES,
  ROLES,
  OPEN_STATES,
  hashPassword,
  verifyPassword,
  generateId,
  generateToken, hashToken, requestContext,
  setFallbackDb
} from './data.js';
import { loadState, saveState, WriteConflict, stageEvidence, readEvidence } from './store.js';
import {looksLikeImage} from './evidence.js';
import { hostelIds, scoped, canView, event, notify, beginCycle, cycleFor, reopen, processDue, hasEscalation, validActionTransition, parseCsv, canStudentReopen } from './rules.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
if(!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length<32) throw new Error('Run npm run setup first: SESSION_SECRET is missing or too short.');
app.set('trust proxy', 1);
const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);

const upload = multer({ storage:multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 3, fields: 35, parts: 45 } });

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static assets
app.use('/static', express.static(path.join(__dirname, 'public')));

// Middlewares
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.json());
app.use(cookieParser());

// Security headers. Do not allow embedding the authenticated interface in third-party iframes.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'; object-src 'none'; base-uri 'self'");
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// Each request reads a fresh, durable snapshot. POSTs are committed using an atomic
// version check. Concurrent conflicting writes return 409 rather than losing data.
app.use(async (req,res,next)=>{
 try {
  const state=await loadState();
  if (state && state.db) setFallbackDb(state.db);
  requestContext.run(state,()=>{
   if(req.method!=='GET' && req.method!=='HEAD'){
    const end=res.end.bind(res);let ending=false;
    res.end=function(...args){
     if(ending)return;ending=true;
     (state.abort?Promise.resolve():saveState(state.version,state.db)).then(()=>end(...args)).catch(error=>{
      console.error('Persistence failed:',error);
      if(!res.headersSent){res.statusCode=error instanceof WriteConflict?409:503;res.removeHeader('Location');res.removeHeader('Content-Length');res.setHeader('Content-Type','text/plain; charset=utf-8');}
      end('Unable to save. '+(error instanceof WriteConflict?'Another user saved first. Refresh and retry.':'Database unavailable. Retry later.'));
     });
    };
   }
   next();
  });
 }catch(error){
  console.error('[HostelCare] SQLite state load failed:',error);
  res.status(503).send('Database unavailable. Please try again later.');
 }
});

// Helper formatting functions
function formatDate(d) {
  if (!d) return '';
  const date = new Date(d);
  return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

function formatDateTime(d) {
  if (!d) return '';
  const date = new Date(d);
  return date.toLocaleDateString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  });
}

function titleCase(str) {
  if (!str) return '';
  return str
    .toLowerCase()
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

// User & Session resolver
app.use((req, res, next) => {
  const sessionToken = req.cookies.hcms_session;
  let currentUser = null;

  if (sessionToken) {
    const session = db.sessions.get(hashToken(sessionToken));
    if (session && !session.revoked_at && new Date(session.expires_at) > new Date()) {
      const user = db.users.get(session.user_id);
      if (user && user.active) {
        currentUser = user;
      }
    }
  }

  req.user = currentUser;
  res.locals.user = currentUser;

  let unreadCount = 0;
  if (currentUser) {
    unreadCount = Array.from(db.notifications.values()).filter(
      n => n.recipient_id === currentUser.id && !n.read_at
    ).length;
  }
  res.locals.unread_count = unreadCount;

  // Double-submit CSRF for login and session-bound HMAC for signed-in users.
  const isHttps = Boolean(req.secure || req.headers['x-forwarded-proto'] === 'https');
  let loginCsrf=req.cookies.hcms_login_csrf;
  if(!loginCsrf){
    loginCsrf=generateToken();
    res.cookie('hcms_login_csrf',loginCsrf,{
      httpOnly:true,
      sameSite: 'lax',
      secure: isHttps,
      path:'/'
    });
  }
  const secret=process.env.SESSION_SECRET;
  if (!secret || secret.length<32) throw new Error('SESSION_SECRET must contain at least 32 characters. Set it in your .env file.');
  res.locals.csrf=currentUser && sessionToken ? crypto.createHmac('sha256',secret).update(sessionToken).digest('hex') : loginCsrf;
  res.locals.msg = typeof req.query.msg==='string'?req.query.msg.slice(0,300):null;
  res.locals.kind = req.query.kind === 'error'?'error':'success';

  // Template utilities
  res.locals.formatDate = formatDate;
  res.locals.formatDateTime = formatDateTime;
  res.locals.titleCase = titleCase;
  res.locals.categories = CATEGORIES;
  res.locals.priorities = PRIORITIES;
  res.locals.roles = ROLES;

  next();
});

// All browser mutations require CSRF. Multipart routes verify after multer parses the body.
const validCsrf=(req,res)=>{
 const supplied=String(req.body?.csrf_token||'');
 const expected=res.locals.csrf||'';
 return supplied.length>10&&supplied.length===expected.length&&crypto.timingSafeEqual(Buffer.from(supplied),Buffer.from(expected));
};
const enforceCsrf=(req,res,next)=>validCsrf(req,res)?next():res.status(403).send('Invalid CSRF token. Refresh the page.');
app.use((req,res,next)=>{
 if(req.method!=='POST'||req.path==='/api/cron/check-complaints'||req.is('multipart/form-data'))return next();
 return enforceCsrf(req,res,next);
});

// Helper to find student allocation [alloc, room, hostel]
function getStudentAllocation(studentId) {
  const alloc = Array.from(db.allocations.values()).find(
    a => a.student_id === studentId && a.active
  );
  if (!alloc) return null;
  const room = db.rooms.get(alloc.room_id);
  if (!room || !room.active) return null;
  const hostel = db.hostels.get(room.hostel_id);
  if (!hostel || !hostel.active) return null;
  return [alloc, room, hostel];
}

// Helper to get hostels accessible by user
function getUserHostelIds(user) {return hostelIds(db,user);}

function addEventRecord(row) {const id=generateId();db.events.set(id,{...row,id});}
function addAssignment(row) {const id=generateId();db.assignments.set(id,{...row,id});}
// Helper for notifications / alerts
function alertUsers(recipients, complaint, title, body) { notify(db,recipients,complaint,title,body); }
export async function runComplaintChecks(now=new Date()) {
  const currentStore = requestContext.getStore();
  if (currentStore) {
    return processDue(currentStore.db, now);
  }
  const state = await loadState();
  let result;
  await requestContext.run(state, async () => {
    result = processDue(state.db, now);
    try {
      await saveState(state.version, state.db);
    } catch (e) {
      console.error('[HostelCare] Periodic saveState error:', e.message);
      throw e;
    }
  });
  return result;
}

function redirectWithMsg(res, url, msg, kind = 'success') {
  const sep = url.includes('?') ? '&' : '?';
  return res.redirect(`${url}${sep}msg=${encodeURIComponent(msg)}&kind=${kind}`);
}

// Auth middlewares
function requireAuth(req, res, next) {
  if (!req.user) {
    return redirectWithMsg(res, '/login', 'Please log in to continue.', 'error');
  }
  if (req.user.force_password_change && req.path !== '/profile/password') {
    return redirectWithMsg(
      res,
      '/profile/password',
      'Please change your temporary password before continuing.',
      'error'
    );
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return redirectWithMsg(res, '/login', 'Please log in.', 'error');
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).render('message', {
        title: 'Access denied',
        error: `Your role (${req.user.role}) does not have permission for this section.`,
        status: 403
      });
    }
    next();
  };
}

// -------------------------------------------------------------
// ROUTES
// -------------------------------------------------------------

// Health check
app.get('/healthz', (req, res) => {
  res.json({
    status: 'ok',
    database: 'sqlite',
    cronInterval: '5 minutes'
  });
});

// Optional protected complaint check endpoint (the local server also runs the timer)
app.post('/api/cron/check-complaints', async (req, res) => {
  const expected=process.env.CRON_SECRET||'';
  const supplied=String(req.headers.authorization||'').replace(/^Bearer /,'');
  if(!expected || supplied.length!==expected.length || !crypto.timingSafeEqual(Buffer.from(supplied),Buffer.from(expected)))return res.status(403).json({error:'Forbidden'});
  const result = await runComplaintChecks();
  res.json({
    success: true,
    timestamp: new Date().toISOString(),
    ...result
  });
});

// Root
app.get('/', (req, res) => {
  if (req.user) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

// Login
app.get('/login', (req, res) => {
  if (req.user) {
    return res.redirect('/dashboard');
  }
  res.render('login');
});

app.post('/login', (req, res) => {
  const loginId = (req.body.login_id || '').trim().toUpperCase();
  const password = req.body.password || '';

  const recentFailures=db.loginAttempts.filter(a=>!a.success&&(a.login_id===loginId||a.ip===req.ip)&&Date.now()-new Date(a.created_at).getTime()<15*60000);
  if(recentFailures.length>=10)return res.status(429).send('Too many failed logins. Try again later.');
  const user = Array.from(db.users.values()).find(
    u => u.login_id === loginId && u.active
  );

  let valid = false;
  if (user) {
    valid = verifyPassword(password, user.password_hash);
  }

  db.loginAttempts.push({
    id: generateId(),
    login_id: loginId,
    ip: req.ip || '127.0.0.1',
    success: valid,
    created_at: new Date()
  });

  if (!valid || !user) {
    return redirectWithMsg(res, '/login', 'Invalid login ID or password.', 'error');
  }

  // Create session
  const token = generateToken();
  const session = {
    id: generateId(),
    user_id: user.id,
    expires_at: new Date(Date.now() + 12 * 3600 * 1000),
    revoked_at: null
  };
  db.sessions.set(hashToken(token), session);

  const isHttps = Boolean(req.secure || req.headers['x-forwarded-proto'] === 'https');
  res.cookie('hcms_session', token, {
    maxAge: 12 * 3600 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: isHttps
  });

  if (user.force_password_change) {
    return res.redirect('/profile/password');
  }
  res.redirect('/dashboard');
});

// Logout
app.post('/logout', (req, res) => {
  const token = req.cookies.hcms_session;
  if (token) {
    const session = db.sessions.get(hashToken(token));
    if (session) {
      session.revoked_at = new Date();
    }
  }
  res.clearCookie('hcms_session');
  redirectWithMsg(res, '/login', 'You have been signed out.');
});

// Change Password
app.get('/profile/password', requireAuth, (req, res) => {
  res.render('password');
});

app.post('/profile/password', requireAuth, (req, res) => {
  const oldPassword = req.body.old_password || '';
  const newPassword = req.body.new_password || '';
  const confirmPassword = req.body.confirm_password || '';

  if (!verifyPassword(oldPassword, req.user.password_hash)) {
    return redirectWithMsg(res, '/profile/password', 'Current password is incorrect.', 'error');
  }

  if (newPassword !== confirmPassword) {
    return redirectWithMsg(res, '/profile/password', 'New passwords do not match.', 'error');
  }

  if (newPassword.length < 12 || newPassword.length > 128 || !/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) return redirectWithMsg(res,'/profile/password','Use 12–128 characters including letters and numbers.','error');

  req.user.password_hash = hashPassword(newPassword);
  req.user.force_password_change = false;
  for(const [key,sess] of db.sessions)if(sess.user_id===req.user.id&&key!==hashToken(req.cookies.hcms_session||''))sess.revoked_at=new Date();

  redirectWithMsg(res, '/dashboard', 'Password updated successfully.');
});

// Profile
app.get('/profile', requireAuth, (req, res) => {
  const allocation = req.user.role === 'STUDENT' ? getStudentAllocation(req.user.id) : null;
  res.render('profile', { allocation });
});

app.post('/profile', requireAuth, (req, res) => {
  const preferredName = String(req.body.preferred_name || '').trim();
  const phone = String(req.body.phone || '').trim();
  if(preferredName.length>80 || phone.length>25 || (phone && !/^[+0-9() .-]{7,25}$/.test(phone)))return redirectWithMsg(res,'/profile','Check the name or phone number.','error');

  req.user.preferred_name = preferredName || null;
  req.user.phone = phone || null;

  redirectWithMsg(res, '/profile', 'Profile updated successfully.');
});

// Notifications
app.get('/notifications', requireAuth, (req, res) => {
  const notes = Array.from(db.notifications.values())
    .filter(n => n.recipient_id === req.user.id)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  res.render('notifications', { notes });
});

app.post('/notifications/read', requireAuth, (req, res) => {
  Array.from(db.notifications.values()).forEach(n => {
    if (n.recipient_id === req.user.id && !n.read_at) {
      n.read_at = new Date();
    }
  });
  res.redirect('/notifications');
});

// Dashboard Router
app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.user;

  if (user.role === 'STUDENT') {
    const complaints = Array.from(db.complaints.values())
      .filter(c => c.student_id === user.id)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    const allocation = getStudentAllocation(user.id);
    return res.render('student', { complaints, allocation });
  }

  if (user.role === 'RECTOR') {
    const hostelIds = getUserHostelIds(user);
    const search = (req.query.q || '').trim().toLowerCase();
    const statusFilter = (req.query.status || '').trim();
    const pageNum = Math.max(1, parseInt(req.query.page || '1', 10));

    let complaints = Array.from(db.complaints.values()).filter(c =>
      hostelIds.includes(c.hostel_id)
    );

    if (search) {
      complaints = complaints.filter(
        c =>
          (c.number && c.number.toLowerCase().includes(search)) ||
          (c.description && c.description.toLowerCase().includes(search))
      );
    }

    if (statusFilter) {
      complaints = complaints.filter(c => c.status === statusFilter);
    }

    // Counts by status
    const counts = {};
    Array.from(db.complaints.values())
      .filter(c => hostelIds.includes(c.hostel_id))
      .forEach(c => {
        counts[c.status] = (counts[c.status] || 0) + 1;
      });

    const total = complaints.length;
    complaints.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    const paged = complaints.slice((pageNum - 1) * 25, pageNum * 25);

    return res.render('rector', {
      complaints: paged,
      counts,
      total,
      page_num: pageNum,
      search,
      status_filter: statusFilter
    });
  }

  if (user.role === 'MAINTENANCE_STAFF') {
    const complaints = Array.from(db.complaints.values())
      .filter(c => c.current_staff_id === user.id)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    return res.render('staff', { complaints });
  }

  if (user.role === 'DEAN') {
    const hostelIds = getUserHostelIds(user);
    const escalations = Array.from(db.escalations.values())
      .filter(e => {
        const c = db.complaints.get(e.complaint_id);
        return c && hostelIds.includes(c.hostel_id);
      })
      .sort((a, b) => new Date(b.escalated_at) - new Date(a.escalated_at));

    const c_by_id = {};
    let unresolved = 0;
    escalations.forEach(e => {
      const c = db.complaints.get(e.complaint_id);
      if (c) {
        c_by_id[e.complaint_id] = c;
        if (!['CLOSED', 'AUTO_CLOSED', 'REJECTED', 'DUPLICATE'].includes(c.status)) {
          unresolved++;
        }
      }
    });

    return res.render('dean', { escalations, c_by_id, unresolved });
  }

  // SYSTEM_ADMIN
  const hostels = Array.from(db.hostels.values()).sort((a, b) => a.name.localeCompare(b.name));
  const userSearch = (req.query.user_search || '').trim().toLowerCase();
  let users = Array.from(db.users.values());
  if (userSearch) {
    users = users.filter(
      u =>
        u.login_id.toLowerCase().includes(userSearch) ||
        u.name.toLowerCase().includes(userSearch)
    );
  }
  users.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  const staff_users = Array.from(db.users.values()).filter(
    u => ['RECTOR', 'DEAN', 'MAINTENANCE_STAFF'].includes(u.role) && u.active
  );

  const rooms = Array.from(db.rooms.values()).sort((a, b) =>
    `${a.building} ${a.number}`.localeCompare(`${b.building} ${b.number}`)
  );

  const hostel_by_id = {};
  hostels.forEach(h => {
    hostel_by_id[h.id] = h;
  });

  const admin_audit = [...db.adminAudit].sort(
    (a, b) => new Date(b.at) - new Date(a.at)
  );

  return res.render('admin', {
    hostels,
    users,
    staff_users,
    rooms,
    user_search: userSearch,
    hostel_by_id,
    admin_audit
  });
});

// Student: New Complaint
app.get('/student/new', requireAuth, requireRole('STUDENT'), (req, res) => {
  const allocation = getStudentAllocation(req.user.id);
  const idempotency_key = generateId();
  res.render('complaint_new', { allocation, idempotency_key });
});

app.post('/student/new', requireAuth, requireRole('STUDENT'), upload.array('photos', 3), asyncRoute(async (req, res) => {
  if(!validCsrf(req,res))return res.status(403).send('Invalid CSRF token');
  const allocation = getStudentAllocation(req.user.id);
  if (!allocation) {
    return redirectWithMsg(res, '/student/new', 'No active room assignment.', 'error');
  }

  const [_, room, hostel] = allocation;
  const category = (req.body.category || '').toUpperCase();
  const priority = (req.body.priority || 'NORMAL').toUpperCase();
  const description = (req.body.description || '').trim();
  const key = String(req.body.idempotency_key || generateId()).slice(0,80);
  const previous=[...db.complaints.values()].find(c=>c.student_id===req.user.id&&c.idempotency_key===key);
  if(previous)return res.redirect(`/complaints/${previous.id}`);

  if (!CATEGORIES.includes(category) || !PRIORITIES.includes(priority) || description.length < 10) {
    return redirectWithMsg(
      res,
      '/student/new',
      'Please select valid category and priority, with at least 10 characters description.',
      'error'
    );
  }

  const cId = generateId();
  const number = `HC-${new Date().getFullYear()}-${cId.slice(0, 8).toUpperCase()}`;

  const complaint = {
    id: cId,
    number,
    student_id: req.user.id,
    hostel_id: hostel.id,
    room_id: room.id,
    category,
    effective_category: category,
    description,
    priority,
    effective_priority: priority,
    status: 'SUBMITTED',
    cycle_number: 1,
    current_staff_id: null,
    work_started_at: null,
    work_completed_at: null,
    confirmation_reminded_at: null,
    closed_at: null,
    closure_reason: null,
    idempotency_key: key,
    created_at: new Date(),
    updated_at: new Date()
  };

  if((req.files||[]).some(f=>!['image/jpeg','image/png','image/webp'].includes(f.mimetype)||!looksLikeImage(f.buffer,f.mimetype)))return redirectWithMsg(res,'/student/new','Upload only valid JPEG, PNG or WebP photos.','error');
  db.complaints.set(complaint.id, complaint);

  // Work cycle
  beginCycle(db,complaint,complaint.created_at);

  // Event
  addEventRecord({
    complaint_id: complaint.id,
    actor_id: req.user.id,
    action: 'SUBMITTED',
    detail: `${category}; ${priority}; Room ${room.number}`,
    at: new Date()
  });

  // Store photo bytes in SQLite as private BLOBs in the same transaction
  if (req.files && req.files.length > 0) {
    for (const f of req.files) {
      const attId = generateId();
      stageEvidence(attId, f.buffer);
      db.attachments.set(attId, {
        id: attId,
        complaint_id: complaint.id,
        uploader_id: req.user.id,
        storage_key: attId,
        filename: f.originalname || 'photo.jpg',
        mime_type: f.mimetype || 'image/jpeg',
        byte_length: f.buffer.length,
        created_at: new Date()
      });
    }
  }

  // Alert Rector(s) for this hostel
  const rectors = Array.from(db.users.values()).filter(
    u => u.role === 'RECTOR' && getUserHostelIds(u).includes(hostel.id)
  );
  alertUsers(
    rectors,
    complaint,
    'New hostel complaint',
    `${complaint.number}: Room ${room.number} — ${description.slice(0, 140)}`
  );

  redirectWithMsg(
    res,
    `/complaints/${complaint.id}`,
    `Complaint registered successfully. Ticket: ${complaint.number}`
  );
}));

// View Complaint Details
app.get('/complaints/:cid', requireAuth, (req, res) => {
  const c = db.complaints.get(req.params.cid);
  if (!c) {
    return res.status(404).render('message', {
      title: 'Not Found',
      error: 'Complaint not found.',
      status: 404
    });
  }

  if (!canView(db,req.user,c)) return res.status(403).render('message', {
    title:'Access denied',error:'You do not have access to view this complaint.',status:403
  });

  const events = Array.from(db.events.values())
    .filter(e => e.complaint_id === c.id)
    .sort((a, b) => new Date(b.at) - new Date(a.at));

  const pics = Array.from(db.attachments.values()).filter(a => a.complaint_id === c.id);
  const escalations = Array.from(db.escalations.values()).filter(e => e.complaint_id === c.id);

  const people = {};
  Array.from(db.users.values()).forEach(u => {
    people[u.id] = u;
  });

  let staff_list = [];
  if (req.user.role === 'RECTOR') {
    staff_list = Array.from(db.users.values()).filter(
      u => u.role === 'MAINTENANCE_STAFF' && u.active && getUserHostelIds(u).includes(c.hostel_id)
    );
  }

  const hostel = db.hostels.get(c.hostel_id);
  const room = db.rooms.get(c.room_id);
  const feedback = db.feedback.get(c.id);

  res.render('complaint_detail', {
    c,
    events,
    pics,
    escalations,
    people,
    staff_list,
    hostel,
    room,
    feedback
  });
});

// Student verify / reopen
app.post('/student/complaints/:cid/verify', requireAuth, requireRole('STUDENT'), (req, res) => {
  const c = db.complaints.get(req.params.cid);
  if (!c || c.student_id !== req.user.id) {
    return redirectWithMsg(res, '/dashboard', 'Complaint not found.', 'error');
  }

  const action = req.body.action;
  const reason = (req.body.reason || '').trim();

  if (action === 'confirm' && c.status === 'AWAITING_CONFIRMATION') {
    const needsRector=c.effective_priority==='EMERGENCY'||hasEscalation(db,c);
    if(needsRector){
      alertUsers(scoped(db,'RECTOR',c.hostel_id),c,'Rector verification required',`${c.number}: student confirmed; verify before closing.`);
    }else{
      c.status = 'CLOSED';c.closed_at = new Date();c.closure_reason = 'STUDENT_CONFIRMED';
    }

    event(db,c,req.user,needsRector?'STUDENT_CONFIRMED_PENDING_RECTOR':'STUDENT_CONFIRMED',needsRector?'Student confirmed; Rector must verify.':'Repair confirmed and closed by student.');

    const rating = parseInt(req.body.rating || '0', 10);
    const comment = (req.body.comment || '').trim();
    if (rating >= 1 && rating <= 5) {
      db.feedback.set(c.id, {
        complaint_id: c.id,
        student_id: req.user.id,
        rating,
        comment,
        created_at: new Date()
      });
    }

    return redirectWithMsg(res, `/complaints/${c.id}`, needsRector?'Confirmation recorded; awaiting Rector verification.':'Thank you! The complaint has been confirmed and closed.');
  }

  if (action === 'reopen' && canStudentReopen(c)) {
    try {reopen(db,c,req.user,reason);}catch(error){return redirectWithMsg(res,`/complaints/${c.id}`,error.message,'error');}
    return redirectWithMsg(res,`/complaints/${c.id}`,'Complaint reopened for another repair cycle.');
  }

  redirectWithMsg(res, `/complaints/${c.id}`, 'Invalid action.', 'error');
});

// Rector actions
app.post('/rector/complaints/:cid/action', requireAuth, requireRole('RECTOR'), (req, res) => {
  const c = db.complaints.get(req.params.cid);
  if (!c) return redirectWithMsg(res, '/dashboard', 'Complaint not found.', 'error');

  if(!getUserHostelIds(req.user).includes(c.hostel_id))return res.status(403).send('Out of assigned hostel scope.');
  const action = req.body.action;
  const reason = (req.body.reason || '').trim();
  if(!validActionTransition('RECTOR',action,c.status))return redirectWithMsg(res,`/complaints/${c.id}`,'This action is not allowed in the current state.','error');

  if (action === 'review' && ['SUBMITTED', 'REOPENED'].includes(c.status)) {
    c.status = 'UNDER_REVIEW';
    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'UNDER_REVIEW',
      detail: reason || 'Under review by Rector',
      at: new Date()
    });
  } else if (action === 'assign') {
    const staffId = req.body.staff_id;
    const staff = db.users.get(staffId);
    if (!staff || !staff.active || staff.role !== 'MAINTENANCE_STAFF' || !getUserHostelIds(staff).includes(c.hostel_id)) {
      return redirectWithMsg(res, `/complaints/${c.id}`, 'Please select valid maintenance staff.', 'error');
    }
    if(c.current_staff_id===staff.id)return redirectWithMsg(res,`/complaints/${c.id}`,'Worker already assigned.','error');
    for(const a of db.assignments.values())if(a.complaint_id===c.id&&!a.ended_at)a.ended_at=new Date();
    c.current_staff_id = staff.id;
    c.status = 'ASSIGNED';

    addAssignment({
      complaint_id: c.id,
      cycle_number: c.cycle_number,
      staff_id: staff.id,
      assigned_by: req.user.id,
      assigned_at: new Date(),
      accepted_at: null,
      ended_at: null
    });

    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'ASSIGNED',
      detail: `Assigned to ${staff.name}. Instructions: ${reason}`,
      at: new Date()
    });

    alertUsers([staff], c, 'New maintenance assignment', `${c.number}: Assigned to you by Rector.`);
  } else if (action === 'classify') {
    const category = req.body.category;
    const priority = req.body.priority;
    if(!CATEGORIES.includes(category)||!PRIORITIES.includes(priority))return redirectWithMsg(res,`/complaints/${c.id}`,'Invalid category or priority.','error');
    c.effective_category=category;c.effective_priority=priority;

    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'CLASSIFIED',
      detail: `Category: ${category}, Priority: ${priority}`,
      at: new Date()
    });
  } else if (action === 'reject') {
    if(reason.length<8)return redirectWithMsg(res,`/complaints/${c.id}`,'Rejection requires 8 characters.','error');
    c.status = 'REJECTED';
    c.closed_at = new Date();
    c.closure_reason = 'REJECTED_BY_RECTOR';

    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'REJECTED',
      detail: reason,
      at: new Date()
    });

    const student = db.users.get(c.student_id);
    if (student) alertUsers([student], c, 'Complaint rejected', `${c.number}: ${reason}`);
  } else if (action === 'verify' && c.status === 'AWAITING_CONFIRMATION') {
    if(reason.length<8)return redirectWithMsg(res,`/complaints/${c.id}`,'Verification reason required.','error');
    if(!hasEscalation(db,c) && c.effective_priority!=='EMERGENCY')return redirectWithMsg(res,`/complaints/${c.id}`,'Ordinary repairs require student confirmation or scheduled auto-close.','error');
    c.status = 'CLOSED';
    c.closed_at = new Date();
    c.closure_reason = 'RECTOR_VERIFIED';

    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'RECTOR_VERIFIED',
      detail: reason,
      at: new Date()
    });

    const student = db.users.get(c.student_id);
    if (student) alertUsers([student], c, 'Repair verified by Rector', `${c.number} closed.`);
  } else if (action === 'reopen') {
    try{reopen(db,c,req.user,reason);}catch(error){return redirectWithMsg(res,`/complaints/${c.id}`,error.message,'error');}
    return redirectWithMsg(res,`/complaints/${c.id}`,'Complaint reopened for a fresh work cycle.');
  }

  redirectWithMsg(res, `/complaints/${c.id}`, 'Rector action recorded.');
});

// Maintenance Staff actions
app.post('/staff/complaints/:cid/action', requireAuth, requireRole('MAINTENANCE_STAFF'), upload.array('photos', 3), asyncRoute(async (req, res) => {
  if(!validCsrf(req,res))return res.status(403).send('Invalid CSRF token');
  const c = db.complaints.get(req.params.cid);
  if (!c || c.current_staff_id !== req.user.id) {
    return redirectWithMsg(res, '/dashboard', 'Task not found or not assigned to you.', 'error');
  }

  const action = req.body.action;
  if(!validActionTransition('MAINTENANCE_STAFF',action,c.status))return redirectWithMsg(res,`/complaints/${c.id}`,'Invalid maintenance state transition.','error');
  const note = (req.body.note || '').trim();
  if(action==='start'&&note.length<5)return redirectWithMsg(res,`/complaints/${c.id}`,'Start requires a 5+ character note.','error');
  if(['hold','complete'].includes(action)&&note.length<8)return redirectWithMsg(res,`/complaints/${c.id}`,'Provide a clear note of at least 8 characters.','error');
  if(action==='progress'&&note.length<3)return redirectWithMsg(res,`/complaints/${c.id}`,'Progress note required.','error');
  if((req.files||[]).some(f=>!['image/jpeg','image/png','image/webp'].includes(f.mimetype)||!looksLikeImage(f.buffer,f.mimetype)))return redirectWithMsg(res,`/complaints/${c.id}`,'Invalid image upload.','error');
  if((req.files||[]).length && !['progress','complete'].includes(action))return redirectWithMsg(res,`/complaints/${c.id}`,'Repair photos are allowed only with progress or completion.','error');

  if (action === 'accept' && c.status === 'ASSIGNED') {
    c.status = 'ACCEPTED';
    const assignment=[...db.assignments.values()].find(a=>a.complaint_id===c.id&&a.staff_id===req.user.id&&!a.ended_at);
    if(assignment)assignment.accepted_at=new Date();
    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'ACCEPTED',
      detail: 'Technician accepted the assignment',
      at: new Date()
    });
  } else if (action === 'start') {
    c.status = 'IN_PROGRESS';
    c.work_started_at = new Date();
    const currentCycle=cycleFor(db,c);if(currentCycle)currentCycle.work_started_at=c.work_started_at;
    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'WORK_STARTED',
      detail: note || 'Work started by technician',
      at: new Date()
    });

    const student = db.users.get(c.student_id);
    if (student) alertUsers([student], c, 'Maintenance started', `${c.number}: technician started repair.`);
  } else if (action === 'hold') {
    c.status = 'ON_HOLD';
    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'ON_HOLD',
      detail: note || 'Put on hold pending spare parts or assistance',
      at: new Date()
    });
  } else if (action === 'resume') {
    c.status = c.work_started_at ? 'IN_PROGRESS' : 'ACCEPTED';
    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'RESUMED',
      detail: note || 'Maintenance resumed',
      at: new Date()
    });
  } else if (action === 'progress') {
    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'PROGRESS',
      detail: note || 'Progress note recorded',
      at: new Date()
    });
  } else if (action === 'complete') {
    c.status = 'AWAITING_CONFIRMATION';
    c.work_completed_at = new Date();
    c.confirmation_reminded_at = null;
    addEventRecord({
      complaint_id: c.id,
      actor_id: req.user.id,
      action: 'WORK_COMPLETED',
      detail: note || 'Repair completed. Awaiting student verification.',
      at: new Date()
    });

    const student = db.users.get(c.student_id);
    if (student) {
      alertUsers([student], c, 'Please confirm the repair', `${c.number} marked repaired.`);
    }
  }

  // Upload repair photos if attached
  if (req.files && req.files.length > 0) {
    for (const f of req.files) {
      const attId = generateId();
      stageEvidence(attId, f.buffer);
      db.attachments.set(attId, {
        id: attId,
        complaint_id: c.id,
        uploader_id: req.user.id,
        storage_key: attId,
        filename: f.originalname || 'repair_photo.jpg',
        mime_type: f.mimetype || 'image/jpeg',
        byte_length: f.buffer.length,
        created_at: new Date()
      });
    }
  }

  redirectWithMsg(res, `/complaints/${c.id}`, 'Maintenance status updated.');
}));

// Dean directive
app.post('/dean/complaints/:cid/directive', requireAuth, requireRole('DEAN'), (req, res) => {
  const c = db.complaints.get(req.params.cid);
  if (!c || !canView(db,req.user,c))return res.status(403).send('Not an authorized escalated complaint.');

  const directive = (req.body.directive || '').trim();
  if (directive.length < 10) {
    return redirectWithMsg(res, `/complaints/${c.id}`, 'Directive must be at least 10 characters.', 'error');
  }

  addEventRecord({
    complaint_id: c.id,
    actor_id: req.user.id,
    action: 'DEAN_DIRECTIVE',
    detail: directive,
    at: new Date()
  });

  const rectors = Array.from(db.users.values()).filter(
    u => u.role === 'RECTOR' && getUserHostelIds(u).includes(c.hostel_id)
  );
  alertUsers(rectors, c, 'Dean corrective directive', `${c.number}: ${directive}`);

  redirectWithMsg(res, `/complaints/${c.id}`, 'Directive recorded and Rector notified.');
});

// Admin: Add Hostel
app.post('/admin/hostels', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const code = (req.body.code || '').trim().toUpperCase();
  const name = (req.body.name || '').trim();
  const emergency_phone = (req.body.emergency_phone || '').trim() || null;

  if (!code || !name) {
    return redirectWithMsg(res, '/dashboard', 'Hostel code and name required.', 'error');
  }

  const existing = Array.from(db.hostels.values()).find(h => h.code === code);
  if (existing) {
    return redirectWithMsg(res, '/dashboard', 'Hostel code already exists.', 'error');
  }

  const hostel = {
    id: generateId(),
    code,
    name,
    emergency_phone,
    active: true,
    created_at: new Date()
  };

  db.hostels.set(hostel.id, hostel);
  db.adminAudit.push({
    id: generateId(),
    actor_id: req.user.id,
    action: 'CREATE_HOSTEL',
    target_type: 'Hostel',
    target_id: hostel.id,
    detail: `${code}: ${name}`,
    at: new Date()
  });

  redirectWithMsg(res, '/dashboard', `Hostel ${name} created.`);
});

// Admin: Toggle Hostel
app.post('/admin/hostels/:hid/toggle', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const h = db.hostels.get(req.params.hid);
  if (!h) return redirectWithMsg(res, '/dashboard', 'Hostel not found.', 'error');

  if(h.active){
    const hasOpen=[...db.complaints.values()].some(c=>c.hostel_id===h.id&&!['CLOSED','AUTO_CLOSED','REJECTED','DUPLICATE'].includes(c.status));
    const residents=[...db.allocations.values()].some(a=>a.active&&db.rooms.get(a.room_id)?.hostel_id===h.id);
    if(hasOpen||residents)return redirectWithMsg(res,'/dashboard','Resolve open complaints and transfer residents before archiving.','error');
  }
  h.active = !h.active;
  db.adminAudit.push({
    id: generateId(),
    actor_id: req.user.id,
    action: h.active ? 'RESTORE_HOSTEL' : 'ARCHIVE_HOSTEL',
    target_type: 'Hostel',
    target_id: h.id,
    detail: h.name,
    at: new Date()
  });

  redirectWithMsg(res, '/dashboard', `Hostel ${h.name} is now ${h.active ? 'Active' : 'Archived'}.`);
});

// Admin: Delete Unused Hostel
app.post('/admin/hostels/:hid/delete', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const h = db.hostels.get(req.params.hid);
  if (!h) return redirectWithMsg(res, '/dashboard', 'Hostel not found.', 'error');

  const hasRooms = Array.from(db.rooms.values()).some(r => r.hostel_id === h.id);
  const hasComplaints = Array.from(db.complaints.values()).some(c => c.hostel_id === h.id);

  const hasScopes=[...db.scopes.values()].some(sc=>sc.hostel_id===h.id);
  if (hasRooms || hasComplaints || hasScopes) {
    return redirectWithMsg(res, '/dashboard', 'Cannot delete hostel with rooms or complaints. Archive instead.', 'error');
  }

  db.hostels.delete(h.id);
  db.adminAudit.push({
    id: generateId(),
    actor_id: req.user.id,
    action: 'DELETE_UNUSED_HOSTEL',
    target_type: 'Hostel',
    target_id: h.id,
    detail: h.name,
    at: new Date()
  });

  redirectWithMsg(res, '/dashboard', 'Hostel deleted.');
});

// Admin: Emergency Contact
app.post('/admin/hostels/:hid/emergency-contact', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const h = db.hostels.get(req.params.hid);
  if (!h) return redirectWithMsg(res, '/dashboard', 'Hostel not found.', 'error');

  h.emergency_phone = (req.body.emergency_phone || '').trim() || null;
  redirectWithMsg(res, '/dashboard', `Emergency contact updated for ${h.name}.`);
});

// Admin: Add Room
app.post('/admin/rooms', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const hostel_id = req.body.hostel_id;
  const building = (req.body.building || 'Main').trim();
  const floor = (req.body.floor || '0').trim();
  const number = (req.body.number || '').trim().toUpperCase();
  const capacity = Number(req.body.capacity || '2');

  if(!db.hostels.get(hostel_id)?.active || !Number.isInteger(capacity) || capacity<1 || capacity>20)return redirectWithMsg(res,'/dashboard','Select an active hostel and room capacity 1–20.','error');
  if (!hostel_id || !number) {
    return redirectWithMsg(res, '/dashboard', 'Hostel and room number required.', 'error');
  }

  const existing = Array.from(db.rooms.values()).find(
    r => r.hostel_id === hostel_id && r.building === building && r.number === number
  );
  if (existing) {
    return redirectWithMsg(res, '/dashboard', 'Room already exists in this hostel/building.', 'error');
  }

  const room = {
    id: generateId(),
    hostel_id,
    building,
    floor,
    number,
    capacity,
    active: true
  };
  db.rooms.set(room.id, room);

  db.adminAudit.push({
    id: generateId(),
    actor_id: req.user.id,
    action: 'CREATE_ROOM',
    target_type: 'Room',
    target_id: room.id,
    detail: `${building} ${number}`,
    at: new Date()
  });

  redirectWithMsg(res, '/dashboard', `Room ${number} added.`);
});

// Admin: Create User Account
app.post('/admin/users', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const role = req.body.role;
  const login_id = (req.body.login_id || '').trim().toUpperCase();
  const name = (req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase() || null;

  if (!ROLES.includes(role) || !/^[A-Z0-9_./-]{4,60}$/.test(login_id) || name.length<2 || name.length>100 || (email && (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254))) {
    return redirectWithMsg(res, '/dashboard', 'Role, Login ID, and Name are required.', 'error');
  }

  const existing = Array.from(db.users.values()).find(u => u.login_id === login_id);
  if (existing) {
    return redirectWithMsg(res, '/dashboard', 'This login ID is already registered.', 'error');
  }

  const tempPwd = `HC-${crypto.randomBytes(16).toString('base64url')}8a`;
  const newUser = {
    id: generateId(),
    login_id,
    urn: role === 'STUDENT' ? login_id : null,
    name,
    preferred_name: null,
    email,
    phone: null,
    role,
    password_hash: hashPassword(tempPwd),
    force_password_change: true,
    active: true,
    created_at: new Date()
  };

  db.users.set(newUser.id, newUser);

  db.adminAudit.push({
    id: generateId(),
    actor_id: req.user.id,
    action: 'CREATE_USER',
    target_type: 'User',
    target_id: newUser.id,
    detail: `${login_id} (${role})`,
    at: new Date()
  });

  res.render('credentials', {
    new_credentials: [[login_id, name, tempPwd]],
    duplicates: []
  });
});

// Admin: Bulk Import Students
app.post('/admin/users/import', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const csvText=String(req.body.csv_text||'');
  if(csvText.length>180000)return redirectWithMsg(res,'/dashboard','CSV too large; import in smaller batches.','error');
  let rows;
  try{rows=parseCsv(csvText);}catch(error){return redirectWithMsg(res,'/dashboard',error.message,'error');}
  if(rows.length<2)return redirectWithMsg(res,'/dashboard','CSV must have a header and rows.','error');
  if(rows.length>251)return redirectWithMsg(res,'/dashboard','Maximum 250 students per import.','error');
  const header=rows[0].map(x=>x.trim().toLowerCase());
  const urnIdx=header.indexOf('urn'),nameIdx=header.indexOf('name'),emailIdx=header.indexOf('email');
  if(urnIdx<0||nameIdx<0)return redirectWithMsg(res,'/dashboard','CSV headers must include urn,name.','error');
  const lines=rows.slice(1);
  const invalid=lines.findIndex(parts=>{
    const urn=(parts[urnIdx]||'').trim().toUpperCase();const name=(parts[nameIdx]||'').trim();const email=emailIdx!==-1?(parts[emailIdx]||'').trim():'';
    return !/^[A-Z0-9_./-]{4,60}$/.test(urn)||name.length<2||(email&&!email.includes('@'));
  });
  if(invalid!==-1)return redirectWithMsg(res,'/dashboard',`Invalid student on CSV line ${invalid+2}; none imported.`,'error');
  const new_credentials = [];
  const duplicates = [];

  for (let i = 0; i < lines.length; i++) {
    const parts = lines[i].map(s => s.trim());
    const urn = (parts[urnIdx] || '').toUpperCase();
    const name = parts[nameIdx] || '';
    const email = emailIdx !== -1 && parts[emailIdx] ? parts[emailIdx].toLowerCase() : null;

    if(!/^[A-Z0-9_./-]{4,60}$/.test(urn)||name.length<2|| (email&&!email.includes('@')))return redirectWithMsg(res,'/dashboard',`Invalid student on CSV line ${i+2}; nothing imported.`,'error');

    const exists = Array.from(db.users.values()).some(u => u.login_id === urn);
    if (exists) {
      duplicates.push(urn);
      continue;
    }

    const tempPwd = `HC-${crypto.randomBytes(16).toString('base64url')}8a`;
    const user = {
      id: generateId(),
      login_id: urn,
      urn,
      name,
      preferred_name: null,
      email,
      phone: null,
      role: 'STUDENT',
      password_hash: hashPassword(tempPwd),
      force_password_change: true,
      active: true,
      created_at: new Date()
    };
    db.users.set(user.id, user);
    new_credentials.push([urn, name, tempPwd]);
  }

  db.adminAudit.push({
    id: generateId(),
    actor_id: req.user.id,
    action: 'BULK_IMPORT_STUDENTS',
    target_type: 'User',
    target_id: 'BATCH',
    detail: `Imported ${new_credentials.length} students; ${duplicates.length} duplicates`,
    at: new Date()
  });

  res.render('credentials', { new_credentials, duplicates });
});

// Admin: Toggle User Active
app.post('/admin/users/:uid/toggle', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const u = db.users.get(req.params.uid);
  if (!u) return redirectWithMsg(res, '/dashboard', 'User not found.', 'error');
  if (u.id === req.user.id) {
    return redirectWithMsg(res, '/dashboard', 'You cannot deactivate your own account.', 'error');
  }

  u.active = !u.active;
  if(!u.active)for(const sess of db.sessions.values())if(sess.user_id===u.id)sess.revoked_at=new Date();
  db.adminAudit.push({
    id: generateId(),
    actor_id: req.user.id,
    action: u.active ? 'ENABLE_USER' : 'DISABLE_USER',
    target_type: 'User',
    target_id: u.id,
    detail: u.login_id,
    at: new Date()
  });

  redirectWithMsg(res, '/dashboard', `Account ${u.login_id} is now ${u.active ? 'Active' : 'Disabled'}.`);
});

// Admin: Reset User Password
app.post('/admin/users/:uid/reset', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const u = db.users.get(req.params.uid);
  if (!u) return redirectWithMsg(res, '/dashboard', 'User not found.', 'error');
  if(u.id===req.user.id)return redirectWithMsg(res,'/dashboard','Use Change Password for your own account.','error');

  const tempPwd = `HC-${crypto.randomBytes(16).toString('base64url')}8a`;
  u.password_hash = hashPassword(tempPwd);
  u.force_password_change = true;
  for(const sess of db.sessions.values())if(sess.user_id===u.id)sess.revoked_at=new Date();

  db.adminAudit.push({
    id: generateId(),
    actor_id: req.user.id,
    action: 'RESET_TEMP_PASSWORD',
    target_type: 'User',
    target_id: u.id,
    detail: u.login_id,
    at: new Date()
  });

  res.render('credentials', {
    new_credentials: [[u.login_id, u.name, tempPwd]],
    duplicates: []
  });
});

// Admin: Grant Hostel Scope
app.post('/admin/scopes', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const user_id = req.body.user_id;
  const hostel_id = req.body.hostel_id;
  const staff = db.users.get(user_id);
  const hostel = db.hostels.get(hostel_id);

  if (!staff || !staff.active || !['RECTOR','DEAN','MAINTENANCE_STAFF'].includes(staff.role) || !hostel || !hostel.active) {
    return redirectWithMsg(res, '/dashboard', 'Valid staff and hostel required.', 'error');
  }

  const existing = Array.from(db.scopes.values()).find(
    s => s.user_id === user_id && s.hostel_id === hostel_id
  );
  if (!existing) {
    const scopeId = generateId();
    db.scopes.set(scopeId, { id: scopeId, user_id, hostel_id });
    db.adminAudit.push({
      id: generateId(),
      actor_id: req.user.id,
      action: 'GRANT_HOSTEL_SCOPE',
      target_type: 'User',
      target_id: staff.id,
      detail: `${staff.role}: ${hostel.code}`,
      at: new Date()
    });
  }

  redirectWithMsg(res, '/dashboard', `${staff.name} authorized for ${hostel.name}.`);
});

// Admin: Allocate Room
app.post('/admin/allocations', requireAuth, requireRole('SYSTEM_ADMIN'), (req, res) => {
  const urn = (req.body.student_urn || '').trim().toUpperCase();
  const room_id = req.body.room_id;
  const student = Array.from(db.users.values()).find(u => u.login_id === urn && u.role === 'STUDENT');
  const room = db.rooms.get(room_id);

  if (!student || !student.active || !room || !room.active || !db.hostels.get(room.hostel_id)?.active) {
    return redirectWithMsg(res, '/dashboard', 'Active Student URN and active room are required.', 'error');
  }
  const occupied=[...db.allocations.values()].filter(a=>a.active&&a.room_id===room.id&&a.student_id!==student.id).length;
  const oldAllocation=[...db.allocations.values()].find(a=>a.student_id===student.id&&a.active);
  if(oldAllocation?.room_id===room.id)return redirectWithMsg(res,'/dashboard','Student already assigned to this room.','error');
  if(occupied>=room.capacity)return redirectWithMsg(res,'/dashboard','Room is at full capacity.','error');

  // Deactivate prior active allocation
  Array.from(db.allocations.values()).forEach(a => {
    if (a.student_id === student.id && a.active) {
      a.active = false;
      a.ended_at = new Date();
    }
  });

  const allocId = generateId();
  db.allocations.set(allocId, {
    id: allocId,
    student_id: student.id,
    room_id: room.id,
    active: true,
    created_at: new Date(),
    ended_at: null
  });

  db.adminAudit.push({
    id: generateId(),
    actor_id: req.user.id,
    action: 'ALLOCATE_ROOM',
    target_type: 'Student',
    target_id: student.id,
    detail: `${student.login_id} -> ${room.building}/${room.number}`,
    at: new Date()
  });

  redirectWithMsg(res, '/dashboard', `${student.name} assigned to room ${room.number}.`);
});

// Photos
app.get('/photos/:aid', requireAuth, (req, res) => {
  const att = db.attachments.get(req.params.aid);
  if (!att) {
    return res.status(404).send('Photo not found');
  }
  const c=db.complaints.get(att.complaint_id);
  if(!canView(db,req.user,c))return res.status(403).send('Forbidden');
  const bytes=readEvidence(att.id);
  if(!bytes)return res.status(404).send('Photo unavailable');
  res.setHeader('Content-Type', ['image/jpeg','image/png','image/webp'].includes(att.mime_type)?att.mime_type:'application/octet-stream');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Content-Disposition','inline');
  return res.send(bytes);
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('message', {
    title: 'Page not found',
    error: 'The requested page does not exist.',
    status: 404
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  const state=requestContext.getStore();if(state)state.abort=true;
  const isFileLimit=err instanceof multer.MulterError;
  res.status(isFileLimit?413:500).render('message', {
    title: isFileLimit?'Invalid photo upload':'Server error',
    error: isFileLimit?'Choose at most 3 valid image files, each no larger than 5 MB.':'An unexpected error occurred. Please try again.',
    status: isFileLimit?413:500
  });
});

const PORT = Number(process.env.PORT || 3000);
const HOST = '0.0.0.0';

if(process.env.RUN_LOCAL_SERVER !== 'false'){
  app.listen(PORT,HOST,()=>console.log(`HostelCare: http://localhost:${PORT}`));
  // Periodic background check for escalations and deadlines (every 5 minutes)
  setInterval(async () => {
    try {
      const stats = await runComplaintChecks();
      if(stats && (stats.escalated || stats.reminded || stats.auto_closed)) {
        console.log('[HostelCare] Periodic complaint checks:', stats);
      }
    } catch(err) {
      console.error('[HostelCare] Complaint check error:', err);
    }
  }, 5 * 60 * 1000);
}
export default app;
