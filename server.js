const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const path = require("path");

const app = express();
const db = new Database(process.env.DB_FILE || "data.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tasks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 account_label TEXT NOT NULL,
 note TEXT DEFAULT '',
 status TEXT NOT NULL DEFAULT 'pending',
 price INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const adminUser = process.env.ADMIN_USERNAME;
const adminPass = process.env.ADMIN_PASSWORD;
if (adminUser && adminPass && !db.prepare("SELECT id FROM users WHERE username=?").get(adminUser)) {
  db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)")
    .run(adminUser, bcrypt.hashSync(adminPass, 12), "admin");
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(session({
 secret: process.env.SESSION_SECRET || "change-this-session-secret-before-deploying",
 resave: false, saveUninitialized: false,
 store: new SQLiteStore({ db: "sessions.sqlite", dir: process.env.DATA_DIR || "." }),
 cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8*60*60*1000 }
}));

const q = (sql) => db.prepare(sql);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const money = n => new Intl.NumberFormat("vi-VN").format(n) + "đ";
function page(title, body, user=null) {
 return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
 <title>${esc(title)}</title><style>
 *{box-sizing:border-box}body{margin:0;background:#f4f6fa;color:#172033;font:15px system-ui,Arial}
 header{background:#172b4d;color:white;padding:16px 22px;display:flex;justify-content:space-between;align-items:center;gap:12px}
 main{max-width:1050px;margin:26px auto;padding:0 16px}.card{background:white;border:1px solid #e3e8f0;border-radius:14px;padding:18px;margin-bottom:16px;box-shadow:0 3px 12px #172b4d0a}
 h1{font-size:22px;margin:0 0 16px}h2{font-size:17px;margin:0 0 14px}.muted{color:#68758b}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.stat{background:#f7f9fc;border-radius:10px;padding:14px}.stat b{display:block;font-size:25px;margin-top:5px}
 input,select,button{font:inherit;padding:11px 12px;border:1px solid #ccd5e2;border-radius:9px;width:100%;background:white}
 button,.btn{background:#2459d3;color:white;border:0;cursor:pointer;text-decoration:none;display:inline-block;text-align:center;padding:11px 14px;border-radius:9px}
 .secondary{background:#e9eef8;color:#20375f}.danger{background:#b42318}.inline{display:flex;gap:9px;align-items:center}.inline>*{flex:1}
 form.grid{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:9px;align-items:end}.field label{display:block;font-size:13px;color:#5e6b80;margin-bottom:5px}
 table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid #edf0f5}th{font-size:13px;color:#68758b}
 .tag{padding:4px 8px;border-radius:20px;font-size:12px;background:#fff3d6;color:#8a5a00}.done{background:#e5f6ed;color:#137547}
 .actions{display:flex;gap:6px;align-items:center}.actions form{margin:0}.actions button{width:auto;padding:7px 9px;font-size:13px}
 .right{display:flex;gap:10px;align-items:center}.right form{margin:0}.error{color:#b42318;background:#fff0ef;padding:10px;border-radius:8px;margin-bottom:12px}
 @media(max-width:700px){.stats{grid-template-columns:1fr}.grid,form.grid{grid-template-columns:1fr}table{font-size:13px}.hide-mobile{display:none}}
 </style></head><body><header><strong>QUẢN LÝ CÔNG VIỆC 2FA</strong>${user?`<div class="right"><span>${esc(user.username)} · ${user.role==="admin"?"Admin":"User"}</span><form method="post" action="/logout"><button class="secondary">Đăng xuất</button></form></div>`:""}</header><main>${body}</main></body></html>`;
}
function auth(req,res,next){ if(!req.session.user) return res.redirect("/login"); const u=q("SELECT id,username,role,active FROM users WHERE id=?").get(req.session.user.id); if(!u||!u.active){req.session.destroy(()=>{});return res.redirect("/login");} req.user=u; next(); }
function admin(req,res,next){if(req.user.role!=="admin")return res.status(403).send(page("Không có quyền","<div class='card'>Bạn không có quyền truy cập.</div>",req.user));next();}
app.get("/",(req,res)=>res.redirect(req.session.user?"/dashboard":"/login"));
app.get("/login",(req,res)=>res.send(page("Đăng nhập",`<div class="card" style="max-width:420px;margin:50px auto"><h1>Đăng nhập</h1>${req.query.e?'<div class="error">Tên đăng nhập hoặc mật khẩu không đúng.</div>':''}<form method="post" action="/login"><div class="field"><label>Tên đăng nhập</label><input name="username" required autocomplete="username"></div><br><div class="field"><label>Mật khẩu</label><input name="password" type="password" required autocomplete="current-password"></div><br><button>Đăng nhập</button></form><p class="muted">Tài khoản do Admin cấp.</p></div>`)));
app.post("/login",(req,res)=>{const u=q("SELECT * FROM users WHERE username=? AND active=1").get(String(req.body.username||"").trim());if(!u||!bcrypt.compareSync(String(req.body.password||""),u.password_hash))return res.redirect("/login?e=1");req.session.user={id:u.id};res.redirect("/dashboard");});
app.post("/logout",(req,res)=>req.session.destroy(()=>res.redirect("/login")));
app.get("/dashboard",auth,(req,res)=>{
 const tasks=q("SELECT * FROM tasks WHERE user_id=? ORDER BY id DESC").all(req.user.id);
 const total=tasks.length, done=tasks.filter(t=>t.status==="done"), sum=done.reduce((a,t)=>a+t.price,0);
 const rows=tasks.map(t=>`<tr><td>${t.id}</td><td>${esc(t.account_label)}</td><td>${esc(t.note)}</td><td><span class="tag ${t.status==="done"?"done":""}">${t.status==="done"?"Đã hoàn thành":"Chưa làm"}</span></td><td>${money(t.price)}</td><td><div class="actions"><form method="post" action="/tasks/${t.id}/toggle"><button class="secondary">${t.status==="done"?"Hoàn tác":"Hoàn thành"}</button></form><form method="post" action="/tasks/${t.id}/delete" onsubmit="return confirm('Xóa mục này?')"><button class="danger">Xóa</button></form></div></td></tr>`).join("");
 const body=`<h1>Bảng điều khiển</h1><div class="stats"><div class="stat"><span class="muted">Tổng số acc ghi nhận</span><b>${total}</b></div><div class="stat"><span class="muted">Đã hoàn thành</span><b>${done.length}</b></div><div class="stat"><span class="muted">Tổng tiền hoàn thành</span><b>${money(sum)}</b></div></div>
 <div class="card"><h2>Thêm mục công việc</h2><form class="grid" method="post" action="/tasks"><div class="field"><label>Mã/tên nhận diện (không nhập mật khẩu hoặc mã 2FA)</label><input name="label" maxlength="100" required placeholder="Ví dụ: mã đơn 001"></div><div class="field"><label>Đơn giá (VNĐ)</label><input name="price" type="number" min="0" max="100000000" value="0" required></div><div class="field"><label>Ghi chú</label><input name="note" maxlength="200" placeholder="Tùy chọn"></div><button>Thêm</button></form></div>
 <div class="card"><div class="inline"><h2>Danh sách của tôi</h2><a class="btn secondary" href="/export.csv">Xuất CSV</a></div>${rows?`<div style="overflow-x:auto"><table><thead><tr><th>#</th><th>Mã/tên</th><th>Ghi chú</th><th>Trạng thái</th><th>Đơn giá</th><th>Thao tác</th></tr></thead><tbody>${rows}</tbody></table></div>`:'<p class="muted">Chưa có dữ liệu. Hãy thêm mục đầu tiên ở trên.</p>'}</div>
 ${req.user.role==="admin"?`<div class="card"><h2>Quản trị người dùng</h2><p class="muted">Tạo tài khoản riêng cho từng người. Admin không xem nội dung danh sách riêng của user.</p><a class="btn" href="/admin/users">Quản lý tài khoản</a></div>`:""}
 <p class="muted">Lưu ý: Đây là công cụ ghi nhận công việc và tính tiền, không thực hiện thay đổi 2FA, không lưu mật khẩu tài khoản bên ngoài, mã OTP hay khóa bí mật.</p>`;
 res.send(page("Bảng điều khiển",body,req.user));
});
app.post("/tasks",auth,(req,res)=>{const label=String(req.body.label||"").trim(),note=String(req.body.note||"").trim(),price=Number(req.body.price);if(!label||!Number.isSafeInteger(price)||price<0||price>100000000)return res.status(400).send("Dữ liệu không hợp lệ");q("INSERT INTO tasks(user_id,account_label,note,price) VALUES(?,?,?,?)").run(req.user.id,label,note,price);res.redirect("/dashboard");});
app.post("/tasks/:id/toggle",auth,(req,res)=>{q("UPDATE tasks SET status=CASE WHEN status='done' THEN 'pending' ELSE 'done' END,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?").run(Number(req.params.id),req.user.id);res.redirect("/dashboard");});
app.post("/tasks/:id/delete",auth,(req,res)=>{q("DELETE FROM tasks WHERE id=? AND user_id=?").run(Number(req.params.id),req.user.id);res.redirect("/dashboard");});
app.get("/export.csv",auth,(req,res)=>{const rows=q("SELECT account_label,note,status,price,created_at FROM tasks WHERE user_id=? ORDER BY id").all(req.user.id);const csv=["Ma/ten,Ghi chu,Trang thai,Don gia,Ngay tao",...rows.map(r=>[r.account_label,r.note,r.status,r.price,r.created_at].map(v=>'"'+String(v??"").replace(/"/g,'""')+'"').join(","))].join("\n");res.setHeader("Content-Type","text/csv; charset=utf-8");res.setHeader("Content-Disposition",'attachment; filename="danh-sach-cong-viec.csv"');res.send("\uFEFF"+csv);});
app.get("/admin/users",auth,admin,(req,res)=>{const users=q("SELECT id,username,active,created_at FROM users ORDER BY id").all();const rows=users.map(u=>`<tr><td>${u.id}</td><td>${esc(u.username)}</td><td>${u.active?"Đang hoạt động":"Đã khóa"}</td><td>${esc(u.created_at)}</td><td>${u.username===process.env.ADMIN_USERNAME?"Admin":`<form method="post" action="/admin/users/${u.id}/toggle"><button class="secondary">${u.active?"Khóa":"Mở khóa"}</button></form>`}</td></tr>`).join("");res.send(page("Quản lý user",`<h1>Quản lý tài khoản</h1><div class="card"><h2>Tạo user mới</h2><form method="post" action="/admin/users" class="grid"><div class="field"><label>Tên đăng nhập</label><input name="username" minlength="3" maxlength="32" pattern="[A-Za-z0-9_.-]+" required></div><div class="field"><label>Mật khẩu (tối thiểu 10 ký tự)</label><input name="password" type="password" minlength="10" required></div><div></div><button>Tạo tài khoản</button></form></div><div class="card"><h2>Danh sách user</h2><div style="overflow-x:auto"><table><tr><th>ID</th><th>Tên đăng nhập</th><th>Trạng thái</th><th>Ngày tạo</th><th></th></tr>${rows}</table></div><p><a href="/dashboard">← Quay lại</a></p></div>`,req.user));});
app.post("/admin/users",auth,admin,(req,res)=>{const username=String(req.body.username||"").trim(),password=String(req.body.password||"");if(!/^[A-Za-z0-9_.-]{3,32}$/.test(username)||password.length<10)return res.status(400).send("Tên đăng nhập hoặc mật khẩu không hợp lệ.");try{q("INSERT INTO users(username,password_hash) VALUES(?,?)").run(username,bcrypt.hashSync(password,12));res.redirect("/admin/users");}catch(e){res.status(400).send("Tên đăng nhập đã tồn tại.");}});
app.post("/admin/users/:id/toggle",auth,admin,(req,res)=>{q("UPDATE users SET active=1-active WHERE id=? AND role='user'").run(Number(req.params.id));res.redirect("/admin/users");});
const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`App listening on ${port}`));
