"""Pro Workout local server. Python 3.10+, no third-party dependencies."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
from http.cookies import SimpleCookie
from pathlib import Path
import sqlite3, secrets, hashlib, hmac, json, re, time, os, threading, sys

ROOT=Path(__file__).resolve().parent
DB=ROOT/'data'/'pro_workout.sqlite3'
ROOT.joinpath('data').mkdir(exist_ok=True)
PORT=int(os.environ.get('PORT','8765'))
lock=threading.Lock()
attempts={}

def conn():
    db=sqlite3.connect(DB,timeout=15)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA journal_mode=WAL')
    return db

def init():
    with conn() as d:
        d.executescript('''
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS workouts(id TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, payload TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY(id,user_id));
        CREATE INDEX IF NOT EXISTS workouts_owner_idx ON workouts(user_id,created DESC);
        ''')

def password_hash(password,salt):
    return hashlib.scrypt(password.encode('utf-8'),salt=bytes.fromhex(salt),n=2**14,r=8,p=1).hex()

def valid_workout(w):
    return (isinstance(w,dict) and isinstance(w.get('id'),str) and 0<len(w['id'])<130 and re.fullmatch(r'\d{4}-\d{2}-\d{2}',str(w.get('date',''))) and isinstance(w.get('exercise'),str) and 0<len(w['exercise'])<120 and type(w.get('sets')) is int and 1<=w['sets']<=50 and type(w.get('reps')) is int and 1<=w['reps']<=500 and type(w.get('weight')) in (int,float) and 0<=w['weight']<=2000 and isinstance(w.get('notes',''),str) and len(w.get('notes',''))<2001)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(ROOT/'public'),**kwargs)
    def send_json(self,code,data,cookie=None):
        b=json.dumps(data).encode();self.send_response(code)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(b)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Frame-Options','DENY')
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(b)
    def user(self,d):
        c=SimpleCookie()
        try:c.load(self.headers.get('Cookie',''))
        except Exception:return None
        if 'pw_session' not in c:return None
        th=hashlib.sha256(c['pw_session'].value.encode()).hexdigest()
        return d.execute('SELECT users.id,users.name,users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires>?',(th,int(time.time()))).fetchone()
    def make_session(self,d,uid):
        token=secrets.token_urlsafe(40)
        d.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),uid,int(time.time())+86400*14))
        return f'pw_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1209600'
    def do_GET(self):
        route=urlparse(self.path).path
        if route.startswith('/api/'):
            with conn() as d:
                u=self.user(d)
                if route=='/api/me':return self.send_json(200,{'user':dict(u) if u else None})
                if not u:return self.send_json(401,{'error':'Please sign in.'})
                if route=='/api/workouts':
                    r=d.execute('SELECT payload FROM workouts WHERE user_id=? ORDER BY created DESC LIMIT 10000',(u['id'],)).fetchall()
                    return self.send_json(200,{'records':[json.loads(x['payload']) for x in r]})
            return self.send_json(404,{'error':'Not found'})
        if route not in ('/','/index.html','/accounts.js','/favicon.ico'):return self.send_error(404)
        self.send_header if False else None
        return super().do_GET()
    def do_POST(self):
        route=urlparse(self.path).path
        if not route.startswith('/api/'):return self.send_json(404,{'error':'Not found'})
        origin=self.headers.get('Origin')
        host=self.headers.get('Host','')
        if origin and urlparse(origin).netloc!=host:return self.send_json(403,{'error':'Invalid request origin'})
        if 'application/json' not in self.headers.get('Content-Type',''):return self.send_json(415,{'error':'JSON required'})
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=2000000:raise ValueError('Invalid request size')
            body=json.loads(self.rfile.read(size))
            if not isinstance(body,dict):raise ValueError('Invalid input')
        except Exception:return self.send_json(400,{'error':'Invalid request'})
        with conn() as d:
            if route=='/api/signup':
                name=str(body.get('name','')).strip()[:80];email=str(body.get('email','')).strip().lower();pw=body.get('password','')
                if len(name)<2 or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email) or not isinstance(pw,str) or not 10<=len(pw)<=256:return self.send_json(400,{'error':'Enter a name, valid email, and password of at least 10 characters.'})
                salt=secrets.token_hex(16);uid=secrets.token_hex(16)
                try:d.execute('INSERT INTO users VALUES(?,?,?,?,?,?)',(uid,name,email,salt,password_hash(pw,salt),int(time.time())))
                except sqlite3.IntegrityError:return self.send_json(409,{'error':'An account already uses this email.'})
                cookie=self.make_session(d,uid)
                return self.send_json(201,{'user':{'id':uid,'name':name,'email':email}},cookie)
            if route=='/api/login':
                email=str(body.get('email','')).strip().lower();pw=body.get('password','')
                ip=self.client_address[0];now=time.time()
                with lock:
                    arr=[t for t in attempts.get(ip,[]) if now-t<600];attempts[ip]=arr
                    if len(arr)>=15:return self.send_json(429,{'error':'Too many login attempts. Try again later.'})
                    arr.append(now)
                u=d.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                salt=u['salt'] if u else '00'*16
                match=hmac.compare_digest(password_hash(pw if isinstance(pw,str) else '',salt),u['hash'] if u else '00'*64)
                if not u or not match:return self.send_json(401,{'error':'Incorrect email or password.'})
                with lock:attempts.pop(ip,None)
                cookie=self.make_session(d,u['id'])
                return self.send_json(200,{'user':{'id':u['id'],'name':u['name'],'email':u['email']}},cookie)
            u=self.user(d)
            if not u:return self.send_json(401,{'error':'Please sign in again.'})
            if route=='/api/logout':
                c=SimpleCookie();c.load(self.headers.get('Cookie',''))
                if 'pw_session' in c:d.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(c['pw_session'].value.encode()).hexdigest(),))
                return self.send_json(200,{'ok':True},'pw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
            if route=='/api/workouts/add':
                w=body.get('workout')
                if not valid_workout(w):return self.send_json(400,{'error':'Workout fields are invalid.'})
                try:d.execute('INSERT INTO workouts VALUES(?,?,?,?)',(w['id'],u['id'],json.dumps(w),int(time.time()*1000)))
                except sqlite3.IntegrityError:return self.send_json(409,{'error':'Workout already exists.'})
                return self.send_json(201,{'ok':True})
            if route=='/api/workouts/delete':
                d.execute('DELETE FROM workouts WHERE id=? AND user_id=?',(str(body.get('id','')),u['id']))
                return self.send_json(200,{'ok':True})
            if route=='/api/workouts/replace':
                items=body.get('records')
                if not isinstance(items,list) or len(items)>10000 or not all(valid_workout(x) for x in items) or len(set(x['id'] for x in items))!=len(items):return self.send_json(400,{'error':'Invalid backup records.'})
                d.execute('DELETE FROM workouts WHERE user_id=?',(u['id'],))
                for x in items:d.execute('INSERT INTO workouts VALUES(?,?,?,?)',(x['id'],u['id'],json.dumps(x),int(time.time()*1000)))
                return self.send_json(200,{'ok':True})
        return self.send_json(404,{'error':'Not found'})

if __name__=='__main__':
    init()
    print(f'Pro Workout running at http://127.0.0.1:{PORT}')
    ThreadingHTTPServer(('127.0.0.1',PORT),Handler).serve_forever()
