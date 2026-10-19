const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=+process.env.PORT||3000,DIR=process.env.DATA_DIR||__dirname,FILE=path.join(DIR,'data.json'),PUB=path.join(__dirname,'..','public');
const ADMIN_PASS=process.env.ADMIN_PASSWORD||'alanff11',TP=!!process.env.TRUST_PROXY;
const IPLIM=process.env.IP_LIMIT===undefined?1:+process.env.IP_LIMIT,SPEED=3;
const PRODUCTS=[
{id:'cdb',n:'Nexus CDB 100% CDI',r:.135,v:0,risk:'Baixo',c:'#34d399'},
{id:'tes',n:'Tesouro Selic',r:.132,v:.004,risk:'Baixo',c:'#60a5fa'},
{id:'fii',n:'Fundo Imobiliário NXS',r:.16,v:.04,risk:'Médio',c:'#fbbf24'},
{id:'btc',n:'Cripto Index',r:.35,v:.12,risk:'Alto',c:'#f472b6'}];
let db={users:{},sessions:{}};
try{db=JSON.parse(fs.readFileSync(FILE,'utf8'))}catch(e){}
db.users=db.users||{};db.sessions=db.sessions||{};
const save=()=>{fs.mkdirSync(DIR,{recursive:true});const t=FILE+'.tmp';fs.writeFileSync(t,JSON.stringify(db));fs.renameSync(t,FILE)};
const E=(c,m)=>({c,m}),R2=n=>Math.round(n*100)/100,rnd=n=>crypto.randomInt(n);
const hash=(p,s)=>crypto.scryptSync(p,s,32).toString('hex');
const check=(u,p)=>crypto.timingSafeEqual(Buffer.from(hash(p,u.salt),'hex'),Buffer.from(u.hash,'hex'));
const prod=id=>PRODUCTS.find(p=>p.id===id);
const invValue=i=>{const p=prod(i.p),d=(Date.now()-i.t)/1000*SPEED;return i.a*Math.pow(1+p.r,d/365)*(1+p.v*(Math.sin(d/6+i.s)-Math.sin(i.s)))};
const addTx=(u,t,v,k,x)=>{u.tx.unshift({id:crypto.randomBytes(5).toString('hex').toUpperCase(),t,v,k,d:new Date().toISOString(),...x});u.tx=u.tx.slice(0,50)};
function mkUser(p,ip){const salt=crypto.randomBytes(8).toString('hex'),now=new Date().toISOString();
const u={salt,hash:hash(p,salt),ip,bal:100,inv:[],tx:[],frozen:false,card:'37'+Array.from({length:13},()=>rnd(10)).join(''),cvv:String(1000+rnd(9000)),exp:('0'+(1+rnd(12))).slice(-2)+'/'+(30+rnd(3)),acc:(10000+rnd(90000))+'-'+rnd(10),since:new Date().getFullYear(),created:now,last:now};
addTx(u,'Bônus de boas-vindas',100,'bonus');return u}
const pub=u=>{const{salt,hash,ip,...r}=u;return r};
const tries={};
function limit(k){const t=tries[k]=tries[k]||{n:0,t:Date.now()};if(Date.now()-t.t>6e5){t.n=0;t.t=Date.now()}if(++t.n>20)throw E(429,'Muitas tentativas. Aguarde alguns minutos.')}
function getIp(req){let ip=req.socket.remoteAddress||'';if(TP)ip=(req.headers['x-forwarded-for']||'').split(',')[0].trim()||ip;return ip.replace('::ffff:','')}
function sess(req){const m=(req.headers.cookie||'').match(/(?:^|; )sid=([a-f0-9]+)/),s=m&&db.sessions[m[1]];return s&&s.exp>Date.now()?s.u:null}
function start(c,u){const now=Date.now();for(const k in db.sessions)if(db.sessions[k].exp<now)delete db.sessions[k];
const tk=crypto.randomBytes(24).toString('hex');db.sessions[tk]={u,exp:now+7*864e5};
c.res.setHeader('Set-Cookie',`sid=${tk}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${c.req.headers['x-forwarded-proto']==='https'?'; Secure':''}`)}
function need(c,admin){if(!c.s||(c.s!=='admin'&&!db.users[c.s]))throw E(401,'Sessão expirada. Entre novamente.');if(admin&&c.s!=='admin')throw E(403,'Acesso negado.');if(!admin&&c.s==='admin')throw E(403,'Use uma conta de cliente.');return c.s}
const nameOf=v=>String(v||'').trim().toLowerCase().replace(/^@/,'');
const routes={
'POST /api/register':c=>{limit(c.ip);const u=nameOf(c.b.user),p=String(c.b.pass||'');
if(!/^[a-z0-9_.]{3,16}$/.test(u)||u==='admin')throw E(400,'Use de 3 a 16 caracteres: letras, números, ponto ou _.');
if(p.length<4||p.length>64)throw E(400,'A senha precisa ter de 4 a 64 caracteres.');
if(db.users[u])throw E(409,'Este usuário já existe.');
if(IPLIM>0&&Object.values(db.users).filter(x=>x.ip===c.ip).length>=IPLIM)throw E(403,'Limite atingido: apenas uma conta por IP.');
db.users[u]=mkUser(p,c.ip);start(c,u);save();return{ok:1,isNew:1}},
'POST /api/login':c=>{limit(c.ip);const u=nameOf(c.b.user),p=String(c.b.pass||'');
if(u==='admin'){if(p!==ADMIN_PASS)throw E(401,'Senha incorreta.');start(c,'admin');save();return{ok:1}}
const x=db.users[u];if(!x)throw E(404,'Usuário não encontrado.');if(!check(x,p))throw E(401,'Senha incorreta.');
x.last=new Date().toISOString();start(c,u);save();return{ok:1}},
'POST /api/logout':c=>{const m=(c.req.headers.cookie||'').match(/sid=([a-f0-9]+)/);if(m)delete db.sessions[m[1]];save();return{ok:1}},
'GET /api/me':c=>{const n=need(c,c.s==='admin');return n==='admin'?{role:'admin'}:{role:'user',name:n,products:PRODUCTS,u:pub(db.users[n])}},
'GET /api/lookup':c=>{need(c);const u=nameOf(c.url.searchParams.get('u'));if(!db.users[u])throw E(404,'Usuário não encontrado.');if(u===c.s)throw E(400,'Você não pode transferir para si mesmo.');return{ok:1,user:u}},
'POST /api/transfer':c=>{const n=need(c);limit('t'+n);const A=db.users[n],to=nameOf(c.b.to),B=db.users[to],a=R2(+c.b.amount),msg=String(c.b.msg||'').replace(/[<>&"']/g,'').slice(0,60);
if(!B)throw E(404,'Destinatário não encontrado.');if(to===n)throw E(400,'Você não pode transferir para si mesmo.');
if(!(a>=.01))throw E(400,'Informe um valor válido.');if(a>5000)throw E(400,'Limite por transferência: R$ 5.000,00.');if(a>A.bal)throw E(400,'Saldo insuficiente.');
if(!check(A,String(c.b.password||'')))throw E(401,'Senha incorreta.');
A.bal=R2(A.bal-a);B.bal=R2(B.bal+a);const id='NX'+crypto.randomBytes(6).toString('hex').toUpperCase();
addTx(A,'Pix para @'+to,-a,'out',{peer:to,msg});addTx(B,'Pix de @'+n,a,'in',{peer:n,msg});A.tx[0].id=B.tx[0].id=id;save();
return{id,to,amount:a,msg,date:A.tx[0].d,bal:A.bal}},
'POST /api/invest':c=>{const n=need(c),u=db.users[n],a=R2(+c.b.amount);if(!prod(c.b.product))throw E(400,'Produto inválido.');
if(!(a>=1))throw E(400,'Aplicação mínima: R$ 1,00.');if(a>u.bal)throw E(400,'Saldo insuficiente.');
u.bal=R2(u.bal-a);u.inv.push({id:crypto.randomBytes(4).toString('hex'),p:c.b.product,a,t:Date.now(),s:Math.random()*6});addTx(u,'Aplicação '+prod(c.b.product).n,-a,'inv');save();return{ok:1}},
'POST /api/redeem':c=>{const n=need(c),u=db.users[n],i=u.inv.find(x=>x.id===c.b.id);if(!i)throw E(404,'Aplicação não encontrada.');
const v=R2(invValue(i));u.bal=R2(u.bal+v);u.inv=u.inv.filter(x=>x!==i);addTx(u,'Resgate '+prod(i.p).n,v,'inv');save();return{value:v}},
'GET /api/ping':c=>{const u=db.users[need(c)];return{tx:u.tx[0]&&u.tx[0].id,bal:u.bal}},
'POST /api/freeze':c=>{const u=db.users[need(c)];u.frozen=!u.frozen;save();return{frozen:u.frozen}},
'GET /api/admin/users':c=>{need(c,1);return{users:Object.entries(db.users).map(([k,o])=>({user:k,ip:o.ip,bal:o.bal,inv:R2(o.inv.reduce((s,i)=>s+invValue(i),0)),last:o.last,created:o.created}))}},
'POST /api/admin/adjust':c=>{need(c,1);const u=db.users[nameOf(c.b.user)],a=R2(+c.b.amount),s=+c.b.sign>0?1:-1;if(!u)throw E(404,'Usuário não encontrado.');
if(!(a>0))throw E(400,'Digite um valor válido.');if(s<0&&a>u.bal)throw E(400,'Saldo insuficiente.');u.bal=R2(u.bal+s*a);addTx(u,s>0?'Crédito Nexus':'Débito Nexus',s*a,'adm');save();return{ok:1}}};
const MIME={'.html':'text/html; charset=utf-8','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
function serve(req,res){let p;try{p=decodeURIComponent(req.url.split('?')[0])}catch(e){p='/'}if(p==='/')p='/index.html';const f=path.join(PUB,path.normalize(p));
if(!f.startsWith(PUB)){res.writeHead(403);return res.end()}
fs.readFile(f,(e,d)=>{if(e){res.writeHead(404);return res.end('Não encontrado')}res.writeHead(200,{'Content-Type':MIME[path.extname(f)]||'application/octet-stream','X-Content-Type-Options':'nosniff','Cache-Control':'no-cache'});res.end(d)})}
const send=(res,c,o)=>{res.writeHead(c,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(o))};
const body=req=>new Promise((ok,no)=>{let d='';req.on('data',x=>{d+=x;if(d.length>1e4){req.destroy();no(E(413,'Requisição muito grande.'))}});req.on('end',()=>{try{ok(d?JSON.parse(d):{})}catch(e){no(E(400,'JSON inválido.'))}})});
http.createServer(async(req,res)=>{try{
if(!req.url.startsWith('/api/'))return serve(req,res);
const url=new URL(req.url,'http://x'),h=routes[req.method+' '+url.pathname];if(!h)throw E(404,'Rota não encontrada.');
send(res,200,h({req,res,url,ip:getIp(req),b:req.method==='POST'?await body(req):{},s:sess(req)}))}
catch(e){if(e&&e.c)send(res,e.c,{error:e.m});else{console.error(e);send(res,500,{error:'Erro interno.'})}}
}).listen(PORT,()=>console.log('Nexus Bank rodando na porta '+PORT));
