const crypto=require('crypto'),{promisify}=require('util'),scrypt=promisify(crypto.scrypt);
const RU=process.env.UPSTASH_REDIS_REST_URL||process.env.KV_REST_API_URL,RT=process.env.UPSTASH_REDIS_REST_TOKEN||process.env.KV_REST_API_TOKEN;
const ADMIN_PASS=process.env.ADMIN_PASSWORD||'alanff11',IPLIM=process.env.IP_LIMIT===undefined?1:+process.env.IP_LIMIT,SPEED=3;
const PRODUCTS=[
{id:'cdb',n:'Nexus CDB 100% CDI',r:.135,v:0,risk:'Baixo',c:'#34d399'},
{id:'tes',n:'Tesouro Selic',r:.132,v:.004,risk:'Baixo',c:'#60a5fa'},
{id:'fii',n:'Fundo Imobiliário NXS',r:.16,v:.04,risk:'Médio',c:'#fbbf24'},
{id:'btc',n:'Cripto Index',r:.35,v:.12,risk:'Alto',c:'#f472b6'}];
const DEBIT="local a=tonumber(redis.call('GET',KEYS[1])) if not a or a<tonumber(ARGV[1]) then return 0 end redis.call('DECRBY',KEYS[1],ARGV[1]) return 1";
const XFER="local a=tonumber(redis.call('GET',KEYS[1])) if not a or a<tonumber(ARGV[1]) then return 0 end redis.call('DECRBY',KEYS[1],ARGV[1]) redis.call('INCRBY',KEYS[2],ARGV[1]) return 1";
const E=(c,m)=>({c,m}),R2=n=>Math.round(n*100)/100,rnd=n=>crypto.randomInt(n),hex=n=>crypto.randomBytes(n).toString('hex').toUpperCase();
async function rx(path,body){
if(!RU||!RT)throw E(500,'Banco de dados não configurado. Veja o README.');
const r=await fetch(RU+path,{method:'POST',headers:{Authorization:'Bearer '+RT},body:JSON.stringify(body)});
const d=await r.json();if(!r.ok)throw new Error(d.error||'redis');return d}
const rc=async c=>{const d=await rx('',c);if(d.error)throw new Error(d.error);return d.result};
const pipe=async cs=>(await rx('/pipeline',cs)).map(x=>{if(x.error)throw new Error(x.error);return x.result});
const ev=async(s,keys,args)=>(await rc(['EVAL',s,String(keys.length),...keys,...args.map(String)]))===1;
const hashPw=async(p,s)=>(await scrypt(p,s,32)).toString('hex');
const check=async(u,p)=>crypto.timingSafeEqual(Buffer.from(await hashPw(p,u.salt),'hex'),Buffer.from(u.hash,'hex'));
const getU=async n=>{const v=await rc(['GET','u:'+n]);return v?JSON.parse(v):null};
const prod=id=>PRODUCTS.find(p=>p.id===id);
const invValue=i=>{const p=prod(i.p),d=(Date.now()-i.t)/1000*SPEED;return i.a*Math.pow(1+p.r,d/365)*(1+p.v*(Math.sin(d/6+i.s)-Math.sin(i.s)))};
const tx=(t,v,k,x)=>JSON.stringify({id:hex(5),t,v,k,d:new Date().toISOString(),...x});
const pushTx=(n,s)=>[['LPUSH','t:'+n,s],['LTRIM','t:'+n,'0','49']];
const nameOf=v=>String(v||'').trim().toLowerCase().replace(/^@/,'');
async function limit(k){const n=await rc(['INCR','rl:'+k]);if(n===1)await rc(['EXPIRE','rl:'+k,'600']);if(n>20)throw E(429,'Muitas tentativas. Aguarde alguns minutos.')}
const cookieSid=req=>{const m=(req.headers.cookie||'').match(/(?:^|; )sid=([a-f0-9]+)/);return m&&m[1]};
async function start(c,u){const tk=crypto.randomBytes(24).toString('hex').toLowerCase();await rc(['SET','s:'+tk,u,'EX','604800']);
c.res.setHeader('Set-Cookie',`sid=${tk}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${process.env.VERCEL?'; Secure':''}`)}
function need(c,admin){if(!c.s)throw E(401,'Sessão expirada. Entre novamente.');if(admin&&c.s!=='admin')throw E(403,'Acesso negado.');if(!admin&&c.s==='admin')throw E(403,'Use uma conta de cliente.');return c.s}
async function view(n){const[u,b,t,h]=await pipe([['GET','u:'+n],['GET','b:'+n],['LRANGE','t:'+n,'0','49'],['HGETALL','inv:'+n]]);
const{salt,hash,ip,...r}=JSON.parse(u),inv=[];for(let i=0;i<h.length;i+=2)inv.push(JSON.parse(h[i+1]));
return{...r,bal:b/100,tx:t.map(x=>JSON.parse(x)),inv}}
const routes={
'POST /api/register':async c=>{await limit('r'+c.ip);const u=nameOf(c.b.user),p=String(c.b.pass||'');
if(!/^[a-z0-9_.]{3,16}$/.test(u)||u==='admin')throw E(400,'Use de 3 a 16 caracteres: letras, números, ponto ou _.');
if(p.length<4||p.length>64)throw E(400,'A senha precisa ter de 4 a 64 caracteres.');
const ipk='ip:'+c.ip,undo=()=>IPLIM>0?rc(['DECR',ipk]):0;
if(IPLIM>0&&await rc(['INCR',ipk])>IPLIM){await undo();throw E(403,'Limite atingido: apenas uma conta por IP.')}
const salt=crypto.randomBytes(8).toString('hex'),now=new Date().toISOString();
const rec={salt,hash:await hashPw(p,salt),ip:c.ip,frozen:false,card:'37'+Array.from({length:13},()=>rnd(10)).join(''),cvv:String(1000+rnd(9000)),exp:('0'+(1+rnd(12))).slice(-2)+'/'+(30+rnd(3)),acc:(10000+rnd(90000))+'-'+rnd(10),since:new Date().getFullYear(),created:now,last:now};
if(!await rc(['SET','u:'+u,JSON.stringify(rec),'NX'])){await undo();throw E(409,'Este usuário já existe.')}
await pipe([['SET','b:'+u,'10000'],['SADD','users',u],...pushTx(u,tx('Bônus de boas-vindas',100,'bonus'))]);await start(c,u);return{ok:1,isNew:1}},
'POST /api/login':async c=>{await limit('l'+c.ip);const u=nameOf(c.b.user),p=String(c.b.pass||'');
if(u==='admin'){if(p!==ADMIN_PASS)throw E(401,'Senha incorreta.');await start(c,'admin');return{ok:1}}
const x=await getU(u);if(!x)throw E(404,'Usuário não encontrado.');if(!await check(x,p))throw E(401,'Senha incorreta.');
x.last=new Date().toISOString();await rc(['SET','u:'+u,JSON.stringify(x)]);await start(c,u);return{ok:1}},
'POST /api/logout':async c=>{const s=cookieSid(c.req);if(s)await rc(['DEL','s:'+s]);return{ok:1}},
'GET /api/me':async c=>{const n=need(c,c.s==='admin');return n==='admin'?{role:'admin'}:{role:'user',name:n,products:PRODUCTS,u:await view(n)}},
'GET /api/ping':async c=>{const n=need(c),[b,t]=await pipe([['GET','b:'+n],['LINDEX','t:'+n,'0']]);return{bal:b/100,tx:t?JSON.parse(t).id:null}},
'GET /api/lookup':async c=>{const n=need(c),u=nameOf(c.url.searchParams.get('u'));if(u===n)throw E(400,'Você não pode transferir para si mesmo.');if(!await getU(u))throw E(404,'Usuário não encontrado.');return{ok:1,user:u}},
'POST /api/transfer':async c=>{const n=need(c);await limit('t'+n);const to=nameOf(c.b.to),a=R2(+c.b.amount),msg=String(c.b.msg||'').replace(/[<>&"']/g,'').slice(0,60);
if(to===n)throw E(400,'Você não pode transferir para si mesmo.');if(!(a>=.01))throw E(400,'Informe um valor válido.');if(a>5000)throw E(400,'Limite por transferência: R$ 5.000,00.');
const[A,B]=await Promise.all([getU(n),getU(to)]);if(!B)throw E(404,'Destinatário não encontrado.');
if(!await check(A,String(c.b.password||'')))throw E(401,'Senha incorreta.');
if(!await ev(XFER,['b:'+n,'b:'+to],[Math.round(a*100)]))throw E(400,'Saldo insuficiente.');
const id='NX'+hex(6);await pipe([...pushTx(n,tx('Pix para @'+to,-a,'out',{id,peer:to,msg})),...pushTx(to,tx('Pix de @'+n,a,'in',{id,peer:n,msg}))]);
const bal=await rc(['GET','b:'+n]);return{id,to,amount:a,msg,date:new Date().toISOString(),bal:bal/100}},
'POST /api/invest':async c=>{const n=need(c),a=R2(+c.b.amount);if(!prod(c.b.product))throw E(400,'Produto inválido.');if(!(a>=1))throw E(400,'Aplicação mínima: R$ 1,00.');
if(!await ev(DEBIT,['b:'+n],[Math.round(a*100)]))throw E(400,'Saldo insuficiente.');
const id=hex(4).toLowerCase();await pipe([['HSET','inv:'+n,id,JSON.stringify({id,p:c.b.product,a,t:Date.now(),s:Math.random()*6})],...pushTx(n,tx('Aplicação '+prod(c.b.product).n,-a,'inv'))]);return{ok:1}},
'POST /api/redeem':async c=>{const n=need(c),id=String(c.b.id||''),raw=await rc(['HGET','inv:'+n,id]);if(!raw)throw E(404,'Aplicação não encontrada.');
if(!await rc(['HDEL','inv:'+n,id]))throw E(404,'Aplicação não encontrada.');const i=JSON.parse(raw),v=R2(invValue(i));
await pipe([['INCRBY','b:'+n,String(Math.round(v*100))],...pushTx(n,tx('Resgate '+prod(i.p).n,v,'inv'))]);return{value:v}},
'POST /api/freeze':async c=>{const n=need(c),u=await getU(n);u.frozen=!u.frozen;await rc(['SET','u:'+n,JSON.stringify(u)]);return{frozen:u.frozen}},
'GET /api/admin/users':async c=>{need(c,1);const names=await rc(['SMEMBERS','users']);if(!names.length)return{users:[]};
const r=await pipe(names.flatMap(n=>[['GET','u:'+n],['GET','b:'+n],['HGETALL','inv:'+n]]));
return{users:names.map((k,i)=>{const u=JSON.parse(r[i*3]),h=r[i*3+2];let inv=0;for(let j=1;j<h.length;j+=2)inv+=invValue(JSON.parse(h[j]));
return{user:k,ip:u.ip,bal:r[i*3+1]/100,inv:R2(inv),last:u.last,created:u.created}})}},
'POST /api/admin/adjust':async c=>{need(c,1);const u=nameOf(c.b.user),a=R2(+c.b.amount),s=+c.b.sign>0?1:-1;
if(!await getU(u))throw E(404,'Usuário não encontrado.');if(!(a>0))throw E(400,'Digite um valor válido.');
const cents=Math.round(a*100);if(s>0)await rc(['INCRBY','b:'+u,String(cents)]);else if(!await ev(DEBIT,['b:'+u],[cents]))throw E(400,'Saldo insuficiente.');
await pipe(pushTx(u,tx(s>0?'Crédito Nexus':'Débito Nexus',s*a,'adm')));return{ok:1}}};
module.exports=async(req,res)=>{try{
const url=new URL(req.url,'http://x'),h=routes[req.method+' '+url.pathname.replace(/\/$/,'')];if(!h)throw E(404,'Rota não encontrada.');
const sid=cookieSid(req),c={req,res,url,b:req.body&&typeof req.body==='object'?req.body:{},
ip:String(req.headers['x-real-ip']||String(req.headers['x-forwarded-for']||'').split(',')[0]||req.socket.remoteAddress||'0').trim().replace('::ffff:',''),
s:sid?await rc(['GET','s:'+sid]):null};
res.setHeader('Cache-Control','no-store');res.status(200).json(await h(c))}
catch(e){if(e&&e.c)res.status(e.c).json({error:e.m});else{console.error(e);res.status(500).json({error:'Erro interno.'})}}};
