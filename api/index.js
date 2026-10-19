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