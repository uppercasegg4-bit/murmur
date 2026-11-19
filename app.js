(()=>{'use strict';
const $=id=>document.getElementById(id);
const dbName='murmur-local-v1';

const state={
  name:'', id:'', peer:null,
  connections:new Map(),
  active:null,
  contacts:{}, keys:{},
  theme:'system', accent:'#32836e', bubble:'rounded', ttl:0,
  revoked:new Set(), // id pesan yang sudah di-revoke
};

const accents=['#32836e','#527fe8','#8c69d4','#e38a55','#d65b76','#2998a8','#526477'];

/* ---------- Utilities ---------- */
function toast(t){const el=$('toast');if(!el)return;el.textContent=t;el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2600)}

function isSecureContextOk(){
  return window.isSecureContext && !!crypto?.subtle;
}

function db(){return new Promise((resolve,reject)=>{
  const r=indexedDB.open(dbName,1);
  r.onupgradeneeded=()=>r.result.createObjectStore('msgs',{keyPath:'key'});
  r.onsuccess=()=>resolve(r.result);
  r.onerror=()=>reject(r.error);
})}

async function putMsg(m){
  const d=await db();
  return new Promise((res,rej)=>{
    const tx=d.transaction('msgs','readwrite');
    tx.objectStore('msgs').put(m);
    tx.oncomplete=()=>res();
    tx.onerror=()=>rej(tx.error);
  });
}

async function getMsgs(peer){
  if(!state.id||!peer)return[];
  const d=await db();
  return new Promise((res,rej)=>{
    const tx=d.transaction('msgs','readonly');
    const r=tx.objectStore('msgs').getAll();
    r.onsuccess=()=>res(r.result
      .filter(x=>x.pair===pairKey(state.id,peer))
      .sort((a,b)=>a.ts-b.ts));
    r.onerror=()=>rej(r.error);
  });
}

async function deleteMsgs(peer){
  const d=await db();
  const list=await getMsgs(peer);
  return new Promise(res=>{
    const tx=d.transaction('msgs','readwrite');
    const s=tx.objectStore('msgs');
    list.forEach(m=>s.delete(m.key));
    tx.oncomplete=()=>res();
  });
}

async function deleteMessageById(key){
  if(!key)return;
  const d=await db();
  return new Promise(res=>{
    const tx=d.transaction('msgs','readwrite');
    tx.objectStore('msgs').delete(key);
    tx.oncomplete=()=>res();
  });
}

function pairKey(a,b){return[a,b].sort().join('::')}
function bytesToB64(b){return btoa(String.fromCharCode(...new Uint8Array(b)))}
function b64ToBytes(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}

/* ---------- Crypto (E2EE) ---------- */
async function getKey(peer){
  const pair=pairKey(state.id,peer);
  if(state.keys[pair])return state.keys[pair];
  const pass=localStorage.getItem('murmur_passphrase')||'';
  if(pass.length<8)throw new Error('Set a chat passphrase (minimum 8 characters) in settings first.');
  const salt=await crypto.subtle.digest('SHA-256',new TextEncoder().encode('murmur-v1:'+pair));
  const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(pass),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey(
    {name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},
    material,
    {name:'AES-GCM',length:256},
    false,
    ['encrypt','decrypt']
  );
  state.keys[pair]=key;
  return key;
}

async function encrypt(peer,obj){
  const k=await getKey(peer);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const data=new TextEncoder().encode(JSON.stringify(obj));
  const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,data);
  return{iv:bytesToB64(iv),cipher:bytesToB64(cipher)};
}

async function decrypt(peer,payload){
  const k=await getKey(peer);
  const clear=await crypto.subtle.decrypt(
    {name:'AES-GCM',iv:b64ToBytes(payload.iv)},
    k,
    b64ToBytes(payload.cipher)
  );
  return JSON.parse(new TextDecoder().decode(clear));
}

/* ---------- Contacts ---------- */
function persistContacts(){localStorage.setItem('murmur_contacts',JSON.stringify(state.contacts))}
function displayName(peer){const n=state.contacts[peer]?.name||'';return !n||n===peer?'Friend':n}
function addContact(id,name='Friend'){if(!id||id===state.id)return;state.contacts[id]={name:name||'Friend'};persistContacts();renderContacts();}

function renderContacts(){
  const box=$('contacts');if(!box)return;
  const q=$('searchContacts').value.toLowerCase();
  const ids=Object.keys(state.contacts).filter(id=>(displayName(id)+' '+id).toLowerCase().includes(q));
  if(!ids.length){box.innerHTML='<div class="empty">No contacts found.</div>';return}
  box.innerHTML='';
  ids.forEach(id=>{
    const b=document.createElement('button');
    b.className='contact'+(state.active===id?' active':'');
    b.innerHTML=`<div class="avatar">${escapeHtml(displayName(id).slice(0,1).toUpperCase())}</div>
      <div class="info"><strong>${escapeHtml(displayName(id))}</strong>
      <small>${state.connections.has(id)?'Connected':'Private contact'}</small></div>
      <span class="dot" title="Contact"></span>`;
    b.onclick=()=>selectChat(id);
    box.append(b);
  });
}

function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

/* ---------- Render pesan ---------- */
function renderMessage(m, opts={}){
  // Skip jika sudah di-revoke
  if(m.key && state.revoked.has(m.key)) return;

  const el=document.createElement('div');
  el.className='bubble'+(m.from===state.id?' mine':'');
  el.dataset.key=m.key||'';

  if(m.type==='text'){
    el.textContent=m.text;
  }else if(m.type==='file'){
    const a=document.createElement('a');
    a.textContent='📎 '+m.name+' ('+Math.ceil(m.size/1024)+' KB)';
    a.href=m.data;a.download=m.name;a.style.color='inherit';
    el.append(a);
  }

  // Tombol revoke untuk pesan sendiri
  if(m.from===state.id && m.key){
    const rev=document.createElement('button');
    rev.className='revoke-btn';
    rev.title='Hapus untuk semua';
    rev.textContent='🗑';
    rev.onclick=(e)=>{e.stopPropagation();revokeMessage(m);};
    el.append(rev);
    if(m.expireAt)el.classList.add('timer');
  }

  const time=document.createElement('span');
  time.className='time';
  const expireLabel=m.expireAt?` · ⏱ ${Math.max(0,Math.ceil((m.expireAt-Date.now())/1000))}s`:'';
  time.textContent=new Date(m.ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})+expireLabel;
  el.append(time);

  $('messages').append(el);
  $('messages').scrollTop=$('messages').scrollHeight;

  // Timer lokal: hapus dari UI + DB saat expire
  if(m.expireAt){
    const delay=m.expireAt-Date.now();
    if(delay<=0){
      el.remove();
      if(m.key)deleteMessageById(m.key);
    }else{
      const t=setTimeout(()=>{
        el.remove();
        if(m.key)deleteMessageById(m.key);
      },delay);
      el._timer=t;
      // update label countdown tiap detik
      const iv=setInterval(()=>{
        if(!document.body.contains(el)){clearInterval(iv);return;}
        const left=Math.ceil((m.expireAt-Date.now())/1000);
        if(left<=0){clearInterval(iv);return;}
        time.textContent=new Date(m.ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})+` · ⏱ ${left}s`;
      },1000);
      el._interval=iv;
    }
  }
}

/* ---------- Revoke (PRD WEB-005) ---------- */
async function revokeMessage(m){
  if(!confirm('Hapus pesan ini untuk semua?'))return;
  state.revoked.add(m.key);
  // Hapus dari DB
  await deleteMessageById(m.key);
  // Hapus dari UI
  const el=$('messages').querySelector(`[data-key="${CSS.escape(m.key)}"]`);
  if(el){clearTimeout(el._timer);clearInterval(el._interval);el.remove();}
  // Kirim sinyal revoke ke peer
  try{
    await sendObj(m.to,{__revoke:true,key:m.key});
  }catch(e){console.warn('Revoke signal failed',e);toast('Sinyal revoke gagal terkirim; peer mungkin masih melihat pesan.')}
  toast('Pesan dihapus untuk semua');
}

/* ---------- Chat ---------- */
async function selectChat(peer){
  state.active=peer;
  addContact(peer);
  $('app').classList.add('chatmode');
  $('chatTitle').textContent=displayName(peer);
  $('chatAvatar').textContent=displayName(peer).slice(0,1).toUpperCase();
  $('chatStatus').textContent=state.connections.has(peer)?'Connected securely (encrypted payloads)':'Not connected';
  $('messageInput').disabled=false;
  $('sendBtn').disabled=false;
  $('messages').innerHTML='';
  const history=await getMsgs(peer);
  history.forEach(renderMessage);
  renderContacts();
  connect(peer);
}

function connect(peer){
  if(state.connections.has(peer))return state.connections.get(peer);
  if(!state.peer){toast('Peer network is not ready yet');return null}
  const c=state.peer.connect(peer,{reliable:true,metadata:{murmur:1}});
  bindConnection(c);
  return c;
}

function bindConnection(c){
  if(!c||state.connections.has(c.peer))return;
  state.connections.set(c.peer,c);
  c.on('open',()=>{
    if(state.active===c.peer)$('chatStatus').textContent='Connected · encrypted chat';
    renderContacts();
  });
  c.on('data',async packet=>{
    try{
      if(packet?.murmur!==1||!packet.payload)return;
      const msg=await decrypt(c.peer,packet.payload);
      // Sinyal revoke
      if(msg.__revoke&&msg.key){
        state.revoked.add(msg.key);
        await deleteMessageById(msg.key);
        const el=$('messages').querySelector(`[data-key="${CSS.escape(msg.key)}"]`);
        if(el){clearTimeout(el._timer);clearInterval(el._interval);el.remove();}
        return;
      }
      if(!['text','file'].includes(msg.type))return;
      if(msg.expireAt&&msg.expireAt<Date.now())return;
      if(msg.key&&state.revoked.has(msg.key))return;
      msg.from=c.peer;msg.to=state.id;msg.pair=pairKey(state.id,c.peer);
      if(!msg.key)msg.key=crypto.randomUUID();
      await putMsg(msg);
      if(state.active===c.peer)renderMessage(msg);
      else toast('New message from '+displayName(c.peer));
    }catch(e){
      console.warn('decrypt failed',e);
      toast('Message could not be decrypted. Check your shared passphrase.');
    }
  });
  c.on('close',()=>{
    state.connections.delete(c.peer);
    if(state.active===c.peer)$('chatStatus').textContent='Disconnected';
    renderContacts();
  });
  c.on('error',e=>toast('Connection error: '+e.type));
  return c;
}

async function sendObj(peer,msg){
  const c=state.connections.get(peer)||connect(peer);
  if(!c||!c.open)throw new Error('Contact not connected yet. Wait for connection, then try again.');
  const payload=await encrypt(peer,msg);
  c.send({murmur:1,payload});
}

async function sendText(){
  const peer=state.active;
  const text=$('messageInput').value.trim();
  if(!peer||!text)return;
  if(text.length>2000){toast('Pesan maksimal 2000 karakter');return}
  const msg={
    type:'text',text,from:state.id,to:peer,ts:Date.now(),
    expireAt:state.ttl?Date.now()+state.ttl*1000:0,
    pair:pairKey(state.id,peer),
    key:crypto.randomUUID()
  };
  try{
    await sendObj(peer,msg);
    await putMsg(msg);
    renderMessage(msg);
    $('messageInput').value='';
    $('messageInput').style.height='auto';
  }catch(e){toast(e.message)}
}

async function sendFile(file){
  if(!state.active||!file)return;
  if(file.size>8*1024*1024){toast('File limit: 8 MB');return}
  const data=await new Promise((res,rej)=>{
    const r=new FileReader();
    r.onload=()=>res(r.result);
    r.onerror=()=>rej(r.error);
    r.readAsDataURL(file);
  });
  const msg={
    type:'file',name:file.name,size:file.size,mime:file.type,data,
    from:state.id,to:state.active,ts:Date.now(),
    expireAt:state.ttl?Date.now()+state.ttl*1000:0,
    pair:pairKey(state.id,state.active),
    key:crypto.randomUUID()
  };
  try{
    await sendObj(state.active,msg);
    await putMsg(msg);
    renderMessage(msg);
  }catch(e){toast(e.message)}
}

/* ---------- Settings / Modal ---------- */
function applyTheme(){
  document.body.classList.toggle('dark',state.theme==='dark'||(state.theme==='system'&&matchMedia('(prefers-color-scheme: dark)').matches));
  document.documentElement.style.setProperty('--accent',state.accent);
  document.documentElement.style.setProperty('--accent2',state.accent);
  document.documentElement.style.setProperty('--radius',
    state.bubble==='square'?'8px':state.bubble==='soft'?'14px':'20px');
}

function saveSettings(){
  localStorage.setItem('murmur_settings',JSON.stringify({
    theme:state.theme,accent:state.accent,bubble:state.bubble,ttl:state.ttl
  }));
  applyTheme();
}

function showModal(content){$('modal').innerHTML=content;$('modalback').style.display='flex'}
function closeModal(){$('modalback').style.display='none'}

function settings(){
  showModal(`<h2>Appearance & privacy</h2>
    <div class="field"><label>Theme</label><select id="setTheme">
      <option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></div>
    <div class="field"><label>Accent color</label><div class="colors" id="colorChoices"></div></div>
    <div class="field"><label>Message bubble shape</label><select id="setBubble">
      <option value="rounded">Rounded</option><option value="soft">Soft</option><option value="square">Square</option></select></div>
    <div class="field"><label>Disappearing messages (default)</label><select id="setTTL">
      <option value="0">Off</option><option value="10">10 seconds</option><option value="30">30 seconds</option>
      <option value="60">1 minute</option><option value="300">5 minutes</option>
      <option value="3600">1 hour</option><option value="86400">24 hours</option></select></div>
    <div class="field"><label>Auto-lock</label><select id="setAutoLock">
      <option value="30">30 seconds</option><option value="60">1 minute</option><option value="300">5 minutes</option>
      <option value="900">15 minutes</option><option value="1800">30 minutes</option>
      <option value="3600">1 hour</option><option value="0">Never</option></select></div>
    <div class="field"><label>Shared chat passphrase (8+ characters)</label>
      <input id="setPass" type="password" autocomplete="new-password" placeholder="Passphrase"></div>
    <p style="font-size:12px;color:var(--muted)">Passphrase is stored locally. This prototype does not provide forward secrecy or audited Signal Protocol security.</p>
    <div class="field"><button class="btn" style="width:100%" id="lockNow">Lock Murmur now</button></div>
    <hr style="border:0;border-top:1px solid var(--line);margin:18px 0">
    <div class="field"><button class="btn dangerbtn" style="width:100%" id="deleteMessagesBtn">Delete all messages</button></div>
    <div class="field"><button class="btn" style="width:100%" id="logoutBtn">Logout</button></div>
    <div class="field"><button class="btn dangerbtn" style="width:100%" id="wipeBtn">Wipe account & all local data</button></div>
    <div class="modalactions">
      <button class="btn" id="cancelSettings">Close</button>
      <button class="btn primary" id="saveSettings">Save changes</button>
    </div>`);
  $('setTheme').value=state.theme;
  $('setBubble').value=state.bubble;
  $('setTTL').value=String(state.ttl);
  $('setAutoLock').value=String(localStorage.getItem('murmur_autolock')||'300');
  $('setPass').value=localStorage.getItem('murmur_passphrase')||'';
  const choices=$('colorChoices');
  accents.forEach(col=>{
    const b=document.createElement('button');
    b.className='swatch'+(col===state.accent?' selected':'');
    b.style.background=col;b.title=col;
    b.onclick=()=>{state.accent=col;choices.querySelectorAll('.swatch').forEach(x=>x.classList.remove('selected'));b.classList.add('selected')};
    choices.append(b);
  });
  $('cancelSettings').onclick=closeModal;
  $('saveSettings').onclick=()=>{
    const p=$('setPass').value;
    if(p&&p.length<8){toast('Passphrase must be at least 8 characters');return}
    state.theme=$('setTheme').value;
    state.bubble=$('setBubble').value;
    state.ttl=Number($('setTTL').value);
    localStorage.setItem('murmur_autolock',$('setAutoLock').value);
    if(p)localStorage.setItem('murmur_passphrase',p);
    state.keys={}; // reset cache karena passphrase mungkin berubah
    saveSettings();resetLockTimer();closeModal();toast('Settings saved');
  };
  $('lockNow').onclick=()=>{closeModal();lockApp()};
  $('deleteMessagesBtn').onclick=async()=>{
    if(!confirm('Delete all messages stored on this device? This cannot be undone.'))return;
    await deleteAllMessages();closeModal();toast('All local messages deleted');
  };
  $('logoutBtn').onclick=logoutAccount;
  $('wipeBtn').onclick=wipeAccount;
}

function newChat(){
  showModal(`<h2>Start a conversation</h2>
    <div class="field"><label>Contact Peer ID</label><input id="peerInput" placeholder="Paste Murmur / Peer ID"></div>
    <div class="field"><label>Display name (optional)</label><input id="nameInput" placeholder="Contact name"></div>
    <div class="modalactions"><button class="btn" id="cancelNew">Cancel</button><button class="btn primary" id="startNew">Connect</button></div>`);
  $('cancelNew').onclick=closeModal;
  $('startNew').onclick=()=>{
    const id=$('peerInput').value.trim(),name=$('nameInput').value.trim();
    if(!id){toast('Enter a Peer ID');return}
    closeModal();addContact(id,name||'Friend');selectChat(id);
  };
}

async function safety(){
  if(!state.active){toast('Select a contact first');return}
  const pair=pairKey(state.id,state.active);
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode('murmur-safety-v1:'+pair));
  const finger=Array.from(new Uint8Array(digest)).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase().match(/.{1,4}/g).join(' ');
  showModal(`<h2>Contact verification</h2>
    <p>Compare this code with your contact over a separate trusted channel. This code identifies the ID pair, but does not by itself authenticate the person.</p>
    <div style="background:var(--bg);padding:14px;border-radius:12px;font-family:monospace;line-height:1.8;word-break:break-all">${finger}</div>
    <p style="color:var(--muted);font-size:12px">Your ID: ${escapeHtml(state.id)}<br>Contact ID: ${escapeHtml(state.active)}</p>
    <div class="modalactions"><button class="btn primary" id="okSafety">Close</button></div>`);
  $('okSafety').onclick=closeModal;
}

function profile(){
  showModal(`<h2>My profile</h2>
    <div class="profilecard">
      <div class="avatar avatar-large" style="margin:0 auto">${escapeHtml(state.name.slice(0,1).toUpperCase()||'M')}</div>
      <h2 style="margin:12px 0 4px">${escapeHtml(state.name)}</h2>
      <p style="color:var(--muted);font-size:13px">Peer ID</p>
      <div class="sharelink">${escapeHtml(state.id)}</div>
      <p style="color:var(--muted);font-size:12px;margin-top:14px">Bagikan ID ini ke kontak agar mereka dapat terhubung.</p>
    </div>
    <div class="modalactions"><button class="btn primary" id="okProfile">Close</button></div>`);
  $('okProfile').onclick=closeModal;
}

/* ---------- Lock ---------- */
let lockTimer=null,locked=false;

function resetLockTimer(){
  if(lockTimer)clearTimeout(lockTimer);
  if(locked)return;
  const seconds=Number(localStorage.getItem('murmur_autolock')||300);
  if(seconds>0)lockTimer=setTimeout(lockApp,seconds*1000);
}

function lockApp(){
  if(locked)return;
  locked=true;
  if(state.peer){try{state.peer.destroy()}catch{}}
  state.peer=null;state.connections.clear();
  $('lockscreen').classList.add('show');
  $('unlockPass').value='';
  setTimeout(()=>$('unlockPass').focus(),80);
}

function unlockApp(){
  const val=$('unlockPass').value;
  if(val!==localStorage.getItem('murmur_passphrase')){toast('Passphrase incorrect');$('unlockPass').value='';return}
  locked=false;
  $('lockscreen').classList.remove('show');
  bootNetworkOnly();
  resetLockTimer();
}

function bootNetworkOnly(){
  if(!window.Peer)return;
  if(state.peer&&state.peer.destroyed===false)return;
  try{
    state.peer=new Peer(state.id,{debug:0});
    state.peer.on('open',id=>{state.id=id;$('chatStatus').textContent='Peer network ready'});
    state.peer.on('connection',c=>{bindConnection(c);if(!state.contacts[c.peer])addContact(c.peer)});
    state.peer.on('error',e=>toast('Peer network: '+e.type));
  }catch(e){console.error(e)}
}

/* ---------- Data ops ---------- */
async function deleteAllMessages(){
  try{
    const d=await db();
    await new Promise((resolve,reject)=>{
      const tx=d.transaction('msgs','readwrite');
      tx.objectStore('msgs').clear();
      tx.oncomplete=resolve;
      tx.onerror=()=>reject(tx.error);
    });
    $('messages').innerHTML='<div class="empty"><div class="big">◌</div><strong>Messages cleared</strong><p>Local conversation history has been removed.</p></div>';
  }catch(e){toast('Unable to clear message database')}
}

function logoutAccount(){
  if(!confirm('Logout from Murmur on this device? Your local chats and contacts will be kept, but your identity setup will need to be completed again.'))return;
  try{state.peer?.destroy()}catch{}
  localStorage.removeItem('murmur_name');
  localStorage.removeItem('murmur_passphrase');
  locked=false;
  location.reload();
}

async function wipeAccount(){
  if(!confirm('WIPE ACCOUNT: permanently delete identity, contacts, messages, keys, settings and local data?'))return;
  if(!confirm('Last confirmation. This cannot be undone. Wipe everything now?'))return;
  try{state.peer?.destroy()}catch{}
  try{
    localStorage.clear();sessionStorage.clear();
    await new Promise(resolve=>{
      const req=indexedDB.deleteDatabase(dbName);
      req.onsuccess=req.onerror=req.onblocked=()=>resolve();
    });
  }finally{location.reload()}
}

/* ---------- Init ---------- */
function init(){
  if(!isSecureContextOk()){
    document.body.innerHTML='<div style="max-width:520px;margin:80px auto;padding:24px;font-family:system-ui;text-align:center">'+
      '<h1>⚠️ Secure context required</h1>'+
      '<p>Murmur needs HTTPS (or localhost) to use Web Crypto for E2EE.</p>'+
      '<p>Buka via <code>https://</code> atau <code>http://localhost</code>.</p></div>';
    return;
  }

  const user=localStorage.getItem('murmur_name');
  if(!user){
    showModal(`<h2>Welcome to Murmur</h2>
      <p>Choose a display name to create your private chat identity.</p>
      <div class="field"><label>Your name</label><input id="firstName" maxlength="32" placeholder="Display name"></div>
      <div class="field"><label>Chat passphrase (shared with contacts, 8+ characters)</label>
        <input id="firstPass" type="password" placeholder="Choose a passphrase"></div>
      <p style="color:var(--muted);font-size:12px">For this prototype, both people must use the same passphrase for their conversation.</p>
      <div class="modalactions"><button class="btn primary" id="createIdentity">Create identity</button></div>`);
    $('createIdentity').onclick=()=>{
      const n=$('firstName').value.trim(),p=$('firstPass').value;
      if(!n||p.length<8){toast('Enter a name and passphrase (8+ characters)');return}
      localStorage.setItem('murmur_name',n);
      localStorage.setItem('murmur_passphrase',p);
      closeModal();boot();
    };
    return;
  }
  boot();
}

function boot(){
  state.name=localStorage.getItem('murmur_name')||'Guest';
  state.id=localStorage.getItem('murmur_peerid');
  if(!state.id){
    state.id='murmur-'+crypto.randomUUID().replaceAll('-','').slice(0,18);
    localStorage.setItem('murmur_peerid',state.id);
  }
  try{state.contacts=JSON.parse(localStorage.getItem('murmur_contacts')||'{}')}catch{}
  try{
    const s=JSON.parse(localStorage.getItem('murmur_settings')||'{}');
    Object.assign(state,s);
  }catch{}
  $('myName').textContent=state.name;
  $('myId').value=state.id;
  applyTheme();renderContacts();resetLockTimer();

  if(!window.Peer){
    $('chatStatus').textContent='PeerJS failed to load';
    toast('PeerJS library unavailable');
    return;
  }
  state.peer=new Peer(state.id,{debug:0});
  state.peer.on('open',id=>{
    $('chatStatus').textContent='Peer network ready';
    $('myId').value=id;state.id=id;
  });
  state.peer.on('connection',c=>{
    bindConnection(c);
    if(!state.contacts[c.peer])addContact(c.peer,'Friend');
    toast('Incoming connection: '+displayName(c.peer));
  });
  state.peer.on('error',e=>{
    console.warn(e);
    if(e.type==='unavailable-id'){
      toast('Your ID is already in use. Refresh to generate a new ID.');
    }else toast('Peer network: '+e.type);
  });
}

/* ---------- Bind UI ---------- */
// Guard semua binding agar tidak crash jika elemen tidak ada
const bind=(id,evt,fn)=>{const el=$(id);if(el)el.addEventListener(evt,fn)};

bind('copyId','click',()=>{
  navigator.clipboard?.writeText(state.id)
    .then(()=>toast('ID copied'))
    .catch(()=>toast('Unable to copy'));
});
bind('newChat','click',newChat);
bind('settingsBtn','click',settings);
bind('profileBtn','click',profile);
bind('safetyBtn','click',safety);
bind('unlockBtn','click',unlockApp);
bind('unlockPass','keydown',e=>{if(e.key==='Enter')unlockApp()});
['pointerdown','keydown','touchstart','mousemove'].forEach(ev=>
  document.addEventListener(ev,resetLockTimer,{passive:true})
);
bind('sendBtn','click',sendText);
bind('attachBtn','click',()=>$('fileInput').click());
bind('fileInput','change',()=>{
  const f=$('fileInput').files[0];
  if(f)sendFile(f);
  $('fileInput').value='';
});
bind('messageInput','keydown',e=>{
  if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendText()}
});
bind('messageInput','input',e=>{
  e.target.style.height='auto';
  e.target.style.height=Math.min(e.target.scrollHeight,140)+'px';
});
bind('searchContacts','input',renderContacts);
bind('backBtn','click',()=>$('app').classList.remove('chatmode'));
bind('modalback','click',e=>{if(e.target===$('modalback'))closeModal()});

init();
})();
