(()=>{'use strict';
const $=id=>document.getElementById(id), dbName='murmur-local-v2';
const state={name:'',id:'',identity:null,peer:null,connections:new Map(),active:null,contacts:{},theme:'system',accent:'#32836e',bubble:'rounded',ttl:0};
const accents=['#32836e','#527fe8','#8c69d4','#e38a55','#d65b76','#2998a8','#526477'];

/* ---------- helpers ---------- */
function toast(t){const el=$('toast');el.textContent=t;el.classList.add('show');clearTimeout(toast._t);toast._t=setTimeout(()=>el.classList.remove('show'),3000)}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function bytesToB64(b){return btoa(String.fromCharCode(...new Uint8Array(b)))}
function b64ToBytes(s){const bin=atob(s),a=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i);return a}
function pairKey(a,b){return[a,b].sort().join('::')}
function displayName(peer){return state.contacts[peer]?.name||peer}

/* ---------- IndexedDB ---------- */
function openDB(){return new Promise((res,rej)=>{const r=indexedDB.open(dbName,1);r.onupgradeneeded=()=>{const d=r.result;if(!d.objectStoreNames.contains('msgs'))d.createObjectStore('msgs',{keyPath:'key'});if(!d.objectStoreNames.contains('meta'))d.createObjectStore('meta',{keyPath:'key'})};r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)})}
async function metaGet(k){const d=await openDB();return new Promise((res,rej)=>{const r=d.transaction('meta','readonly').objectStore('meta').get(k);r.onsuccess=()=>res(r.result?.value);r.onerror=()=>rej(r.error)})}
async function metaSet(k,v){const d=await openDB();return new Promise((res,rej)=>{const tx=d.transaction('meta','readwrite');tx.objectStore('meta').put({key:k,value:v});tx.oncomplete=()=>res();tx.onerror=()=>rej(tx.error)})}
async function putMsg(m){const d=await openDB();return new Promise((res,rej)=>{const tx=d.transaction('msgs','readwrite');tx.objectStore('msgs').put(m);tx.oncomplete=()=>res();tx.onerror=()=>rej(tx.error)})}
async function getMsgs(peer){const d=await openDB();return new Promise((res,rej)=>{const r=d.transaction('msgs','readonly').objectStore('msgs').getAll();r.onsuccess=()=>res(r.result.filter(x=>x.pair===pairKey(state.id,peer)).sort((a,b)=>a.ts-b.ts));r.onerror=()=>rej(r.error)})}

/* ---------- CRYPTO ---------- */
async function generateIdentity(){
  const temp=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const pubRaw=new Uint8Array(await crypto.subtle.exportKey('raw',temp.publicKey));
  const privJwk=await crypto.subtle.exportKey('jwk',temp.privateKey);
  const privateKey=await crypto.subtle.importKey('jwk',privJwk,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  return {privateKey, publicRaw:pubRaw};
}
async function importPeerPub(rawB64){return crypto.subtle.importKey('raw',b64ToBytes(rawB64),{name:'ECDH',namedCurve:'P-256'},false,[])}
async function computeShared(priv,pub){return new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:pub},priv,256))}
async function deriveMsgKey(shared){const ikm=await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(0),info:new TextEncoder().encode('murmur-v2-msg')},ikm,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}

async function encryptForPeer(theirPub, plaintext){
  const eph=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const shared=await computeShared(eph.privateKey, theirPub);
  const key=await deriveMsgKey(shared);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(plaintext));
  const ephPub=new Uint8Array(await crypto.subtle.exportKey('raw',eph.publicKey));
  return {eph:bytesToB64(ephPub), iv:bytesToB64(iv), ct:bytesToB64(ct)};
}
async function decryptFromPeer(ourPriv, ephB64, ivB64, ctB64){
  const ephPub=await importPeerPub(ephB64);
  const shared=await computeShared(ourPriv, ephPub);
  const key=await deriveMsgKey(shared);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64ToBytes(ivB64)},key,b64ToBytes(ctB64));
  return new TextDecoder().decode(pt);
}
async function safetyNumber(ourPub, theirPub){
  const a=new Uint8Array(ourPub), b=new Uint8Array(theirPub);
  const [x,y]=[a,b].sort((p,q)=>{for(let i=0;i<Math.min(p.length,q.length);i++)if(p[i]!==q[i])return p[i]-q[i];return p.length-q.length});
  const combined=new Uint8Array(x.length+y.length);combined.set(x,0);combined.set(y,x.length);
  const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',combined));
  let big=0n;for(let i=0;i<25;i++)big=(big<<8n)|BigInt(hash[i]);
  let str=big.toString();while(str.length<60)str='0'+str;str=str.slice(0,60);
  return str.match(/.{1,5}/g).join(' ');
}

/* ---------- contacts ---------- */
function persistContacts(){localStorage.setItem('murmur_contacts',JSON.stringify(state.contacts))}
function addContact(id,name=id){if(!id||id===state.id)return;if(!state.contacts[id]){state.contacts[id]={name:name||id,pubKey:null,verified:false};persistContacts();renderContacts()}}
function renderContacts(){
  const box=$('contacts'),q=$('searchContacts').value.toLowerCase();
  const ids=Object.keys(state.contacts).filter(id=>(displayName(id)+' '+id).toLowerCase().includes(q));
  if(!ids.length){box.innerHTML='<div class="empty">No conversations yet.<br>Tap “Add friend” to start.</div>';return}
  box.innerHTML='';
  ids.forEach(id=>{
    const c=state.contacts[id], b=document.createElement('button');
    b.className='contact'+(state.active===id?' active':'');
    const badge=c.verified?'<span class="badge verified" title="Verified">✓</span>':'<span class="badge unverified" title="Unverified">!</span>';
    b.innerHTML=`<div class="avatar">${escapeHtml(displayName(id).slice(0,1).toUpperCase())}</div><div class="info"><strong>${escapeHtml(displayName(id))}</strong><small>${escapeHtml(id)}</small></div>${badge}`;
    b.onclick=()=>selectChat(id);box.append(b);
  });
}

/* ---------- messages ---------- */
function renderMessage(m){
  const el=document.createElement('div');el.className='bubble'+(m.from===state.id?' mine':'');
  if(m.type==='text')el.textContent=m.text;
  else if(m.type==='file'){const a=document.createElement('a');a.textContent='📎 '+m.name+' ('+Math.ceil(m.size/1024)+' KB)';a.href=m.data;a.download=m.name;a.style.color='inherit';el.append(a)}
  const time=document.createElement('span');time.className='time';time.textContent=new Date(m.ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});el.append(time);
  $('messages').append(el);$('messages').scrollTop=$('messages').scrollHeight;
  if(m.expireAt){const d=m.expireAt-Date.now();if(d<=0)el.remove();else setTimeout(()=>el.remove(),d)}
}

function updateChatStatus(){
  if(!state.active)return;
  const c=state.contacts[state.active], conn=state.connections.get(state.active);
  let s = conn?.open?'Connected':'Connecting…';
  if(!c?.pubKey)s+=' · Exchanging keys…';
  else if(c.verified)s+=' · 🔒 Verified';
  else s+=' · ⚠ Unverified';
  $('chatStatus').textContent=s;
  if(state.active){const a=state.contacts[state.active];$('chatAvatar').textContent=(a?.name||'?').slice(0,1).toUpperCase()}
}

async function selectChat(peer){
  state.active=peer;addContact(peer);
  $('app').classList.add('chatmode');
  $('chatTitle').textContent=displayName(peer);
  updateChatStatus();
  $('messageInput').disabled=false;$('sendBtn').disabled=false;
  $('messages').innerHTML='<div class="empty"><div class="big">◌</div><strong>Loading…</strong></div>';
  const history=await getMsgs(peer);
  if(state.active!==peer)return;
  $('messages').innerHTML='';
  if(!history.length)$('messages').innerHTML='<div class="empty"><div class="big">◌</div><strong>Say hello.</strong><p>Messages are encrypted on your device with per-message ephemeral keys.</p></div>';
  else history.forEach(renderMessage);
  renderContacts();
  if(!state.connections.has(peer))connect(peer);
}

/* ---------- connections ---------- */
function connect(peer){
  if(state.connections.has(peer))return state.connections.get(peer);
  if(!state.peer||state.peer.destroyed){toast('Peer network not ready');return null}
  const c=state.peer.connect(peer,{reliable:true,metadata:{murmur:2}});
  return bindConnection(c);
}

function bindConnection(c){
  if(!c||state.connections.has(c.peer))return c;
  state.connections.set(c.peer,c);
  c.on('open',()=>{
    if(state.active===c.peer)updateChatStatus();
    try{c.send({murmur:2,type:'handshake',pub:bytesToB64(state.identity.publicRaw)})}catch(e){console.warn('handshake send failed',e)}
    renderContacts();
  });
  c.on('data',async packet=>{
    try{
      if(packet?.murmur!==2)return;
      if(packet.type==='handshake'){await handleHandshake(c.peer,packet.pub);return}
      if(packet.type==='msg'){
        const contact=state.contacts[c.peer];
        if(!contact?.pubKey){toast('Received message before key exchange');return}
        const json=await decryptFromPeer(state.identity.privateKey,packet.eph,packet.iv,packet.ct);
        const msgObj=JSON.parse(json);
        if(!['text','file'].includes(msgObj.type))return;
        if(msgObj.expireAt&&msgObj.expireAt<Date.now())return;
        const msg={...msgObj,from:c.peer,to:state.id,pair:pairKey(state.id,c.peer),key:crypto.randomUUID()};
        await putMsg(msg);
        if(state.active===c.peer)renderMessage(msg);
        else toast('New message from '+displayName(c.peer));
      }
    }catch(e){console.warn('decrypt failed',e);toast('Could not decrypt message')}
  });
  c.on('close',()=>{
    state.connections.delete(c.peer);
    if(state.active===c.peer)updateChatStatus();
    renderContacts();
  });
  c.on('error',e=>{
    state.connections.delete(c.peer);
    if(state.active===c.peer)updateChatStatus();
    if(e?.type==='peer-unavailable')toast('Contact is offline or ID is invalid');
    else toast('Connection error: '+(e?.type||'unknown'));
  });
  return c;
}

async function handleHandshake(peerId, pubB64){
  if(!state.contacts[peerId])addContact(peerId);
  const contact=state.contacts[peerId];
  const isNew=!contact.pubKey;
  const changed=contact.pubKey && contact.pubKey!==pubB64;
  contact.pubKey=pubB64;
  if(isNew){
    contact.verified=false;persistContacts();renderContacts();updateChatStatus();
    toast('Key received. Tap ⌁ to verify '+displayName(peerId));
  }else if(changed){
    contact.verified=false;persistContacts();renderContacts();updateChatStatus();
    showKeyChangeAlert(peerId);
  }else{
    updateChatStatus();
  }
}

/* ---------- send ---------- */
async function sendObj(peer, msgObj){
  const contact=state.contacts[peer];
  if(!contact?.pubKey)throw new Error('Waiting for key exchange…');
  const c=state.connections.get(peer);
  if(!c?.open)throw new Error('Not connected');
  const theirPub=await importPeerPub(contact.pubKey);
  const encrypted=await encryptForPeer(theirPub, JSON.stringify(msgObj));
  c.send({murmur:2,type:'msg',...encrypted});
}

async function sendText(){
  const peer=state.active, text=$('messageInput').value.trim();
  if(!peer||!text)return;
  const msgObj={type:'text',text,ts:Date.now(),expireAt:state.ttl?Date.now()+state.ttl*1000:0};
  try{
    await sendObj(peer,msgObj);
    const local={...msgObj,from:state.id,to:peer,pair:pairKey(state.id,peer),key:crypto.randomUUID()};
    await putMsg(local);
    $('messageInput').value='';$('messageInput').style.height='auto';
    if(state.active===peer)renderMessage(local);
  }catch(e){toast(e.message)}
}

async function sendFile(file){
  if(!state.active||!file)return;
  if(file.size>8*1024*1024){toast('File limit: 8 MB');return}
  const peer=state.active;
  const data=await new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result);r.onerror=()=>rej(r.error);r.readAsDataURL(file)});
  const msgObj={type:'file',name:file.name,size:file.size,mime:file.type,data,ts:Date.now(),expireAt:state.ttl?Date.now()+state.ttl*1000:0};
  try{
    await sendObj(peer,msgObj);
    const local={...msgObj,from:state.id,to:peer,pair:pairKey(state.id,peer),key:crypto.randomUUID()};
    await putMsg(local);
    if(state.active===peer)renderMessage(local);
  }catch(e){toast(e.message)}
}

/* ---------- appearance ---------- */
function applyTheme(){
  document.body.classList.toggle('dark',state.theme==='dark'||(state.theme==='system'&&matchMedia('(prefers-color-scheme: dark)').matches));
  document.documentElement.style.setProperty('--accent',state.accent);
  document.documentElement.style.setProperty('--accent2',state.accent);
  document.documentElement.style.setProperty('--radius',state.bubble==='square'?'8px':state.bubble==='soft'?'14px':'20px');
}
function saveSettings(){localStorage.setItem('murmur_settings',JSON.stringify({theme:state.theme,accent:state.accent,bubble:state.bubble,ttl:state.ttl}));applyTheme()}

/* ---------- modals ---------- */
function showModal(html){$('modal').innerHTML=html;$('modalback').style.display='flex'}
function closeModal(){$('modalback').style.display='none'}

function settings(){
  showModal(`<h2>Appearance & privacy</h2>
  <div class="field"><label>Theme</label><select id="setTheme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></div>
  <div class="field"><label>Accent color</label><div class="colors" id="colorChoices"></div></div>
  <div class="field"><label>Message bubble shape</label><select id="setBubble"><option value="rounded">Rounded</option><option value="soft">Soft</option><option value="square">Square</option></select></div>
  <div class="field"><label>Disappearing messages</label><select id="setTTL"><option value="0">Off</option><option value="30">30 seconds</option><option value="60">1 minute</option><option value="300">5 minutes</option><option value="3600">1 hour</option><option value="86400">24 hours</option></select></div>
  <p style="font-size:12px;color:var(--muted);line-height:1.5">🔒 <strong>Security model:</strong> messages are encrypted with per-message ephemeral ECDH keys (forward secrecy). Verify each contact's safety number over a trusted channel before sharing sensitive information.</p>
  <div class="modalactions"><button class="btn" id="cancelSettings">Close</button><button class="btn primary" id="saveSettings">Save</button></div>`);
  $('setTheme').value=state.theme;$('setBubble').value=state.bubble;$('setTTL').value=String(state.ttl);
  const choices=$('colorChoices');
  accents.forEach(col=>{const b=document.createElement('button');b.className='swatch'+(col===state.accent?' selected':'');b.style.background=col;b.title=col;b.onclick=()=>{state.accent=col;choices.querySelectorAll('.swatch').forEach(x=>x.classList.remove('selected'));b.classList.add('selected')};choices.append(b)});
  $('cancelSettings').onclick=closeModal;
  $('saveSettings').onclick=()=>{state.theme=$('setTheme').value;state.bubble=$('setBubble').value;state.ttl=Number($('setTTL').value);saveSettings();closeModal();toast('Settings saved')};
}

function inviteData(){return location.href.split('#')[0]+'#invite='+encodeURIComponent(JSON.stringify({id:state.id,name:state.name}))}

function profile(){
  const link=inviteData();
  showModal(`<div class="profilecard">
    <div class="avatar">${escapeHtml((state.name||'M').slice(0,1).toUpperCase())}</div>
    <h2>${escapeHtml(state.name)}</h2>
    <p>Share this invite link or QR. Your public key is exchanged automatically after connection.</p>
    <div class="qrwrap"><div id="profileQR"></div></div>
    <div class="sharelink">${escapeHtml(link)}</div>
    <div class="modalactions" style="justify-content:center;flex-wrap:wrap">
      <button class="btn" id="copyInvite">Copy invite</button>
      <button class="btn primary" id="shareInvite">Share profile</button>
    </div>
    <p style="font-size:11px;color:var(--muted)">Your technical PeerJS ID is embedded in the link.</p>
  </div>`);
  try{new QRCode($('profileQR'),{text:link,width:190,height:190,colorDark:'#17221e',colorLight:'#ffffff',correctLevel:QRCode.CorrectLevel.M})}catch{$('profileQR').textContent='QR code unavailable'}
  $('copyInvite').onclick=()=>navigator.clipboard?.writeText(link).then(()=>toast('Invite copied')).catch(()=>toast('Copy failed'));
  $('shareInvite').onclick=()=>{if(navigator.share)navigator.share({title:'Murmur invite',url:link}).catch(()=>{});else navigator.clipboard?.writeText(link).then(()=>toast('Invite copied'))};
}

function newChat(){
  let invited={};
  try{if(location.hash.startsWith('#invite='))invited=JSON.parse(decodeURIComponent(location.hash.slice(8)))}catch{}
  showModal(`<h2>Add a friend</h2>
  <p style="font-size:13px;color:var(--muted)">Paste an invite link or Peer ID. Keys are exchanged automatically after connection.</p>
  <div class="field"><label>Invite link or Peer ID</label><input id="peerInput" placeholder="Paste invite link or ID" value="${escapeHtml(invited.id||'')}"></div>
  <div class="field"><label>Name (optional)</label><input id="nameInput" placeholder="Friend's name" value="${escapeHtml(invited.name||'')}"></div>
  <div class="modalactions"><button class="btn" id="cancelNew">Cancel</button><button class="btn primary" id="startNew">Connect</button></div>`);
  $('cancelNew').onclick=closeModal;
  $('startNew').onclick=()=>{
    let raw=$('peerInput').value.trim(),name=$('nameInput').value.trim(),id=raw;
    try{if(raw.includes('#invite=')){const u=new URL(raw),data=JSON.parse(decodeURIComponent(u.hash.slice(8)));id=data.id;if(!name)name=data.name||''}}catch{}
    if(!id){toast('Paste an invite link or Peer ID');return}
    closeModal();addContact(id,name||id);selectChat(id);
  };
}

async function safety(){
  if(!state.active){toast('Select a contact first');return}
  const contact=state.contacts[state.active];
  if(!contact?.pubKey){toast('Waiting for key exchange…');return}
  const sn=await safetyNumber(state.identity.publicRaw, b64ToBytes(contact.pubKey));
  const verifiedBadge=contact.verified?'<span style="color:#287b63;font-weight:700">✓ Verified</span>':'<span style="color:#a86b00;font-weight:700">⚠ Unverified</span>';
  showModal(`<h2>Safety number</h2>
  <p>Compare this number with <strong>${escapeHtml(displayName(state.active))}</strong> over a trusted channel (voice call or in person).</p>
  <div style="background:var(--bg);padding:16px;border-radius:12px;font-family:ui-monospace,monospace;font-size:14px;letter-spacing:1px;line-height:2;word-break:break-all;text-align:center;user-select:all">${sn}</div>
  <p style="font-size:12px;color:var(--muted)">Status: ${verifiedBadge}</p>
  <p style="font-size:12px;color:var(--muted)">If numbers match, mark as verified. If not, someone may be intercepting — do not trust this contact.</p>
  <div class="modalactions">
    <button class="btn" id="cancelVerify">Close</button>
    <button class="btn primary" id="confirmVerify">${contact.verified?'Re-verify':'I verified — trust'}</button>
  </div>`);
  $('cancelVerify').onclick=closeModal;
  $('confirmVerify').onclick=()=>{
    contact.verified=true;persistContacts();renderContacts();updateChatStatus();
    closeModal();toast('✓ Contact verified');
  };
}

function showKeyChangeAlert(peerId){
  showModal(`<h2 style="color:#c44">⚠ Security alert</h2>
  <p>The encryption key for <strong>${escapeHtml(displayName(peerId))}</strong> has changed.</p>
  <p style="font-size:13px;color:var(--muted);line-height:1.6">This can mean:</p>
  <ul style="font-size:13px;color:var(--muted);line-height:1.7">
    <li>They reinstalled the app or cleared data</li>
    <li>Someone is intercepting your conversation (man-in-the-middle)</li>
  </ul>
  <p style="font-size:13px">Verify the safety number with them over a trusted channel before continuing.</p>
  <div class="modalactions"><button class="btn primary" id="okKeyChange">Got it</button></div>`);
  $('okKeyChange').onclick=closeModal;
}

/* ---------- boot ---------- */
async function init(){
  if(!crypto.subtle){document.body.innerHTML='<div style="padding:40px;font-family:sans-serif;text-align:center"><h2>Insecure context</h2><p>Murmur requires HTTPS (or localhost). Web Crypto is unavailable.</p></div>';return}
  state.identity=await metaGet('identity');
  if(!state.identity){state.identity=await generateIdentity();await metaSet('identity',state.identity)}
  if(!localStorage.getItem('murmur_name')){
    showModal(`<h2>Welcome to Murmur</h2>
    <p>Choose a display name. Your encryption keys are generated automatically on this device.</p>
    <div class="field"><label>Your name</label><input id="firstName" maxlength="32" placeholder="Display name"></div>
    <p style="font-size:12px;color:var(--muted);line-height:1.5">🔐 End-to-end encryption with ECDH P-256. Forward secrecy per message. Verify safety numbers with each contact.</p>
    <div class="modalactions"><button class="btn primary" id="createIdentity">Create identity</button></div>`);
    $('createIdentity').onclick=()=>{
      const n=$('firstName').value.trim();
      if(!n){toast('Enter a name');return}
      localStorage.setItem('murmur_name',n);closeModal();boot();
    };
    return;
  }
  boot();
}

function boot(){
  state.name=localStorage.getItem('murmur_name')||'Guest';
  state.id=localStorage.getItem('murmur_peerid')||('murmur-'+crypto.randomUUID().replaceAll('-','').slice(0,18));
  localStorage.setItem('murmur_peerid',state.id);
  try{state.contacts=JSON.parse(localStorage.getItem('murmur_contacts')||'{}')}catch{}
  try{Object.assign(state,JSON.parse(localStorage.getItem('murmur_settings')||'{}'))}catch{}
  $('myName').textContent=state.name;
  $('myAvatar').textContent=(state.name||'M').slice(0,1).toUpperCase();
  applyTheme();renderContacts();
  if(!window.Peer){$('chatStatus').textContent='PeerJS failed to load';toast('PeerJS unavailable');return}
  state.peer=new Peer(state.id,{debug:0});
  state.peer.on('open',id=>{
    if(id&&id!==state.id){state.id=id;localStorage.setItem('murmur_peerid',id)}
    if(!state.active)$('chatStatus').textContent='Peer network ready';
  });
  state.peer.on('connection',c=>{
    bindConnection(c);
    if(!state.contacts[c.peer])addContact(c.peer);
    toast('Incoming connection: '+displayName(c.peer));
  });
  state.peer.on('error',e=>{
    console.warn(e);
    if(e.type==='unavailable-id')toast('ID already in use. Refresh to generate a new one.');
    else toast('Peer network: '+e.type);
  });
  if(location.hash.startsWith('#invite='))setTimeout(newChat,500);
}

/* ---------- wiring ---------- */
$('profileBtn').onclick=profile;
$('newChat').onclick=newChat;
$('settingsBtn').onclick=settings;
$('safetyBtn').onclick=safety;
$('sendBtn').onclick=sendText;
$('attachBtn').onclick=()=>$('fileInput').click();
$('fileInput').onchange=()=>{const f=$('fileInput').files[0];if(f)sendFile(f);$('fileInput').value=''};
$('messageInput').onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendText()}};
$('messageInput').oninput=e=>{e.target.style.height='auto';e.target.style.height=Math.min(e.target.scrollHeight,140)+'px'};
$('searchContacts').oninput=renderContacts;
$('backBtn').onclick=()=>{$('app').classList.remove('chatmode');state.active=null};
$('modalback').onclick=e=>{if(e.target===$('modalback'))closeModal()};
init().catch(e=>{console.error(e);toast('Init failed: '+e.message)});
})();
