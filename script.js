/* =========================================================================
 *  Stegodon — stegodon.help
 *  Static, CSP-clean steganography: embed · extract · detect
 *
 *  By: $t@$h, QVLx Labs. All Rights Reserved.
 * ========================================================================= */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  /* ========================= THEME SWITCHER ============================= */
  const themeSel = document.getElementById("theme");
  const root = document.documentElement;
  const THEME_KEY = "stegodon.theme";

  function applyTheme(val){
    root.setAttribute("data-theme", val);
    try{ localStorage.setItem(THEME_KEY, val); }catch{}
  }
  (function initTheme(){
    const t = (localStorage.getItem(THEME_KEY) || "tusk");
    themeSel.value = t; applyTheme(t);
  })();
  themeSel.addEventListener("change", () => applyTheme(themeSel.value));

  /* ========================= TABS ====================================== */
  const tabs = document.querySelectorAll(".tab");
  const panels = {
    embed: document.getElementById("embed-panel"),
    extract: document.getElementById("extract-panel"),
    detect: document.getElementById("detect-panel"),
    help: document.getElementById("help-panel"),
  };
  tabs.forEach(btn => btn.addEventListener("click", () => {
    tabs.forEach(b=>b.classList.remove("is-active"));
    btn.classList.add("is-active");
    Object.values(panels).forEach(p=>{p.hidden=true;p.classList.remove("is-active");});
    const k = btn.dataset.tab;
    panels[k].hidden=false; panels[k].classList.add("is-active");
  }));

  /* ========================= LOGO: Pixel pattern engine ================= */
  (function initLogoPixels(){
    const svg = document.querySelector(".logo-stego");
    if (!svg) return;
    const prefersReduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const px = Array.from(svg.querySelectorAll(".pixels .px"));
    if (px.length !== 9) return;

    const P = [
      { name:"diagTLBR", idx:[0,4,8] },
      { name:"diagTRBL", idx:[2,4,6] },
      { name:"topRow",   idx:[0,1,2] },
      { name:"midRow",   idx:[3,4,5] },
      { name:"botRow",   idx:[6,7,8] },
      { name:"leftCol",  idx:[0,3,6] },
      { name:"midCol",   idx:[1,4,7] },
      { name:"rightCol", idx:[2,5,8] },
      { name:"corners",  idx:[0,2,6,8] },
      { name:"diamond",  idx:[1,3,4,5,7] },
      { name:"random3",  idx:"rand3" },
    ];
    function pickPattern(){
      const p = P[Math.floor(Math.random()*P.length)];
      if (p.idx === "rand3"){
        const all = [0,1,2,3,4,5,6,7,8];
        for (let i=all.length-1;i>0;i--){ const j = Math.floor(Math.random()*(i+1)); [all[i],all[j]]=[all[j],all[i]]; }
        return {name:"random3", idx: all.slice(0,3)};
      }
      return p;
    }
    function applyPattern(pat){
      px.forEach(r => { r.classList.remove("hot"); r.style.removeProperty("--d"); });
      pat.idx.forEach((i,k) => { const node = px[i]; if (!node) return; node.classList.add("hot"); node.style.setProperty("--d", (k*0.18)+"s"); });
    }
    applyPattern({name:"diagTLBR", idx:[0,4,8]});
    if (!prefersReduce){
      let lastName = "diagTLBR";
      setInterval(() => {
        let next;
        do { next = pickPattern(); } while (next.name === lastName);
        lastName = next.name;
        applyPattern(next);
      }, 2800);
    }
  })();

  /* ========================= ELEMENTS ================================== */
  // Embed
  const carrierIn = document.getElementById("carrier");
  const lsbCountSel = document.getElementById("lsbCount");
  const chR = document.getElementById("chR"), chG = document.getElementById("chG"), chB = document.getElementById("chB");
  const randomizeCb = document.getElementById("randomize");
  const encryptCb = document.getElementById("encrypt");
  const passIn = document.getElementById("pass");
  const secretRow = document.getElementById("secretRow");
  const analyzeBtn = document.getElementById("analyze");
  const capacityOut = document.getElementById("capacityOut");
  const payloadText = document.getElementById("payloadText");
  const payloadFile = document.getElementById("payloadFile");
  const embedBtn = document.getElementById("embedBtn");
  const clearEmbed = document.getElementById("clearEmbed");
  const embedWarn = document.getElementById("embedWarn");
  const channelRow = document.getElementById("channelRow");

  const canvasOrig = document.getElementById("canvasOrig");
  const canvasStego = document.getElementById("canvasStego");
  const imgOrig = document.getElementById("imgOrig");
  const imgStego = document.getElementById("imgStego");
  const audioOrig = document.getElementById("audioOrig");
  const audioStego = document.getElementById("audioStego");
  const downloadLink = document.getElementById("downloadLink");

  // Extract
  const stegoIn = document.getElementById("stegoIn");
  const pass2 = document.getElementById("pass2");
  const extractBtn = document.getElementById("extractBtn");
  const extractWarn = document.getElementById("extractWarn");
  const xSummary = document.getElementById("xSummary");
  const xText = document.getElementById("xText");
  const xFile = document.getElementById("xFile");

  // Detect
  const detectIn = document.getElementById("detectIn");
  const detectBtn = document.getElementById("detectBtn");
  const dSummary = document.getElementById("dSummary");
  const bars = document.getElementById("bars");

  // Payload mode toggle
  const payloadRadios = Array.from(document.querySelectorAll('input[name="payloadMode"]'));
  function updatePayloadMode(){
    const mode = payloadRadios.find(r=>r.checked)?.value || "text";
    if (mode==="text"){ payloadText.classList.remove("hide"); payloadFile.classList.add("hide"); }
    else { payloadText.classList.add("hide"); payloadFile.classList.remove("hide"); }
  }
  payloadRadios.forEach(r=>r.addEventListener("change", updatePayloadMode));
  updatePayloadMode();

  // Secret row visibility
  function updateSecretVisibility(){
    const need = randomizeCb.checked || encryptCb.checked;
    secretRow.style.display = need ? "block" : "none";
  }
  randomizeCb.addEventListener("change", updateSecretVisibility);
  encryptCb.addEventListener("change", updateSecretVisibility);
  updateSecretVisibility();

  // Carrier awareness
  carrierIn.addEventListener("change", () => {
    const file = carrierIn.files?.[0];
    if (!file) return;
    const isAudio = /audio\/wav|audio\/x-wav/.test(file.type) || /\.wav$/i.test(file.name);
    channelRow.style.display = isAudio ? "none" : "block";
    analyzeBtn.click();
    clearPreview();
  });

  clearEmbed.addEventListener("click", () => {
    carrierIn.value = "";
    payloadText.value = "";
    payloadFile.value = "";
    capacityOut.value = "";
    showWarn(embedWarn, "");
    clearPreview();
  });

  function clearPreview(){
    [canvasOrig, canvasStego].forEach(c=>{c.hidden=true; c.getContext && c.getContext("2d").clearRect(0,0,c.width,c.height);});
    [imgOrig, imgStego].forEach(i=>{i.hidden=true; i.removeAttribute("src");});
    [audioOrig, audioStego].forEach(a=>{a.hidden=true; a.removeAttribute("src"); a.load && a.load();});
    downloadLink.hidden = true; downloadLink.removeAttribute("href"); downloadLink.removeAttribute("download");
  }

  /* ========================= CONSTANTS / HEADER ========================= */
  const MAGIC = new Uint8Array([0x53,0x47,0x44,0x4E]); // 'SGDN'

  function buildHeader({isFile, lsbCount, channelMask, payloadLen, filename, crypto, randomized, salt, iv}){
    const nameBytes = isFile && filename ? new TextEncoder().encode(filename) : new Uint8Array();
    const fixedLen = 15 + nameBytes.length + (crypto?28:0); // MIN = 15 bytes
    const buf = new Uint8Array(fixedLen);
    let o=0;
    buf.set(MAGIC, o); o+=4;
    buf[o++] = 1; // version
    buf[o++] = (fixedLen >>> 8) & 0xff;
    buf[o++] = (fixedLen) & 0xff;
    const flags = (crypto?1:0) | (randomized?2:0) | (isFile?4:0) | (((lsbCount-1)&3)<<3);
    buf[o++] = flags;
    buf[o++] = channelMask & 0x07;
    buf[o++] = (payloadLen>>>24)&0xff;
    buf[o++] = (payloadLen>>>16)&0xff;
    buf[o++] = (payloadLen>>>8)&0xff;
    buf[o++] = payloadLen&0xff;
    buf[o++] = (nameBytes.length>>>8)&0xff;
    buf[o++] = (nameBytes.length)&0xff;
    if (nameBytes.length){ buf.set(nameBytes, o); o+=nameBytes.length; }
    if (crypto){
      buf.set(salt, o); o+=16;
      buf.set(iv, o); o+=12;
    }
    return buf;
  }

  function parseHeader(bytes){
    // FIX: header can be 15 bytes minimum
    if (bytes.length < 15) throw new Error("Header too short.");
    if (!(bytes[0]===0x53&&bytes[1]===0x47&&bytes[2]===0x44&&bytes[3]===0x4E)) throw new Error("Magic not found.");
    const version = bytes[4]; if (version!==1) throw new Error("Unsupported header version.");
    const headerLen = (bytes[5]<<8) | bytes[6];
    if (bytes.length < headerLen) throw new Error("Incomplete header.");
    const flags = bytes[7];
    const crypto = !!(flags & 1);
    const randomized = !!(flags & 2);
    const isFile = !!(flags & 4);
    const lsbCount = ((flags>>3)&3)+1;
    const channelMask = bytes[8];
    const payloadLen = (bytes[9]<<24)|(bytes[10]<<16)|(bytes[11]<<8)|bytes[12];
    const nameLen = (bytes[13]<<8)|bytes[14];
    let o = 15;
    let filename = "";
    if (nameLen){ filename = new TextDecoder().decode(bytes.slice(o, o+nameLen)); o += nameLen; }
    let salt = null, iv = null;
    if (crypto){ salt = bytes.slice(o, o+16); o+=16; iv = bytes.slice(o, o+12); o+=12; }
    return {version, headerLen, crypto, randomized, isFile, lsbCount, channelMask, payloadLen, filename, salt, iv};
  }

  /* ========================= HELPERS ==================================== */
  const enc = new TextEncoder(); const dec = new TextDecoder();

  function showWarn(el, msg){ if (!msg){ el.classList.remove("show"); el.textContent=""; } else { el.textContent=msg; el.classList.add("show"); } }
  function fmtBytes(n){
    if (n<1024) return `${n} B`;
    const u = ["KB","MB","GB","TB"]; let i=-1; do{ n/=1024; i++; }while(n>=1024 && i<u.length-1);
    return `${n.toFixed(2)} ${u[i]}`;
  }
  function escapeHtml(s){
    return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  }
  function channelMaskFromUI(){ let m=0; if (chR.checked) m|=1; if (chG.checked) m|=2; if (chB.checked) m|=4; return m||7; }
  function clamp01(x){ return Math.max(0, Math.min(1, x)); }

  // PRNG + shuffle
  function xorshift32(seed){ let x = seed>>>0 || 0x9E3779B9; return ()=>{ x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x>>>0; }; }
  async function seedFromPassphrase(pass){
    const h = await crypto.subtle.digest("SHA-256", enc.encode("STEGO-SEED::"+(pass||"")));
    const b = new Uint8Array(h); return (b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3];
  }
  function fisherYates(arr, rnd){
    for (let i=arr.length-1;i>0;i--){ const j = rnd()% (i+1); [arr[i], arr[j]] = [arr[j], arr[i]]; }
    return arr;
  }

  // Crypto (AES-GCM, PBKDF2)
  async function deriveKey(pass, salt){
    const baseKey = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      {name:"PBKDF2", salt, iterations:150000, hash:"SHA-256"},
      baseKey, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]
    );
  }
  async function encryptBytes(data, pass){
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(pass, salt);
    const ct = new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, data));
    return {cipher: ct, salt, iv};
  }
  async function decryptBytes(cipher, pass, salt, iv){
    const key = await deriveKey(pass, salt);
    return new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, cipher));
  }

  // Bits <-> bytes
  function bytesToBits(bytes){ const bits = new Uint8Array(bytes.length*8); let k=0; for (let i=0;i<bytes.length;i++){ const b=bytes[i]; for (let j=7;j>=0;j--){ bits[k++] = (b>>j)&1; } } return bits; }
  function bitsToBytes(bits){ const n = Math.ceil(bits.length/8); const out = new Uint8Array(n); for (let i=0;i<n;i++){ let v=0; for (let j=0;j<8;j++){ const idx=i*8+j; v = (v<<1) | (idx<bits.length ? bits[idx] : 0); } out[i]=v; } return out; }
  function bytesToSymbols(bytes, lsbCount){
    if (lsbCount===1) return bytesToBits(bytes);
    const bits = bytesToBits(bytes);
    const symbols = new Uint8Array(Math.ceil(bits.length/lsbCount));
    let s=0, acc=0, left=lsbCount;
    for (let i=0;i<bits.length;i++){
      acc = (acc<<1) | (bits[i]&1);
      left--;
      if (left===0){ symbols[s++]=acc; acc=0; left=lsbCount; }
    }
    if (left!==lsbCount){ symbols[s++]=acc; }
    return symbols;
  }
  function symbolsToBytes(symbols, lsbCount, expectedBytes){
    if (lsbCount===1){ const bytes = bitsToBytes(symbols); return expectedBytes!=null ? bytes.slice(0, expectedBytes) : bytes; }
    const bits = new Uint8Array(symbols.length * lsbCount);
    let k=0;
    for (let i=0;i<symbols.length;i++){
      const sym = symbols[i];
      for (let j=lsbCount-1;j>=0;j--) bits[k++] = (sym>>j)&1;
    }
    const bytes = bitsToBytes(bits);
    return expectedBytes!=null ? bytes.slice(0, expectedBytes) : bytes;
  }

  // File helpers
  function readAsArrayBuffer(file){ return new Promise((res,rej)=>{ const r=new FileReader(); r.onload=()=>res(r.result); r.onerror=rej; r.readAsArrayBuffer(file); }); }
  function readAsDataURL(file){ return new Promise((res,rej)=>{ const r=new FileReader(); r.onload=()=>res(r.result); r.onerror=rej; r.readAsDataURL(file); }); }

  /* ========================= IMAGE PIPELINE ============================= */
  async function loadImageToCanvas(file, canvas){
    const url = await readAsDataURL(file);
    const img = new Image(); img.src=url; await img.decode();
    canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
    const ctx = canvas.getContext("2d"); ctx.drawImage(img, 0, 0);
    return {width:canvas.width, height:canvas.height, ctx};
  }
  function imageCapacity(imgDataLen, mask, lsbCount){
    const channels = ((mask&1)?1:0) + ((mask&2)?1:0) + ((mask&4)?1:0);
    const pixels = imgDataLen / 4;
    const bits = pixels * channels * lsbCount;
    return {bits, bytes: Math.floor(bits/8)};
  }
  function imagePositions(width, height, mask){
    const positions = [];
    const perPix = []; if (mask&1) perPix.push(0); if (mask&2) perPix.push(1); if (mask&4) perPix.push(2);
    const stride = width*4;
    for (let y=0;y<height;y++){
      const row = y*stride;
      for (let x=0;x<width;x++){
        const base = row + x*4;
        for (const ch of perPix) positions.push(base+ch);
      }
    }
    return positions;
  }
  function embedSymbolsIntoImage(imgData, positions, headerSyms, payloadSyms, lsbCount, randomized, seed){
    const mask=(1<<lsbCount)-1;
    let idx = 0;
    for (let i=0;i<headerSyms.length;i++){
      if (idx>=positions.length) throw new Error("Insufficient capacity for header.");
      const p = positions[idx++];
      imgData[p] = (imgData[p] & ~mask) | (headerSyms[i] & mask);
    }
    let pool = positions.slice(idx);
    if (randomized){ const rnd = xorshift32(seed>>>0); pool = fisherYates(pool, rnd); }
    if (payloadSyms.length > pool.length) throw new Error("Insufficient capacity for payload.");
    for (let i=0;i<payloadSyms.length;i++){
      const p = pool[i];
      imgData[p] = (imgData[p] & ~mask) | (payloadSyms[i] & mask);
    }
  }
  function extractSymbolsFromImage(imgData, positions, symsNeeded, lsbCount, randomized, seed, headerSymCount){
    const mask=(1<<lsbCount)-1;
    const headerSyms=[]; let idx=0;
    for (let i=0;i<headerSymCount;i++){ const p = positions[idx++]; headerSyms.push(imgData[p] & mask); }
    const remaining = positions.slice(idx);
    let pool = remaining;
    if (randomized){ const rnd = xorshift32(seed>>>0); pool = fisherYates(pool, rnd); }
    const payloadCount = Math.max(0, symsNeeded - headerSymCount);
    const payloadSyms=[];
    for (let i=0;i<payloadCount;i++){ const p = pool[i]; payloadSyms.push(imgData[p] & mask); }
    return {headerSyms, payloadSyms};
  }

  /* ========================= WAV PIPELINE =============================== */
  function parseWav(buffer){
    const dv = new DataView(buffer);
    function str(off,len){ let s=""; for(let i=0;i<len;i++) s+=String.fromCharCode(dv.getUint8(off+i)); return s; }
    if (str(0,4)!=="RIFF" || str(8,4)!=="WAVE") throw new Error("Not a RIFF/WAVE file.");
    let off = 12;
    let fmt=null, dataOff=null, dataLen=null;
    while (off + 8 <= dv.byteLength){
      const id = str(off,4); const size = dv.getUint32(off+4, true); const body = off+8;
      if (id==="fmt "){
        const audioFormat = dv.getUint16(body, true);
        const numChannels = dv.getUint16(body+2, true);
        const sampleRate = dv.getUint32(body+4, true);
        const bitsPerSample = dv.getUint16(body+14, true);
        fmt = {audioFormat, numChannels, sampleRate, bitsPerSample, chunkOff:off, chunkLen:size};
      } else if (id==="data"){
        dataOff = body; dataLen = size;
      }
      off = body + size + (size%2);
    }
    if (!fmt || dataOff==null) throw new Error("Invalid WAV: missing fmt or data chunk.");
    if (fmt.audioFormat!==1 || (fmt.bitsPerSample!==16 && fmt.bitsPerSample!==8)) throw new Error("Only PCM 8/16-bit WAV supported.");
    return {fmt, dataOff, dataLen, dv};
  }
  function wavCapacity(fmt, dataLen, lsbCount){
    const bytesPerSamp = fmt.bitsPerSample/8;
    const samples = dataLen / bytesPerSamp;
    const bits = samples * lsbCount;
    return {bits, bytes: Math.floor(bits/8)};
  }
  function setSampleLSBs(bufU8, off, bps, symbol, lsbCount){
    const mask = (1<<lsbCount)-1;
    if (bps===16){
      let v = (bufU8[off+1]<<8)|bufU8[off];
      v = (v & ~mask) | (symbol & mask);
      bufU8[off] = v & 0xff; bufU8[off+1] = (v>>8)&0xff;
    } else {
      let v = bufU8[off];
      v = (v & ~mask) | (symbol & mask);
      bufU8[off] = v;
    }
  }
  function readSampleLSBs(bufU8, off, bps, lsbCount){
    const mask=(1<<lsbCount)-1;
    if (bps===16){ const v = (bufU8[off+1]<<8)|bufU8[off]; return v & mask; }
    else { const v = bufU8[off]; return v & mask; }
  }
  function embedSymbolsIntoWav(bufU8, fmt, dataOff, dataLen, headerSyms, payloadSyms, lsbCount, randomized, seed){
    const bytesPerSamp = fmt.bitsPerSample/8;
    const totalSyms = Math.floor(dataLen / bytesPerSamp);
    const positions = new Array(totalSyms).fill(0).map((_,i)=>i);
    let p=0;
    for (let i=0;i<headerSyms.length;i++){
      if (p>=positions.length) throw new Error("Insufficient capacity for header.");
      const off = dataOff + positions[p++]*bytesPerSamp;
      setSampleLSBs(bufU8, off, bytesPerSamp*8, headerSyms[i], lsbCount);
    }
    let pool = positions.slice(p);
    if (randomized){ const rnd = xorshift32(seed>>>0); pool = fisherYates(pool, rnd); }
    if (payloadSyms.length > pool.length) throw new Error("Insufficient capacity for payload.");
    for (let i=0;i<payloadSyms.length;i++){
      const off = dataOff + pool[i]*bytesPerSamp;
      setSampleLSBs(bufU8, off, bytesPerSamp*8, payloadSyms[i], lsbCount);
    }
  }
  function extractSymbolsFromWav(bufU8, fmt, dataOff, dataLen, totalSymsNeeded, lsbCount, randomized, seed, headerSymCount){
    const bytesPerSamp = fmt.bitsPerSample/8;
    const totalSyms = Math.floor(dataLen / bytesPerSamp);
    const positions = new Array(totalSyms).fill(0).map((_,i)=>i);
    const headerSyms=[]; let p=0;
    for (let i=0;i<headerSymCount;i++){
      const off = dataOff + positions[p++]*bytesPerSamp;
      headerSyms.push(readSampleLSBs(bufU8, off, bytesPerSamp*8, lsbCount));
    }
    let pool = positions.slice(p);
    if (randomized){ const rnd = xorshift32(seed>>>0); pool = fisherYates(pool, rnd); }
    const payloadCount = Math.max(0, totalSymsNeeded - headerSymCount);
    const payloadSyms = [];
    for (let i=0;i<payloadCount;i++){
      const off = dataOff + pool[i]*bytesPerSamp;
      payloadSyms.push(readSampleLSBs(bufU8, off, bytesPerSamp*8, lsbCount));
    }
    return {headerSyms, payloadSyms};
  }

  /* ========================= CAPACITY / ANALYZE ========================= */
  analyzeBtn.addEventListener("click", async () => {
    capacityOut.value = "";
    const file = carrierIn.files?.[0];
    if (!file){ capacityOut.value = "Choose a carrier file."; return; }
    const lsbCount = parseInt(lsbCountSel.value,10);
    try{
      let bytes=0, extra="";
      if (/audio\/wav|audio\/x-wav/.test(file.type) || /\.wav$/i.test(file.name)){
        const buf = new Uint8Array(await readAsArrayBuffer(file));
        const {fmt, dataOff, dataLen} = parseWav(buf.buffer);
        bytes = wavCapacity(fmt, dataLen, lsbCount).bytes;
        extra = `${fmt.numChannels}ch, ${fmt.sampleRate}Hz, ${fmt.bitsPerSample}-bit`;
      } else {
        const {ctx, width, height} = await loadImageToCanvas(file, canvasOrig);
        const imgData = ctx.getImageData(0,0,width,height);
        const cap = imageCapacity(imgData.data.length, channelMaskFromUI(), lsbCount);
        bytes = cap.bytes; extra = `${width}×${height}px`;
      }
      capacityOut.value = `Approx capacity: ${fmtBytes(bytes)} • ${extra}`;
    } catch(err){
      capacityOut.value = `Error: ${String(err.message||err)}`;
    }
  });

  /* ========================= EMBED ====================================== */
  embedBtn.addEventListener("click", async () => {
    try{
      const file = carrierIn.files?.[0];
      if (!file) throw new Error("Select a carrier image or WAV first.");
      const lsbCount = parseInt(lsbCountSel.value,10);
      const randomized = !!randomizeCb.checked;
      const cryptoOn = !!encryptCb.checked;
      const pass = passIn.value || "";
      if ((randomized || cryptoOn) && pass.length === 0) throw new Error("Passphrase is required when randomization and/or encryption is enabled.");

      const mode = payloadRadios.find(r=>r.checked)?.value || "text";
      let payloadBytes, filename="", isFile=false;
      if (mode==="text"){
        payloadBytes = enc.encode(payloadText.value||"");
      } else {
        const pf = payloadFile.files?.[0];
        if (!pf) throw new Error("Choose a payload file.");
        payloadBytes = new Uint8Array(await readAsArrayBuffer(pf));
        filename = pf.name; isFile=true;
      }

      let dataToEmbed = payloadBytes;
      let salt=null, iv=null;
      if (cryptoOn){
        const res = await encryptBytes(dataToEmbed, pass);
        dataToEmbed = res.cipher; salt=res.salt; iv=res.iv;
      }

      const isWav = /audio\/wav|audio\/x-wav/.test(file.type) || /\.wav$/i.test(file.name);
      const channelMask = isWav ? 0 : channelMaskFromUI();
      const seed = randomized ? await seedFromPassphrase(pass) : 0;

      const header = buildHeader({
        isFile, lsbCount, channelMask, payloadLen: dataToEmbed.length,
        filename, crypto: cryptoOn, randomized, salt, iv
      });

      const headerSyms = bytesToSymbols(header, lsbCount);
      const payloadSyms = bytesToSymbols(dataToEmbed, lsbCount);

      if (isWav){
        const bufU8 = new Uint8Array(await readAsArrayBuffer(file));
        const {fmt, dataOff, dataLen} = parseWav(bufU8.buffer);
        const cap = wavCapacity(fmt, dataLen, lsbCount).bytes;
        if ((header.length + dataToEmbed.length) > cap) throw new Error(`Payload too large. Capacity ~${fmtBytes(cap)}.`);
        embedSymbolsIntoWav(bufU8, fmt, dataOff, dataLen, headerSyms, payloadSyms, lsbCount, randomized, seed);

        audioOrig.hidden=false; audioOrig.src = URL.createObjectURL(new Blob([new Uint8Array(await readAsArrayBuffer(file))], {type:"audio/wav"}));
        audioStego.hidden=false; audioStego.src = URL.createObjectURL(new Blob([bufU8], {type:"audio/wav"}));
        downloadLink.hidden = false; downloadLink.href = audioStego.src; downloadLink.download = suggestOutName(file.name, true);
        canvasOrig.hidden=true; canvasStego.hidden=true; imgOrig.hidden=true; imgStego.hidden=true;
        showWarn(embedWarn, "");
      } else {
        const {ctx, width, height} = await loadImageToCanvas(file, canvasOrig);
        const imgData = ctx.getImageData(0,0,width,height);
        const cap = imageCapacity(imgData.data.length, channelMask, lsbCount).bytes;
        if ((header.length + dataToEmbed.length) > cap) throw new Error(`Payload too large. Capacity ~${fmtBytes(cap)} with current settings.`);
        const positions = imagePositions(width, height, channelMask);
        embedSymbolsIntoImage(imgData.data, positions, headerSyms, payloadSyms, lsbCount, randomized, seed);
        const ctx2 = canvasStego.getContext("2d");
        canvasStego.width = width; canvasStego.height = height;
        ctx2.putImageData(imgData, 0, 0);

        imgOrig.hidden=false; imgOrig.src = canvasOrig.toDataURL("image/png");
        imgStego.hidden=false; imgStego.src = canvasStego.toDataURL("image/png");
        canvasStego.toBlob(blob => {
          const url = URL.createObjectURL(blob);
          downloadLink.hidden=false; downloadLink.href = url; downloadLink.download = suggestOutName(file.name, false);
        }, "image/png");
        audioOrig.hidden=true; audioStego.hidden=true;
        showWarn(embedWarn, "");
      }
    } catch(err){
      showWarn(embedWarn, String(err.message||err));
    }
  });

  function suggestOutName(name, isWav){
    const base = name.replace(/\.(\w+)$/,"");
    return isWav ? `${base}.stego.wav` : `${base}.stego.png`;
  }

  /* ========================= HEADER SEARCH HELPERS ====================== */
  function matchesMagic64(bytes64){
    return bytes64[0]===0x53 && bytes64[1]===0x47 && bytes64[2]===0x44 && bytes64[3]===0x4E; // SGDN
  }
  function findHeaderInImage(imgData, width, height){
    const masks = [0b111, 0b001, 0b010, 0b100]; // all, R, G, B
    for (const mask of masks){
      const positions = imagePositions(width, height, mask);
      for (const lsb of [1,2]){
        const nSyms = Math.ceil(64*8/lsb);
        const {headerSyms} = extractSymbolsFromImage(imgData, positions, nSyms, lsb, false, 0, nSyms);
        const first64 = symbolsToBytes(headerSyms, lsb, 64);
        if (matchesMagic64(first64)){
          const headerLen = (first64[5]<<8)|first64[6];
          const totalSyms = Math.ceil(headerLen*8/lsb);
          const {headerSyms:hs2} = extractSymbolsFromImage(imgData, positions, totalSyms, lsb, false, 0, totalSyms);
          const headerBytes = symbolsToBytes(hs2, lsb, headerLen);
          const info = parseHeader(headerBytes);
          return {info, lsb, mask};
        }
      }
    }
    return null;
  }
  function findHeaderInWav(bufU8, fmt, dataOff, dataLen){
    for (const lsb of [1,2]){
      const nSyms = Math.ceil(64*8/lsb);
      const {headerSyms} = extractSymbolsFromWav(bufU8, fmt, dataOff, dataLen, nSyms, lsb, false, 0, nSyms);
      const first64 = symbolsToBytes(headerSyms, lsb, 64);
      if (matchesMagic64(first64)){
        const headerLen = (first64[5]<<8)|first64[6];
        const totalSyms = Math.ceil(headerLen*8/lsb);
        const {headerSyms:hs2} = extractSymbolsFromWav(bufU8, fmt, dataOff, dataLen, totalSyms, lsb, false, 0, totalSyms);
        const headerBytes = symbolsToBytes(hs2, lsb, headerLen);
        const info = parseHeader(headerBytes);
        return {info, lsb};
      }
    }
    return null;
  }

  /* ========================= EXTRACT ==================================== */
  extractBtn.addEventListener("click", async () => {
    try{
      const file = stegoIn.files?.[0];
      if (!file) throw new Error("Choose a stego image or WAV.");
      const pass = pass2.value || "";
      xSummary.innerHTML = ""; xText.classList.add("hide"); xFile.classList.add("hide");
      showWarn(extractWarn,"");

      if (/audio\/wav|audio\/x-wav/.test(file.type) || /\.wav$/i.test(file.name)){
        const bufU8 = new Uint8Array(await readAsArrayBuffer(file));
        const {fmt, dataOff, dataLen} = parseWav(bufU8.buffer);
        const found = findHeaderInWav(bufU8, fmt, dataOff, dataLen);
        if (!found) throw new Error("No Stegodon header found.");
        const {info, lsb} = found;

        if (info.randomized && !pass) throw new Error("Passphrase required (randomized payload).");
        const seed = info.randomized ? await seedFromPassphrase(pass) : 0;

        const headerSymsCount = Math.ceil(info.headerLen*8/lsb);
        const totalNeeded = headerSymsCount + Math.ceil(info.payloadLen*8/lsb);
        const {payloadSyms} = extractSymbolsFromWav(bufU8, fmt, dataOff, dataLen, totalNeeded, lsb, info.randomized, seed, headerSymsCount);
        const payloadBytes = symbolsToBytes(payloadSyms, lsb, info.payloadLen);
        const plain = info.crypto ? await decryptBytes(payloadBytes, pass, info.salt, info.iv) : payloadBytes;

        renderExtractResult(info, plain, "wav");
      } else {
        const {ctx, width, height} = await loadImageToCanvas(file, canvasOrig);
        const imgData = ctx.getImageData(0,0,width,height).data;
        const found = findHeaderInImage(imgData, width, height);
        if (!found) throw new Error("No Stegodon header found.");
        const {info, lsb, mask} = found;

        const positions = imagePositions(width, height, (info.channelMask||mask||0b111));
        if (info.randomized && !pass) throw new Error("Passphrase required (randomized payload).");
        const seed = info.randomized ? await seedFromPassphrase(pass) : 0;

        const headerSymsCount = Math.ceil(info.headerLen*8/lsb);
        const totalNeeded = headerSymsCount + Math.ceil(info.payloadLen*8/lsb);
        const {payloadSyms} = extractSymbolsFromImage(imgData, positions, totalNeeded, lsb, info.randomized, seed, headerSymsCount);
        const payloadBytes = symbolsToBytes(payloadSyms, lsb, info.payloadLen);
        const plain = info.crypto ? await decryptBytes(payloadBytes, pass, info.salt, info.iv) : payloadBytes;

        renderExtractResult(info, plain, "image");
      }
    } catch(err){
      showWarn(extractWarn, String(err.message||err));
    }
  });

  function renderExtractResult(info, bytes, kind){
    const rows = [];
    rows.push(kv("Magic","SGDN v"+info.version));
    rows.push(kv("Carrier", kind==="wav"?"WAV (PCM)":"Image"));
    rows.push(kv("Type", info.isFile?"File":"Text"));
    rows.push(kv("Randomized", info.randomized?"Yes":"No"));
    rows.push(kv("Encrypted", info.crypto?"Yes":"No"));
    rows.push(kv("LSB per channel/sample", String(info.lsbCount)));
    if (kind==="image") rows.push(kv("Image channels", maskName(info.channelMask)));
    rows.push(kv("Payload length", fmtBytes(info.payloadLen)));
    if (info.filename) rows.push(kv("Filename", info.filename));
    xSummary.innerHTML = rows.join("");

    if (!info.isFile){
      try{ xText.value = dec.decode(bytes); } catch{ xText.value = "(binary text)"; }
      xText.classList.remove("hide");
      xFile.classList.add("hide");
    } else {
      xText.classList.add("hide");
      const name = info.filename || "extracted.bin";
      const url = URL.createObjectURL(new Blob([bytes]));
      xFile.href = url; xFile.download = name; xFile.classList.remove("hide");
    }
  }

  function maskName(m){ const arr=[]; if (m&1) arr.push("R"); if (m&2) arr.push("G"); if (m&4) arr.push("B"); return arr.join("+")||"—"; }
  function kv(k,v){ return `<div class="kv"><div class="k">${escapeHtml(k)}</div><div class="v"><code>${escapeHtml(String(v))}</code></div></div>`; }

  /* ========================= DETECT ===================================== */
  detectBtn.addEventListener("click", async () => {
    try{
      dSummary.innerHTML=""; bars.innerHTML="";
      const file = detectIn.files?.[0];
      if (!file) throw new Error("Choose an image or WAV to analyze.");

      if (/audio\/wav|audio\/x-wav/.test(file.type) || /\.wav$/i.test(file.name)){
        const bufU8 = new Uint8Array(await readAsArrayBuffer(file));
        const {fmt, dataOff, dataLen} = parseWav(bufU8.buffer);

        const found = findHeaderInWav(bufU8, fmt, dataOff, dataLen);
        const headerFound = !!found;

        const stats = lsbStatsWav(bufU8, fmt, dataOff, dataLen);
        const score = suspicionScoreWav(stats);
        dSummary.innerHTML = [
          kv("File type","WAV (PCM)"),
          kv("Header", headerFound ? "Stegodon header found" : "Not found"),
          kv("LSB χ² p-value", stats.pValue.toFixed(6)),
          kv("Suspicion", score.label)
        ].join("");
        drawBars([
          {label:"Uniformity (p-value)", value:score.uniformity, hint:"Higher often indicates LSB replacement"},
          {label:"Pairs-of-values", value:score.pov, hint:"Higher suggests replacement/matching"},
        ]);
      } else {
        const {ctx, width, height} = await loadImageToCanvas(file, canvasOrig);
        const imgData = ctx.getImageData(0,0,width,height).data;

        const found = findHeaderInImage(imgData, width, height);
        const headerFound = !!found;

        const stats = lsbStatsImage(imgData);
        const score = suspicionScoreImage(stats);
        dSummary.innerHTML = [
          kv("File type","Image"),
          kv("Header", headerFound ? "Stegodon header found" : "Not found"),
          kv("LSB χ² p-value (R/G/B)", `${stats.pR.toFixed(6)} / ${stats.pG.toFixed(6)} / ${stats.pB.toFixed(6)}`),
          kv("Suspicion", score.label)
        ].join("");
        drawBars([
          {label:"Uniformity R (p)", value:score.uR, hint:"Higher often indicates LSB replacement"},
          {label:"Uniformity G (p)", value:score.uG, hint:""},
          {label:"Uniformity B (p)", value:score.uB, hint:""},
          {label:"Pairs-of-values", value:score.pov, hint:""},
        ]);
      }
    } catch(err){
      dSummary.innerHTML=""; bars.innerHTML="";
      dSummary.innerHTML = `<div class="kv"><div class="k">Error</div><div class="v"><code>${escapeHtml(String(err.message||err))}</code></div></div>`;
    }
  });

  // Detection helpers + bars
  function erfc(x){
    const z = Math.abs(x);
    const t = 1/(1+0.5*z);
    const r = t * Math.exp(-z*z - 1.26551223 + t*(1.00002368 +
            t*(0.37409196 + t*(0.09678418 + t*(-0.18628806 +
            t*(0.27886807 + t*(-1.13520398 + t*(1.48851587 +
            t*(-0.82215223 + t*0.17087277)))))))));
    return x>=0 ? r : 2 - r;
  }
  function chiSquareP_from_counts(evens, odds){
    const n = evens+odds; if (n===0) return 1;
    const exp = n/2;
    const chi = ((evens-exp)**2)/exp + ((odds-exp)**2)/exp; // df=1
    return erfc(Math.sqrt(chi/2));
  }
  function lsbChannelStats(hist){
    let even=0, odd=0;
    for (let v=0; v<256; v++){ if ((v&1)===0) even += hist[v]; else odd += hist[v]; }
    const p = chiSquareP_from_counts(even, odd); // higher ~ flatter ~ more suspicious for replacement
    // PoV heuristic: equalization across pairs (2k,2k+1) implies higher suspicion; normalize to [0..1]
    let diff=0, total=0;
    for (let k=0;k<128;k++){ const a=hist[2*k], b=hist[2*k+1]; diff += Math.abs(a-b); total += a+b; }
    const pov = total? (1 - diff/total) : 0;
    return [p, pov];
  }
  function lsbStatsImage(data){
    const hR = new Uint32Array(256), hG = new Uint32Array(256), hB = new Uint32Array(256);
    for (let i=0;i<data.length;i+=4){ hR[data[i]]++; hG[data[i+1]]++; hB[data[i+2]]++; }
    const [pR, povR] = lsbChannelStats(hR);
    const [pG, povG] = lsbChannelStats(hG);
    const [pB, povB] = lsbChannelStats(hB);
    return { pR, pG, pB, pov:(povR+povG+povB)/3 };
  }
  function lsbStatsWav(bufU8, fmt, dataOff, dataLen){
    const bps = fmt.bitsPerSample/8;
    let zeros=0, ones=0;
    for (let off=dataOff; off<dataOff+dataLen; off+=bps){
      const v = bps===2 ? ((bufU8[off+1]<<8)|bufU8[off]) : bufU8[off];
      if ((v&1)===0) zeros++; else ones++;
    }
    const pValue = chiSquareP_from_counts(zeros, ones); // higher ~ flatter ~ suspicious for replacement
    // quick-and-clean transition-based proxy
    let trans=0, total=0, prev=null;
    for (let off=dataOff; off<dataOff+dataLen; off+=bps){
      const v = bps===2 ? ((bufU8[off+1]<<8)|bufU8[off]) : bufU8[off];
      const bit = v&1;
      if (prev!=null && bit!==prev) trans++;
      prev = bit; total++;
    }
    const pov = Math.min(1, trans/Math.max(1,total-1)*2);
    return {pValue, pov};
  }
  function suspicionScoreImage(stats){
    const uR = clamp01(stats.pR), uG = clamp01(stats.pG), uB = clamp01(stats.pB);
    const uniformityAvg = (uR+uG+uB)/3;
    const combined = 0.6*uniformityAvg + 0.4*(stats.pov||0);
    const label = combined>0.66 ? "High" : combined>0.45 ? "Medium" : "Low";
    return {uR,uG,uB,pov:stats.pov||0, uniformity:uniformityAvg, label};
  }
  function suspicionScoreWav(stats){
    const u = clamp01(stats.pValue);
    const combined = 0.6*u + 0.4*(stats.pov||0);
    const label = combined>0.66 ? "High" : combined>0.45 ? "Medium" : "Low";
    return {uniformity:u, pov:stats.pov||0, label};
  }

  function drawBars(items){
    bars.innerHTML = items.map(it => {
      const pct = Math.round(Math.min(1, Math.max(0, it.value)) * 100);
      return `<div class="bar">
        <div class="label"><span>${escapeHtml(it.label)}</span><span>${pct}%</span></div>
        <div class="track"><div class="fill" style="width:${pct}%"></div></div>
      </div>`;
    }).join("");
  }
});
