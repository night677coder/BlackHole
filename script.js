// BLACKHOLE Cloud Storage Application - Modernized Version
// Memory-safety updates:
// - Store encrypted blobs in IndexedDB instead of localStorage base64

// Backend for non-expiring encrypted share links (mode B)
const SHARE_SERVER_DEFAULT = 'https://blackhole-7muz.onrender.com'; // default; we will auto-resolve at runtime
let SHARE_SERVER_RESOLVED = null;

    class BlackholeStorage {
    #currentUser = null;
    #cryptoKey = null;
    #userFiles = [];
    #isInitialized = false;
    #currentFilter = '';
    #dbPromise = null;

    static MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024; // 2GB soft cap (browser/device limits may apply)
    static CHUNK_SIZE = 16 * 1024 * 1024; // 16MB per chunk
    static CHUNK_THRESHOLD = 64 * 1024 * 1024; // Use chunked path for files >= 64MB

    constructor() {
        if (BlackholeStorage.instance) {
            return BlackholeStorage.instance;
        }
        BlackholeStorage.instance = this;

        document.addEventListener('contextmenu', (event) => {
            event.preventDefault();
        });
    }

    // Resolve the running share server base URL (127.0.0.1 vs localhost)
    async #resolveShareServer() {
        if (SHARE_SERVER_RESOLVED) return SHARE_SERVER_RESOLVED;
        const candidates = [
            SHARE_SERVER_DEFAULT,
            'http://127.0.0.1:3000',
            'http://localhost:3000',
            'https://blackhole-jkby.onrender.com'
        ];
        for (const base of candidates) {
            try {
                const res = await fetch(base + '/api/health', { method: 'GET' });
                if (res.ok) {
                    SHARE_SERVER_RESOLVED = base;
                    return base;
                }
            } catch {}
        }
        throw new Error('Share server not reachable. Make sure it is running on port 3000 or check your deployment.');
    }

    // IndexedDB Helpers
    async #openDB() {
        if (this.#dbPromise) return this.#dbPromise;
        this.#dbPromise = new Promise((resolve, reject) => {
            const request = indexedDB.open('blackhole_db', 2);
            request.onupgradeneeded = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains('files')) {
                    db.createObjectStore('files'); // single encrypted blob store (legacy)
                }
                if (!db.objectStoreNames.contains('chunks')) {
                    db.createObjectStore('chunks'); // key: `${id}:${index}` -> Blob
                }
                if (!db.objectStoreNames.contains('manifests')) {
                    db.createObjectStore('manifests'); // key: id -> manifest json
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
        return this.#dbPromise;
    }

    async #storeEncryptedBlob(id, blob) {
        const db = await this.#openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('files', 'readwrite');
            tx.objectStore('files').put(blob, id);
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => reject(tx.error);
        });
    }

    async #uploadChunked(blob, onProgress) {
        // Uses server chunk endpoints to upload large files without a single huge POST
        const base = await this.#resolveShareServer();
        const resInit = await fetch(`${base}/api/upload/init`, { method: 'POST' });
        if (!resInit.ok) throw new Error('init_failed');
        const { id } = await resInit.json();
        if (typeof onProgress === 'function') onProgress(0.5); // show immediate progress after init

        const chunkSize = 16 * 1024 * 1024; // 16MB chunks for faster upstream throughput
        const total = blob.size;
        let uploaded = 0;
        let index = 0;
        for (let offset = 0; offset < total; offset += chunkSize, index++) {
            const end = Math.min(offset + chunkSize, total);
            const chunk = blob.slice(offset, end);
            const res = await fetch(`${base}/api/upload/chunk/${id}/${index}`, {
                method: 'POST',
                body: chunk,
            });
            if (!res.ok) throw new Error(`chunk_failed_${index}`);
            uploaded = end;
            if (typeof onProgress === 'function') {
                const pct = (uploaded / total) * 100;
                onProgress(pct);
            }
        }

        const resDone = await fetch(`${base}/api/upload/complete/${id}`, { method: 'POST' });
        if (!resDone.ok) throw new Error('complete_failed');
        return await resDone.json(); // { id, url }
    }

    async #getEncryptedBlob(file) {
        // Prefer IndexedDB by id; fallback to legacy base64 string
        if (!file?.encryptedDataId) {
            return file?.encryptedData || null;
        }
        const db = await this.#openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('files', 'readonly');
            const req = tx.objectStore('files').get(file.encryptedDataId);
            req.onsuccess = () => {
                const result = req.result;
                if (result) resolve(result);
                else resolve(file?.encryptedData || null);
            };
            req.onerror = () => reject(req.error);
        });
    }

    async #deleteEncryptedBlob(id) {
        const db = await this.#openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('files', 'readwrite');
            tx.objectStore('files').delete(id);
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => reject(tx.error);
        });
    }

    // Chunked storage helpers
    async #storeChunk(fileId, index, blob) {
        const db = await this.#openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('chunks', 'readwrite');
            tx.objectStore('chunks').put(blob, `${fileId}:${index}`);
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => reject(tx.error);
        });
    }

    async #getChunk(fileId, index) {
        const db = await this.#openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('chunks', 'readonly');
            const req = tx.objectStore('chunks').get(`${fileId}:${index}`);
            req.onsuccess = () => resolve(req.result || null);
            req.onerror = () => reject(req.error);
        });
    }

    async #deleteChunks(fileId, count) {
        const db = await this.#openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('chunks', 'readwrite');
            const store = tx.objectStore('chunks');
            for (let i = 0; i < count; i++) {
                store.delete(`${fileId}:${i}`);
            }
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => reject(tx.error);
        });
    }

    async #saveManifest(manifest) {
        const db = await this.#openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('manifests', 'readwrite');
            tx.objectStore('manifests').put(manifest, manifest.id);
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => reject(tx.error);
        });
    }

    async #getManifest(id) {
        const db = await this.#openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('manifests', 'readonly');
            const req = tx.objectStore('manifests').get(id);
            req.onsuccess = () => resolve(req.result || null);
            req.onerror = () => reject(req.error);
        });
    }

    async #assembleDecryptedBlob(file) {
        // Assemble decrypted chunks sequentially into a Blob (memory heavy for very large files)
        if (!file.chunked) throw new Error('assemble called on non-chunked file');
        const manifest = await this.#getManifest(file.encryptedDataId);
        const parts = [];
        for (let i = 0; i < (manifest?.chunkCount || file.chunkCount || 0); i++) {
            const enc = await this.#getChunk(file.encryptedDataId, i);
            if (!enc) throw new Error(`Missing chunk ${i}`);
            const dec = await this.#decryptFile(enc, file.type || this.#inferMimeFromName(file.name));
            parts.push(dec);
        }
        return new Blob(parts, { type: file.type || this.#inferMimeFromName(file.name) });
    }

    async #streamDecryptAndUpload(file, shareKey, onProgress) {
        if (!file?.chunked) throw new Error('streamDecrypt called on non-chunked file');
        const type = file.type || this.#inferMimeFromName(file.name) || 'application/octet-stream';
        const totalSize = BigInt(file.size || 0);
        const segSize = 4 * 1024 * 1024; // 4MB segments reduce request count
        const segCount = Number((totalSize + BigInt(segSize - 1)) / BigInt(segSize));

        // Build header for segmented format
        const header = new Uint8Array(32);
        const magic = new TextEncoder().encode('BHSEG_v1');
        header.set(magic.slice(0, 8), 0);
        const dv = new DataView(header.buffer);
        dv.setUint32(8, segSize, true);
        dv.setUint32(12, Number(totalSize & 0xffffffffn), true);
        dv.setUint32(16, Number((totalSize >> 32n) & 0xffffffffn), true);
        dv.setUint32(20, segCount, true);

        // Init upload session
        const base = await this.#resolveShareServer();
        const resInit = await fetch(`${base}/api/upload/init`, { method: 'POST' });
        if (!resInit.ok) throw new Error('init_failed');
        const { id } = await resInit.json();
        let index = 0;
        let uploaded = 0;

        const send = async (buf) => {
            let attempt = 0; let lastErr;
            while (attempt < 3) {
                try {
                    const r = await fetch(`${base}/api/upload/chunk/${id}/${index++}`, { method: 'POST', body: buf });
                    if (!r.ok) throw new Error(`chunk_failed_${index-1}`);
                    uploaded += buf.byteLength || buf.size || 0;
                    if (typeof onProgress === 'function') {
                        const totalEncrypted = Number(32n + (BigInt(segCount) * (12n + 16n)) + totalSize);
                        let pct = Math.min(100, (uploaded / totalEncrypted) * 100);
                        if (uploaded > 0 && pct < 1) pct = 1;
                        onProgress(pct);
                    }
                    return;
                } catch (e) { lastErr = e; attempt++; await new Promise(r => setTimeout(r, 500 * attempt)); }
            }
            throw lastErr || new Error('chunk_failed');
        };

        // Send header
        await send(header);

        // Iterate encrypted chunks -> decrypt -> split into segments -> encrypt each segment and send
        const manifest = await this.#getManifest(file.encryptedDataId);
        const chunkCount = manifest?.chunkCount || file.chunkCount || 0;
        let plainSent = 0n;
        for (let ci = 0; ci < chunkCount; ci++) {
            const enc = await this.#getChunk(file.encryptedDataId, ci);
            if (!enc) throw new Error(`Missing chunk ${ci}`);
            const decBlob = await this.#decryptFile(enc, type);
            let off = 0;
            while (off < decBlob.size) {
                const end = Math.min(off + segSize, decBlob.size);
                const slice = decBlob.slice(off, end);
                const plain = await slice.arrayBuffer();
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, shareKey, plain);
                const combined = new Uint8Array(iv.length + cipher.byteLength);
                combined.set(iv);
                combined.set(new Uint8Array(cipher), iv.length);
                await send(combined);
                off = end;
                plainSent += BigInt(slice.size);
            }
        }

        const resDone = await fetch(`${base}/api/upload/complete/${id}`, { method: 'POST' });
        if (!resDone.ok) throw new Error('complete_failed');
        return await resDone.json();
    }
    async #handleLargeFileShare(file) {
        try {
            this.#showProgress('Preparing share link...', 0);
            const shareKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
            
            const filename = file.name || 'file';
            const mime = file.type || this.#inferMimeFromName(filename) || 'application/octet-stream';
            
            const { id, url } = await this.#streamDecryptAndUpload(file, shareKey, 
                (pct) => this.#updateProgress(pct));
            
            const raw = await crypto.subtle.exportKey('raw', shareKey);
            const keyB64 = btoa(String.fromCharCode(...new Uint8Array(raw)))
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
            
            const base = await this.#resolveShareServer();
            const shareUrl = `${base}/view/${id}#k=${keyB64}&n=${encodeURIComponent(filename)}&t=${encodeURIComponent(mime)}&m=blob`;
            
            this.#saveSharedLink(file.id, { url: shareUrl, name: filename, type: mime, createdAt: Date.now() });
            this.#renderFilteredFiles(this.#userFiles);
            
            try {
                await navigator.clipboard.writeText(shareUrl);
                this.#showSuccess('Public share link copied to clipboard');
            } catch (e) {
                prompt('Copy this share link:', shareUrl);
            }
        } catch (error) {
            throw error;
        } finally {
            this.#hideProgress();
        }
    }

    // Segmented share encryption (groundwork for progressive streaming)
    async #segmentedEncrypt(plainBlob, shareKey, opts = {}) {
        const chunkSize = opts.chunkSize || (4 * 1024 * 1024); // 4MB
        const totalSize = plainBlob.size >>> 0; // low 32 bits for header; high handled separately
        const totalSizeBig = BigInt(plainBlob.size);
        const chunkCount = Math.ceil(plainBlob.size / chunkSize);

        // 32-byte binary header
        // [0..7]   magic: 'BHSEG_v1'
        // [8..11]  chunkSize (u32, LE)
        // [12..15] totalSize low (u32, LE)
        // [16..19] totalSize high (u32, LE)
        // [20..23] chunkCount (u32, LE)
        // [24..31] reserved zero
        const header = new Uint8Array(32);
        const magic = new TextEncoder().encode('BHSEG_v1');
        header.set(magic.slice(0, 8), 0);
        const dv = new DataView(header.buffer);
        dv.setUint32(8, chunkSize, true);
        dv.setUint32(12, Number(totalSizeBig & 0xffffffffn), true);
        dv.setUint32(16, Number((totalSizeBig >> 32n) & 0xffffffffn), true);
        dv.setUint32(20, chunkCount, true);

        const parts = [header.buffer];

        let offset = 0;
        for (let i = 0; i < chunkCount; i++) {
            const end = Math.min(offset + chunkSize, plainBlob.size);
            const slice = plainBlob.slice(offset, end);
            const plain = await slice.arrayBuffer();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, shareKey, plain);
            // Each segment: [12B IV][cipher+tag]
            parts.push(iv.buffer, cipher);
            offset = end;
        }

        return new Blob(parts, { type: 'application/octet-stream' });
    }

    async #encryptAndUploadSegmented(plainBlob, shareKey, onProgress) {
        // Stream-encrypt segments and upload as we go using chunked upload API
        const chunkSize = 4 * 1024 * 1024; // 4MB segments
        const totalSizeBig = BigInt(plainBlob.size);
        const chunkCount = Math.ceil(plainBlob.size / chunkSize);

        // Build header (same as #segmentedEncrypt)
        const header = new Uint8Array(32);
        const magic = new TextEncoder().encode('BHSEG_v1');
        header.set(magic.slice(0, 8), 0);
        const dv = new DataView(header.buffer);
        dv.setUint32(8, chunkSize, true);
        dv.setUint32(12, Number(totalSizeBig & 0xffffffffn), true);
        dv.setUint32(16, Number((totalSizeBig >> 32n) & 0xffffffffn), true);
        dv.setUint32(20, chunkCount, true);

        // Init upload
        const base = await this.#resolveShareServer();
        const resInit = await fetch(`${base}/api/upload/init`, { method: 'POST' });
        if (!resInit.ok) throw new Error('init_failed');
        const { id } = await resInit.json();

        // Send header as chunk 0
        let index = 0;
        let uploaded = 0;
        const sendChunk = async (buf) => {
            let attempt = 0;
            const maxAttempts = 3;
            let lastErr;
            while (attempt < maxAttempts) {
                try {
                    const res = await fetch(`${base}/api/upload/chunk/${id}/${index++}`, { method: 'POST', body: buf });
                    if (!res.ok) throw new Error(`chunk_failed_${index-1}`);
                    uploaded += buf.byteLength || buf.size || 0;
                    if (typeof onProgress === 'function') {
                        const totalEncrypted = Number(32n + (BigInt(chunkCount) * (12n + 16n)) + totalSizeBig);
                        let pct = Math.min(100, (uploaded / totalEncrypted) * 100);
                        if (uploaded > 0 && pct < 1) pct = 1; // ensure visible progress after first bytes
                        onProgress(pct);
                    }
                    return;
                } catch (e) {
                    lastErr = e;
                    attempt++;
                    await new Promise(r => setTimeout(r, 500 * attempt));
                }
            }
            throw lastErr || new Error('chunk_failed');
        };
        await sendChunk(header);

        // Encrypt and send each segment
        let offset = 0;
        for (let i = 0; i < chunkCount; i++) {
            const end = Math.min(offset + chunkSize, plainBlob.size);
            const slice = plainBlob.slice(offset, end);
            const plain = await slice.arrayBuffer();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, shareKey, plain);
            // Send [IV][cipher+tag] as one chunk
            const combined = new Uint8Array(iv.length + cipher.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(cipher), iv.length);
            await sendChunk(combined);
            offset = end;
        }

        // Finalize
        const resDone = await fetch(`${base}/api/upload/complete/${id}`, { method: 'POST' });
        if (!resDone.ok) throw new Error('complete_failed');
        return await resDone.json();
    }

    async init() {
        if (this.#isInitialized) return;

        try {
            // Wait for DOM to be ready
            if (document.readyState === 'loading') {
                await new Promise(resolve => {
                    document.addEventListener('DOMContentLoaded', resolve);
                });
            }

            this.#bindEvents();

            // Ensure IndexedDB is ready
            await this.#openDB();

            await this.#restoreState();
            this.#isInitialized = true;
        } catch (error) {
            console.error('Initialization failed:', error);
            this.#showError('Failed to initialize application');
        }
    }

    // Shared link persistence
    #getSharedLinksStore() {
        try {
            return JSON.parse(localStorage.getItem('blackhole_shared_links') || '{}');
        } catch { return {}; }
    }

    #saveSharedLink(fileId, data) {
        const store = this.#getSharedLinksStore();
        store[fileId] = data; // keep latest link per file
        localStorage.setItem('blackhole_shared_links', JSON.stringify(store));
    }

    #getSharedLink(fileId) {
        const store = this.#getSharedLinksStore();
        return store[fileId] || null;
    }

    #bindEvents() {
        console.log('Binding events...');

        // Welcome dialog
        const enterBtn = document.getElementById('enterBtn');
        if (enterBtn) {
            enterBtn.addEventListener('click', this.#handleEnter.bind(this));
        }

        const welcomeDialog = document.getElementById('welcomeDialog');
        if (welcomeDialog) {
            welcomeDialog.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    enterBtn?.click();
                }
            });
        }

        // Auth toggle
        const showSignup = document.getElementById('showSignup');
        const showSignin = document.getElementById('showSignin');
        if (showSignup) {
            showSignup.addEventListener('click', this.#showSignupForm.bind(this));
        }
        if (showSignin) {
            showSignin.addEventListener('click', this.#showSigninForm.bind(this));
        }

        // Forms
        const signupForm = document.getElementById('signupFormElement');
        const signinForm = document.getElementById('signinFormElement');
        if (signupForm) {
            signupForm.addEventListener('submit', this.#handleSignup.bind(this));
        }
        if (signinForm) {
            signinForm.addEventListener('submit', this.#handleSignin.bind(this));
        }

        // Dashboard events
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', this.#logout.bind(this));
        }

        // File upload
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        if (uploadArea) {
            uploadArea.addEventListener('click', () => fileInput?.click());
            uploadArea.addEventListener('dragover', this.#handleDragOver.bind(this));
            uploadArea.addEventListener('dragleave', this.#handleDragLeave.bind(this));
            uploadArea.addEventListener('drop', this.#handleFileDrop.bind(this));
        }
        if (fileInput) {
           fileInput.addEventListener('change', this.#handleFileInput.bind(this));
        }

          
        // Search and filter
        const searchInput = document.getElementById('searchInput');
        const filterType = document.getElementById('filterType');
        if (searchInput) {
            searchInput.addEventListener('input', this.#handleSearch.bind(this));
        }
        if (filterType) {
            filterType.addEventListener('change', this.#handleFilter.bind(this));
        }

        // Video player
        const closeVideo = document.getElementById('closeVideo');
        const fullscreenBtn = document.getElementById('fullscreenBtn');
        if (closeVideo) {
            closeVideo.addEventListener('click', this.#closeVideoPlayer.bind(this));
        }
        if (fullscreenBtn) {
            fullscreenBtn.addEventListener('click', this.#toggleFullscreen.bind(this));
        }
    }

    async #ensureKey() {
        if (this.#cryptoKey) return;
        // Prompt for password to unlock the key when session restored without key
        const userData = JSON.parse(localStorage.getItem('blackhole_user') || 'null');
        if (!userData) {
            throw new Error('No user data. Please sign in again.');
        }
        const pwd = window.prompt('Enter your password to unlock files');
        if (!pwd) throw new Error('Password required to decrypt');
        this.#cryptoKey = await this.#importKey(userData.encryptedKey, pwd);
        if (!this.#currentUser) this.#currentUser = userData.username || null;
    }

    #showProgress(title, percent) {
        let overlay = document.getElementById('uploadProgressOverlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'uploadProgressOverlay';
            overlay.style.position = 'fixed';
            overlay.style.right = '16px';
            overlay.style.bottom = '16px';
            overlay.style.width = '280px';
            overlay.style.padding = '12px';
            overlay.style.background = 'rgba(17, 24, 39, 0.95)';
            overlay.style.color = '#fff';
            overlay.style.borderRadius = '10px';
            overlay.style.boxShadow = '0 8px 24px rgba(0,0,0,.35)';
            overlay.style.zIndex = '9999';
            overlay.innerHTML = `
                <div id="up-title" style="font-weight:600;margin-bottom:8px;font-size:14px;"></div>
                <div style="height:8px;background:#374151;border-radius:6px;overflow:hidden">
                    <div id="up-bar" style="height:8px;background:#10b981;width:0%"></div>
                </div>
                <div id="up-pct" style="margin-top:6px;font-size:12px;opacity:.85">0%</div>
            `;
            document.body.appendChild(overlay);
        }
        const titleEl = overlay.querySelector('#up-title');
        const barEl = overlay.querySelector('#up-bar');
        const pctEl = overlay.querySelector('#up-pct');
        if (titleEl) titleEl.textContent = title || 'Uploading...';
        const pct = Math.max(0, Math.min(100, Math.round(percent || 0)));
        if (barEl) barEl.style.width = pct + '%';
        if (pctEl) pctEl.textContent = pct + '%';
    }

    #updateProgress(percent) {
        this.#showProgress('Uploading...', percent);
    }

    #hideProgress() {
        const overlay = document.getElementById('uploadProgressOverlay');
        if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
    }

    #uploadWithProgress(url, formData, onProgress) {
        return new Promise((resolve, reject) => {
            try {
                const xhr = new XMLHttpRequest();
                xhr.open('POST', url, true);
                xhr.responseType = 'json';
                xhr.upload.onprogress = (e) => {
                    if (e.lengthComputable) {
                        const pct = (e.loaded / e.total) * 100;
                        if (typeof onProgress === 'function') onProgress(pct);
                    }
                };
                xhr.onload = () => {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        resolve(xhr.response);
                    } else {
                        reject(new Error(`Upload failed (${xhr.status})`));
                    }
                };
                xhr.onerror = () => reject(new Error('Network error during upload'));
                xhr.send(formData);
            } catch (err) {
                reject(err);
            }
        });
    }

    #handleEnter(e) {
        console.log('Enter button clicked!');
        console.log('Event object:', e);

        e.preventDefault();
        console.log('Calling hideWelcomeDialog...');
        this.#hideWelcomeDialog();
        // Ensure dashboard is fully hidden and auth is shown
        const dashboard = document.getElementById('dashboard');
        const footer = document.getElementById('footer');
        const body = document.body;
        if (dashboard) dashboard.style.display = 'none';
        if (footer) footer.style.display = 'none';
        body.classList.remove('dashboard-active');

        console.log('Calling showAuthSection...');
        this.#showAuthSection();
    }

    // Welcome Dialog
    #showWelcomeDialog() {
        const dialog = document.getElementById('welcomeDialog');
        if (dialog) {
            dialog.style.display = 'flex';
        }
    }

    #hideWelcomeDialog() {
        const dialog = document.getElementById('welcomeDialog');
        if (dialog) {
            dialog.style.display = 'none';
        }
    }

    #resetToWelcome() {
        const dialog = document.getElementById('welcomeDialog');
        const authSection = document.getElementById('authSection');
        const dashboard = document.getElementById('dashboard');
        const footer = document.getElementById('footer');
        const body = document.body;

        if (dashboard) dashboard.style.display = 'none';
        if (footer) footer.style.display = 'none';
        if (authSection) authSection.style.display = 'none';
        if (dialog) {
            dialog.style.display = 'flex';
            dialog.focus();
        }
        body.classList.remove('dashboard-active');
    }

    // Authentication Section
    #showAuthSection() {
        console.log('showAuthSection called');
        const authSection = document.getElementById('authSection');
        const welcomeDialog = document.getElementById('welcomeDialog');
        const dashboard = document.getElementById('dashboard');
        const footer = document.getElementById('footer');
        const body = document.body;

        console.log('Welcome dialog element:', welcomeDialog);
        console.log('Auth section element:', authSection);

        if (welcomeDialog) {
            console.log('Hiding welcome dialog');
            welcomeDialog.style.display = 'none';
        }

        if (authSection) {
            console.log('Showing auth section');
            authSection.style.display = 'block';
            this.#showSignupForm();
            console.log('Auth section shown'); // Debug log
        } else {
            console.error('Auth section element not found!');
        }

        // Ensure dashboard is hidden while in auth
        if (dashboard) dashboard.style.display = 'none';
        if (footer) footer.style.display = 'none';
        body.classList.remove('dashboard-active');
        console.log('Removed dashboard-active class from body while in auth');
    }

    #showSignupForm() {
        this.#toggleAuthForm('signup');
    }
    #showSigninForm() {
        this.#toggleAuthForm('signin');
    }

    #toggleAuthForm(formType) {
        const signinForm = document.getElementById('signinForm');
        const signupForm = document.getElementById('signupForm');
        
        if (formType === 'signin') {
            signinForm?.classList.add('active');
            signupForm?.classList.remove('active');
            console.log('Signin form activated'); // Debug log
        } else {
            signupForm?.classList.add('active');
            signinForm?.classList.remove('active');
            console.log('Signup form activated'); // Debug log
        }
    }

    // Authentication Handlers
    async #handleSignup(e) {
        e.preventDefault();

        const formData = new FormData(e.target);
        let { username, email, password } = Object.fromEntries(formData);

        username = username?.trim() || '';
        email = email?.trim() || '';

        if (!username || !email || !password) {
            this.#showError('Please fill in all fields');
            return;
        }

        try {
            console.log('Starting signup process...');

            // Check if Web Crypto API is available
            if (!crypto || !crypto.subtle) {
                throw new Error('Web Crypto API not supported in this browser');
            }

            console.log('Generating encryption key...');
            this.#cryptoKey = await this.#generateEncryptionKey(password);
            console.log('Encryption key generated successfully');

            const userData = {
                username: username.toLowerCase(),
                email: email.toLowerCase(),
                encryptedKey: await this.#exportKey(this.#cryptoKey),
                createdAt: new Date().toISOString()
            };

            console.log('Saving user data to localStorage...');
            localStorage.setItem('blackhole_user', JSON.stringify(userData));
            localStorage.setItem('blackhole_files', JSON.stringify([]));

            // Do not auto-login; require explicit signin
            this.#cryptoKey = null;
            this.#currentUser = null;
            console.log('Signup completed successfully');
            this.#showSigninForm();
            this.#showSuccess('Account created successfully! Please sign in.');

        } catch (error) {
            console.error('Signup failed:', error);
            this.#showError(`Failed to create account: ${error.message}`);
        }
    }
    async #handleSignin(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        let { username, password } = Object.fromEntries(formData);
        username = (username?.trim() || '').toLowerCase();

        if (!username || !password) {
            this.#showError('Please enter username and password');
            return;
        }

        try {
            const userData = JSON.parse(localStorage.getItem('blackhole_user') || 'null');

            if (userData && userData.username === username) {
                this.#cryptoKey = await this.#importKey(userData.encryptedKey, password);
                this.#currentUser = username;
                await this.#loadUserFiles();
                this.#showDashboard();
                this.#showSuccess('Welcome back!');
                // Persist session across refresh
                localStorage.setItem('blackhole_session', 'active');
                localStorage.setItem('blackhole_username', username);
            } else {
                this.#showError('Invalid username or password');
            }

        } catch (error) {
            console.error('Signin failed:', error);
            this.#showError('Failed to sign in. Please check your credentials.');
        }
    }

    #logout() {
        this.#currentUser = null;
        this.#cryptoKey = null;
        this.#userFiles = [];
        
        const dashboard = document.getElementById('dashboard');
        const footer = document.getElementById('footer');
        const authSection = document.getElementById('authSection');
        const body = document.body;
        
        if (dashboard) dashboard.style.display = 'none';
        if (footer) footer.style.display = 'none';
        if (authSection) authSection.style.display = 'block';
        
        // Remove full-screen class
        body.classList.remove('dashboard-active');
        
        this.#showSigninForm();
        this.#showSuccess('Logged out successfully');
        // Clear session persistence
        localStorage.removeItem('blackhole_session');
        localStorage.removeItem('blackhole_username');
    }

    #handleSearch(e) {
        const searchTerm = (e?.target?.value || '').toLowerCase();
        console.log('[Search] term =', searchTerm);
        this.#filterAndRenderFiles(searchTerm, this.#currentFilter);
    }

    #handleFilter(e) {
        const filterType = e?.target?.value || '';
        console.log('[Filter] type =', filterType);
        this.#currentFilter = filterType;
        const searchTerm = document.getElementById('searchInput')?.value.toLowerCase() || '';
        this.#filterAndRenderFiles(searchTerm, filterType);
    }

    #filterAndRenderFiles(searchTerm = '', filterType = '') {
        let filteredFiles = this.#userFiles;

        // Apply search filter
        if (searchTerm) {
            filteredFiles = filteredFiles.filter(file =>
                file.name.toLowerCase().includes(searchTerm)
            );
        }

        // Apply type filter
        if (filterType) {
            const isMatchByExt = (name, kind) => {
                const lower = name.toLowerCase();
                const sets = {
                    'image/': /(\.png|\.jpg|\.jpeg|\.gif|\.bmp|\.webp|\.svg)$/,
                    'video/': /(\.mp4|\.webm|\.ogg|\.mkv|\.mov|\.avi)$/,
                    'audio/': /(\.mp3|\.wav|\.ogg|\.flac|\.m4a)$/,
                    'text/': /(\.txt|\.md|\.csv|\.json|\.log|\.xml|\.html|\.pdf)$/
                };
            
                const rx = sets[kind];
                return rx ? rx.test(lower) : false;
            };

            filteredFiles = filteredFiles.filter(file =>
                (file.type && file.type.startsWith(filterType)) || isMatchByExt(file.name, filterType)
            );
        }

        this.#renderFilteredFiles(filteredFiles);
    }

    #renderFilteredFiles(files) {
        const filesList = document.getElementById('filesList');
        if (!filesList) return;

        if (files.length === 0) {
            filesList.classList.add('empty');
            if (this.#userFiles.length === 0) {
                filesList.innerHTML = '<p class="no-files">No files uploaded yet. Drag & drop files here or click to browse.</p>';
            } else {
                filesList.innerHTML = '<p class="no-files">No files match your search criteria.</p>';
            }
            return;
        }

        filesList.classList.remove('empty');
        filesList.innerHTML = files.map(file => `
            <div class="file-item" data-id="${file.id}">
                <div class="file-info">
                    <div class="file-icon">${this.#getFileIcon(file.type)}</div>
                    <div class="file-details">
                        <h4>${this.#escapeHtml(file.name || '(unnamed)')}</h4>
                        <p>${this.#formatFileSize(file.size)} • ${this.#formatDate(file.uploadDate)}</p>
                    </div>
                </div>
                <div class="file-actions">
                    ${this.#getFileActions(file)}
                    <button class="btn-delete" onclick="blackhole.deleteFile('${file.id}')">🗑️</button>
                </div>
            </div>
        `).join('');
    }

    #showDashboard() {
        const authSection = document.getElementById('authSection');
        const dashboard = document.getElementById('dashboard');
        const footer = document.getElementById('footer');
        const body = document.body;

        if (authSection) authSection.style.display = 'none';
        if (dashboard) dashboard.style.display = 'flex';
        if (footer) footer.style.display = 'block';

        // Add full-screen class to body
        body.classList.add('dashboard-active');

        this.#renderFilteredFiles(this.#userFiles);
    }

    async #restoreState() {
        try {
            const session = localStorage.getItem('blackhole_session');
            if (session === 'active') {
                // Attempt to restore username and load files; cryptoKey still required for decrypt
                this.#currentUser = localStorage.getItem('blackhole_username') || null;
                await this.#loadUserFiles();
                this.#showDashboard();
                return;
            }
        } catch (e) {
            console.warn('Restore state failed:', e);
        }
        this.#resetToWelcome();
    }

    // File Management
    async #handleFileInput(e) {
        const files = Array.from(e.target.files || []);
        if (files.length > 0) {
            await this.#handleFileUpload(files);
        }
        // Reset input
        e.target.value = '';
    }

    #handleDragOver(e) {
        e.preventDefault();
        e.target.style.background = '#e9ecef';
    }

    #handleDragLeave(e) {
        e.preventDefault();
        e.target.style.background = '#f8f9fa';
    }

    async #handleFileDrop(e) {
        e.preventDefault();
        e.target.style.background = '#f8f9fa';
        
        const files = Array.from(e.dataTransfer.files || []);
        if (files.length > 0) {
            await this.#handleFileUpload(files);
        }
    }

    async #handleFileUpload(files) {
        const validFiles = files.filter(f => {
            if (f.size > BlackholeStorage.MAX_FILE_SIZE) {
                this.#showError(`${f.name}: exceeds ${(BlackholeStorage.MAX_FILE_SIZE / (1024*1024))|0}MB limit`);
                return false;
            }
            return true;
        });

        // Ensure encryption key is available (handles refreshed sessions)
        try {
            await this.#ensureKey();
        } catch (e) {
            this.#showError('Please enter your password to unlock uploads');
            return;
        }

        const uploadPromises = validFiles.map(file => this.#processFile(file));
        
        try {
            const results = await Promise.allSettled(uploadPromises);
            const ok = results.filter(r => r.status === 'fulfilled').length;
            this.#renderFilteredFiles(this.#userFiles);
            if (ok > 0) this.#showSuccess(`${ok} file(s) uploaded successfully`);
            const failed = results.length - ok;
            if (failed > 0) this.#showError(`${failed} file(s) failed to upload`);
        } catch (error) {
            console.error('Upload failed:', error);
            this.#showError('Some files failed to upload');
        }
    }

    async #processFile(file) {
        try {
            const id = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            let fileData;

            if (file.size >= BlackholeStorage.CHUNK_THRESHOLD) {
                // Chunked path
                const manifest = await this.#encryptAndStoreChunks(file, id);
                await this.#saveManifest(manifest);
                fileData = {
                    id,
                    name: file.name,
                    size: file.size,
                    type: file.type,
                    encryptedDataId: id,
                    chunked: true,
                    chunkSize: manifest.chunkSize,
                    chunkCount: manifest.chunkCount,
                    uploadDate: new Date().toISOString(),
                    lastModified: file.lastModified
                };
            } else {
                // Single-blob path (legacy-compatible)
                const encryptedBlob = await this.#encryptFile(file);
                await this.#storeEncryptedBlob(id, encryptedBlob);
                fileData = {
                    id,
                    name: file.name,
                    size: file.size,
                    type: file.type,
                    encryptedDataId: id,
                    chunked: false,
                    uploadDate: new Date().toISOString(),
                    lastModified: file.lastModified
                };
            }

            this.#userFiles.push(fileData);
            this.#saveUserFiles();
            return fileData;

        } catch (error) {
            console.error(`Failed to upload ${file.name}:`, error);
            throw new Error(`Failed to upload ${file.name}`);
        }
    }

    async #encryptAndStoreChunks(file, id) {
        const size = file.size;
        const chunkSize = BlackholeStorage.CHUNK_SIZE;
        const chunkCount = Math.ceil(size / chunkSize);

        for (let index = 0; index < chunkCount; index++) {
            const start = index * chunkSize;
            const end = Math.min(start + chunkSize, size);
            const slice = file.slice(start, end);
            const encryptedBlob = await this.#encryptFile(slice);
            await this.#storeChunk(id, index, encryptedBlob);
        }

        return {
            id,
            chunkSize,
            chunkCount,
            size,
            type: file.type,
            createdAt: Date.now()
        };
    }

    #renderFiles() {
        const filesList = document.getElementById('filesList');
        if (!filesList) return;

        if (this.#userFiles.length === 0) {
            filesList.classList.add('empty');
            filesList.innerHTML = '<p class="no-files">No files uploaded yet. Drag & drop files here or click to browse.</p>';
            return;
        }

        filesList.classList.remove('empty');
        filesList.innerHTML = this.#userFiles.map(file => `
            <div class="file-item" data-id="${file.id}">
                <div class="file-info">
                    <div class="file-icon">${this.#getFileIcon(file.type)}</div>
                    <div class="file-details">
                        <h4>${this.#escapeHtml(file.name)}</h4>
                        <p>${this.#formatFileSize(file.size)} • ${this.#formatDate(file.uploadDate)}</p>
                    </div>
                </div>
                <div class="file-actions">
                    ${this.#getFileActions(file)}
                    <button class="btn-delete" onclick="blackhole.deleteFile('${file.id}')">🗑️</button>
                </div>
            </div>
        `).join('');
    }

    #getFileIcon(mimeType) {
        const m = (mimeType || '').toLowerCase();
        if (m.startsWith('image/')) return '🖼️';
        if (m.startsWith('video/')) return '🎥';
        if (m.startsWith('audio/')) return '🎵';
        if (m.includes('pdf')) return '📄';
        if (m.includes('document') || m.includes('text')) return '📝';
        return '📁';
    }

    #getFileActions(file) {
        const actions = [];
        
        const name = (file.name || '').toLowerCase();
        const isImage = (file.type && file.type.startsWith('image/')) || /(\.png|\.jpg|\.jpeg|\.gif|\.bmp|\.webp|\.svg)$/.test(name);
        const isVideo = (file.type && file.type.startsWith('video/')) || /(\.mp4|\.webm|\.ogg|\.mkv|\.mov|\.avi)$/.test(name);

        if (isImage) {
            actions.push(`<button class="btn-preview" onclick="blackhole.previewFile('${file.id}')">👁️</button>`);
        }
        
        if (isVideo) {
            actions.push(`<button class="btn-play" onclick="blackhole.playVideo('${file.id}')">▶️</button>`);
        }
        
        actions.push(`<button class="btn-download" onclick="blackhole.downloadFile('${file.id}')">⬇️</button>`);

        // Share link indicator/actions
        const link = this.#getSharedLink(file.id);
        if (link?.url) {
            // show copy/open icons when a link exists
            actions.push(`<button class="btn-share" title="Copy share link" onclick="blackhole.copySharedLink('${file.id}')">🔗</button>`);
            actions.push(`<button class="btn-open-share" title="Open share link" onclick="blackhole.openSharedLink('${file.id}')">🌐</button>`);
        } else {
            // show create-share action when none exists yet
            actions.push(`<button class="btn-share" title="Create share link" onclick="blackhole.shareFile('${file.id}')">🔗</button>`);
        }
        
        return actions.join('');
    }

    copySharedLink(fileId) {
        const link = this.#getSharedLink(fileId);
        if (!link?.url) {
            this.#showError('No share link for this file yet');
            return;
        }
        const url = link.url;
        (async () => {
            try {
                if (!window.isSecureContext) throw new Error('Not a secure context');
                await navigator.clipboard.writeText(url);
                this.#showSuccess('Share link copied');
            } catch {
                try {
                    const tmp = document.createElement('input');
                    tmp.style.position = 'fixed'; tmp.style.left = '-9999px';
                    tmp.value = url; document.body.appendChild(tmp); tmp.select();
                    const ok = document.execCommand('copy'); document.body.removeChild(tmp);
                    if (ok) this.#showSuccess('Share link copied'); else throw new Error();
                } catch {
                    prompt('Copy this share link:', url);
                }
            }
        })();
    }

    openSharedLink(fileId) {
        const link = this.#getSharedLink(fileId);
        if (!link?.url) {
            this.#showError('No share link for this file yet');
            return;
        }
        window.open(link.url, '_blank');
    }

    async shareFile(fileId) {
        const file = this.#userFiles.find(f => f.id === fileId);
        if (!file) {
            console.error('File not found:', fileId);
            return;
        }

        console.log('Starting share for file:', file.name, 'chunked:', file.chunked);

        try {
            await this.#ensureKey();
            console.log('Key ensured successfully');
            
            if (file.chunked) {
                console.log('Sharing chunked file');
                await this.#handleLargeFileShare(file);
            } else {
                console.log('Sharing small file');
                await this.#handleSmallFileShare(file);
            }
            console.log('Share completed successfully');
        } catch (error) {
            console.error('Share failed:', error);
            this.#showError('Failed to create share link: ' + error.message);
        }
    }

    async #handleSmallFileShare(file) {
        console.log('Starting small file share for:', file.name);
        try {
            this.#showProgress('Preparing share link...', 0);
            
            // Generate share key
            console.log('Generating share key...');
            const shareKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
            console.log('Share key generated');
            
            const filename = file.name || 'file';
            const mime = file.type || this.#inferMimeFromName(filename) || 'application/octet-stream';
            console.log('Filename:', filename, 'MIME:', mime);
            
            // Get and decrypt the file
            console.log('Getting encrypted blob...');
            const encrypted = await this.#getEncryptedBlob(file);
            console.log('Encrypted blob retrieved, size:', encrypted?.size);
            
            console.log('Decrypting file...');
            const decryptedBlob = await this.#decryptFile(
                encrypted,
                file.type || this.#inferMimeFromName(file.name)
            );
            console.log('File decrypted, size:', decryptedBlob?.size);
            
            // Re-encrypt and upload as segments
            console.log('Starting upload...');
            const { id, url } = await this.#encryptAndUploadSegmented(decryptedBlob, shareKey, 
                (pct) => {
                    console.log('Upload progress:', pct);
                    this.#updateProgress(pct);
                });
            console.log('Upload completed, id:', id, 'url:', url);
            
            // Create share URL
            console.log('Creating share URL...');
            const raw = await crypto.subtle.exportKey('raw', shareKey);
            const keyB64 = btoa(String.fromCharCode(...new Uint8Array(raw)))
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
            
            const base = await this.#resolveShareServer();
            const shareUrl = `${base}/view/${id}#k=${keyB64}&n=${encodeURIComponent(filename)}&t=${encodeURIComponent(mime)}&m=blob`;
            console.log('Share URL created:', shareUrl);
            
            this.#saveSharedLink(file.id, { url: shareUrl, name: filename, type: mime, createdAt: Date.now() });
            this.#renderFilteredFiles(this.#userFiles);
            
            try {
                await navigator.clipboard.writeText(shareUrl);
                this.#showSuccess('Public share link copied to clipboard');
            } catch (e) {
                prompt('Copy this share link:', shareUrl);
            }
        } catch (error) {
            console.error('Small file share failed:', error);
            throw error;
        } finally {
            this.#hideProgress();
        }
    }

    #escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    async previewFile(fileId) {
        const file = this.#userFiles.find(f => f.id === fileId);
        if (!file) return;

        try {
            await this.#ensureKey();
            const encrypted = await this.#getEncryptedBlob(file);
            const decryptedBlob = await this.#decryptFile(
                encrypted,
                file.type || this.#inferMimeFromName(file.name)
            );
            
            if (file.type.startsWith('image/')) {
                this.#showImagePreview(decryptedBlob, file.name);
            } else {
                this.#showDocumentPreview(decryptedBlob, file.name);
            }
        } catch (error) {
            console.error('Preview failed:', error);
            this.#showError('Failed to preview file');
        }
    }

    #showImagePreview(blob, fileName) {
        const url = URL.createObjectURL(blob);
        const preview = document.createElement('div');
        preview.className = 'image-preview-overlay';
        preview.innerHTML = `
            <div class="image-preview-content">
                <img src="${url}" alt="${fileName}" />
                <button class="btn-close-preview" onclick="this.parentElement.parentElement.remove()">×</button>
            </div>
        `;
        
        preview.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 4000;
            cursor: pointer;
        `;
        
        const content = preview.querySelector('.image-preview-content');
        content.style.cssText = `
            position: relative;
            max-width: 90%;
            max-height: 90%;
        `;
        
        const img = content.querySelector('img');
        img.style.cssText = `
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
        `;
        
        document.body.appendChild(preview);
        
        preview.addEventListener('click', (e) => {
            if (e.target === preview) {
                preview.remove();
                URL.revokeObjectURL(url);
            }
        });
    }

    #showDocumentPreview(blob, fileName) {
        // For now, just download the file
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        a.click();
        URL.revokeObjectURL(url);
    }

    async playVideo(fileId) {
        const file = this.#userFiles.find(f => f.id === fileId);
        if (!file) return;

        try {
            await this.#ensureKey();
            let videoUrl = '';
            if (file.chunked) {
                // Reliable path: assemble decrypted Blob from chunks (MSE disabled for now)
                const blob = await this.#assembleDecryptedBlob(file);
                videoUrl = URL.createObjectURL(blob);
            } else {
                const encrypted = await this.#getEncryptedBlob(file);
                const decryptedBlob = await this.#decryptFile(
                    encrypted,
                    file.type || this.#inferMimeFromName(file.name)
                );
                videoUrl = URL.createObjectURL(decryptedBlob);
            }

            const videoElement = document.getElementById('videoElement');
            if (videoElement && videoUrl) {
                try {
                    videoElement.pause();
                    videoElement.srcObject = null;
                    videoElement.src = '';
                    // Assign new URL and load
                    videoElement.src = videoUrl;
                    videoElement.load();
                    // Try autoplay; some browsers require user gesture
                    const p = videoElement.play();
                    if (p && typeof p.then === 'function') {
                        p.catch(err => console.warn('Autoplay failed (likely requires user gesture):', err));
                    }
                } catch (e) {
                    console.warn('Video element setup failed:', e);
                }
            }

            const videoPlayer = document.getElementById('videoPlayer');
            if (videoPlayer) {
                videoPlayer.style.display = 'flex';
            }

        } catch (error) {
            console.error('Video playback failed:', error);
            this.#showError('Failed to play video file');
        }
    }

    async #streamPlayVideo(file) {
        const videoElement = document.getElementById('videoElement');
        const videoPlayer = document.getElementById('videoPlayer');
        if (!videoElement || !videoPlayer) return false;

        const type = file.type || this.#inferMimeFromName(file.name) || 'video/mp4';

        if (typeof MediaSource === 'undefined' || !MediaSource.isTypeSupported) return false;

        // Try a few MIME variants for common containers
        const candidates = [
            type,
            type.startsWith('video/mp4') ? 'video/mp4; codecs="avc1.42E01E, mp4a.40.2"' : '',
            type.startsWith('video/webm') ? 'video/webm; codecs="vp9,opus"' : '',
            type.startsWith('video/webm') ? 'video/webm; codecs="vp8,vorbis"' : ''
        ].filter(Boolean);

        let chosen = candidates.find(m => MediaSource.isTypeSupported(m));
        if (!chosen) return false;

        const mediaSource = new MediaSource();
        const url = URL.createObjectURL(mediaSource);
        videoElement.src = url;
        videoPlayer.style.display = 'flex';

        return await new Promise((resolve) => {
            mediaSource.addEventListener('sourceopen', async () => {
                let sourceBuffer;
                try {
                    sourceBuffer = mediaSource.addSourceBuffer(chosen);
                } catch (e) {
                    console.warn('Failed to add SourceBuffer:', e);
                    mediaSource.endOfStream();
                    resolve(false);
                    return;
                }

                const manifest = await this.#getManifest(file.encryptedDataId);
                const total = manifest?.chunkCount || file.chunkCount || 0;
                let index = 0;
                let aborted = false;

                const appendNext = async () => {
                    if (aborted) return;
                    if (index >= total) {
                        try { mediaSource.endOfStream(); } catch {}
                        resolve(true);
                        return;
                    }
                    try {
                        const enc = await this.#getChunk(file.encryptedDataId, index);
                        if (!enc) throw new Error(`Missing chunk ${index}`);
                        const decBlob = await this.#decryptFile(enc, chosen.split(';')[0]);
                        const buf = await decBlob.arrayBuffer();
                        if (!sourceBuffer.updating) {
                            sourceBuffer.appendBuffer(buf);
                            index++;
                        } else {
                            // wait and retry
                            setTimeout(appendNext, 10);
                            return;
                        }
                    } catch (e) {
                        console.error('MSE append error:', e);
                        try { mediaSource.endOfStream('network'); } catch {}
                        resolve(false);
                        return;
                    }
                };

                sourceBuffer.addEventListener('updateend', appendNext);
                sourceBuffer.addEventListener('error', () => {
                    console.error('SourceBuffer error');
                    aborted = true;
                    try { mediaSource.endOfStream('decode'); } catch {}
                    resolve(false);
                });

                appendNext();
            }, { once: true });
        });
    }

    #closeVideoPlayer() {
        const videoPlayer = document.getElementById('videoPlayer');
        const videoElement = document.getElementById('videoElement');
        
        if (videoPlayer) {
            videoPlayer.style.display = 'none';
        }
        
        if (videoElement) {
            try { videoElement.pause(); } catch {}
            try { URL.revokeObjectURL(videoElement.src); } catch {}
            videoElement.removeAttribute('src');
            videoElement.srcObject = null;
            try { videoElement.load(); } catch {}
        }
    }

    #toggleFullscreen() {
        const videoPlayer = document.getElementById('videoPlayer');
        if (!videoPlayer) return;

        try {
            if (!document.fullscreenElement) {
                videoPlayer.requestFullscreen();
            } else {
                document.exitFullscreen();
            }
        } catch (error) {
            console.error('Fullscreen toggle failed:', error);
        }
    }

    async downloadFile(fileId) {
        const file = this.#userFiles.find(f => f.id === fileId);
        if (!file) return;

        try {
            await this.#ensureKey();
            let blob;
            if (file.chunked) {
                blob = await this.#assembleDecryptedBlob(file);
            } else {
                const encrypted = await this.#getEncryptedBlob(file);
                blob = await this.#decryptFile(
                    encrypted,
                    file.type || this.#inferMimeFromName(file.name)
                );
            }
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = file.name;
            a.click();
            
            setTimeout(() => URL.revokeObjectURL(url), 100);

        } catch (error) {
            console.error('Download failed:', error);
            this.#showError('Failed to download file');
        }
    }

    deleteFile(fileId) {
        const index = this.#userFiles.findIndex(f => f.id === fileId);
        if (index === -1) return;
        
        const [removed] = this.#userFiles.splice(index, 1);
        this.#saveUserFiles();
        if (removed?.encryptedDataId) {
            if (removed.chunked && removed.chunkCount) {
                this.#deleteChunks(removed.encryptedDataId, removed.chunkCount).catch(e => console.warn('Failed to delete chunks:', e));
                // Also remove manifest
                this.#saveManifest({ id: removed.encryptedDataId, deleted: true }).catch(() => {});
            } else {
                this.#deleteEncryptedBlob(removed.encryptedDataId).catch(e => console.warn('Failed to delete blob:', e));
            }
        }
        this.#renderFilteredFiles(this.#userFiles);
        this.#showSuccess('File deleted successfully');
    }

    async #loadUserFiles() {
        try {
            const files = localStorage.getItem('blackhole_files');
            if (files) {
                this.#userFiles = JSON.parse(files);
                this.#renderFilteredFiles(this.#userFiles);
            }
        } catch (error) {
            console.error('Failed to load files:', error);
            this.#userFiles = [];
        }
    }

    #saveUserFiles() {
        try {
            localStorage.setItem('blackhole_files', JSON.stringify(this.#userFiles));
        } catch (error) {
            console.error('Failed to save files:', error);
            this.#showError('Failed to save files locally');
        }
    }

    // Encryption Utilities
    async #generateEncryptionKey(password) {
        try {
            console.log('Starting key generation...');

            // Validate password
            if (!password || password.length < 8) {
                throw new Error('Password must be at least 8 characters long');
            }

            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(password),
                'PBKDF2',
                false,
                ['deriveBits', 'deriveKey']
            );

            console.log('Key material imported successfully');

            const salt = new TextEncoder().encode('blackhole-salt-2024');
            console.log('Deriving key with PBKDF2...');

            return await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 200000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                true, // Changed from false to true to make key extractable
                ['encrypt', 'decrypt']
            );
        } catch (error) {
            console.error('Key generation failed:', error);
            throw new Error(`Key generation failed: ${error.message}`);
        }
    }

    async #exportKey(key) {
        const exported = await crypto.subtle.exportKey('raw', key);
        return btoa(String.fromCharCode(...new Uint8Array(exported)));
    }

    async #importKey(encryptedKeyStr, password) {
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: new TextEncoder().encode('blackhole-salt-2024'),
                iterations: 200000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true, // Changed from false to true to make key extractable
            ['encrypt', 'decrypt']
        );
    }

    async #encryptFile(file) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const plain = await file.arrayBuffer();
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.#cryptoKey,
            plain
        );

        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);

        return new Blob([combined], { type: 'application/octet-stream' });
    }

    // Decode standard or URL-safe base64 to Uint8Array with padding and data URL handling
    #b64ToBytes(b64) {
        if (typeof b64 !== 'string') throw new Error('Expected base64 string');
        let s = b64.trim();
        // Strip data URL prefix if present
        const m = s.match(/^data:.*?;base64,(.*)$/);
        if (m) s = m[1];
        // Normalize URL-safe -> standard and remove whitespace
        s = s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
        // Fix padding
        const pad = s.length % 4;
        if (pad === 1) throw new Error('Invalid base64 length');
        if (pad) s += '='.repeat(4 - pad);
        try {
            const bin = atob(s);
            const out = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
            return out;
        } catch (e) {
            throw new Error('Invalid base64 payload');
        }
    }

    async #decryptFile(encryptedPayload, contentType = '') {
        // Backward compatibility: support base64 string payloads stored earlier
        let combinedU8;
        if (typeof encryptedPayload === 'string') {
            combinedU8 = this.#b64ToBytes(encryptedPayload);
        } else if (encryptedPayload instanceof Blob) {
            const buf = await encryptedPayload.arrayBuffer();
            combinedU8 = new Uint8Array(buf);
        } else if (encryptedPayload instanceof Uint8Array) {
            combinedU8 = encryptedPayload;
        } else {
            throw new Error('Unsupported encrypted payload format');
        }

        const iv = combinedU8.slice(0, 12);
        const encrypted = combinedU8.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.#cryptoKey,
            encrypted
        );

        return contentType
            ? new Blob([decrypted], { type: contentType })
            : new Blob([decrypted]);
    }

    #inferMimeFromName(name = '') {
        const n = name.toLowerCase();
        if (/\.mp4$/.test(n)) return 'video/mp4';
        if (/\.webm$/.test(n)) return 'video/webm';
        if (/\.ogg$/.test(n)) return 'video/ogg';
        if (/\.mkv$/.test(n)) return 'video/x-matroska';
        if (/\.mov$/.test(n)) return 'video/quicktime';
        if (/\.avi$/.test(n)) return 'video/x-msvideo';
        if (/\.png$/.test(n)) return 'image/png';
        if (/\.jpg$/.test(n) || /\.jpeg$/.test(n)) return 'image/jpeg';
        if (/\.gif$/.test(n)) return 'image/gif';
        if (/\.webp$/.test(n)) return 'image/webp';
        if (/\.svg$/.test(n)) return 'image/svg+xml';
        if (/\.mp3$/.test(n)) return 'audio/mpeg';
        if (/\.wav$/.test(n)) return 'audio/wav';
        if (/\.flac$/.test(n)) return 'audio/flac';
        if (/\.m4a$/.test(n)) return 'audio/mp4';
        if (/\.pdf$/.test(n)) return 'application/pdf';
        if (/\.txt$/.test(n)) return 'text/plain';
        if (/\.json$/.test(n)) return 'application/json';
        if (/\.csv$/.test(n)) return 'text/csv';
        if (/\.html$/.test(n)) return 'text/html';
        return '';
    }

    // Utility Functions
    #formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
    }

    #formatDate(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        
        if (diffDays === 0) {
            return 'Today';
        } else if (diffDays === 1) {
            return 'Yesterday';
        } else if (diffDays < 7) {
            return `${diffDays} days ago`;
        } else {
            return date.toLocaleDateString();
        }
    }

    #showError(message) {
        this.#showNotification(message, 'error');
    }

    #showSuccess(message) {
        this.#showNotification(message, 'success');
    }

    #showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        
        const colors = {
            error: { bg: '#dc3545', color: '#fff' },
            success: { bg: '#28a745', color: '#fff' },
            info: { bg: '#17a2b8', color: '#fff' }
        };
        
        const style = colors[type] || colors.info;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${style.bg};
            color: ${style.color};
            padding: 1rem 1.5rem;
            border-radius: 8px;
            z-index: 5000;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            font-weight: 500;
            max-width: 300px;
            word-wrap: break-word;
            animation: slideInRight 0.3s ease-out;
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }, 4000);
    }
}

// Initialize the application
console.log('Initializing BLACKHOLE application...');
const blackhole = new BlackholeStorage();

// Ensure DOM is ready before initializing
if (document.readyState === 'loading') {
    console.log('DOM still loading, waiting...');
    document.addEventListener('DOMContentLoaded', () => {
        console.log('DOM ready, initializing...');
        blackhole.init();
    });
} else {
    console.log('DOM already ready, initializing immediately...');
    blackhole.init();
}

// Add CSS animations
if (!document.getElementById('notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
        @keyframes slideInRight {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @keyframes slideOutRight {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }
        
        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 0.5rem;
            background: #fff;
            transition: box-shadow 0.2s;
        }
        
        .file-item:hover {
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        
        .file-info {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .file-icon {
            font-size: 1.5rem;
        }
        
        .file-details h4 {
            margin: 0 0 0.25rem 0;
            font-size: 1rem;
        }
        
        .file-details p {
            margin: 0;
            font-size: 0.875rem;
            color: #666;
        }
        
        .file-actions {
            display: flex;
            gap: 0.5rem;
        }
        
        .btn-preview, .btn-play, .btn-download, .btn-delete {
            background: none;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 0.5rem;
            cursor: pointer;
            font-size: 1rem;
            transition: background-color 0.2s;
        }
        
        .btn-preview:hover { background-color: #e9ecef; }
        .btn-play:hover { background-color: #e9ecef; }
        .btn-download:hover { background-color: #e9ecef; }
        .btn-delete:hover { background-color: #f8d7da; }
        
        .no-files {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 2rem;
            border: 2px dashed #dee2e6;
            border-radius: 8px;
            background: #f8f9fa;
        }
    `;
    document.head.appendChild(style);
}
