// ============================================================
// STATE
// ============================================================
let myKeyPair   = null;   // ECDH CryptoKeyPair
let sharedKey   = null;   // AES-GCM CryptoKey
let myPublicB64 = null;   // base64 of our own public key

// ============================================================
// DOM REFS
// ============================================================
const myPublicKeyTA = document.getElementById("myPublicKey");
const friendKeyTA   = document.getElementById("friendKey");
const connectBtn    = document.getElementById("connectBtn");
const statusEl      = document.getElementById("status");
const chatDiv       = document.getElementById("chat");
const emptyState    = document.getElementById("emptyState");
const inputRow      = document.getElementById("input-row");
const lockedNotice  = document.getElementById("locked-notice");
const messageInput  = document.getElementById("message");
const sendBtn       = document.getElementById("sendBtn");

// ============================================================
// UTILITY — ArrayBuffer <-> Base64
// ============================================================
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

// ============================================================
// STATUS BANNER
// ============================================================
function showStatus(msg, type = "info") {
  statusEl.textContent = msg;
  statusEl.className = type;
}

// ============================================================
// 1 & 2. GENERATE KEY PAIR + EXPORT PUBLIC KEY
// ============================================================
async function generateKeys() {
  try {
    myKeyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );

    const rawPub = await crypto.subtle.exportKey("raw", myKeyPair.publicKey);
    myPublicB64 = bufToBase64(rawPub);
    myPublicKeyTA.value = myPublicB64;

    connectBtn.disabled = false;
    showStatus("Keys generated — share your public key, paste your friend's, then click Connect.", "info");
  } catch (err) {
    console.error(err);
    showStatus("Key generation failed: " + err.message, "error");
  }
}

// Copy own public key on click
myPublicKeyTA.addEventListener("click", () => {
  if (!myPublicKeyTA.value) return;
  navigator.clipboard.writeText(myPublicKeyTA.value)
    .then(() => showStatus("Public key copied to clipboard!", "success"))
    .catch(() => {});
});

// ============================================================
// 3 & 4. IMPORT FRIEND KEY + DERIVE SHARED AES-GCM KEY
// ============================================================
async function connect() {
  const friendB64 = friendKeyTA.value.trim();
  if (!friendB64) { showStatus("Paste your friend's public key first.", "error"); return; }
  if (!myKeyPair)  { showStatus("Generate your keys first.", "error"); return; }

  try {
    const friendPub = await crypto.subtle.importKey(
      "raw",
      base64ToBuf(friendB64),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    sharedKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: friendPub },
      myKeyPair.privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    showStatus("✓ Secure channel established — AES-256-GCM active.", "success");

    // Reveal chat input, hide locked notice
    inputRow.style.display = "flex";
    lockedNotice.style.display = "none";
    messageInput.disabled = false;
    sendBtn.disabled = false;
    connectBtn.disabled = true;
    messageInput.focus();

    subscribeToMessages();
  } catch (err) {
    console.error(err);
    showStatus("Connection failed — make sure you pasted a valid P-256 key.", "error");
  }
}

// ============================================================
// 5. ENCRYPT MESSAGE  →  iv:ciphertext  (both base64)
// ============================================================
async function encryptMessage(plaintext) {
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const cipher  = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, sharedKey, encoded);
  return bufToBase64(iv) + ":" + bufToBase64(cipher);
}

// ============================================================
// 8. DECRYPT MESSAGE
// ============================================================
async function decryptMessage(payload) {
  const [ivB64, cipherB64] = payload.split(":");
  if (!ivB64 || !cipherB64) throw new Error("malformed payload");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBuf(ivB64) },
    sharedKey,
    base64ToBuf(cipherB64)
  );
  return new TextDecoder().decode(plain);
}

// ============================================================
// 6. SEND ENCRYPTED MESSAGE TO SUPABASE
// ============================================================
async function sendMessage() {
  const text = messageInput.value.trim();
  if (!text || !sharedKey) return;

  try {
    const encrypted = await encryptMessage(text);
    const { error } = await supabase.from("messages").insert({ content: encrypted });
    if (error) throw error;
    messageInput.value = ""; // clear after send
  } catch (err) {
    console.error("Send failed:", err);
    showStatus("Send failed: " + err.message, "error");
  }
}

// Enter key to send
messageInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

// ============================================================
// 7. SUBSCRIBE TO REALTIME INSERTS
// ============================================================
let subscribed = false;
function subscribeToMessages() {
  if (subscribed) return;
  subscribed = true;

  supabase
    .channel("public:messages")
    .on(
      "postgres_changes",
      { event: "INSERT", schema: "public", table: "messages" },
      async (payload) => {
        const encrypted = payload.new?.content;
        if (!encrypted) return;
        try {
          const plaintext = await decryptMessage(encrypted);
          appendMessage(plaintext);
        } catch {
          // 10. Silently ignore messages encrypted with a different key
          console.info("Skipped undecryptable message.");
        }
      }
    )
    .subscribe();
}

// ============================================================
// 9. APPEND MESSAGE TO DOM
// ============================================================
function appendMessage(text) {
  if (emptyState && emptyState.parentNode) emptyState.remove();

  const div  = document.createElement("div");
  div.className = "message";

  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  const body = document.createElement("div");
  body.textContent = text;

  div.appendChild(meta);
  div.appendChild(body);
  chatDiv.appendChild(div);
  chatDiv.scrollTop = chatDiv.scrollHeight;
}

// ============================================================
// AUTO-GENERATE KEYS ON LOAD
// ============================================================
generateKeys();
