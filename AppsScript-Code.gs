
const SITE_URL =
  "https://sites.google.com/sd215.net/iliveinaboxgames/games-a-z";

const SITE_PREFIX =
  "https://sites.google.com/sd215.net/iliveinaboxgames/games-a-z/";

const CACHE_SECONDS = 21600;
const SAVED_ARTWORK_FILE = "InABoxGames_ArtworkCache_v1.json";

function doGet() {
  return HtmlService.createHtmlOutputFromFile("Index")
    .setTitle("InABox Games")
    // Allow this web app to be embedded in the GitHub Pages iframe.
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

 
// --------------------------------------------------
// CLOUDFLARE TEST API BRIDGE
// Keeps the existing Apps Script functions as the backend.
// Only methods used by the website frontend are exposed.
// --------------------------------------------------
function doPost(e) {
  const output = (payload) => ContentService
    .createTextOutput(JSON.stringify(payload))
    .setMimeType(ContentService.MimeType.JSON);
  try {
    const request = JSON.parse(e && e.postData && e.postData.contents || "{}");
    const method = String(request.method || "");
    const args = Array.isArray(request.args) ? request.args : [];
    const allowed = {
      getGames: getGames,
      getSwfGameInfo: getSwfGameInfo,
      getSwfGameChunk: getSwfGameChunk,
      getGameEmbed: getGameEmbed,
      uploadSwfGame: uploadSwfGame,
      addGameToCatalog: addGameToCatalog,
      deleteGameFromCatalog: deleteGameFromCatalog,
      saveGameEditsInCatalog_v2: saveGameEditsInCatalog_v2,
      uploadArtworkForGame: uploadArtworkForGame,
      authorizeAdminDevice: authorizeAdminDevice,
      validateAdminDevice: validateAdminDevice,
      setPreferredArtworkForGame: setPreferredArtworkForGame,
      getSavedArtworkAlternativesForGame: getSavedArtworkAlternativesForGame,
      findAlternateArtworkForGame: findAlternateArtworkForGame,
      getSharedBackgrounds: getSharedBackgrounds,
      getSharedBackgroundInfo: getSharedBackgroundInfo,
      getSharedBackgroundChunk: getSharedBackgroundChunk,
      uploadSharedBackground: uploadSharedBackground
    };
    const fn = allowed[method];
    if (typeof fn !== "function") return output({ok:false,error:"This API method is not allowed."});
    const result = fn.apply(null, args);
    return output({ok:true,result:result === undefined ? null : result});
  } catch (error) {
    return output({ok:false,error:error && error.message ? error.message : String(error)});
  }
}


// --------------------------------------------------
// SERVER-SIDE ADMIN AUTHENTICATION
// --------------------------------------------------
// One-time setup: set Script Property ADMIN_PASSWORD_SETUP to your chosen
// password, then run initializeAdminSecurity() manually from the editor.
// The function stores only a salted SHA-256 hash and deletes the setup value.
function initializeAdminSecurity() {
  const props = PropertiesService.getScriptProperties();
  const password = props.getProperty('ADMIN_PASSWORD_SETUP');
  if (!password || password.length < 12) throw new Error('Set ADMIN_PASSWORD_SETUP to a password of at least 12 characters first.');
  const salt = Utilities.getUuid() + Utilities.getUuid();
  props.setProperties({ ADMIN_PASSWORD_SALT: salt, ADMIN_PASSWORD_HASH: adminHash_(password, salt) });
  props.deleteProperty('ADMIN_PASSWORD_SETUP');
  return 'Admin password initialized. The temporary setup property was deleted.';
}

function adminHash_(value, salt) {
  const bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(salt) + String(value), Utilities.Charset.UTF_8);
  return bytes.map(b => ('0' + ((b + 256) % 256).toString(16)).slice(-2)).join('');
}

function authorizeAdminDevice(password) {
  const props = PropertiesService.getScriptProperties();
  const salt = props.getProperty('ADMIN_PASSWORD_SALT');
  const expected = props.getProperty('ADMIN_PASSWORD_HASH');
  if (!salt || !expected) throw new Error('Admin password is not configured.');
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    const now = Date.now();
    let attempts = {};
    try { attempts = JSON.parse(props.getProperty('ADMIN_LOGIN_LIMIT') || '{}'); } catch (_) {}
    if (Number(attempts.resetAt || 0) < now) attempts = { count: 0, resetAt: now + 15 * 60 * 1000 };
    if (Number(attempts.count || 0) >= 12) throw new Error('Too many password attempts. Try again in 15 minutes.');
    const supplied = adminHash_(String(password || ''), salt);
    if (supplied !== expected) {
      attempts.count = Number(attempts.count || 0) + 1;
      props.setProperty('ADMIN_LOGIN_LIMIT', JSON.stringify(attempts));
      throw new Error('Incorrect admin password.');
    }
    props.deleteProperty('ADMIN_LOGIN_LIMIT');
    const token = Utilities.getUuid() + '-' + Utilities.getUuid() + '-' + Utilities.getUuid();
    const tokenHash = adminHash_(token, salt);
    let devices = {};
    try { devices = JSON.parse(props.getProperty('ADMIN_DEVICE_TOKENS') || '{}'); } catch (_) {}
    devices[tokenHash] = { createdAt: new Date().toISOString() };
    const keys = Object.keys(devices);
    keys.slice(0, Math.max(0, keys.length - 50)).forEach(key => delete devices[key]);
    props.setProperty('ADMIN_DEVICE_TOKENS', JSON.stringify(devices));
    return { success: true, token: token };
  } finally { lock.releaseLock(); }
}

function validateAdminDevice(token) {
  return !!adminDeviceRecord_(token);
}

// Sign out only the browser/device that requested it.
function revokeAdminDevice(token) {
  if (!adminDeviceRecord_(token)) return true;
  const props = PropertiesService.getScriptProperties();
  const salt = props.getProperty('ADMIN_PASSWORD_SALT');
  const tokenHash = adminHash_(token, salt);
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    let devices = {};
    try { devices = JSON.parse(props.getProperty('ADMIN_DEVICE_TOKENS') || '{}'); } catch (_) {}
    delete devices[tokenHash];
    props.setProperty('ADMIN_DEVICE_TOKENS', JSON.stringify(devices));
    return true;
  } finally { lock.releaseLock(); }
}

function adminDeviceRecord_(token) {
  if (!token || typeof token !== 'string') return false;
  const props = PropertiesService.getScriptProperties();
  const salt = props.getProperty('ADMIN_PASSWORD_SALT');
  if (!salt) return false;
  let devices = {};
  try { devices = JSON.parse(props.getProperty('ADMIN_DEVICE_TOKENS') || '{}'); } catch (_) {}
  return !!devices[adminHash_(token, salt)];
}

function requireAdmin_(token) {
  if (!adminDeviceRecord_(token)) throw new Error('Admin authorization required. Type LET ME IN and verify this device.');
}

// Run manually from the Apps Script editor to sign out every saved device.
function revokeAllAdminDevices_() {
  PropertiesService.getScriptProperties().deleteProperty('ADMIN_DEVICE_TOKENS');
  return 'All admin devices have been signed out.';
}

// Game catalog is migrated into Apps Script storage on first run.
// Google Sites is only read during the one-time import or an explicit refresh;
// visitors use the saved catalog and the external game URLs directly.
const GAME_CATALOG_FILE = "InABoxGames_GameCatalog_v2.json";

function getGames() {
  const catalog = loadGameCatalog_();
  const savedByUrl = loadSavedGamesArtwork().games || {};
  return catalog.map(game => {
    const entry = savedByUrl[game.url] || {};
    const candidates = (entry.imageCandidates || entry.thumbnails || [])
      .filter(u => !/archive\.org\/services\/img\//i.test(String(u)));
    const preferred = entry.preferredThumbnail || entry.thumbnail || "";
    const ordered = preferred && candidates.includes(preferred)
      ? [preferred].concat(candidates.filter(u => u !== preferred)) : candidates;
    return {
      title: game.title, url: game.url, slug: game.slug,
      playUrl: game.playUrl || "",
      swfUrl: game.swfUrl || "",
      swfFileId: game.swfFileId || "",
      swfGame: !!game.swfGame,
      embedCode: (game.embedCode && game.embedCode.length <= 30000) ? game.embedCode : "",
      hasEmbed: !!game.embedCode,
      help: game.help || "",
      thumbnail: ordered[0] || "",
      preferredThumbnail: preferred && ordered.includes(preferred) ? preferred : (ordered[0] || ""),
      thumbnails: ordered, imageCandidates: ordered,
      hasSavedArtwork: ordered.length > 0
    };
  });
}


// Parse manual game input without importing an old launcher page.
// A direct iframe (including one HTML-encoded inside a data="...") becomes
// only its src URL. Actual custom game documents remain as embedCode.
function parseCatalogGameInput_(input) {
  input = String(input || "").trim();
  if (!input) return { playUrl: "", embedCode: "" };
  const direct = input.match(/^https?:\/\/[^\s<>"']+$/i);
  if (direct) return { playUrl: direct[0], embedCode: "" };

  // A complete HTML page is an intentional custom embed document. Preserve
  // it exactly as supplied, even when it contains a single iframe. Only treat
  // a standalone iframe snippet as a URL shortcut below.
  if (/^\s*(?:<!doctype\s+html\b|<html\b|<head\b|<body\b)/i.test(input)) {
    return { playUrl: "", embedCode: input };
  }

  let decoded = input;
  for (let i = 0; i < 4; i++) {
    const next = decoded
      .replace(/&#x([0-9a-f]+);/gi, (m, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(/&#(\d+);/g, (m, d) => String.fromCharCode(parseInt(d, 10)))
      .replace(/&quot;|&#34;/gi, '"')
      .replace(/&#39;|&apos;/gi, "'")
      .replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
      .replace(/&amp;/gi, "&");
    if (next === decoded) break;
    decoded = next;
  }

  const iframeTags = decoded.match(/<iframe\b[^>]*>/gi) || [];
  const iframeUrls = [];
  iframeTags.forEach(tag => {
    const m = tag.match(/\b(?:src|data-src|data-url)\s*=\s*["']([^"']+)["']/i);
    if (m && /^https?:\/\//i.test(m[1]) && iframeUrls.indexOf(m[1]) < 0) iframeUrls.push(m[1]);
  });
  if (iframeUrls.length === 1) return { playUrl: iframeUrls[0], embedCode: "" };

  if (input.indexOf("<") < 0) throw new Error("The game URL must start with http:// or https://.");
  return { playUrl: "", embedCode: input };
}

// Add a game from the private admin panel. The input may be a direct game URL
// or a complete HTML embed document. Manual entries are stored in Drive and
// remain available even if the old Google Sites directory is removed.
function addGameToCatalog(adminToken, title, gameInput, imageUrl, imageDataUrl, imageFileName) {
  requireAdmin_(adminToken);
  title = String(title || "").trim();
  gameInput = String(gameInput || "").trim();
  imageUrl = String(imageUrl || "").trim();
  if (!title) throw new Error("Enter a game name.");
  if (!gameInput) throw new Error("Enter the game URL or embed code.");

  const parsedSource = parseCatalogGameInput_(gameInput);
  const playUrl = parsedSource.playUrl;
  const embedCode = parsedSource.embedCode;
  if (playUrl && !/^https?:\/\//i.test(playUrl)) throw new Error("The game URL must start with http:// or https://.");

  const games = loadGameCatalog_();
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || ("game-" + Date.now());
  const key = "https://inaboxgames.local/manual/" + slug;
  const existing = games.findIndex(g => String(g.title).toLowerCase() === title.toLowerCase());
  const entry = { title: title, url: key, slug: slug, playUrl: playUrl, embedCode: embedCode };
  if (existing >= 0) games[existing] = entry; else games.push(entry);
  games.sort((a,b) => a.title.localeCompare(b.title));
  saveGameCatalog_(games);

  if (imageUrl) {
    if (!/^https?:\/\//i.test(imageUrl)) throw new Error("The image URL must start with http:// or https://.");
    const saved = loadSavedGamesArtwork();
    const byUrl = saved.games || {};
    byUrl[key] = byUrl[key] || { imageCandidates: [], thumbnails: [] };
    byUrl[key].imageCandidates = [imageUrl];
    byUrl[key].thumbnails = [imageUrl];
    byUrl[key].thumbnail = imageUrl;
    byUrl[key].preferredThumbnail = imageUrl;
    saveSavedGamesArtwork_(byUrl);
  } else if (imageDataUrl) {
    uploadArtworkForGame(adminToken, key, imageDataUrl, imageFileName || (slug + ".png"));
  }
  return { success: true, games: getGames(), title: title };
}

// Admin-only SWF upload. The binary is stored in Drive; the catalog stores only metadata.
function uploadSwfGame(adminToken, title, dataUrl, fileName, imageUrl, imageDataUrl, imageFileName) {
  requireAdmin_(adminToken);
  title = String(title || "").trim();
  fileName = String(fileName || "game.swf").trim();
  imageUrl = String(imageUrl || "").trim();
  if (!title) throw new Error("Enter a game name.");
  if (!/\.swf$/i.test(fileName)) throw new Error("Choose a .swf file.");
  if (imageUrl && !/^https?:\/\//i.test(imageUrl)) throw new Error("The image URL must start with http:// or https://.");
  const match = String(dataUrl || "").match(/^data:[^,]*;base64,([A-Za-z0-9+/=\s]+)$/i);
  if (!match) throw new Error("The SWF file could not be read.");
  const bytes = Utilities.base64Decode(match[1]);
  if (!bytes.length || bytes.length > 20 * 1024 * 1024) throw new Error("SWF files must be 20 MB or smaller.");
  const signature = bytes[0] & 255;
  if (signature !== 0x46 && signature !== 0x43 && signature !== 0x5A) throw new Error("The selected file does not have a valid SWF signature.");

  const folderName = "InABOX SWF Games";
  const folders = DriveApp.getFoldersByName(folderName);
  const folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(folderName);
  const file = folder.createFile(Utilities.newBlob(bytes, "application/x-shockwave-flash", fileName));
  file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
  const swfUrl = "https://drive.google.com/uc?export=download&id=" + encodeURIComponent(file.getId());

  const games = loadGameCatalog_();
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || ("game-" + Date.now());
  const key = "https://inaboxgames.local/manual/" + slug;
  const existingIndex = games.findIndex(g => String(g.title || "").toLowerCase() === title.toLowerCase());
  const old = existingIndex >= 0 ? games[existingIndex] : {};
  const entry = Object.assign({}, old, {
    title: title, url: old.url || key, slug: old.slug || slug,
    playUrl: "", embedCode: "", swfGame: true, swfFileId: file.getId(),
    swfUrl: swfUrl, manualSource: true, sourceUpdatedAt: new Date().toISOString()
  });
  if (existingIndex >= 0) games[existingIndex] = entry; else games.push(entry);
  games.sort((a, b) => String(a.title || "").localeCompare(String(b.title || "")));
  saveGameCatalog_(games);
  if (old.swfFileId && old.swfFileId !== file.getId()) { try { DriveApp.getFileById(old.swfFileId).setTrashed(true); } catch (e) {} }

  if (imageUrl) {
    const artwork = loadSavedGamesArtwork();
    const byUrl = artwork.games || {};
    byUrl[entry.url] = byUrl[entry.url] || { imageCandidates: [], thumbnails: [] };
    byUrl[entry.url].imageCandidates = [imageUrl];
    byUrl[entry.url].thumbnails = [imageUrl];
    byUrl[entry.url].thumbnail = imageUrl;
    byUrl[entry.url].preferredThumbnail = imageUrl;
    saveSavedGamesArtwork_(byUrl);
  } else if (imageDataUrl) {
    uploadArtworkForGame(adminToken, entry.url, imageDataUrl, imageFileName || (slug + ".png"));
  }
  return { success: true, games: getGames(), title: title, swfUrl: swfUrl };
}

// Lightweight metadata check so the browser can request all byte ranges in parallel.
function getSwfGameInfo(fileId) {
  fileId = String(fileId || '').trim();
  if (!fileId) throw new Error('Missing SWF file ID.');
  const file = DriveApp.getFileById(fileId);
  let inSwfFolder = false;
  const parents = file.getParents();
  while (parents.hasNext()) {
    if (parents.next().getName() === 'InABOX SWF Games') { inSwfFolder = true; break; }
  }
  if (!inSwfFolder) throw new Error('This SWF file is not in the InABOX SWF Games folder.');
  const totalBytes = file.getSize();
  if (!totalBytes || totalBytes > 20 * 1024 * 1024) throw new Error('The stored SWF is empty or exceeds the 20 MB limit.');
  return { totalBytes: totalBytes };
}

// Stream only the requested byte range from Drive. This avoids downloading the
// entire SWF again for every chunk, which was the main source of slow loading.
function getSwfGameChunk(fileId, offset, requestedChunkSize) {
  fileId = String(fileId || '').trim();
  offset = Math.max(0, Math.floor(Number(offset) || 0));
  const chunkSize = Math.min(4 * 1024 * 1024, Math.max(512 * 1024, Math.floor(Number(requestedChunkSize) || 4 * 1024 * 1024)));
  if (!fileId) throw new Error('Missing SWF file ID.');
  const file = DriveApp.getFileById(fileId);
  let inSwfFolder = false;
  const parents = file.getParents();
  while (parents.hasNext()) {
    if (parents.next().getName() === 'InABOX SWF Games') { inSwfFolder = true; break; }
  }
  if (!inSwfFolder) throw new Error('This SWF file is not in the InABOX SWF Games folder.');
  const totalBytes = file.getSize();
  if (!totalBytes || totalBytes > 20 * 1024 * 1024) throw new Error('The stored SWF is empty or exceeds the 20 MB limit.');
  if (offset >= totalBytes) return { chunkBase64: '', nextOffset: totalBytes, totalBytes: totalBytes, done: true };

  const end = Math.min(totalBytes, offset + chunkSize);
  const response = UrlFetchApp.fetch(
    'https://www.googleapis.com/drive/v3/files/' + encodeURIComponent(fileId) + '?alt=media',
    {
      method: 'get',
      headers: {
        Authorization: 'Bearer ' + ScriptApp.getOAuthToken(),
        Range: 'bytes=' + offset + '-' + (end - 1)
      },
      muteHttpExceptions: true
    }
  );
  const status = response.getResponseCode();
  if (status !== 206 && status !== 200) throw new Error('Google Drive could not send this part of the SWF (HTTP ' + status + ').');
  let bytes = response.getContent();
  // Fallback for an intermediary that ignores Range and returns the whole file.
  if (status === 200 && bytes.length === totalBytes) bytes = bytes.slice(offset, end);
  if (bytes.length !== end - offset) throw new Error('Google Drive returned an incomplete SWF data range. Please try again.');
  return {
    chunkBase64: Utilities.base64Encode(bytes),
    nextOffset: end,
    totalBytes: totalBytes,
    done: end >= totalBytes
  };
}

// Delete a game only after the admin explicitly types the required word.
function deleteGameFromCatalog(adminToken, gameUrl, confirmation) {
  requireAdmin_(adminToken);
  gameUrl = String(gameUrl || "").trim();
  confirmation = String(confirmation || "").trim();
  if (confirmation !== "CONFIRM") throw new Error('Type CONFIRM exactly to delete this game.');
  if (!gameUrl) throw new Error("The game could not be identified.");

  const games = loadGameCatalog_();
  const index = games.findIndex(game => String(game.url || "") === gameUrl);
  if (index < 0) throw new Error("That game was not found in the saved catalog.");
  const deleted = games.splice(index, 1)[0];
  saveGameCatalog_(games);
  if (deleted && deleted.swfFileId) { try { DriveApp.getFileById(deleted.swfFileId).setTrashed(true); } catch (e) {} }

  // Remove its saved artwork references too, so it will not remain in caches.
  const artwork = loadSavedGamesArtwork();
  const byUrl = artwork.games || {};
  if (Object.prototype.hasOwnProperty.call(byUrl, gameUrl)) {
    delete byUrl[gameUrl];
    saveSavedGamesArtwork_(byUrl);
  }
  return { success: true, title: deleted.title, games: getGames() };
}

// Update the name and launch URL/embed code for an existing game; preserve its artwork.
function updateGameUrlInCatalog(adminToken, gameUrl, gameTitle, gameInput) {
  requireAdmin_(adminToken);
  gameUrl = String(gameUrl || "").trim();
  gameTitle = String(gameTitle || "").trim();
  gameInput = String(gameInput || "").trim();
  if (!gameUrl) throw new Error("The game could not be identified.");
  if (!gameTitle) throw new Error("Enter the game name.");
  if (!gameInput) throw new Error("Enter the new game URL or embed code.");

  const parsedSource = parseCatalogGameInput_(gameInput);
  const playUrl = parsedSource.playUrl;
  const embedCode = parsedSource.embedCode;
  if (playUrl && !/^https?:\/\//i.test(playUrl)) throw new Error("The game URL must start with http:// or https://.");

  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  let savedTitle = gameTitle;
  try {
    const games = loadGameCatalog_();
    const index = games.findIndex(game => String(game.url || "") === gameUrl);
    if (index < 0) throw new Error("That game was not found in the saved catalog.");
    games[index].title = gameTitle;
    games[index].playUrl = playUrl;
    games[index].embedCode = embedCode;
    games[index].manualSource = true;
    games[index].sourceUpdatedAt = new Date().toISOString();
    savedTitle = games[index].title;
    saveGameCatalog_(games);
    const verified = loadGameCatalog_().find(g => String(g.url || "") === gameUrl);
    if (!verified || String(verified.playUrl || "") !== String(playUrl || "") || String(verified.embedCode || "") !== String(embedCode || "")) throw new Error("The new game source did not persist. The save was not reported as successful.");
  } finally { lock.releaseLock(); }
  return { success: true, games: getGames(), title: savedTitle, savedPlayUrl: playUrl || "", savedEmbed: !!embedCode };
}

// Compatibility endpoint used by the existing Index.html edit form.
// Keep this name: the UI calls updateGameFieldsInCatalog, not updateGameUrlInCatalog.
function updateGameFieldsInCatalog(adminToken, gameUrl, gameTitle, gameInput, sourceChanged, helpText) {
  requireAdmin_(adminToken);
  gameUrl = String(gameUrl || "").trim();
  gameTitle = String(gameTitle || "").trim();
  gameInput = String(gameInput || "").trim();
  helpText = String(helpText || "").trim();
  if (!gameUrl) throw new Error("The game could not be identified.");
  if (!gameTitle) throw new Error("Enter the game name.");
  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    const games = loadGameCatalog_();
    const index = games.findIndex(g => String(g.url || "") === gameUrl);
    if (index < 0) throw new Error("That game was not found in the saved catalog.");
    if (sourceChanged) {
      const parsed = parseCatalogGameInput_(gameInput);
      games[index].playUrl = parsed.playUrl || "";
      games[index].embedCode = parsed.embedCode || "";
      games[index].manualSource = true;
      games[index].sourceUpdatedAt = new Date().toISOString();
    }
    games[index].title = gameTitle;
    games[index].help = helpText;
    games[index].helpUpdatedAt = new Date().toISOString();
    saveGameCatalog_(games);
    const check = loadGameCatalog_().find(g => String(g.url || "") === gameUrl);
    if (!check || check.title !== gameTitle || String(check.help || "") !== helpText ||
        (sourceChanged && (String(check.playUrl || "") !== String(games[index].playUrl || "") || String(check.embedCode || "") !== String(games[index].embedCode || "")))) {
      throw new Error("Save verification failed. The changes were not retained.");
    }
  } finally { lock.releaseLock(); }
  return { success: true, games: getGames(), title: gameTitle };
}

// Fetch large saved embeds on demand; getGames() intentionally keeps responses small.

/** v2 edit endpoint: unique name avoids collisions with older project functions. */
function saveGameEditsInCatalog_v2(adminToken, gameUrl, gameTitle, gameInput, helpText) {
  requireAdmin_(adminToken);
  gameUrl = String(gameUrl || '').trim();
  gameTitle = String(gameTitle || '').trim();
  gameInput = String(gameInput || '').trim();
  helpText = String(helpText || '').trim();
  if (!gameUrl) throw new Error('The game could not be identified.');
  if (!gameTitle) throw new Error('Enter the game name.');

  // Keep this operation short: no nested getGames()/artwork loading in the save response.
  var games = loadGameCatalog_();
  var index = games.findIndex(function(g) { return String(g.url || '') === gameUrl; });
  if (index < 0) throw new Error('Game not found in the saved catalog: ' + gameUrl);
  var parsed = parseCatalogGameInput_(gameInput);
  games[index].title = gameTitle;
  games[index].playUrl = parsed.playUrl || '';
  games[index].embedCode = parsed.embedCode || '';
  games[index].help = helpText;
  games[index].manualSource = true;
  games[index].sourceUpdatedAt = new Date().toISOString();
  games[index].helpUpdatedAt = new Date().toISOString();
  saveGameCatalog_(games);

  // Verify directly against the persisted Drive file without building the full homepage payload.
  var persisted = loadGameCatalog_();
  var saved = persisted.find(function(g) { return String(g.url || '') === gameUrl; });
  if (!saved || String(saved.title || '') !== gameTitle ||
      String(saved.playUrl || '') !== String(games[index].playUrl || '') ||
      String(saved.embedCode || '') !== String(games[index].embedCode || '') ||
      String(saved.help || '') !== helpText) {
    throw new Error('Save verification failed: the catalog did not retain the edited game.');
  }
  return { success: true, title: gameTitle, url: gameUrl,
    playUrl: String(saved.playUrl || ''), embedCode: String(saved.embedCode || ''), help: String(saved.help || '') };
}

function getGameEmbed(gameUrl) {
  gameUrl = String(gameUrl || "").trim();
  const game = loadGameCatalog_().find(g => String(g.url || "") === gameUrl);
  if (!game) throw new Error("That game was not found.");
  return { embedCode: String(game.embedCode || "") };
}

function getGameCatalogFile_() {
  const props = PropertiesService.getScriptProperties();
  const savedId = props.getProperty("GAME_CATALOG_FILE_ID");
  if (savedId) { try { return DriveApp.getFileById(savedId); } catch (e) { props.deleteProperty("GAME_CATALOG_FILE_ID"); } }
  const files = DriveApp.getFilesByName(GAME_CATALOG_FILE);
  let chosen = null, newest = -1;
  while (files.hasNext()) {
    const file = files.next();
    try { const parsed = JSON.parse(file.getBlob().getDataAsString("UTF-8")); if (parsed && Array.isArray(parsed.games) && file.getLastUpdated().getTime() > newest) { chosen=file; newest=file.getLastUpdated().getTime(); } }
    catch (e) { console.warn("Skipping invalid duplicate game catalog: " + e); }
  }
  if (chosen) props.setProperty("GAME_CATALOG_FILE_ID", chosen.getId());
  return chosen;
}
function loadGameCatalog_() {
  const file = getGameCatalogFile_();
  if (file) { const parsed=JSON.parse(file.getBlob().getDataAsString("UTF-8")); if (parsed && Array.isArray(parsed.games)) return parsed.games; }
  const games=buildGameCatalogFromGoogleSites_(); saveGameCatalog_(games); return games;
}
function saveGameCatalog_(games) {
  const payload=JSON.stringify({version:3,updatedAt:new Date().toISOString(),games:games});
  let file=getGameCatalogFile_();
  if (file) file.setContent(payload);
  else { file=DriveApp.createFile(GAME_CATALOG_FILE,payload,MimeType.PLAIN_TEXT); PropertiesService.getScriptProperties().setProperty("GAME_CATALOG_FILE_ID",file.getId()); }
}

// Run manually after adding games to the old Google Sites directory.
// Existing game entries are replaced with the freshly extracted list.
function refreshGameCatalogFromSource_() {
  const imported = buildGameCatalogFromGoogleSites_();
  const existing = loadGameCatalog_();
  const manualByUrl = {};
  existing.forEach(game => { if (game && game.manualSource && game.url) manualByUrl[game.url] = game; });
  const seen = new Set();
  const games = imported.map(game => {
    const manual = manualByUrl[game.url];
    seen.add(game.url);
    return manual || game;
  });
  // Keep manually added games even when they are not listed on the old site.
  existing.forEach(game => {
    if (game && game.manualSource && game.url && !seen.has(game.url)) games.push(game);
  });
  games.sort((a, b) => String(a.title || "").localeCompare(String(b.title || "")));
  saveGameCatalog_(games);
  return { success: true, count: games.length, playable: games.filter(g => g.playUrl || g.embedCode).length,
    missingPlayableUrl: games.filter(g => !g.playUrl && !g.embedCode).map(g => g.title) };
}

function buildGameCatalogFromGoogleSites_() {
  const response = UrlFetchApp.fetch(SITE_URL, {
    followRedirects: true, muteHttpExceptions: true,
    headers: { "User-Agent": "Mozilla/5.0" }
  });
  if (response.getResponseCode() !== 200) {
    throw new Error("Could not import the game list from the old site. HTTP " + response.getResponseCode());
  }
  const html = response.getContentText();
  const found = new Map();
  const pattern = /href\s*=\s*["']([^"'#?]*\/iliveinaboxgames\/games-a-z\/[^"'#?]*)["']/gi;
  let match;
  while ((match = pattern.exec(html)) !== null) {
    let url = match[1].replace(/&amp;/g, "&");
    if (url.startsWith("/")) url = "https://sites.google.com" + url;
    url = url.replace(/\/+$/, "");
    if (!url.startsWith(SITE_PREFIX)) continue;
    const slug = url.slice(SITE_PREFIX.length);
    if (!slug || slug.includes("/")) continue;
    const title = slugToTitle(slug);
    if (title) found.set(url, { title: title, url: url, slug: slug, playUrl: "", embedCode: "" });
  }
  const games = [...found.values()].sort((a,b) => a.title.localeCompare(b.title));
  // Fetch individual game pages in batches. The extracted game URLs are then
  // saved to Drive so students no longer need to load Google Sites at all.
  for (let offset = 0; offset < games.length; offset += 25) {
    const batch = games.slice(offset, offset + 25);
    const responses = UrlFetchApp.fetchAll(batch.map(game => ({
      url: game.url, method: "get", followRedirects: true, muteHttpExceptions: true,
      headers: { "User-Agent": "Mozilla/5.0" }
    })));
    responses.forEach((page, i) => {
      if (page.getResponseCode() !== 200) {
        console.warn("Could not read game page " + batch[i].title + ": HTTP " + page.getResponseCode());
        return;
      }
      const pageHtml = page.getContentText();
      // GameImporter preserves custom engine documents (Unity/canvas/etc.) and
      // extracts encoded iframe launchers. Keep the legacy extractor as fallback
      // so this Code.gs still works if that helper file is not installed.
      const extracted = (typeof extractGameSource_ === "function")
        ? extractGameSource_(pageHtml)
        : extractPlayableSource_(pageHtml);
      batch[i].playUrl = extracted.playUrl || "";
      batch[i].embedCode = extracted.embedCode || "";
      if (!batch[i].playUrl && !batch[i].embedCode) {
        console.warn("No playable game source found for " + batch[i].title);
      }
    });
  }
  console.log("Imported " + games.length + " games; playable URLs found: " + games.filter(g => g.playUrl).length);
  return games;
}

function extractPlayableSource_(html) {
  if (!html) return { playUrl: "", embedCode: "" };

  const candidates = [];
  const dataCodeBlocks = [];
  const dataUrlValues = [];

  function decodeHtml(value) {
    return String(value || "")
      .replace(/&quot;|&#34;/gi, '"')
      .replace(/&#39;|&apos;/gi, "'")
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&amp;/gi, "&")
      .replace(/\\u003d/gi, "=")
      .replace(/\\u0026/gi, "&")
      .replace(/\\\//g, "/");
  }

  function cleanUrl(value) {
    if (!value) return "";
    let url = decodeHtml(value).trim();
    if (url.startsWith("//")) url = "https:" + url;
    return /^https?:\/\//i.test(url) ? url : "";
  }

  function isGoogleInfrastructure(url) {
    return /^https?:\/\/(?:www\.)?gstatic\.com\/atari\/embeds\/.*intermediate-frame/i.test(url) ||
      /^https?:\/\/(?:accounts|drive|docs)\.google\.com\//i.test(url) ||
      /^https?:\/\/sites\.google\.com\//i.test(url);
  }

  function addCandidate(value) {
    const url = cleanUrl(value);
    if (!url || isGoogleInfrastructure(url)) return;
    if (!candidates.includes(url)) candidates.push(url);
  }

  let match;

  // Direct Google Sites embed URLs. The generic gstatic intermediate frame is
  // excluded, but host-specific Atari inner frames are retained as a last
  // resort below when their paired data-code contains a real game document.
  const dataUrlPattern = /\bdata-url\s*=\s*["']([^"']+)["']/gi;
  while ((match = dataUrlPattern.exec(html)) !== null) {
    const value = cleanUrl(match[1]);
    if (value) dataUrlValues.push(value);
    if (value && !/googleusercontent\.com\/embeds\/.*inner-frame-minified\.html/i.test(value)) {
      addCandidate(value);
    }
  }

  // Google Sites often stores the actual HTML document in data-code rather
  // than data-html. Decode it and inspect game-specific launch configuration.
  const dataCodePattern = /\bdata-code\s*=\s*["']([\s\S]*?)["'](?=\s+(?:data-|jsaction|class=|id=)|>)/gi;
  while ((match = dataCodePattern.exec(html)) !== null) {
    const code = decodeHtml(match[1]);
    if (code && code.length > 20) dataCodeBlocks.push(code);
  }

  // Also support older custom embeds stored in data-html.
  const dataHtmlPattern = /\bdata-html\s*=\s*["']([\s\S]*?)["'](?=\s+(?:data-|jsaction|class=|id=)|>)/gi;
  while ((match = dataHtmlPattern.exec(html)) !== null) {
    const code = decodeHtml(match[1]);
    if (code && code.length > 20) dataCodeBlocks.push(code);
  }

  dataCodeBlocks.forEach(code => {
    let m;

    // EmulatorJS and similar ROM-based games.
    // Emulator ROM archives are intentionally not returned as playUrl values.
    // The embedded HTML wrapper initializes the emulator around those files.

    // Direct HTML/Unity/WebGL game entry points. SWF and ROM assets are not
    // standalone playable pages; their embedded wrapper must initialize them.
    const directPatterns = [
      /<iframe\b[^>]*\bsrc\s*=\s*["'](https?:\/\/[^"']+)["']/i,
      /\b(?:gameFrame|gameIframe|iframe)\s*\.\s*src\s*=\s*["'](https?:\/\/[^"']+)["']/i,
      /\b(?:gameUrl|gameURL|playUrl|playURL)\s*=\s*["'](https?:\/\/[^"']+)["']/i
    ];
    for (const re of directPatterns) {
      m = code.match(re);
      if (m) addCandidate(m[1]);
    }

    // Some pages open a generated game document in a new tab. Search only
    // inside that function so unrelated artwork/store links are ignored.
    const docMatch = code.match(/function\s+gameDocument\s*\(\s*\)\s*\{([\s\S]{0,30000}?)(?=\}\s*(?:function\s|window\.|<\/script>|$))/i);
    if (docMatch) {
      const body = docMatch[1];
      const urlPatterns = [
        /(?:src|href)\s*=\s*["'](https?:\/\/[^"']+)["']/ig,
        /(?:var|let|const)\s+(?:url|gameUrl|gameURL|src)\s*=\s*["'](https?:\/\/[^"']+)["']/ig
      ];
      urlPatterns.forEach(re => {
        let u;
        while ((u = re.exec(body)) !== null) {
          if (!/store\.steampowered\.com|image\.thum\.io|googleusercontent\.com\/embeds/i.test(u[1])) addCandidate(u[1]);
        }
      });
    }

    // Older pages put the URL directly in openLink().
    const openLinkMatch = code.match(/function\s+openLink\s*\(\s*\)\s*\{[\s\S]{0,6000}?\b(?:var|let|const)\s+url\s*=\s*["'](https?:\/\/[^"']+)["']/i);
    if (openLinkMatch) addCandidate(openLinkMatch[1]);
  });

  // Raw escaped openLink fallback for custom embeds that could not be parsed
  // as a complete data-code attribute.
  const rawOpenLinkMatch = decodeHtml(html).match(
    /function\s+openLink\s*\(\s*\)\s*\{[\s\S]{0,6000}?\b(?:var|let|const)\s+url\s*=\s*["'](https?:\/\/[^"']+)["']/i
  );
  if (rawOpenLinkMatch) addCandidate(rawOpenLinkMatch[1]);

  // Some old launchers put iframe HTML inside a generic data attribute,
  // with quotes encoded as &quot;. Decode the value and extract only its src,
  // not the surrounding button/PlayTo launcher page.
  const dataAttributePattern = /\bdata\s*=\s*(["'])([\s\S]*?)\1(?=\s|>)/gi;
  while ((match = dataAttributePattern.exec(html)) !== null) {
    let value = match[2];
    for (let pass = 0; pass < 4; pass++) {
      const decoded = decodeHtml(value);
      if (decoded === value) break;
      value = decoded;
    }
    const nestedIframe = value.match(/<iframe\b[^>]*>/i);
    if (nestedIframe) {
      const nestedSrc = nestedIframe[0].match(/\b(?:src|data-src|data-url)\s*=\s*["']([^"']+)["']/i);
      if (nestedSrc) addCandidate(nestedSrc[1]);
    }
  }

  // Direct iframe sources and lazy-loaded iframe sources.
  const iframePattern = /<iframe\b[^>]*>/gi;
  while ((match = iframePattern.exec(decodeHtml(html))) !== null) {
    const srcMatch = match[0].match(/\b(?:src|data-src|data-url)\s*=\s*["']([^"']+)["']/i);
    if (srcMatch) addCandidate(srcMatch[1]);
  }

  // Unwrap common URL query parameters.
  candidates.slice().forEach(url => {
    const queryMatch = url.match(/[?&](?:url|src|href)=([^&]+)/i);
    if (queryMatch) {
      let nested = queryMatch[1];
      try { nested = decodeURIComponent(nested); } catch (e) {}
      addCandidate(nested);
    }
  });

  // Last resort: the host-specific Atari inner frame is the Google Sites
  // renderer for the adjacent data-code document. It is usable only when we
  // confirmed that the page contains a substantive embedded game document.
  if (!candidates.length) {
    // Google Sites' host-specific Atari inner frame is often the actual
    // launch surface even when the embedded document uses an unfamiliar
    // engine or stores its configuration in an unrecognized format. Prefer
    // this over leaving a game unavailable. The generic gstatic intermediate
    // frame remains excluded by isGoogleInfrastructure().
    const innerFrame = dataUrlValues.find(url =>
      /^https?:\/\/\d+-atari-embeds\.googleusercontent\.com\/embeds\/[a-f0-9]+\/inner-frame-minified\.html(?:[?#].*)?$/i.test(url)
    );
    if (innerFrame) addCandidate(innerFrame);
  }

  // Explicit Play/Launch links are the final fallback.
  if (!candidates.length) {
    const anchorPattern = /<a\b[^>]*href\s*=\s*["'](https?:[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    while ((match = anchorPattern.exec(html)) !== null) {
      const label = match[2].replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
      if (/\b(play|launch|start game|open game)\b/i.test(label)) addCandidate(match[1]);
    }
  }

  return { playUrl: candidates[0] || "", embedCode: "" };
}

// Called automatically by Index.html after saved artwork has rendered.
// A page visit retries every game missing artwork, four games per request.
// The client passes attempted URLs so failed games are not repeated endlessly
// during the same visit; they can be retried on the next visit.
function processMissingArtworkBatch(attemptedUrls) {
  const attempted = Array.isArray(attemptedUrls) ? attemptedUrls : [];
  const before = getGames();
  const missing = before.filter(game => {
    const images = game.imageCandidates || game.thumbnails || [];
    return images.length === 0 && attempted.indexOf(game.url) === -1;
  });

  let processedUrls = [];
  if (missing.length) {
    const batch = missing.slice(0, 4);
    processedUrls = batch.map(game => game.url);
    getGamesAndFindArtwork_(4, attempted, processedUrls);
  } else {
    // Once missing covers have been attempted, revisit games that already have
    // screenshots and search for better title/logo/cover art. Failed checks are
    // eligible again after six hours; they are never permanently marked done.
    const saved = loadSavedGamesArtwork();
    const byUrl = saved.games || {};
    const now = Date.now();
    const due = before.filter(game => {
      if (attempted.indexOf(game.url) !== -1) return false;
      const entry = byUrl[game.url];
      if (!entry || !(entry.imageCandidates || entry.thumbnails || []).length) return false;
      // Retry unsuccessful title-art searches on every new visit. Once a
      // title-art candidate has been found, keep it and avoid needless repeats.
      return !entry.lastTitleArtworkFoundAt;
    }).slice(0, 3);
    if (due.length) {
      processedUrls = due.map(game => game.url);
      refreshTitleArtworkBatch_(due, byUrl);
      saveSavedGamesArtwork_(byUrl);
    }
  }

  const updated = getGames();
  const attemptedThisPass = attempted.concat(processedUrls);
  const missingRemaining = updated.filter(game => {
    const images = game.imageCandidates || game.thumbnails || [];
    return images.length === 0 && attemptedThisPass.indexOf(game.url) === -1;
  }).length;
  const savedNow = loadSavedGamesArtwork().games || {};
  const titleRemaining = updated.filter(game => {
    if (attemptedThisPass.indexOf(game.url) !== -1) return false;
    const entry = savedNow[game.url];
    if (!entry || !(entry.imageCandidates || entry.thumbnails || []).length) return false;
    return !entry.lastTitleArtworkFoundAt;
  }).length;

  return {
    games: updated,
    remaining: missingRemaining + titleRemaining,
    processedUrls: processedUrls
  };
}

function refreshTitleArtworkBatch_(games, byUrl) {
  if (!games || !games.length) return;
  const bing = getBingGameImageSearch_(games);
  const extra = getAdditionalImageSearchSources_(games);
  games.forEach(game => {
    const entry = byUrl[game.url];
    if (!entry) return;
    const old = (entry.imageCandidates || entry.thumbnails || []).filter(isUsableArtworkUrl);
    const titleCandidates = [];
    (bing[game.title] || []).forEach(url => addCandidate(titleCandidates, url));
    (extra[game.title] || []).forEach(url => addCandidate(titleCandidates, url));
    // Keep a visitor's explicitly selected image first. Otherwise prefer newly
    // discovered title/cover art, while retaining screenshots as fallbacks.
    const preferred = entry.preferredThumbnail || "";
    const combined = titleCandidates.concat(old.filter(url => !titleCandidates.includes(url)));
    if (preferred && combined.includes(preferred)) {
      entry.imageCandidates = [preferred].concat(combined.filter(url => url !== preferred));
    } else {
      entry.imageCandidates = combined;
      if (titleCandidates.length) entry.thumbnail = titleCandidates[0];
    }
    entry.thumbnails = entry.imageCandidates;
    entry.lastTitleArtworkAttemptAt = new Date().toISOString();
    entry.titleArtworkChecked = false; // legacy flag is intentionally not permanent
    if (titleCandidates.length) entry.lastTitleArtworkFoundAt = new Date().toISOString();
    byUrl[game.url] = entry;
    console.log("Title-art refresh for " + game.title + ": " + titleCandidates.length + " new candidate(s)");
  });
}

function getGamesAndFindArtwork_(batchLimit, excludedUrls, onlyUrls) {
  // Game names and source URLs are now read from the Apps Script catalog.
  const games = loadGameCatalog_();
  const saved = loadSavedGamesArtwork();
  const savedByUrl = saved.games || {};

  // Remove Internet Archive service thumbnails from previously saved results.
  // /services/img/ returns a generic archive icon when an item has no cover art.
  Object.keys(savedByUrl).forEach(url => {
    const entry = savedByUrl[url];
    if (!entry) return;
    const oldCandidates = entry.imageCandidates || entry.thumbnails || [];
    const filtered = oldCandidates.filter(imageUrl =>
      !/archive\.org\/services\/img\//i.test(String(imageUrl))
    );
    entry.imageCandidates = filtered;
    entry.thumbnails = filtered;
    entry.thumbnail = filtered[0] || "";
  });

  // Only search games without saved artwork. There is no 7-day retry limit.
  // `onlyUrls` lets the page request a specific batch chosen for this visit.
  const excluded = Array.isArray(excludedUrls) ? excludedUrls : [];
  const requested = Array.isArray(onlyUrls) ? onlyUrls : [];
  const allNewGames = games.filter(game => {
    const savedGame = savedByUrl[game.url];
    const candidates = savedGame &&
      (savedGame.imageCandidates || savedGame.thumbnails || []);
    if (candidates && candidates.length) return false;
    if (requested.length) return requested.indexOf(game.url) !== -1;
    return excluded.indexOf(game.url) === -1;
  });
  // Process only a small batch per request so the gallery stays responsive.
  const newGames = allNewGames.slice(0, Math.max(1, Number(batchLimit) || 4));

  if (newGames.length > 0) {
    console.log(
      "New games needing artwork lookup: " + newGames.length
    );

    const catalogs = getAllThumbnailCatalogs();
    // Targeted catalog lookups for titles missed by bulk catalogs.
    catalogs.thegamesdb = getTheGamesDbThumbnails_(newGames.map(game => game.title));
    const truffledCatalog = getTruffledThumbnails();

    const sourceMatchCounts = {};
    const sourceNames = [
      "coolmath", "foundplay", "itchio", "newgrounds", "gamepix",
      "crazygames", "gamedistribution", "gamearter", "freetogame",
      "y8", "mmobomb", "thegamesdb", "kongregate", "armorgames",
      "addictinggames", "miniplay", "internetarchive", "gameflare",
      "html5games", "kizi", "gamemonetize", "flashpoint"
    ];

    const prepared = newGames.map(game => {
      const catalogCandidates = [];
      const matchedSourcesForGame = new Set();

      titleKeys(game.title).forEach(key => {
        sourceNames.forEach(sourceName => {
          const match = findCatalogArtwork(catalogs[sourceName], key);
          if (match) {
            const before = catalogCandidates.length;
            addCandidate(catalogCandidates, match);
            if (catalogCandidates.length > before || catalogCandidates.includes(match)) {
              matchedSourcesForGame.add(sourceName);
            }
          }
        });
      });

      matchedSourcesForGame.forEach(sourceName => {
        sourceMatchCounts[sourceName] = (sourceMatchCounts[sourceName] || 0) + 1;
      });

      return {
        ...game,
        catalogCandidates,
        candidates: []
      };
    });

    console.log("Catalog games matched by source: " + JSON.stringify(sourceMatchCounts));
    console.log("Games matched by catalogs before fallbacks: " +
      prepared.filter(game => game.catalogCandidates.length > 0).length + "/" + prepared.length);
    console.log("Still unmatched after catalogs: " +
      JSON.stringify(prepared.filter(game => game.catalogCandidates.length === 0)
        .map(game => game.title).slice(0, 60)));

    // Prefer Coolmath catalog artwork, then try Poki search for games
    // that still have no image. Poki search is best-effort and may be blocked.
    prepared.forEach(game => {
      game.catalogCandidates.forEach(url =>
        addCandidate(game.candidates, url)
      );

      // Truffled is an extra artwork source after the established catalogs.
      const truffledUrl = findTruffledArtwork(game.title, truffledCatalog);
      addCandidate(game.candidates, truffledUrl);
    });

    const needsPoki = prepared.filter(game => game.candidates.length === 0);
    const pokiImages = getPokiImages(needsPoki);
    prepared.forEach(game => {
      (pokiImages[game.title] || []).forEach(url =>
        addCandidate(game.candidates, url)
      );
    });

    // Steam is the next fallback; do not cache failed searches.
    const needsSteam = prepared.filter(game => game.candidates.length < 4);
    const steamImages = getSteamImages(needsSteam);
    prepared.forEach(game => {
      (steamImages[game.title] || []).forEach(url =>
        addCandidate(game.candidates, url)
      );
    });

    // Final fallback: search Bing Images for actual game artwork. This is
    // especially useful for browser games absent from the large game catalogs.
    const needsImageSearch = prepared.filter(game => game.candidates.length < 2);
    const bingImages = getBingGameImageSearch_(needsImageSearch);
    prepared.forEach(game => {
      (bingImages[game.title] || []).forEach(url =>
        addCandidate(game.candidates, url)
      );
    });

    // Run the ten extra image-search sources that were previously only logged
    // in the diagnostic version. These are best-effort; blocked sources are
    // skipped, and any extracted direct image URLs are added to the game.
    const stillNeedsExtraSearch = prepared.filter(game => game.candidates.length < 2);
    const extraSearchImages = getAdditionalImageSearchSources_(stillNeedsExtraSearch);
    prepared.forEach(game => {
      (extraSearchImages[game.title] || []).forEach(url =>
        addCandidate(game.candidates, url)
      );
    });

    // RAWG returned repeated HTTP 522 errors in the latest run and was
    // consuming several minutes. Retry only a small batch of games still
    // missing artwork after browser-image search, so later work can finish.
    const needsRawg = prepared.filter(game => game.candidates.length === 0).slice(0, 8);
    if (needsRawg.length) {
      const rawgImages = getRawgImages(needsRawg);
      prepared.forEach(game => {
        (rawgImages[game.title] || []).forEach(url =>
          addCandidate(game.candidates, url)        );
      });
    }

    // IGDB is another fallback for games still missing artwork.
    const needsIGDB = prepared.filter(game => game.candidates.length < 4);
    const igdbImages = getIGDBImages(needsIGDB);
    prepared.forEach(game => {
      (igdbImages[game.title] || []).forEach(url =>
        addCandidate(game.candidates, url)
      );
    });

    // Search SteamGridDB when fewer than four images have been found.
    const needsGridArt = prepared.filter(
      game => game.candidates.length < 4
    );

    const gridImages = getSteamGridDBImages(needsGridArt);

    prepared.forEach(game => {
      (gridImages[game.title] || []).forEach(url =>
        addCandidate(game.candidates, url)
      );
    });

    // Save artwork permanently in the Drive JSON file.
    prepared.forEach(game => {
      savedByUrl[game.url] = {
        title: game.title,
        url: game.url,
        slug: game.slug,
        thumbnail: game.candidates[0] || "",
        thumbnails: game.candidates,
        imageCandidates: game.candidates,
        lastArtworkAttemptAt: new Date().toISOString()
      };
    });

    saveSavedGamesArtwork_(savedByUrl);
  }

  // Return the current game list in alphabetical order.
  return games.map(game => Object.assign({}, game, savedByUrl[game.url] || {
    thumbnail: "", thumbnails: [], imageCandidates: []
  }));
}


// --------------------------------------------------
// BING IMAGES FALLBACK FOR WEB/BROWSER GAMES
// --------------------------------------------------
// Queries title + game screenshot, extracts direct image URLs from Bing's
// result metadata, and caches successful results only. Search results can
// occasionally be imperfect, so catalog matches are always preferred first.
function getBingGameImageSearch_(games) {
  const cache = CacheService.getScriptCache();
  const results = {};
  const pending = [];

  games.forEach(game => {
    const key = "bing_title_art_v2_" + normalizeGameTitle(game.title).slice(0, 110);
    const cached = cache.get(key);
    if (cached !== null) {
      try {
        const urls = JSON.parse(cached);
        if (Array.isArray(urls) && urls.length) results[game.title] = urls;
      } catch (e) {}
    } else {
      pending.push({ game, key });
    }
  });

  for (let offset = 0; offset < pending.length; offset += 5) {
    const batch = pending.slice(offset, offset + 5);
    let responses;
    try {
      responses = UrlFetchApp.fetchAll(batch.map(item => ({
        url: "https://www.bing.com/images/search?q=" +
          encodeURIComponent('"' + item.game.title + '" video game cover art poster key art title logo') +
          "&form=HDRSC2&first=1",
        method: "get",
        followRedirects: true,
        muteHttpExceptions: true,
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml"
        }
      })));
    } catch (e) {
      console.warn("Bing Images batch failed: " + e);
      continue;
    }

    responses.forEach((response, i) => {
      const item = batch[i];
      const urls = [];
      try {
        if (response.getResponseCode() !== 200) return;
        const html = response.getContentText();
        const pattern = /"murl"\s*:\s*"((?:\\.|[^"\\])+)"/g;
        let match;
        while ((match = pattern.exec(html)) !== null && urls.length < 4) {
          let url = match[1];
          try { url = JSON.parse('"' + url + '"'); } catch (e) {
            url = url.replace(/\\u0026/g, "&").replace(/\\\//g, "/").replace(/\\"/g, '"');
          }
          url = String(url || "").replace(/&amp;/g, "&");
          if (!/^https?:\/\//i.test(url)) continue;
          if (/\.svg(?:[?#]|$)/i.test(url)) continue;
          if (/archive\.org\/services\/img\//i.test(url)) continue;
          addCandidate(urls, url);
        }
      } catch (e) {
        console.warn("Bing Images parsing failed for " + item.game.title + ": " + e);
      }
      if (urls.length) {
        results[item.game.title] = urls;
        try { cache.put(item.key, JSON.stringify(urls), CACHE_SECONDS); } catch (e) {}
      }
    });
  }
  console.log("Bing Images fallback matches (including Flashpoint, Newgrounds and Game Jolt targeted results): " + Object.keys(results).length + "/" + games.length);
  return results;
}

// --------------------------------------------------
// TEN ADDITIONAL IMAGE SEARCH SOURCES
// --------------------------------------------------
function getAdditionalImageSearchSources_(games) {
  const results = {};
  if (!games || !games.length) {
    console.log("Additional image-search sources: no games need fallback search.");
    return results;
  }
  const engines = [
    {name:"Google Images", url:q=>"https://www.google.com/search?tbm=isch&q="+encodeURIComponent(q)},
    {name:"DuckDuckGo Images", url:q=>"https://duckduckgo.com/?iax=images&ia=images&q="+encodeURIComponent(q)},
    {name:"Yahoo Images", url:q=>"https://images.search.yahoo.com/search/images?p="+encodeURIComponent(q)},
    {name:"Ecosia Images", url:q=>"https://www.ecosia.org/images?q="+encodeURIComponent(q)},
    {name:"Yandex Images", url:q=>"https://yandex.com/images/search?text="+encodeURIComponent(q)},
    {name:"Qwant Images", url:q=>"https://www.qwant.com/?t=images&q="+encodeURIComponent(q)},
    {name:"Brave Search", url:q=>"https://search.brave.com/images?q="+encodeURIComponent(q)},
    {name:"Mojeek Images", url:q=>"https://www.mojeek.com/search?q="+encodeURIComponent(q+" images")},
    {name:"Startpage Images", url:q=>"https://www.startpage.com/sp/search?query="+encodeURIComponent(q)+"&cat=images"},
    {name:"Swisscows Images", url:q=>"https://swisscows.com/en/image?query="+encodeURIComponent(q)}
  ];
  const diagnostics = {};
  const jobs = [];
  games.forEach(game => {
    const query = '"' + game.title + '" game cover art poster key art title logo';
    engines.forEach(engine => jobs.push({game, engine, url:engine.url(query)}));
  });
  // Fetch in modest chunks to avoid one oversized request batch.
  for (let offset=0; offset<jobs.length; offset+=20) {
    const chunk=jobs.slice(offset,offset+20);
    let responses;
    try {
      responses=UrlFetchApp.fetchAll(chunk.map(job=>({
        url:job.url, method:"get", followRedirects:true, muteHttpExceptions:true,
        headers:{"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36", "Accept":"text/html,application/xhtml+xml"}
      })));
    } catch(err) {
      console.warn("Extra image-search batch failed: "+err);
      continue;
    }
    responses.forEach((response,i)=>{
      const job=chunk[i], name=job.engine.name;
      if(!diagnostics[name]) diagnostics[name]={http200:0,blockedOrError:0,imageCandidates:0};
      const code=response.getResponseCode();
      if(code!==200){diagnostics[name].blockedOrError++; return;}
      diagnostics[name].http200++;
      const html=response.getContentText();
      const urls=[];
      // Search engines encode source image URLs in several common formats.
      const patterns=[
        /[?&](?:imgurl|mediaurl|image_url|img_url)=([^&"'\\s<>]+)/gi,
        /"(?:contentUrl|originalImageUrl|image_url|imageUrl|murl)"\s*:\s*"((?:\\.|[^"\\])+)"/gi,
        /(?:src|data-src|data-original|data-lazy-src)\s*=\s*["'](https?:\\?\/\\?\/[^"']+)["']/gi
      ];
      patterns.forEach((re,pi)=>{
        let m;
        while((m=re.exec(html))!==null && urls.length<6){
          let u=m[1];
          try {
            if(pi===0) u=decodeURIComponent(u.replace(/&amp;/g,"&"));
            else if(pi===1){try{u=JSON.parse('"'+u+'"')}catch(e){u=u.replace(/\\u0026/g,"&").replace(/\\\//g,"/").replace(/\\"/g,'"')}}
            else u=u.replace(/\\\//g,"/").replace(/&amp;/g,"&");
          } catch(e) {}
          if(!/^https?:\/\//i.test(u)) return;
          if(/\.(?:svg|gif)(?:[?#]|$)/i.test(u)) return;
          if(/(?:favicon|sprite|logo|avatar|icon|googleusercontent\.com\/.*=s\d+-c)/i.test(u)) return;
          if(/\.(?:jpg|jpeg|png|webp)(?:[?#]|$)/i.test(u) || /(?:image|img|media|cdn|static)/i.test(u)) addCandidate(urls,u);
        }
      });
      if(urls.length){
        if(!results[job.game.title]) results[job.game.title]=[];
        urls.forEach(u=>addCandidate(results[job.game.title],u));
        diagnostics[name].imageCandidates += urls.length;
      }
    });
  }
  console.log("Additional image-search source diagnostics: "+JSON.stringify(diagnostics));
  console.log("Additional image-search sources: "+engines.length+" engines; matches for "+Object.keys(results).length+"/"+games.length+" games");
  return results;
}

// --------------------------------------------------
// PERMANENT ARTWORK CACHE IN GOOGLE DRIVE
// --------------------------------------------------

function loadSavedGamesArtwork() {
  const files = DriveApp.getFilesByName(SAVED_ARTWORK_FILE);

  if (!files.hasNext()) {
    return { games: {} };
  }

  try {
    const merged = {};
    let newest = null;
    while (files.hasNext()) {
      const file = files.next();
      try {
        const parsed = JSON.parse(file.getBlob().getDataAsString("UTF-8"));
        if (!parsed || !parsed.games) continue;
        Object.keys(parsed.games).forEach(url => {
          const incoming = parsed.games[url] || {};
          const prior = merged[url] || {};
          const preferred = incoming.preferredThumbnail || prior.preferredThumbnail || "";
          const list = [];
          (incoming.imageCandidates || incoming.thumbnails || []).concat(prior.imageCandidates || prior.thumbnails || []).forEach(u => {
            if (isUsableArtworkUrl(u) && !list.includes(u)) list.push(u);
          });
          if (preferred && list.includes(preferred)) list.unshift(preferred);
          merged[url] = Object.assign({}, prior, incoming, {
            imageCandidates: list, thumbnails: list,
            thumbnail: preferred || incoming.thumbnail || prior.thumbnail || list[0] || "",
            preferredThumbnail: preferred
          });
        });
        newest = parsed;
      } catch (fileError) {
        console.warn("Could not parse one artwork catalog copy: " + fileError);
      }
    }
    return { version: 1, updatedAt: newest && newest.updatedAt || "", games: merged };
  } catch (error) {
    console.warn("Could not read saved artwork cache: " + error);
    return { games: {} };
  }
}

function saveSavedGamesArtwork_(gamesByUrl) {
  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    const payload = JSON.stringify({
      version: 1,
      updatedAt: new Date().toISOString(),
      games: gamesByUrl
    });

    const files = DriveApp.getFilesByName(SAVED_ARTWORK_FILE);
    let found = false;
    while (files.hasNext()) {
      files.next().setContent(payload);
      found = true;
    }
    if (!found) DriveApp.createFile(SAVED_ARTWORK_FILE, payload, MimeType.PLAIN_TEXT);
  } finally {
    lock.releaseLock();
  }
}


// --------------------------------------------------
// GAME TITLE HELPERS
// --------------------------------------------------

function slugToTitle(slug) {
  return decodeURIComponent(slug)
    .replace(/[-_]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b[a-z]/g, letter => letter.toUpperCase());
}

function normalizeGameTitle(title) {
  return String(title || "")
    .toLowerCase()
    .replace(/&amp;/g, "&")
    .replace(/&/g, "and")
    .replace(/ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢|ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â®|ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â©/g, "")
    .replace(/\b(the|a|an)\b/g, "")
    .replace(/[^a-z0-9]/g, "");
}

function titleKeys(title) {
  const original = String(title || "").trim();
  const normalized = normalizeGameTitle(original);

  // Common aliases and spelling variants found on browser-game catalogs.
  // Keep aliases title-specific to avoid accidental matches between unrelated games.
  const aliases = {
    ducklife1: ["Duck Life", "Duck Life 1", "Duck Life: Origin"],
    btd3: ["Bloons Tower Defense 3", "Bloons TD 3"],
    btd5: ["Bloons Tower Defense 5", "Bloons TD 5"],
    bloonssupermonkey: ["Bloons Super Monkey", "Bloons Supermonkey"],
    jsab: ["Just Shapes and Beats", "Just Shapes & Beats"],
    justshapeandbeats: ["Just Shapes and Beats", "Just Shapes & Beats"],
    pokemonruby: ["Pokemon Ruby", "PokÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â©mon Ruby"],
    pokemonsaphire: ["Pokemon Sapphire", "PokÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â©mon Sapphire", "Pokemon Saphire"],
    pokemonleafgreen: ["Pokemon LeafGreen", "PokÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â©mon Leaf Green"],
    pokemonyellow: ["Pokemon Yellow", "PokÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â©mon Yellow"],
    henrystickmanfleeingthecomplex: ["Fleeing the Complex", "Henry Stickmin: Fleeing the Complex"],
    impossiblepasswordgame: ["The Impossible Quiz?", "Impossible Password"],
    monkeymart: ["Monkey Mart"],
    bobtherobber5: ["Bob the Robber 5", "Bob The Robber Five"],
    funnyshooter2: ["Funny Shooter 2"],
    tunnelrush2: ["Tunnel Rush 2"],
    bloonssupermonkey: ["Bloons Super Monkey", "Bloons Supermonkey"]
  };

  const variants = [
    original,
    original.replace(/ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾Ãƒâ€šÃ‚Â¢|ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â®|ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â©/g, ""),
    original.replace(/:/g, " "),
    original.replace(/\s*-\s*/g, " "),
    original.replace(/\b(edition|remastered|deluxe)\b/gi, ""),
    original.replace(/\b(web|browser|html5|port)\b/gi, ""),
    ...(aliases[normalized] || [])
  ];

  return [...new Set(variants.map(normalizeGameTitle).filter(Boolean))];
}


// Finds exact Foundplay title matches first, then conservative partial matches.
// Foundplay often adds words like "cover" or uses slightly different title punctuation.
function findCatalogArtwork(catalog, normalizedTitle) {
  if (!catalog || !normalizedTitle) return "";

  if (catalog[normalizedTitle]) return catalog[normalizedTitle];

  const keys = Object.keys(catalog);
  // Only allow partial matches when the shorter title is substantial enough
  // to avoid matching unrelated short names (e.g. "run", "red", "go").
  for (let i = 0; i < keys.length; i++) {
    const candidateKey = keys[i];
    if (Math.min(candidateKey.length, normalizedTitle.length) < 6) continue;
    if (
      candidateKey.includes(normalizedTitle) ||
      normalizedTitle.includes(candidateKey)
    ) {
      return catalog[candidateKey];
    }
  }

  return "";
}

function addCandidate(list, value) {
  if (typeof value !== "string") return;

  const url = value.trim();

  if (!/^https?:\/\//i.test(url)) return;

  if (!list.includes(url)) {
    list.push(url);
  }
}

function fetchJson(url) {
  try {
    const response = UrlFetchApp.fetch(url, {
      followRedirects: true,
      muteHttpExceptions: true,
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0"
      }
    });

    if (response.getResponseCode() !== 200) {
      return null;
    }

    return JSON.parse(response.getContentText());

  } catch (error) {
    console.warn("JSON fetch failed: " + error);
    return null;
  }
}


// --------------------------------------------------
// IMAGE CATALOGS
// --------------------------------------------------

function getAllThumbnailCatalogs() {
  return {
    coolmath: getCoolmathThumbnails(),
    foundplay: getFoundplayThumbnails(),
    itchio: getItchIoThumbnails(),
    newgrounds: getNewgroundsThumbnails(),
    kongregate: getKongregateThumbnails(),
    armorgames: getArmorGamesThumbnails(),
    addictinggames: getAddictingGamesThumbnails(),
    miniplay: getMiniplayThumbnails(),
    gamepix: getGamePixThumbnails(),
    crazygames: getCrazyGamesThumbnails(),
    gamedistribution: getGameDistributionThumbnails(),
    internetarchive: getInternetArchiveGameThumbnails(),
    gamearter: getGameArterThumbnails(),
    freetogame: getFreeToGameThumbnails(),
    y8: getY8Thumbnails(),
    mmobomb: getMMOBombThumbnails(),
    gameflare: getGameFlareThumbnails(),
    html5games: getHTML5GamesThumbnails(),
    kizi: getKiziThumbnails(),
    gamemonetize: getGameMonetizeThumbnails(),
    flashpoint: getFlashpointThumbnails()
  };
}

function getCatalogFromCache(prefix, builder) {
  const cache = CacheService.getScriptCache();
  const countKey = prefix + "_count";
  const cachedCount = cache.get(countKey);

  if (cachedCount !== null) {
    try {
      const combined = {};

      for (let i = 0; i < Number(cachedCount); i++) {
        const part = cache.get(prefix + "_part_" + i);

        if (part === null) {
          throw new Error("Missing cache part");
        }

        Object.assign(combined, JSON.parse(part));
      }

      return combined;

    } catch (error) {
      console.warn("Catalog cache needs rebuilding: " + error);
    }
  }

  const result = builder() || {};
  const entries = Object.entries(result);
  const chunks = [];

  if (entries.length === 0) {
    console.warn(prefix + ": catalog returned zero entries.");
    return result;
  }

  for (let i = 0; i < entries.length; i += 300) {
    chunks.push(
      Object.fromEntries(entries.slice(i, i + 300))
    );
  }

  try {
    const oldCount = Number(cache.get(countKey) || 0);

    for (let i = 0; i < oldCount; i++) {
      cache.remove(prefix + "_part_" + i);
    }

    cache.remove(countKey);

    chunks.forEach((chunk, i) => {
      cache.put(
        prefix + "_part_" + i,
        JSON.stringify(chunk),
        CACHE_SECONDS
      );
    });

    cache.put(
      countKey,
      String(chunks.length),
      CACHE_SECONDS
    );

  } catch (error) {
    console.warn("Catalog cache failed: " + error);
  }

  return result;
}

function getCoolmathThumbnails() {
  // v2 forces a fresh scrape after the older selector returned too few cards.
  return getCatalogFromCache("coolmath_catalog_v3", () => {
    const results = {};
    const pages = [
      "https://www.coolmathgames.com/",
      "https://www.coolmathgames.com/c/popular-games",
      "https://www.coolmathgames.com/c/new-games",
      "https://www.coolmathgames.com/c/daily-games",
      "https://www.coolmathgames.com/en/categories",
    ];

    pages.forEach(pageUrl => {
      try {
        const response = UrlFetchApp.fetch(pageUrl, {
          followRedirects: true,
          muteHttpExceptions: true,
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; InABoxGamesArtwork/1.0)",
            "Accept": "text/html,application/xhtml+xml"
          }
        });
        if (response.getResponseCode() !== 200) {
          console.warn("Coolmath HTTP " + response.getResponseCode() + " for " + pageUrl);
          return;
        }

        const html = response.getContentText();
        // Parse each image and inspect the nearest preceding anchor, instead of
        // assuming a particular attribute order or that src is not lazy-loaded.
        const imgPattern = /<img\b[^>]*>/gi;
        let imgMatch;
        while ((imgMatch = imgPattern.exec(html)) !== null) {
          const tag = imgMatch[0];
          const altMatch = tag.match(/\balt\s*=\s*["']([^"']*)["']/i);
          const titleAttr = tag.match(/\btitle\s*=\s*["']([^"']*)["']/i);
          const urlMatch = tag.match(/\b(?:src|data-src|data-lazy-src|data-original|data-lazy|data-image)\s*=\s*["']([^"']+)["']/i);
          if (!urlMatch) continue;

          // Look back to the nearest anchor opening tag and use its slug as the
          // title when possible; Coolmath card alt text often includes a tagline.
          const before = html.slice(Math.max(0, imgMatch.index - 1400), imgMatch.index);
          const anchorMatches = [...before.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>/gi)];
          const href = anchorMatches.length ? anchorMatches[anchorMatches.length - 1][1] : "";
          let title = "";
          if (href && /coolmathgames\.com/i.test(href)) {
            const slugMatch = href.match(/\/([^\/?#]+)\/?(?:[?#].*)?$/);
            if (slugMatch && !/^(?:c|en|sites|themes|user|about|privacy|terms)$/i.test(slugMatch[1])) {
              title = slugToTitle(slugMatch[1]);
            }
          }
          if (!title) title = (altMatch && altMatch[1]) || (titleAttr && titleAttr[1]) || "";
          title = title
            .replace(/^Image loaded successfully:\s*/i, "")
            .replace(/^Image:\s*/i, "")
            .replace(/\s+/g, " ")
            .trim();
          // The current site uses descriptive alt text like "Appel: Crunch on...".
          if (/^Image loaded successfully:/i.test(title)) title = title.replace(/^Image loaded successfully:\s*/i, "");
          if (title.includes(": ")) title = title.split(": ")[0].trim();

          let imageUrl = urlMatch[1].replace(/&amp;/g, "&").trim();
          if (imageUrl.startsWith("//")) imageUrl = "https:" + imageUrl;
          else if (imageUrl.startsWith("/")) imageUrl = "https://www.coolmathgames.com" + imageUrl;
          if (!title || !/^https?:\/\//i.test(imageUrl)) continue;
          if (/logo|avatar|icon|placeholder|banner|advert/i.test(imageUrl)) continue;
          const key = normalizeGameTitle(title);
          if (key && !results[key]) results[key] = imageUrl;
        }
      } catch (error) {
        console.warn("Coolmath fetch failed for " + pageUrl + ": " + error);
      }
    });

    console.log("Coolmath titles: " + Object.keys(results).length);
    console.log("Coolmath sample titles: " + Object.keys(results).slice(0, 12).join(", "));
    return results;
  });
}

function getGameArterThumbnails() {
  return getCatalogFromCache("ga_catalog_v4", () => {
    const results = {};
    const base = "https://www.gamearter.com/api/v1/catalog/games";

    for (let offset = 0; offset < 5000; offset += 100) {
      const data = fetchJson(base + "?limit=100&offset=" + offset);
      if (!data || !Array.isArray(data.games)) {
        console.warn("GameArter catalog response missing games at offset " + offset);
        break;
      }
      data.games.forEach(game => {
        const title = game.name || game.title;
        const image = game.thumbnail || game.image || game.cover;
        if (!title || !image) return;
        const key = normalizeGameTitle(title);
        if (key && !results[key]) results[key] = image;
      });
      if (data.next_offset == null || data.next_offset <= offset || data.games.length === 0) break;
    }
    console.log("GameArter API titles: " + Object.keys(results).length);
    return results;
  });
}

function getFreeToGameThumbnails() {
  return getCatalogFromCache("ftg_catalog_v4", () => {
    const results = {};
    // Browser-platform endpoint is attempted first, then the broad catalog.
    const datasets = [
      fetchJson("https://www.freetogame.com/api/games?platform=browser"),
      fetchJson("https://www.freetogame.com/api/games")
    ];
    datasets.forEach(data => {
      if (!Array.isArray(data)) return;
      data.forEach(game => {
        if (!game.title || !game.thumbnail) return;
        const key = normalizeGameTitle(game.title);
        if (key && !results[key]) results[key] = game.thumbnail;
      });
    });
    console.log("FreeToGame titles: " + Object.keys(results).length);
    return results;
  });
}

function getMMOBombThumbnails() {
  return getCatalogFromCache("mmobomb_catalog_v3", () => {
    const results = {};
    const data = fetchJson(
      "https://www.mmobomb.com/api1/games"
    );

    if (!Array.isArray(data)) return results;

    data.forEach(game => {
      if (!game.title || !game.thumbnail) return;

      const key = normalizeGameTitle(game.title);

      if (key && !results[key]) {
        results[key] = game.thumbnail;
      }
    });

    console.log(
      "MMOBomb titles: " + Object.keys(results).length
    );

    return results;
  });
}


// --------------------------------------------------
// FOUNDPLAY BROWSER GAME ARTWORK
// Foundplay lists thousands of indie, original, mashup, and browser-port games.
// This scraper uses image alt text as the title and caches the catalog.
// --------------------------------------------------

function getFoundplayThumbnails() {
  return getCatalogFromCache("foundplay_catalog_v3", () => {
    const results = {};
    const pages = [
      "https://foundplay.io/browse",
      "https://foundplay.io/browse?sort=new",
      "https://foundplay.io/browse?sort=trending"
    ];

    pages.forEach(pageUrl => {
      try {
        const response = UrlFetchApp.fetch(pageUrl, {
          followRedirects: true,
          muteHttpExceptions: true,
          headers: {
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html"
          }
        });

        if (response.getResponseCode() !== 200) {
          console.warn("Foundplay HTTP " + response.getResponseCode());
          return;
        }

        const html = response.getContentText();
        const imgPattern = /<img\b[^>]*>/gi;
        let match;

        while ((match = imgPattern.exec(html)) !== null) {
          const tag = match[0];
          const altMatch = tag.match(/\balt\s*=\s*["']([^"']+)["']/i);
          const srcMatch = tag.match(/\b(?:src|data-src|data-lazy-src|data-original)\s*=\s*["']([^"']+)["']/i)
            || tag.match(/\bsrcset\s*=\s*["']([^"']+)["']/i);
          if (!altMatch || !srcMatch) continue;

          // Foundplay may use relative Next.js image URLs (for example /_next/image?...).
          // Convert relative URLs to absolute URLs before saving them.
          let title = altMatch[1]
            .replace(/^Image:\s*/i, "")
            .replace(/\s+cover(?:Video)?$/i, "")
            .trim();
          let imageUrl = srcMatch[1].replace(/&amp;/g, "&").split(",")[0].trim().split(/\s+/)[0];

          if (imageUrl.startsWith("//")) imageUrl = "https:" + imageUrl;
          else if (imageUrl.startsWith("/")) imageUrl = "https://foundplay.io" + imageUrl;
          else if (!/^https?:\/\//i.test(imageUrl)) continue;

          if (!title || /placeholder|avatar|logo|icon/i.test(imageUrl)) continue;

          const key = normalizeGameTitle(title);
          if (key && !results[key]) results[key] = imageUrl;
        }
      } catch (error) {
        console.warn("Foundplay catalog fetch failed: " + error);
      }
    });

    console.log("Foundplay titles: " + Object.keys(results).length);
    return results;
  });
}



// --------------------------------------------------
// ITCH.IO HTML5 GAME ARTWORK
// Large indie catalog. Scrapes listing pages for game title + cover image.
// --------------------------------------------------
function getItchIoThumbnails() {
  return getCatalogFromCache("itchio_catalog_v1", () => {
    const results = {};
    const pages = [
      "https://itch.io/games/html5",
      "https://itch.io/games/html5?page=2",
      "https://itch.io/games/html5?page=3",
      "https://itch.io/games/html5?page=4",
      "https://itch.io/games/html5?page=5"
    ];
    scrapeGameArtworkPages_(pages, "itch.io", results);
    console.log("itch.io titles: " + Object.keys(results).length);
    return results;
  });
}

// --------------------------------------------------
// NEWGROUNDS GAME ARTWORK
// Indie and creator-made games. Scrapes several game listing pages.
// --------------------------------------------------
function getNewgroundsThumbnails() {
  return getCatalogFromCache("newgrounds_catalog_v1", () => {
    const results = {};
    const pages = [
      "https://www.newgrounds.com/games",
      "https://www.newgrounds.com/games/browse",
      "https://www.newgrounds.com/games/featured"
    ];
    scrapeGameArtworkPages_(pages, "newgrounds.com", results);
    console.log("Newgrounds titles: " + Object.keys(results).length);
    return results;
  });
}

// Shared best-effort HTML scraper. It associates image alt/title text with
// image URLs and handles lazy-loaded and relative image URLs.
function scrapeGameArtworkPages_(pages, host, results) {
  pages.forEach(pageUrl => {
    try {
      const response = UrlFetchApp.fetch(pageUrl, {
        followRedirects: true,
        muteHttpExceptions: true,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; InABoxGamesArtwork/1.0)",
          "Accept": "text/html"
        }
      });
      if (response.getResponseCode() !== 200) {
        console.warn(host + " HTTP " + response.getResponseCode() + " for " + pageUrl);
        return;
      }

      const html = response.getContentText();
      const imgPattern = /<img\b[^>]*>/gi;
      let match;
      while ((match = imgPattern.exec(html)) !== null) {
        const tag = match[0];
        const altMatch = tag.match(/\balt\s*=\s*["']([^"']+)["']/i);
        const titleMatch = tag.match(/\btitle\s*=\s*["']([^"']+)["']/i);
        const srcMatch = tag.match(/\b(?:src|data-src|data-lazy-src|data-original|data-lazy)\s*=\s*["']([^"']+)["']/i);
        const name = (altMatch && altMatch[1]) || (titleMatch && titleMatch[1]) || "";
        if (!name || !srcMatch) continue;

        let title = name
          .replace(/&amp;/g, "&")
          .replace(/&#39;|&apos;/g, "'")
          .replace(/&quot;/g, '"')
          .replace(/^Image:\s*/i, "")
          .replace(/\s+(cover|thumbnail|thumb)$/i, "")
          .trim();
        let imageUrl = srcMatch[1].replace(/&amp;/g, "&").trim();

        if (imageUrl.startsWith("//")) imageUrl = "https:" + imageUrl;
        else if (imageUrl.startsWith("/")) {
          imageUrl = "https://" + host + imageUrl;
        }
        if (!title || !/^https?:\/\//i.test(imageUrl)) continue;
        if (/avatar|emoji|logo|icon|blank|placeholder|rating/i.test(imageUrl)) continue;

        const key = normalizeGameTitle(title);
        if (key && !results[key]) results[key] = imageUrl;
      }
    } catch (error) {
      console.warn(host + " artwork fetch failed: " + error);
    }
  });
}




// --------------------------------------------------
// LEGACY FLASH-GAME PORTALS / BROWSER GAME CATALOGS
// These are extra best-effort sources. Sites can change markup or block
// automated requests, so each catalog logs the number of title/image pairs.
// --------------------------------------------------
function getKongregateThumbnails() {
  return getCatalogFromCache("kongregate_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://www.kongregate.com/",
      "https://www.kongregate.com/games"
    ], "www.kongregate.com", results);
    console.log("Kongregate titles: " + Object.keys(results).length);
    return results;
  });
}

function getArmorGamesThumbnails() {
  return getCatalogFromCache("armorgames_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://armorgames.com/",
      "https://armorgames.com/category/strategy-games"
    ], "armorgames.com", results);
    console.log("Armor Games titles: " + Object.keys(results).length);
    return results;
  });
}

function getAddictingGamesThumbnails() {
  return getCatalogFromCache("addictinggames_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://www.addictinggames.com/",
      "https://www.addictinggames.com/strategy"
    ], "www.addictinggames.com", results);
    console.log("Addicting Games titles: " + Object.keys(results).length);
    return results;
  });
}

function getMiniplayThumbnails() {
  return getCatalogFromCache("miniplay_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://www.miniplay.com/",
      "https://www.miniplay.com/games"
    ], "www.miniplay.com", results);
    console.log("Miniplay titles: " + Object.keys(results).length);
    return results;
  });
}


// --------------------------------------------------
// GAMEPIX GAME ARTWORK
// Listing pages may change; this is a best-effort HTML catalog scrape.
// --------------------------------------------------
function getGamePixThumbnails() {
  return getCatalogFromCache("gamepix_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://www.gamepix.com/games",
      "https://www.gamepix.com/"
    ], "www.gamepix.com", results);
    console.log("GamePix titles: " + Object.keys(results).length);
    return results;
  });
}

// --------------------------------------------------
// CRAZYGAMES GAME ARTWORK
// Pull game-card image/title pairs from public browse pages.
// --------------------------------------------------
function getCrazyGamesThumbnails() {
  return getCatalogFromCache("crazygames_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://www.crazygames.com/",
      "https://www.crazygames.com/t/2d",
      "https://www.crazygames.com/t/arcade",
      "https://www.crazygames.com/t/puzzle"
    ], "www.crazygames.com", results);
    console.log("CrazyGames titles: " + Object.keys(results).length);
    return results;
  });
}

// --------------------------------------------------
// GAMEDISTRIBUTION GAME ARTWORK
// Public catalog pages can be blocked or reshaped; log counts per run.
// --------------------------------------------------
function getGameDistributionThumbnails() {
  return getCatalogFromCache("gamedistribution_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://gamedistribution.com/games/",
      "https://gamedistribution.com/"
    ], "gamedistribution.com", results);
    console.log("GameDistribution titles: " + Object.keys(results).length);
    return results;
  });
}

// --------------------------------------------------
// Y8 BROWSER GAME ARTWORK
// Best-effort scrape of public game listing pages. Availability depends on Y8 response.
// --------------------------------------------------
function getY8Thumbnails() {
  return getCatalogFromCache("y8_catalog_v2", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://www.y8.com/",
      "https://www.y8.com/games",
      "https://www.y8.com/categories/skill",
      "https://www.y8.com/categories/puzzle"
    ], "www.y8.com", results);
    console.log("Y8 titles: " + Object.keys(results).length);
    return results;
  });
}



// --------------------------------------------------
// ADDITIONAL BROWSER-GAME ARTWORK SOURCES
// Best-effort listing scrapers. These sources may block automated requests,
// change their HTML, or expose only a subset of their catalog.
// --------------------------------------------------
function getGameFlareThumbnails() {
  return getCatalogFromCache("gameflare_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://www.gameflare.com/",
      "https://www.gameflare.com/online-games/",
      "https://www.gameflare.com/new-games/"
    ], "GameFlare", results);
    console.log("GameFlare titles: " + Object.keys(results).length);
    return results;
  });
}

function getHTML5GamesThumbnails() {
  return getCatalogFromCache("html5games_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://www.html5games.com/",
      "https://www.html5games.com/games/",
      "https://www.html5games.com/new-games/"
    ], "HTML5Games", results);
    console.log("HTML5Games titles: " + Object.keys(results).length);
    return results;
  });
}

function getKiziThumbnails() {
  return getCatalogFromCache("kizi_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://kizi.com/",
      "https://kizi.com/games",
      "https://kizi.com/new-games"
    ], "Kizi", results);
    console.log("Kizi titles: " + Object.keys(results).length);
    return results;
  });
}

function getGameMonetizeThumbnails() {
  return getCatalogFromCache("gamemonetize_catalog_v1", () => {
    const results = {};
    scrapeGameArtworkPages_([
      "https://gamemonetize.com/",
      "https://gamemonetize.com/games",
      "https://gamemonetize.com/game-portal"
    ], "GameMonetize", results);
    console.log("GameMonetize titles: " + Object.keys(results).length);
    return results;
  });
}
function getFlashpointThumbnails() {
  return getCatalogFromCache("flashpoint_catalog_v1", () => {
    const results = {};
    // Flashpoint is primarily a preservation project rather than a normal
    // browser-game storefront, so these are best-effort pages, not a guarantee
    // of a complete searchable game database.
    scrapeGameArtworkPages_([
      "https://flashpointarchive.org/",
      "https://flashpointarchive.org/datahub/",
      "https://flashpointarchive.org/datahub/Download_Flashpoint"
    ], "Flashpoint Archive", results);
    console.log("Flashpoint titles: " + Object.keys(results).length);
    return results;
  });
}


// --------------------------------------------------
// INTERNET ARCHIVE GAME/SOFTWARE THUMBNAILS
// Uses Internet Archive's public Advanced Search API and thumbnail endpoint.
// It is a broad supplemental source; many items will not match modern browser games.
// --------------------------------------------------
function getInternetArchiveGameThumbnails() {
  return getCatalogFromCache("internetarchive_games_catalog_v1", () => {
    const results = {};
    const queries = [
      'mediatype:software AND subject:games',
      'mediatype:software AND title:game'
    ];
    queries.forEach(query => {
      try {
        const api = "https://archive.org/advancedsearch.php?q=" +
          encodeURIComponent(query) +
          "&fl[]=identifier&fl[]=title&rows=500&page=1&output=json";
        const response = UrlFetchApp.fetch(api, {
          followRedirects: true,
          muteHttpExceptions: true,
          headers: { "Accept": "application/json" }
        });
        if (response.getResponseCode() !== 200) {
          console.warn("Internet Archive HTTP " + response.getResponseCode());
          return;
        }
        const data = JSON.parse(response.getContentText());
        const docs = data && data.response && data.response.docs || [];
        docs.forEach(item => {
          if (!item || !item.title || !item.identifier) return;
          const key = normalizeGameTitle(item.title);
          if (!key || results[key]) return;
          results[key] = "https://archive.org/services/img/" +
            encodeURIComponent(item.identifier);
        });
      } catch (error) {
        console.warn("Internet Archive artwork fetch failed: " + error);
      }
    });
    console.log("Internet Archive game titles: " + Object.keys(results).length);
    return results;
  });
}

// --------------------------------------------------
// INTERNET ARCHIVE targeted title search. Uses the official public API.
function getInternetArchiveTitleSearch_(titles) {
  const cache = CacheService.getScriptCache();
  const cacheKey = "internet_archive_targeted_v1";
  const cached = cache.get(cacheKey);
  if (cached) {
    try { return JSON.parse(cached); } catch (e) {}
  }
  const results = {};
  const uniqueTitles = Array.from(new Set(titles)).slice(0, 50);
  const requests = uniqueTitles.map(title => {
    const escaped = String(title).replace(/["\\]/g, " ").replace(/\s+/g, " ").trim();
    const query = 'title:("' + escaped + '") AND mediatype:software';
    return {
      url: "https://archive.org/advancedsearch.php?q=" + encodeURIComponent(query) +
        "&fl[]=identifier&fl[]=title&fl[]=mediatype&rows=5&page=1&output=json",
      method: "get",
      muteHttpExceptions: true,
      headers: { "Accept": "application/json" }
    };
  });
  for (let offset = 0; offset < requests.length; offset += 10) {
    try {
      UrlFetchApp.fetchAll(requests.slice(offset, offset + 10)).forEach(response => {
        if (response.getResponseCode() !== 200) return;
        try {
          const data = JSON.parse(response.getContentText());
          const docs = data && data.response && data.response.docs || [];
          docs.forEach(doc => {
            if (!doc.identifier || !doc.title) return;
            const key = normalizeGameTitle(doc.title);
            if (key && !results[key]) {
              results[key] = "https://archive.org/services/img/" + encodeURIComponent(doc.identifier);
            }
          });
        } catch (e) {}
      });
    } catch (e) {
      console.warn("Internet Archive targeted search failed: " + e);
    }
  }
  console.log("Internet Archive targeted titles: " + Object.keys(results).length);
  try { cache.put(cacheKey, JSON.stringify(results), 21600); } catch (e) {}
  return results;
}

// TheGamesDB can help with older console/classic games. Optional API key:
// Script Properties > THEGAMESDB_API_KEY.
function getTheGamesDbThumbnails_(titles) {
  const apiKey = PropertiesService.getScriptProperties().getProperty("THEGAMESDB_API_KEY");
  if (!apiKey) {
    console.log("TheGamesDB skipped: add THEGAMESDB_API_KEY to Script Properties.");
    return {};
  }
  const cache = CacheService.getScriptCache();
  const cacheKey = "thegamesdb_catalog_v1";
  const cached = cache.get(cacheKey);
  if (cached) {
    try { return JSON.parse(cached); } catch (e) {}
  }
  const results = {};
  Array.from(new Set(titles)).slice(0, 50).forEach(title => {
    try {
      const url = "https://api.thegamesdb.net/v1/Games/ByGameName?apikey=" +
        encodeURIComponent(apiKey) + "&name=" + encodeURIComponent(title);
      const response = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
      if (response.getResponseCode() !== 200) return;
      const data = JSON.parse(response.getContentText());
      const games = data && data.data && data.data.games || [];
      const wanted = normalizeGameTitle(title);
      const game = games.find(item => item && item.game_title &&
        normalizeGameTitle(item.game_title) === wanted);
      if (!game || !game.id) return;
      const boxart = data.include && data.include.boxart &&
        data.include.boxart.data && data.include.boxart.data[game.id];
      if (!Array.isArray(boxart) || !boxart.length) return;
      const front = boxart.find(item => item.side === "front") || boxart[0];
      if (front && front.filename) {
        results[wanted] = "https://cdn.thegamesdb.net/images/original/" + front.filename;
      }
    } catch (e) {
      console.warn("TheGamesDB lookup failed for " + title + ": " + e);
    }
  });
  console.log("TheGamesDB artwork matches: " + Object.keys(results).length);
  try { cache.put(cacheKey, JSON.stringify(results), 21600); } catch (e) {}
  return results;
}

// TRUFFLED GAME ARTWORK
// --------------------------------------------------

function getTruffledThumbnails() {
  const cache = CacheService.getScriptCache();
  const cacheKey = "truffled_art_catalog_v1";
  const cached = cache.get(cacheKey);

  if (cached !== null) {
    try {
      return JSON.parse(cached);
    } catch (error) {
      cache.remove(cacheKey);
    }
  }

  const results = {};

  try {
    const response = UrlFetchApp.fetch("https://truffled.lol/g", {
      followRedirects: true,
      muteHttpExceptions: true,
      headers: {
        "User-Agent": "Mozilla/5.0",
        Accept: "text/html"
      }
    });

    if (response.getResponseCode() !== 200) {
      console.warn("Truffled gallery returned HTTP " + response.getResponseCode());
      return results;
    }

    const html = response.getContentText();
    const pattern = /(?:https?:\/\/truffled\.lol)?\/?png\/games\/[a-z0-9_-]+\.(?:webp|png|jpe?g|avif)/gi;
    let match;

    while ((match = pattern.exec(html)) !== null) {
      let url = match[0];
      if (url.startsWith("/")) url = "https://truffled.lol" + url;
      if (!url.startsWith("http")) url = "https://truffled.lol/" + url.replace(/^\/+/, "");

      const filename = url.substring(url.lastIndexOf("/") + 1).replace(/\.[^.]+$/, "");
      const key = normalizeGameTitle(filename);
      if (key && !results[key]) results[key] = url;
    }

    if (Object.keys(results).length) {
      cache.put(cacheKey, JSON.stringify(results), CACHE_SECONDS);
    }

    console.log("Truffled artwork filenames: " + Object.keys(results).length);
  } catch (error) {
    console.warn("Truffled artwork lookup failed: " + error);
  }

  return results;
}

function findTruffledArtwork(title, catalog) {
  if (!catalog || typeof catalog !== "object") return "";

  const aliases = {
    "20minutestilldawn": ["20mtd"],
    "1v1lo": ["1v1"],
    "angrybirds": ["angry", "angrybirdsonline"],
    "angrybirds2": ["ab2"],
    "ageofwar": ["aow"],
    "ageofwar2": ["aow2"],
    "ataribreakout": ["breakout"],
    "sausageflip": ["sausageflip"]
  };

  const keys = titleKeys(title);
  const normalizedTitle = normalizeGameTitle(title);

  (aliases[normalizedTitle] || []).forEach(alias => {
    if (!keys.includes(alias)) keys.push(alias);
  });

  for (const key of keys) {
    if (catalog[key]) return catalog[key];
  }

  return "";
}


// --------------------------------------------------
// POKI SEARCH ARTWORK (BEST-EFFORT)
// --------------------------------------------------

function getPokiImages(games) {
  const cache = CacheService.getScriptCache();
  const results = {};
  const pending = [];

  games.forEach(game => {
    const cacheKey = "poki_art_v2_" + normalizeGameTitle(game.title).slice(0, 130);
    const cached = cache.get(cacheKey);
    if (cached !== null) {
      try {
        const item = JSON.parse(cached);
        if (Array.isArray(item.urls) && item.urls.length) results[game.title] = item.urls;
      } catch (error) {}
    } else {
      pending.push({ game, cacheKey });
    }
  });

  for (let start = 0; start < pending.length; start += 8) {
    const batch = pending.slice(start, start + 8);
    let responses;
    try {
      responses = UrlFetchApp.fetchAll(batch.map(item => ({
        url: "https://poki.com/en/search?q=" + encodeURIComponent(item.game.title),
        method: "get",
        followRedirects: true,
        muteHttpExceptions: true,
        headers: { "User-Agent": "Mozilla/5.0", Accept: "text/html" }
      })));
    } catch (error) {
      console.warn("Poki search batch failed: " + error);
      continue;
    }

    responses.forEach((response, i) => {
      const item = batch[i];
      const urls = [];
      try {
        if (response.getResponseCode() !== 200) return;
        const html = response.getContentText();
        const wanted = normalizeGameTitle(item.game.title);
        // Match a nearby title/name in HTML and collect image URLs from that card.
        const escapedTitle = item.game.title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const titleRx = new RegExp(escapedTitle, "i");
        const imageRx = /(?:src|data-src|srcset)=["']([^"']+)["']/gi;
        let m;
        while ((m = imageRx.exec(html)) !== null) {
          let src = m[1].split(",")[0].trim().split(/\s+/)[0];
          src = src.replace(/&amp;/g, "&");
          if (!/^https?:\/\//i.test(src)) continue;
          const pos = m.index;
          const nearby = html.slice(Math.max(0, pos - 900), Math.min(html.length, pos + 300));
          if (titleRx.test(nearby) || normalizeGameTitle(nearby).includes(wanted)) addCandidate(urls, src);
          if (urls.length >= 5) break;
        }
      } catch (error) {
        console.warn("Poki result failed for " + item.game.title + ": " + error);
      }
      // Cache only successful results, so failed/blocked searches retry next run.
      if (urls.length) {
        try { cache.put(item.cacheKey, JSON.stringify({ urls }), CACHE_SECONDS); } catch (error) {}
        results[item.game.title] = urls;
      }
    });
  }
  console.log("Poki artwork matches: " + Object.keys(results).length);
  return results;
}

// --------------------------------------------------
// STEAM ARTWORK
// --------------------------------------------------

function getSteamImages(games) {
  const cache = CacheService.getScriptCache();
  const results = {};
  const pending = [];

  games.forEach(game => {
    const cacheKey =
      "steam_art_v3_" +
      normalizeGameTitle(game.title).slice(0, 150);

    const cached = cache.get(cacheKey);

    if (cached !== null) {
      try {
        const item = JSON.parse(cached);

        if (Array.isArray(item.urls)) {
          results[game.title] = item.urls;
        }

      } catch (error) {}

    } else {
      pending.push({ game, cacheKey });
    }
  });

  for (let start = 0; start < pending.length; start += 20) {
    const batch = pending.slice(start, start + 20);

    const requests = batch.map(item => ({
      url:
        "https://store.steampowered.com/api/storesearch/?term=" +
        encodeURIComponent(item.game.title) +
        "&l=english&cc=US",
      method: "get",
      followRedirects: true,
      muteHttpExceptions: true,
      headers: { Accept: "application/json" }
    }));

    let responses;

    try {
      responses = UrlFetchApp.fetchAll(requests);

    } catch (error) {
      console.warn("Steam batch failed: " + error);
      continue;
    }

    responses.forEach((response, i) => {
      const item = batch[i];
      const urls = [];

      try {
        if (response.getResponseCode() === 200) {
          const data = JSON.parse(response.getContentText());

          const matches = Array.isArray(data.items)
            ? data.items
            : [];

          const steamGame = matches.find(candidate =>
            candidate.name &&
            isCloseTitleMatch(
              item.game.title,
              candidate.name
            )
          );

          if (steamGame && steamGame.appid) {
            const base =
              "https://cdn.akamai.steamstatic.com/steam/apps/" +
              steamGame.appid +
              "/";

            addCandidate(
              urls,
              base + "library_600x900.jpg"
            );

            addCandidate(urls, base + "header.jpg");

            addCandidate(
              urls,
              base + "capsule_616x353.jpg"
            );

            addCandidate(urls, base + "library_hero.jpg");

            addCandidate(
              urls,
              steamGame.tiny_image || ""
            );
          }
        }

      } catch (error) {
        console.warn(
          "Steam result failed for " + item.game.title
        );
      }

      // Cache only successful results; failed searches can retry later.
      if (urls.length) {
        try {
          cache.put(item.cacheKey, JSON.stringify({ urls }), CACHE_SECONDS);
        } catch (error) {}
        results[item.game.title] = urls;
      }
    });
  }

  console.log(
    "Steam artwork matches: " + Object.keys(results).length
  );

  return results;
}


// --------------------------------------------------
// STEAMGRIDDB ARTWORK
// --------------------------------------------------

function getSteamGridDBImages(games) {
  const apiKey = PropertiesService.getScriptProperties()
    .getProperty("STEAMGRIDDB_API_KEY");

  if (!apiKey) {
    console.log(
      "SteamGridDB skipped: add STEAMGRIDDB_API_KEY to Script Properties to enable it."
    );

    return {};
  }

  const cache = CacheService.getScriptCache();
  const results = {};
  const pending = [];

  games.forEach(game => {
    const cacheKey =
      "sgdb_art_v2_" +
      normalizeGameTitle(game.title).slice(0, 130);

    const cached = cache.get(cacheKey);

    if (cached !== null) {
      try {
        const item = JSON.parse(cached);

        if (Array.isArray(item.urls) && item.urls.length) {
          results[game.title] = item.urls;
        }

      } catch (error) {}

    } else {
      pending.push({ game, cacheKey });
    }
  });

  for (let start = 0; start < pending.length; start += 15) {
    const batch = pending.slice(start, start + 15);
    let searches;

    try {
      searches = UrlFetchApp.fetchAll(
        batch.map(item => ({
          url:
            "https://www.steamgriddb.com/api/v2/search/autocomplete/" +
            encodeURIComponent(item.game.title),
          method: "get",
          followRedirects: true,
          muteHttpExceptions: true,
          headers: {
            Authorization: "Bearer " + apiKey,
            Accept: "application/json"
          }
        }))
      );

    } catch (error) {
      console.warn(
        "SteamGridDB search batch failed: " + error
      );

      continue;
    }

    const matched = [];

    searches.forEach((response, i) => {
      try {
        if (response.getResponseCode() !== 200) return;

        const data = JSON.parse(response.getContentText());

        const items =
          data && Array.isArray(data.data)
            ? data.data
            : [];

        const gameMatch = items.find(candidate =>
          candidate.name &&
          candidate.id &&
          isCloseTitleMatch(
            batch[i].game.title,
            candidate.name
          )
        );

        if (gameMatch) {
          matched.push({
            ...batch[i],
            gameId: gameMatch.id
          });

        }

      } catch (error) {
        console.warn(
          "SteamGridDB search parse failed for " +
          batch[i].game.title
        );
      }
    });

    for (let j = 0; j < matched.length; j += 15) {
      const artBatch = matched.slice(j, j + 15);
      let artResponses;

      try {
        artResponses = UrlFetchApp.fetchAll(
          artBatch.map(item => ({
            url:
              "https://www.steamgriddb.com/api/v2/grids/game/" +
              item.gameId +
              "?dimensions=600x900&types=static",
            method: "get",
            followRedirects: true,
            muteHttpExceptions: true,
            headers: {
              Authorization: "Bearer " + apiKey,
              Accept: "application/json"
            }
          }))
        );

      } catch (error) {
        console.warn(
          "SteamGridDB art batch failed: " + error
        );

        continue;
      }

      artResponses.forEach((response, i) => {
        const item = artBatch[i];
        const urls = [];

        try {
          if (response.getResponseCode() === 200) {
            const data = JSON.parse(
              response.getContentText()
            );

            (
              Array.isArray(data.data)
                ? data.data
                : []
            ).slice(0, 6).forEach(art => {
              addCandidate(urls, art.url || "");
            });
          }

        } catch (error) {
          console.warn(
            "SteamGridDB art parse failed for " +
            item.game.title
          );
        }

        if (urls.length) {
          try {
            cache.put(item.cacheKey, JSON.stringify({ urls }), CACHE_SECONDS);
          } catch (error) {}
          results[item.game.title] = urls;
        }
      });
    }
  }

  console.log(
    "SteamGridDB artwork matches: " +
    Object.keys(results).length
  );

  return results;
}


// --------------------------------------------------
// IGDB ARTWORK (Twitch OAuth)
// Set IGDB_CLIENT_ID and IGDB_CLIENT_SECRET in Script Properties.
// --------------------------------------------------
function getIGDBAccessToken_() {
  const props = PropertiesService.getScriptProperties();
  const clientId = props.getProperty("IGDB_CLIENT_ID");
  const clientSecret = props.getProperty("IGDB_CLIENT_SECRET");
  if (!clientId || !clientSecret) {
    console.warn("IGDB skipped: add IGDB_CLIENT_ID and IGDB_CLIENT_SECRET to Script Properties.");
    return "";
  }

  const cache = CacheService.getScriptCache();
  const cached = cache.get("igdb_oauth_token_v1");
  if (cached) return cached;

  const url = "https://id.twitch.tv/oauth2/token";
  const response = UrlFetchApp.fetch(url, {
    method: "post",
    payload: {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "client_credentials"
    },
    muteHttpExceptions: true
  });
  if (response.getResponseCode() !== 200) {
    console.warn("IGDB OAuth HTTP " + response.getResponseCode() + ": " + response.getContentText().slice(0, 250));
    return "";
  }
  const data = JSON.parse(response.getContentText());
  if (!data.access_token) return "";
  cache.put("igdb_oauth_token_v1", data.access_token, Math.max(60, Math.min(Number(data.expires_in || 3600) - 300, 21600)));
  return data.access_token;
}

function getIGDBImages(games) {
  const props = PropertiesService.getScriptProperties();
  const clientId = props.getProperty("IGDB_CLIENT_ID");
  const token = getIGDBAccessToken_();
  if (!clientId || !token || !games || !games.length) return {};

  const cache = CacheService.getScriptCache();
  const results = {};
  let matched = 0;
  games.forEach(game => {
    const normalized = normalizeGameTitle(game.title);
    const cacheKey = "igdb_art_v1_" + normalized.slice(0, 130);
    const cached = cache.get(cacheKey);
    if (cached !== null) {
      try { results[game.title] = JSON.parse(cached); } catch (e) {}
      return;
    }

    // IGDB uses its own query language and expects POST text/plain.
    const queryNames = titleKeys(game.title).slice(0, 4);
    const safeTitle = String(queryNames[0] || game.title).replace(/\\/g, " ").replace(/"/g, " ").trim();
    const body = 'search "' + safeTitle + '"; fields name,cover.image_id,screenshots.image_id; limit 8;';
    try {
      const response = UrlFetchApp.fetch("https://api.igdb.com/v4/games", {
        method: "post",
        contentType: "text/plain",
        payload: body,
        headers: {
          "Client-ID": clientId,
          "Authorization": "Bearer " + token,
          "Accept": "application/json"
        },
        muteHttpExceptions: true
      });
      if (response.getResponseCode() !== 200) {
        console.warn("IGDB HTTP " + response.getResponseCode() + " for " + game.title + ": " + response.getContentText().slice(0, 160));
        return;
      }
      const rows = JSON.parse(response.getContentText()) || [];
      const wanted = normalizeGameTitle(game.title);
      let best = null;
      let bestScore = -1;
      rows.forEach(row => {
        const candidate = normalizeGameTitle(row.name || "");
        let score = candidate === wanted ? 100 : 0;
        if (!score && candidate && wanted) {
          if (candidate.includes(wanted) || wanted.includes(candidate)) score = Math.min(candidate.length, wanted.length) >= 6 ? 70 : 0;
        }
        if (score > bestScore) { best = row; bestScore = score; }
      });

      const urls = [];
      if (best && bestScore >= 70) {
        if (best.cover && best.cover.image_id) urls.push(igdbImageUrl_(best.cover.image_id, "t_cover_big"));
        (best.screenshots || []).forEach(item => {
          if (item.image_id) urls.push(igdbImageUrl_(item.image_id, "t_screenshot_big"));
        });
        matched++;
      }
      results[game.title] = urls;
      cache.put(cacheKey, JSON.stringify(urls), 21600);
      Utilities.sleep(100);
    } catch (error) {
      console.warn("IGDB lookup failed for " + game.title + ": " + error);
    }
  });
  console.log("IGDB artwork matches: " + matched);
  return results;
}

function igdbImageUrl_(imageId, size) {
  return "https://images.igdb.com/igdb/image/upload/" + size + "/" + encodeURIComponent(imageId) + ".jpg";
}

// --------------------------------------------------
// RAWG ARTWORK
// --------------------------------------------------

function getRawgImages(games) {
  const apiKey = PropertiesService.getScriptProperties()
    .getProperty("RAWG_API_KEY");

  if (!apiKey) {
    console.warn(
      "RAWG_API_KEY is missing from Script Properties."
    );

    return {};
  }

  const cache = CacheService.getScriptCache();
  const results = {};
  const pending = [];

  games.forEach(game => {
    const cacheKey =
      "rawg_art_v3_" +
      normalizeGameTitle(game.title).slice(0, 140);

    const cached = cache.get(cacheKey);

    if (cached !== null) {
      try {
        const item = JSON.parse(cached);

        if (Array.isArray(item.urls) && item.urls.length) {
          results[game.title] = item.urls;
        }

      } catch (error) {}

    } else {
      pending.push({ game, cacheKey });
    }
  });

  for (let start = 0; start < pending.length; start += 15) {
    const batch = pending.slice(start, start + 15);

    const requests = batch.map(item => ({
      url:
        "https://api.rawg.io/api/games?key=" +
        encodeURIComponent(apiKey) +
        "&search=" +
        encodeURIComponent(item.game.title) +
        "&page_size=8",
      method: "get",
      followRedirects: true,
      muteHttpExceptions: true,
      headers: { Accept: "application/json" }
    }));

    let responses;

    try {
      responses = UrlFetchApp.fetchAll(requests);

    } catch (error) {
      console.warn("RAWG batch failed: " + error);
      continue;
    }

    responses.forEach((response, i) => {
      const item = batch[i];
      const urls = [];

      try {
        if (response.getResponseCode() === 200) {
          const data = JSON.parse(
            response.getContentText()
          );

          const found =
            data && Array.isArray(data.results)
              ? data.results
              : [];

          const matches = found.filter(candidate =>
            candidate.name &&
            isCloseTitleMatch(
              item.game.title,
              candidate.name
            )
          );

          matches.forEach(candidate => {
            addCandidate(
              urls,
              candidate.background_image || ""
            );

            addCandidate(
              urls,
              candidate.background_image_additional || ""
            );
          });

        } else {
          console.warn(
            "RAWG HTTP " +
            response.getResponseCode() +
            " for " +
            item.game.title
          );
        }

      } catch (error) {
        console.warn(
          "RAWG result failed for " + item.game.title
        );
      }

      // Cache successful results. Failed requests can retry later.
      if (urls.length) {
        try {
          cache.put(
            item.cacheKey,
            JSON.stringify({ urls }),
            CACHE_SECONDS
          );
        } catch (error) {}

        results[item.game.title] = urls;
      }
    });
  }

  console.log(
    "RAWG artwork matches: " + Object.keys(results).length
  );

  return results;
}


// --------------------------------------------------
// MATCHING AND CACHE UTILITIES
// --------------------------------------------------

function isCloseTitleMatch(wanted, found) {
  const a = normalizeGameTitle(wanted);
  const b = normalizeGameTitle(found);

  if (!a || !b) return false;
  if (a === b) return true;

  const shorter = a.length <= b.length ? a : b;
  const longer = a.length > b.length ? a : b;

  return shorter.length >= 6 &&
    longer.includes(shorter) &&
    shorter.length / longer.length >= 0.72;
}

// Upgrade existing gameplay thumbnails to title/cover art when a suitable image can be found.
// Run from the Apps Script function dropdown; checks all eligible games in one run.
function upgradeExistingArtworkToTitleImagesBatch_() {
  const all = getGames();
  const saved = loadSavedGamesArtwork();
  const byUrl = saved.games || {};
  const pending = all.filter(game => {
    const entry = byUrl[game.url];
    if (!entry) return false;
    if (entry.titleArtworkChecked === true) return false;
    return (entry.imageCandidates || entry.thumbnails || []).length > 0;
  });

  if (!pending.length) {
    console.log("Title-art upgrade complete: no unchecked games with existing artwork remain.");
    return {processed: 0, remaining: 0};
  }

  console.log("Checking existing artwork for title/cover art: " + pending.map(g => g.title).join(", "));
  // Query Bing and the additional engines specifically for cover/title artwork.
  const bing = getBingGameImageSearch_(pending);
  const extra = getAdditionalImageSearchSources_(pending);
  pending.forEach(game => {
    const entry = byUrl[game.url];
    const old = entry.imageCandidates || entry.thumbnails || [];
    const titleCandidates = [];
    (bing[game.title] || []).forEach(u => addCandidate(titleCandidates, u));
    (extra[game.title] || []).forEach(u => addCandidate(titleCandidates, u));
    // Put newly found title art first; retain existing gameplay images as fallbacks.
    entry.imageCandidates = titleCandidates.concat(old.filter(u => !titleCandidates.includes(u)));
    entry.thumbnails = entry.imageCandidates;
    entry.thumbnail = entry.imageCandidates[0] || "";
    entry.titleArtworkChecked = true;
    entry.titleArtworkCheckedAt = new Date().toISOString();
    byUrl[game.url] = entry;
    console.log("Title-art candidates for " + game.title + ": " + titleCandidates.length);
  });
  saveSavedGamesArtwork_(byUrl);
  const remaining = all.filter(game => {
    const entry = byUrl[game.url];
    return entry && !entry.titleArtworkChecked && (entry.imageCandidates || entry.thumbnails || []).length > 0;
  }).length;
  console.log("Title-art upgrade batch complete. Remaining unchecked games: " + remaining);
  return {processed: pending.length, remaining};
}

function clearThumbnailCache_() {
  const cache = CacheService.getScriptCache();

  [
    "coolmath_catalog_v1",
    "coolmath_catalog_v3",
    "foundplay_catalog_v3",
    "internet_archive_targeted_v1",
    "thegamesdb_catalog_v1",
    "itchio_catalog_v1",
    "newgrounds_catalog_v1",
    "kongregate_catalog_v1",
    "armorgames_catalog_v1",
    "addictinggames_catalog_v1",
    "miniplay_catalog_v1",
    "gamepix_catalog_v1",
    "crazygames_catalog_v1",
    "gamedistribution_catalog_v1",
    "internetarchive_games_catalog_v1",
    "ga_catalog_v3",
    "ga_catalog_v4",
    "ftg_catalog_v3",
    "ftg_catalog_v4",
    "y8_catalog_v2",
    "mmobomb_catalog_v3",
    "bing_game_images_v1"
  ].forEach(prefix => {
    cache.remove(prefix + "_count");

    for (let i = 0; i < 30; i++) {
      cache.remove(prefix + "_part_" + i);
    }
  });

  // The permanent Drive artwork file is intentionally preserved.
  console.log(
    "Catalog cache cleared. Existing saved artwork was preserved."
  );
}

function diagnoseThumbnails() {
  const games = getGames();

  console.log("Games found: " + games.length);

  console.log(
    "Games with image candidates: " +
    games.filter(game => game.imageCandidates.length).length
  );

  console.log(
    JSON.stringify(
      games.slice(0, 30).map(game => ({
        title: game.title,
        thumbnail: game.thumbnail,
        candidates: game.imageCandidates.length
      }))
    )
  );
}


// Artwork URL validation shared by manual controls and background refreshes.
function isUsableArtworkUrl(value) {
  if (typeof value !== "string") return false;
  const url = value.trim();
  return /^https?:\/\//i.test(url) &&
    !/archive\.org\/services\/img\//i.test(url) &&
    !/(?:favicon|sprite|avatar|placeholder)(?:[./_-]|$)/i.test(url);
}

function normalizeArtworkGameUrl_(gameUrl) {
  if (typeof gameUrl !== "string") throw new Error("Invalid game URL.");
  const value = gameUrl.trim();
  // Older games use their Google Sites page URL. Games created in the admin
  // panel use this stable internal key, so both formats must be accepted by
  // every shared-artwork operation (upload, paste, switch, and search).
  const isLegacyGame = /^https:\/\/sites\.google\.com\/sd215\.net\/iliveinaboxgames\/games-a-z\//i.test(value);
  const isManualGame = /^https:\/\/inaboxgames\.local\/manual\/[a-z0-9-]+\/?$/i.test(value);
  if (!isLegacyGame && !isManualGame) throw new Error("Invalid game URL.");
  return value.replace(/\/+$/, "");
}

function findArtworkEntry_(byUrl, normalizedUrl) {
  if (byUrl[normalizedUrl]) return byUrl[normalizedUrl];
  if (byUrl[normalizedUrl + "/"]) return byUrl[normalizedUrl + "/"];
  const targetSlug = normalizedUrl.split("/").pop().toLowerCase();
  const key = Object.keys(byUrl).find(k =>
    String(k).replace(/\/+$/, "").split("/").pop().toLowerCase() === targetSlug
  );
  return key ? byUrl[key] : null;
}

// Switch Img: return only candidates already stored in the shared Drive catalog.
// It never performs a web search and never mutates the catalog.
function getSavedArtworkAlternativesForGame(gameUrl, currentImage) {
  const normalizedUrl = normalizeArtworkGameUrl_(gameUrl);
  const saved = loadSavedGamesArtwork();
  const entry = findArtworkEntry_(saved.games || {}, normalizedUrl);
  if (!entry) return { success: true, alternatives: [], message: "No saved artwork entry." };
  const candidates = [];
  (entry.imageCandidates || entry.thumbnails || []).forEach(url => {
    if (isUsableArtworkUrl(url) && !candidates.includes(url)) candidates.push(url);
  });
  [entry.preferredThumbnail, entry.thumbnail].forEach(url => {
    if (isUsableArtworkUrl(url) && !candidates.includes(url)) candidates.unshift(url);
  });
  const current = isUsableArtworkUrl(currentImage) ? currentImage : (entry.preferredThumbnail || entry.thumbnail || "");
  return { success: true, title: entry.title || "", alternatives: candidates.filter(url => url !== current) };
}

// Search for genuinely new artwork. Newly found URLs are added to the shared
// catalog, but are not made preferred until the browser confirms they load.
function findAlternateArtworkForGame(adminToken, gameUrl) {
  requireAdmin_(adminToken);
  const normalizedUrl = normalizeArtworkGameUrl_(gameUrl);
  const saved = loadSavedGamesArtwork();
  const byUrl = saved.games || {};
  const entry = findArtworkEntry_(byUrl, normalizedUrl);
  const slug = normalizedUrl.split("/").pop();
  const game = {
    title: entry && entry.title ? entry.title : slugToTitle(slug),
    url: normalizedUrl
  };
  let found = [];
  try {
    const bing = getBingGameImageSearch_([game]);
    (bing[game.title] || []).forEach(url => { if (isUsableArtworkUrl(url)) addCandidate(found, url); });
  } catch (error) {
    console.warn("Alternate Bing artwork search failed for " + game.title + ": " + error);
  }
  try {
    const extra = getAdditionalImageSearchSources_([game]);
    (extra[game.title] || []).forEach(url => { if (isUsableArtworkUrl(url)) addCandidate(found, url); });
  } catch (error) {
    console.warn("Alternate multi-source artwork search failed for " + game.title + ": " + error);
  }

  const existing = entry ? (entry.imageCandidates || entry.thumbnails || []).filter(isUsableArtworkUrl) : [];
  const current = entry ? (entry.preferredThumbnail || entry.thumbnail || existing[0] || "") : "";
  const fresh = found.filter(url => url !== current && !existing.includes(url));
  if (!fresh.length) {
    return { success: false, title: game.title, alternatives: [], message: "No genuinely new image was found; current artwork was kept." };
  }

  const updatedCandidates = existing.slice();
  fresh.forEach(url => addCandidate(updatedCandidates, url));
  const record = entry || { title: game.title, url: normalizedUrl, slug: slug };
  record.imageCandidates = updatedCandidates;
  record.thumbnails = updatedCandidates;
  record.thumbnail = current || updatedCandidates[0] || "";
  byUrl[normalizedUrl] = record;
  saveSavedGamesArtwork_(byUrl);
  console.log("New artwork candidates saved for " + game.title + ": " + fresh.length);
  return { success: true, title: game.title, alternatives: fresh };
}

// Persist the selected image as the preferred image for every visitor.
// The read/modify/write occurs under one lock to prevent concurrent saves
// from replacing one another with stale catalog copies.
function setPreferredArtworkForGame(adminToken, gameUrl, imageUrl) {
  requireAdmin_(adminToken);
  const normalizedUrl = normalizeArtworkGameUrl_(gameUrl);
  if (!isUsableArtworkUrl(imageUrl)) return { success: false, message: "Invalid image URL." };

  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    const byUrl = loadSavedGamesArtwork().games || {};
    const existingKey = Object.keys(byUrl).find(k => k.replace(/\/+$/, "") === normalizedUrl) || normalizedUrl;
    const entry = byUrl[existingKey] || {
      title: slugToTitle(normalizedUrl.split("/").pop()),
      url: normalizedUrl,
      slug: normalizedUrl.split("/").pop(),
      imageCandidates: [], thumbnails: [], thumbnail: ""
    };
    const old = (entry.imageCandidates || entry.thumbnails || []).filter(isUsableArtworkUrl);
    const next = [imageUrl].concat(old.filter(url => url !== imageUrl));
    entry.imageCandidates = next;
    entry.thumbnails = next;
    entry.thumbnail = imageUrl;
    entry.preferredThumbnail = imageUrl;
    entry.preferredThumbnailUpdatedAt = new Date().toISOString();
    byUrl[existingKey] = entry;
    writeSavedGamesArtworkUnlocked_(byUrl);
    return { success: true, thumbnail: imageUrl };
  } finally {
    lock.releaseLock();
  }
}

// Called only while the script lock is held.
function writeSavedGamesArtworkUnlocked_(gamesByUrl) {
  const payload = JSON.stringify({ version: 1, updatedAt: new Date().toISOString(), games: gamesByUrl });
  const files = DriveApp.getFilesByName(SAVED_ARTWORK_FILE);
  let found = false;
  while (files.hasNext()) {
    const file = files.next();
    if (!found) found = true;
    file.setContent(payload); // Keep duplicate-named catalogs synchronized.
  }
  if (!found) DriveApp.createFile(SAVED_ARTWORK_FILE, payload, MimeType.PLAIN_TEXT);
}
// Add this function to the bottom of your EXISTING Code.gs.
// It stores uploaded images in Google Drive, makes them viewable by anyone
// with the link, then saves the Drive image URL as the game's shared artwork.
function uploadArtworkForGame(adminToken, gameUrl, dataUrl, originalFileName) {
  requireAdmin_(adminToken);
  // Validate both legacy Google Sites games and games created in the admin
  // panel. normalizeArtworkGameUrl_ also canonicalizes trailing slashes.
  gameUrl = normalizeArtworkGameUrl_(gameUrl);
  if (typeof dataUrl !== 'string' || dataUrl.length > 8 * 1024 * 1024) {
    throw new Error('Image upload is too large. Please use an image under 5 MB.');
  }

  var match = dataUrl.match(/^data:(image\/(?:png|jpeg|jpg|gif|webp|avif));base64,([A-Za-z0-9+/=]+)$/i);
  if (!match) throw new Error('Please upload a PNG, JPG, GIF, WebP, or AVIF image.');

  var mimeType = match[1].toLowerCase();
  var bytes = Utilities.base64Decode(match[2]);
  if (bytes.length > 5 * 1024 * 1024) throw new Error('Please use an image smaller than 5 MB.');

  var safeName = String(originalFileName || 'game-artwork').replace(/[^a-z0-9._-]/gi, '_').slice(0, 90);
  var blob = Utilities.newBlob(bytes, mimeType, 'InABox_' + safeName);
  var file = DriveApp.createFile(blob);
  try {
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    var imageUrl = 'https://drive.google.com/thumbnail?id=' + file.getId() + '&sz=w1600';
    var saved = setPreferredArtworkForGame(adminToken, gameUrl, imageUrl);
    if (!saved || !saved.success) throw new Error('The image uploaded but could not be saved as the shared game artwork.');
    return { success: true, thumbnail: imageUrl, fileId: file.getId() };
  } catch (error) {
    // Keep the uploaded file if catalog saving failed so it can be recovered.
    throw error;
  }
}


// Diagnostic: inspect the saved game URLs after refreshGameCatalogFromSource_().
// Run this manually and check the execution log for direct URLs vs Google wrappers.
function diagnosePlayableUrls() {
  const games = loadGameCatalog_();
  const total = games.length;
  const withUrl = games.filter(game => game.playUrl);
  const missing = games.filter(game => !game.playUrl);
  const wrappers = withUrl.filter(game =>
    /gstatic\.com\/atari\/embeds\/.*intermediate-frame|googleusercontent\.com\/embeds\/.*(?:inner|intermediate)-frame/i.test(game.playUrl)
  );

  console.log("===== PLAYABLE URL DIAGNOSTIC =====");
  console.log("Total games: " + total);
  console.log("Games with a URL: " + withUrl.length);
  console.log("Games with no URL: " + missing.length);
  console.log("Google intermediary URLs: " + wrappers.length);
  console.log("\nFIRST 50 FOUND URLS (review whether these are actual game hosts):");
  withUrl.slice(0, 50).forEach(game => {
    console.log(game.title + " | " + game.playUrl);
  });
  console.log("\nGAMES WITH NO URL:");
  missing.forEach(game => console.log(game.title + " | " + game.url));
  return { total: total, withUrl: withUrl.length, missing: missing.length, googleWrappers: wrappers.length };
}

// Diagnostic for games whose playable URL was not found by the catalog importer.
// Run inspectMissingGameMarkup() from the Apps Script function dropdown.
// This only reads the 0v0 page and writes useful embed markup to the execution log;
// it does not change the saved game catalog.
function inspectMissingGameMarkup() {
  const gameUrl = SITE_PREFIX + "0v0";
  console.log("===== MISSING GAME PAGE INSPECTION =====");
  console.log("Game: 0v0");
  console.log("Page: " + gameUrl);

  const response = UrlFetchApp.fetch(gameUrl, {
    followRedirects: true,
    muteHttpExceptions: true,
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml"
    }
  });

  console.log("HTTP status: " + response.getResponseCode());
  if (response.getResponseCode() !== 200) {
    console.warn("Could not inspect 0v0 page. HTTP " + response.getResponseCode());
    return { success: false, status: response.getResponseCode() };
  }

  const html = response.getContentText();
  console.log("HTML length: " + html.length);

  const patterns = [
    { name: "IFRAME TAGS", regex: /<iframe\b[^>]*>/gi },
    { name: "EMBED TAGS", regex: /<embed\b[^>]*>/gi },
    { name: "OBJECT TAGS", regex: /<object\b[^>]*>/gi },
    { name: "DATA URL / SOURCE ATTRIBUTES", regex: /\b(?:data-url|data-src|data-href|src|href)\s*=\s*["'][^"']+["']/gi }
  ];

  patterns.forEach(item => {
    const matches = html.match(item.regex) || [];
    console.log("\n--- " + item.name + " (" + matches.length + ") ---");
    matches.slice(0, 35).forEach(value => console.log(value.slice(0, 1200)));
  });

  // Show context around likely Google Sites embed containers and game hosts.
  const contextPatterns = [
    /data-url\s*=/gi,
    /<iframe\b/gi,
    /<embed\b/gi,
    /<object\b/gi,
    /gstatic\.com\/atari/gi,
    /googleusercontent\.com/gi
  ];
  const ranges = [];
  contextPatterns.forEach(regex => {
    let match;
    while ((match = regex.exec(html)) !== null && ranges.length < 80) {
      const start = Math.max(0, match.index - 700);
      const end = Math.min(html.length, match.index + 1800);
      if (!ranges.some(range => start < range.end && end > range.start)) {
        ranges.push({ start: start, end: end });
      }
    }
  });

  console.log("\n--- EMBED CONTEXT (up to 20 sections) ---");
  ranges.slice(0, 20).forEach((range, index) => {
    console.log("\n[SECTION " + (index + 1) + "]\n" + html.slice(range.start, range.end));
  });

  const extracted = extractPlayableSource_(html);
  console.log("\nCurrent extractor result: " + (extracted.playUrl || "NO URL FOUND"));
  console.log("===== END 0v0 INSPECTION =====");

  return {
    success: true,
    status: response.getResponseCode(),
    htmlLength: html.length,
    iframeCount: (html.match(/<iframe\b/gi) || []).length,
    dataUrlCount: (html.match(/\bdata-url\s*=/gi) || []).length,
    extractedUrl: extracted.playUrl || ""
  };
}


// Deeper read-only diagnostic for Google Sites custom embeds that do not expose
// their game URL in a normal iframe src or data-url attribute.
// Run inspectGoogleSitesEmbedConfig() and inspect the execution log.
function inspectGoogleSitesEmbedConfig() {
  const gameUrl = SITE_PREFIX + "0v0";
  const response = UrlFetchApp.fetch(gameUrl, {
    followRedirects: true,
    muteHttpExceptions: true,
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml"
    }
  });
  const html = response.getContentText();
  console.log("===== GOOGLE SITES EMBED CONFIG DIAGNOSTIC =====");
  console.log("HTTP: " + response.getResponseCode() + "; HTML chars: " + html.length);

  const iframeMatch = html.match(/<iframe\b[^>]*\bid=["']([^"']+)["'][^>]*>/i);
  const iframeId = iframeMatch ? iframeMatch[1] : "";
  console.log("Iframe tag: " + (iframeMatch ? iframeMatch[0] : "NOT FOUND"));
  if (iframeId) {
    const idPos = html.indexOf(iframeId);
    console.log("\n--- HTML AROUND IFRAME ID ---\n" + html.slice(Math.max(0, idPos - 2500), Math.min(html.length, idPos + 5000)));
  }

  // Script sources help identify which Google Sites runtime supplies the embed.
  const scriptTags = html.match(/<script\b[^>]*>/gi) || [];
  console.log("\n--- SCRIPT TAGS (first 80) count=" + scriptTags.length + " ---");
  scriptTags.slice(0, 80).forEach(tag => console.log(tag.slice(0, 1000)));

  // Search inline script/config text for the iframe ID and likely embed metadata.
  const scriptRegex = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  let scriptMatch, scriptIndex = 0, logged = 0;
  while ((scriptMatch = scriptRegex.exec(html)) !== null) {
    scriptIndex++;
    const attrs = scriptMatch[1] || "";
    const body = scriptMatch[2] || "";
    const lower = body.toLowerCase();
    const hits = [];
    if (iframeId && body.indexOf(iframeId) >= 0) hits.push("IFRAME_ID");
    ["custom embed", "customembed", "0v0", "embed", "contenturl", "iframe", "atari"].forEach(term => {
      if (lower.indexOf(term) >= 0 && hits.indexOf(term) < 0) hits.push(term);
    });
    if (hits.length && logged < 25) {
      logged++;
      console.log("\n--- SCRIPT " + scriptIndex + " attrs=" + attrs.slice(0, 300) + " hits=" + hits.join(",") + " chars=" + body.length + " ---");
      let pos = iframeId ? body.indexOf(iframeId) : -1;
      if (pos < 0) {
        const candidates = ["custom embed", "customembed", "contenturl", "0v0", "iframe", "atari"];
        for (let i = 0; i < candidates.length && pos < 0; i++) pos = lower.indexOf(candidates[i]);
      }
      if (pos >= 0) console.log(body.slice(Math.max(0, pos - 1800), Math.min(body.length, pos + 4200)));
      else console.log(body.slice(0, 2500));
    }
  }
  console.log("\nInline scripts scanned: " + scriptIndex + "; matching scripts logged: " + logged);

  // Look for JSON-like bootstrap/config keys that may hold an embedded URL.
  const keyRegex = /(?:"|')?(?:url|src|contentUrl|embedUrl|iframeUrl|resourceUrl|dataUrl)(?:"|')?\s*[:=]\s*(?:"|')([^"']{5,500})(?:"|')/gi;
  let keyMatch, keyCount = 0;
  console.log("\n--- URL-LIKE CONFIG VALUES (first 100) ---");
  while ((keyMatch = keyRegex.exec(html)) !== null && keyCount < 100) {
    const value = keyMatch[1];
    if (/https?:|\/\//i.test(value) && !/googleapis|gstatic|google\.com\/sitesv-images|fonts\./i.test(value)) {
      keyCount++;
      console.log(value.slice(0, 500));
    }
  }
  console.log("URL-like config values logged: " + keyCount);
  console.log("===== END GOOGLE SITES EMBED CONFIG DIAGNOSTIC =====");
  return { success: response.getResponseCode() === 200, status: response.getResponseCode(), htmlLength: html.length, iframeId: iframeId, scriptCount: scriptTags.length, inlineScriptCount: scriptIndex, matchingScripts: logged };
}


// Read-only batch diagnostic for the games still missing playable URLs.
// Run inspectRemainingGameMarkup() and review the execution log. It does not
// modify the saved catalog. It fetches only games whose playUrl is currently blank.
function inspectRemainingGameMarkupDeep() {
  const games = loadGameCatalog_();
  const missing = games.filter(game => !game.playUrl);
  console.log("===== DEEP REMAINING GAME MARKUP DIAGNOSTIC =====");
  console.log("Missing URLs: " + missing.length);
  if (!missing.length) return { success: true, inspected: 0 };

  const headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml"
  };
  const results = [];

  for (let offset = 0; offset < missing.length; offset += 8) {
    const batch = missing.slice(offset, offset + 8);
    const responses = UrlFetchApp.fetchAll(batch.map(game => ({
      url: game.url, method: "get", followRedirects: true,
      muteHttpExceptions: true, headers: headers
    })));

    responses.forEach((response, index) => {
      const game = batch[index];
      const html = response.getContentText() || "";
      const snippets = [];
      const seen = {};
      const patterns = [
        { name: "openLink", re: /openLink/ig },
        { name: "EJS_gameUrl", re: /EJS_gameUrl/ig },
        { name: "gameUrl", re: /gameUrl/ig },
        { name: "iframe\.src", re: /iframe\s*\.\s*src/ig },
        { name: "window\.open", re: /window\s*\.\s*open/ig },
        { name: "location\.href", re: /location\s*\.\s*href/ig },
        { name: "data-url-with-http", re: /data-url\s*=\s*[\"'][^\"']*https?:/ig },
        { name: "zip-rom-game-path", re: /(?:\.zip|\.wasm|\.html|\/game\/|\/play\/)/ig }
      ];
      patterns.forEach(pattern => {
        let m, count = 0;
        while ((m = pattern.re.exec(html)) !== null && count < 5) {
          const start = Math.max(0, m.index - 500);
          const end = Math.min(html.length, m.index + 1100);
          const key = pattern.name + "@" + m.index;
          if (!seen[key]) {
            seen[key] = true;
            snippets.push({ term: pattern.name, at: m.index, text: html.slice(start, end).replace(/\s+/g, " ") });
          }
          count++;
        }
      });

      // Decode entity-escaped HTML once, then look again for game launch settings.
      const decoded = html
        .replace(/&quot;|&#34;/gi, '"')
        .replace(/&#39;|&apos;/gi, "'")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&amp;/gi, "&")
        .replace(/\\u003d/gi, "=")
        .replace(/\\u0026/gi, "&")
        .replace(/\\\//g, "/");
      [
        { name: "DECODED openLink", re: /openLink/ig },
        { name: "DECODED EJS_gameUrl", re: /EJS_gameUrl/ig },
        { name: "DECODED gameUrl", re: /gameUrl/ig }
      ].forEach(pattern => {
        let m, count = 0;
        while ((m = pattern.re.exec(decoded)) !== null && count < 5) {
          const start = Math.max(0, m.index - 600);
          const end = Math.min(decoded.length, m.index + 1300);
          const key = pattern.name + "@" + m.index;
          if (!seen[key]) {
            seen[key] = true;
            snippets.push({ term: pattern.name, at: m.index, text: decoded.slice(start, end).replace(/\s+/g, " ") });
          }
          count++;
        }
      });

      // Capture data-url attribute values near the end of the page too; the first
      // hundreds of attributes are Google infrastructure and are not useful.
      const dataUrls = [];
      const du = /\bdata-url\s*=\s*[\"']([^\"']{1,1200})[\"']/ig;
      let dm;
      while ((dm = du.exec(html)) !== null) {
        const value = dm[1].replace(/&amp;/gi, "&");
        if (/https?:/i.test(value) && !/googleapis|gstatic|sites\\.google\\.com/i.test(value)) {
          dataUrls.push({ at: dm.index, value: value.slice(0, 900) });
          if (dataUrls.length >= 12) break;
        }
      }

      console.log("\n### " + game.title + " | HTTP " + response.getResponseCode() + " | chars " + html.length);
      console.log("DATA-URL VALUES: " + JSON.stringify(dataUrls));
      snippets.slice(0, 14).forEach(item => console.log("[" + item.term + " @" + item.at + "] " + item.text));
      results.push({ title: game.title, status: response.getResponseCode(), snippetCount: snippets.length, dataUrlCount: dataUrls.length });
    });
  }
  console.log("===== END DEEP DIAGNOSTIC =====");
  return { success: true, inspected: results.length, results: results };
}


function inspectRemainingGameMarkup() {
  const games = loadGameCatalog_();
  const missing = games.filter(game => !game.playUrl);
  console.log("===== REMAINING GAME MARKUP DIAGNOSTIC =====");
  console.log("Catalog games: " + games.length + "; missing URLs to inspect: " + missing.length);
  if (!missing.length) {
    console.log("No missing game URLs.");
    return { success: true, total: games.length, inspected: 0, missing: 0 };
  }

  const headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml"
  };
  const results = [];

  // Keep batches modest to avoid stressing Google Sites or Apps Script quotas.
  for (let offset = 0; offset < missing.length; offset += 10) {
    const batch = missing.slice(offset, offset + 10);
    let responses;
    try {
      responses = UrlFetchApp.fetchAll(batch.map(game => ({
        url: game.url,
        method: "get",
        followRedirects: true,
        muteHttpExceptions: true,
        headers: headers
      })));
    } catch (error) {
      console.warn("Batch fetch failed at offset " + offset + ": " + error);
      batch.forEach(game => results.push({ title: game.title, page: game.url, status: "FETCH_ERROR", extracted: "" }));
      continue;
    }

    responses.forEach((response, index) => {
      const game = batch[index];
      const status = response.getResponseCode();
      const html = response.getContentText() || "";
      const extracted = status === 200 ? extractPlayableSource_(html) : { playUrl: "" };
      const urls = [];
      const urlRegex = /https?:\/\/[^\s"'<>\\]{8,500}/gi;
      let match;
      while ((match = urlRegex.exec(html)) !== null && urls.length < 18) {
        let value = match[0]
          .replace(/&amp;/gi, "&")
          .replace(/\\u003d/gi, "=")
          .replace(/\\u0026/gi, "&")
          .replace(/\\\//g, "/")
          .replace(/[),;]+$/g, "");
        if (!/^https?:\/\//i.test(value)) continue;
        if (/googleapis\.com|gstatic\.com|google\.com\/sitesv-images|fonts\.googleapis|googleusercontent\.com\/embeds/i.test(value)) continue;
        if (!urls.includes(value)) urls.push(value);
      }

      const dataUrlCount = (html.match(/\bdata-url\s*=/gi) || []).length;
      const dataHtmlCount = (html.match(/\bdata-html\s*=/gi) || []).length;
      const iframeTags = (html.match(/<iframe\b[^>]*>/gi) || []).slice(0, 3);
      const scriptHints = [];
      ["openLink", "iframe.src", "window.location", "location.href", "gameUrl", "embedUrl", "data-html"].forEach(term => {
        const pos = html.toLowerCase().indexOf(term.toLowerCase());
        if (pos >= 0) {
          scriptHints.push(term + " @" + pos + ": " + html.slice(Math.max(0, pos - 120), Math.min(html.length, pos + 420)).replace(/\s+/g, " "));
        }
      });

      const item = {
        title: game.title,
        page: game.url,
        status: status,
        htmlLength: html.length,
        extracted: extracted.playUrl || "",
        dataUrlCount: dataUrlCount,
        dataHtmlCount: dataHtmlCount,
        iframeTags: iframeTags,
        urls: urls,
        scriptHints: scriptHints
      };
      results.push(item);

      console.log("\n### " + game.title + " | HTTP " + status + " | chars " + html.length);
      console.log("EXTRACTOR: " + (item.extracted || "NO URL"));
      console.log("data-url=" + dataUrlCount + "; data-html=" + dataHtmlCount);
      if (iframeTags.length) console.log("IFRAMES: " + JSON.stringify(iframeTags));
      if (urls.length) console.log("EXTERNAL URL CANDIDATES: " + JSON.stringify(urls));
      if (scriptHints.length) console.log("EMBED/SCRIPT HINTS: " + JSON.stringify(scriptHints));
      if (!html.length) console.log("EMPTY RESPONSE BODY");
    });
  }

  const found = results.filter(item => item.extracted).length;
  console.log("\n===== END REMAINING GAME MARKUP DIAGNOSTIC =====");
  console.log("Inspected: " + results.length + "; extractor now recognizes: " + found + "; still unresolved: " + (results.length - found));
  return {
    success: true,
    total: games.length,
    inspected: results.length,
    recognizedByCurrentExtractor: found,
    unresolved: results.length - found,
    results: results
  };
}


// Shared, site-wide animated backgrounds. Uploads require an authorized admin device.
const SHARED_BACKGROUNDS_PROPERTY = "INABOX_SHARED_BACKGROUNDS_V1";
function getSharedBackgrounds() {
  const props = PropertiesService.getScriptProperties();
  let items = []; try { items = JSON.parse(props.getProperty(SHARED_BACKGROUNDS_PROPERTY) || "[]"); } catch (_) {}
  return items.filter(x => x && x.id && x.name).map(x => ({ id:String(x.id), name:String(x.name), url:"https://drive.usercontent.google.com/download?id=" + encodeURIComponent(String(x.id)) + "&export=download&authuser=0&confirm=t", type:String(x.type || "") }));
}
function getSharedBackgroundInfo(fileId) {
  fileId = String(fileId || "");
  var items = [];
  try { items = JSON.parse(PropertiesService.getScriptProperties().getProperty(SHARED_BACKGROUNDS_PROPERTY) || "[]"); } catch (_) {}
  if (!items.some(function(item){ return item && String(item.id) === fileId; })) throw new Error("That background is not in the shared background list.");
  var blob = DriveApp.getFileById(fileId).getBlob();
  return { size: blob.getBytes().length, type: blob.getContentType() || "video/mp4" };
}
function getSharedBackgroundChunk(fileId, offset, chunkSize) {
  fileId = String(fileId || ""); offset = Math.max(0, Number(offset) || 0); chunkSize = Math.min(1000000, Math.max(1, Number(chunkSize) || 1000000));
  var items = [];
  try { items = JSON.parse(PropertiesService.getScriptProperties().getProperty(SHARED_BACKGROUNDS_PROPERTY) || "[]"); } catch (_) {}
  if (!items.some(function(item){ return item && String(item.id) === fileId; })) throw new Error("That background is not in the shared background list.");
  var bytes = DriveApp.getFileById(fileId).getBlob().getBytes();
  if (bytes.length > 25 * 1024 * 1024) throw new Error("The shared background exceeds the 25 MB limit.");
  var end = Math.min(bytes.length, offset + chunkSize);
  if (offset >= bytes.length) throw new Error("Requested background chunk is outside the file.");
  return { base64: Utilities.base64Encode(bytes.slice(offset, end)), offset:offset, total:bytes.length };
}

function getSharedBackgroundData(fileId) {
  fileId = String(fileId || "");
  let items = [];
  try { items = JSON.parse(PropertiesService.getScriptProperties().getProperty(SHARED_BACKGROUNDS_PROPERTY) || "[]"); } catch (_) {}
  if (!items.some(item => item && String(item.id) === fileId)) throw new Error("That shared background is not in the approved background list.");
  const file = DriveApp.getFileById(fileId);
  const blob = file.getBlob();
  const bytes = blob.getBytes();
  if (bytes.length > 25 * 1024 * 1024) throw new Error("This shared background exceeds the 25 MB limit.");
  return { type: blob.getContentType() || "application/octet-stream", base64: Utilities.base64Encode(bytes) };
}

function uploadSharedBackground(adminToken, name, dataUrl, originalFileName) {
  requireAdmin_(adminToken);
  name = String(name || "").trim().slice(0,40);
  if (!name) throw new Error("Enter a background name.");
  if (typeof dataUrl !== "string" || dataUrl.length > 35 * 1024 * 1024) throw new Error("Upload too large. Maximum file size is 25 MB.");
  const match = dataUrl.match(/^data:(video\/(?:webm|mp4)|image\/(?:gif|webp));base64,([A-Za-z0-9+/=]+)$/i);
  if (!match) throw new Error("Use WebM, MP4, GIF, or WebP.");
  const bytes = Utilities.base64Decode(match[2]);
  if (bytes.length > 25 * 1024 * 1024) throw new Error("Maximum file size is 25 MB.");
  const ext = String(originalFileName || "background").match(/\.(webm|mp4|gif|webp)$/i);
  if (!ext) throw new Error("Unsupported file extension.");
  const safeName = name.replace(/[^a-z0-9 _-]/gi, "").slice(0,40) || "Custom Background";
  const blob = Utilities.newBlob(bytes, match[1].toLowerCase(), "InABox_Background_" + safeName.replace(/\s+/g,"_") + ext[0].toLowerCase());
  const file = DriveApp.createFile(blob);
  file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
  const item = { id:file.getId(), name:safeName, type:match[1].toLowerCase(), url:"https://drive.usercontent.google.com/download?id=" + file.getId() + "&export=download&authuser=0&confirm=t", createdAt:new Date().toISOString() };
  const lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    const props = PropertiesService.getScriptProperties(); let items = [];
    try { items = JSON.parse(props.getProperty(SHARED_BACKGROUNDS_PROPERTY) || "[]"); } catch (_) {}
    items = items.filter(x => x && x.id !== item.id); items.push(item);
    if (items.length > 20) throw new Error("The shared background list is full (20 maximum). Remove an old background first.");
    props.setProperty(SHARED_BACKGROUNDS_PROPERTY, JSON.stringify(items));
  } finally { lock.releaseLock(); }
  return { success:true, id:item.id, name:item.name };
}