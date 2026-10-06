import {
  app,
  BrowserWindow,
  dialog,
  type IpcMainInvokeEvent,
  ipcMain,
  Menu,
  net,
  powerMonitor,
  protocol,
  safeStorage,
  session,
  shell,
  type Session,
} from 'electron';
import { stat, readFile } from 'node:fs/promises';
import { parseTransportPins, matchesTransportPin, type TransportPins } from './transport-pins.js';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  APP_HOST,
  APP_SCHEME,
  APP_URL,
  deploymentNamespace,
  isAllowedBackendRequestDestination,
  isAllowedExternalUrl,
  isAllowedMediaPermission,
  isBackendPath,
  isTrustedRendererUrl,
  normalizeIdleLockMinutes,
  normalizeServerUrl,
  resolveBundledPath,
  withBackendRequestOrigin,
} from './security-policy.js';
import { SettingsStore, type DesktopSettings } from './settings.js';
import { SecretVault, type VaultCrypto } from './vault.js';
import { NativeFileSaveManager } from './file-save.js';
import { desktopLocale, desktopStrings, normalizeDesktopLocale, type DesktopLocale } from './strings.js';

const PARTITION = 'persist:alparts';
const MAX_WINDOW_DIMENSION = 16_384;
const PRELOAD_PATH = fileURLToPath(new URL('./preload.cjs', import.meta.url));
const DEVELOPMENT_ICON_PATH = fileURLToPath(new URL('../build/icon.png', import.meta.url));
let DEVELOPMENT_URL: string | null = null;
let MANAGED_SERVER_URL: string | null = null;

protocol.registerSchemesAsPrivileged([{
  scheme: APP_SCHEME,
  privileges: {
    standard: true,
    secure: true,
    supportFetchAPI: true,
    stream: true,
    codeCache: true,
  },
}]);
app.enableSandbox();
app.setName('alparts');

let mainWindow: BrowserWindow | null = null;
let desktopSession: Session;
let settingsStore: SettingsStore;
let vault: SecretVault;
let fileSaves: NativeFileSaveManager;
let settings: DesktopSettings;
let lockTriggered = false;
let idleTimer: NodeJS.Timeout | null = null;
let quitAfterCleanup = false;
let runtimeReady = false;
let transportPins: TransportPins = {};
// The system language until the app reports the language the user chose.
let locale: DesktopLocale = 'en';

const singleInstance = app.requestSingleInstanceLock();
if (!singleInstance) app.quit();

app.on('second-instance', () => {
  if (!mainWindow) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', (event) => {
  if (!fileSaves || quitAfterCleanup) return;
  event.preventDefault();
  void fileSaves.abortAll().finally(() => {
    quitAfterCleanup = true;
    app.quit();
  });
});

app.on('activate', () => {
  if (!runtimeReady) return;
  if (BrowserWindow.getAllWindows().length === 0) void createWindow();
  else mainWindow?.show();
});

if (singleInstance) {
  void app.whenReady().then(async () => {
    locale = desktopLocale(app.getPreferredSystemLanguages());
    DEVELOPMENT_URL = readDevelopmentUrl();
    transportPins = parseTransportPins(JSON.parse(await readFile(new URL('./transport-pins.json', import.meta.url), 'utf8')), app.isPackaged);
    MANAGED_SERVER_URL = readManagedServerUrl();
    app.setAppUserModelId('org.alparts.desktop');
    if (process.platform === 'darwin') app.dock?.setIcon(applicationIconPath());
    settingsStore = new SettingsStore(app.getPath('userData'));
    const persistedSettings = await settingsStore.load();
    settings = MANAGED_SERVER_URL
      ? { ...persistedSettings, serverUrl: MANAGED_SERVER_URL }
      : persistedSettings;
    desktopSession = session.fromPartition(PARTITION);
    vault = new SecretVault(app.getPath('userData'), electronVaultCrypto());
    if (
      MANAGED_SERVER_URL
      && persistedSettings.serverUrl
      && persistedSettings.serverUrl !== MANAGED_SERVER_URL
    ) {
      await desktopSession.clearStorageData({ origin: persistedSettings.serverUrl });
      await vault.deleteNamespace(deploymentNamespace(persistedSettings.serverUrl));
    }
    fileSaves = new NativeFileSaveManager(async (suggestedName) => {
      if (!mainWindow || mainWindow.isDestroyed()) return null;
      const result = await dialog.showSaveDialog(mainWindow, {
        title: desktopStrings(locale).saveAttachmentTitle,
        defaultPath: suggestedName,
        buttonLabel: desktopStrings(locale).saveButton,
        properties: ['showOverwriteConfirmation', 'createDirectory'],
      });
      return result.canceled || !result.filePath ? null : result.filePath;
    });

    registerProtocolHandlers(desktopSession);
    configureSession(desktopSession);
    registerIpcHandlers();
    installApplicationMenu();
    installLockMonitoring();
    runtimeReady = true;
    await createWindow();
  }).catch((error: unknown) => {
    if (!app.isPackaged) console.error(error);
    const text = desktopStrings(locale);
    dialog.showErrorBox(text.startFailedTitle, text.startFailedMessage);
    app.exit(1);
  });
}

async function createWindow(): Promise<void> {
  if (mainWindow && !mainWindow.isDestroyed()) return;
  const window = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 960,
    minHeight: 640,
    maxWidth: MAX_WINDOW_DIMENSION,
    maxHeight: MAX_WINDOW_DIMENSION,
    show: false,
    backgroundColor: '#313338',
    title: 'alparts',
    icon: applicationIconPath(),
    autoHideMenuBar: process.platform !== 'darwin',
    webPreferences: {
      preload: PRELOAD_PATH,
      partition: PARTITION,
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      devTools: !app.isPackaged,
      spellcheck: true,
      navigateOnDragDrop: false,
    },
  });
  mainWindow = window;
  window.setContentProtection(true);
  secureWebContents(window);
  window.once('ready-to-show', () => window.show());
  window.on('closed', () => {
    if (mainWindow === window) mainWindow = null;
  });
  await loadApplication(window);
}

async function loadApplication(window: BrowserWindow): Promise<void> {
  if (DEVELOPMENT_URL) {
    await window.loadURL(DEVELOPMENT_URL);
    return;
  }
  await window.loadURL(settings.serverUrl ? `${settings.serverUrl}/` : APP_URL);
}

function secureWebContents(window: BrowserWindow): void {
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (isAllowedExternalUrl(url)) void shell.openExternal(url, { activate: true }).catch(() => undefined);
    return { action: 'deny' };
  });
  const guardNavigation = (event: Electron.Event, url: string) => {
    if (isTrustedRendererUrl(url, settings.serverUrl, DEVELOPMENT_URL || undefined)) return;
    event.preventDefault();
    if (isAllowedExternalUrl(url)) void shell.openExternal(url, { activate: true }).catch(() => undefined);
  };
  window.webContents.on('will-navigate', guardNavigation);
  window.webContents.on('will-redirect', guardNavigation);
  window.webContents.on('will-attach-webview', (event) => event.preventDefault());
  window.webContents.on('before-input-event', (event, input) => {
    if (app.isPackaged && (input.key === 'F12' || (input.control && input.shift && input.key.toLowerCase() === 'i'))) {
      event.preventDefault();
    }
  });
}

function configureSession(target: Session): void {
  target.setCertificateVerifyProc((request, callback) => {
    // -3 preserves Chromium's normal CA/hostname/expiry checks. Never return 0,
    // which would override a certificate error. Packaged clients require pins.
    const required = app.isPackaged || Object.hasOwn(transportPins, request.hostname);
    callback(!required || matchesTransportPin(request.hostname, request.certificate.data, transportPins) ? -3 : -2);
  });
  target.setPermissionRequestHandler((webContents, permission, callback, details) => {
    if (!webContents || webContents.id !== mainWindow?.webContents.id || !trustedFrame(details.requestingUrl)) {
      callback(false);
      return;
    }
    callback(isAllowedMediaPermission(permission, (details as { mediaTypes?: string[] }).mediaTypes));
  });
  target.setPermissionCheckHandler((webContents, permission, requestingOrigin, details) => {
    if (!webContents || webContents.id !== mainWindow?.webContents.id || !trustedFrame(requestingOrigin)) return false;
    return isAllowedMediaPermission(permission, details.mediaType ? [details.mediaType] : undefined);
  });
  target.setDevicePermissionHandler(() => false);
  target.setDisplayMediaRequestHandler((_request, callback) => callback({}));
  // All saves use the bounded native stream exposed by the preload. Chromium
  // downloads would bypass cancellation cleanup and quarantine handling.
  target.on('will-download', (event) => event.preventDefault());
}

function trustedFrame(url: string): boolean {
  return isTrustedRendererUrl(url, settings.serverUrl, DEVELOPMENT_URL || undefined);
}

function registerProtocolHandlers(target: Session): void {
  target.protocol.handle(APP_SCHEME, (request) => serveAppRequest(request));
  for (const scheme of ['http', 'https']) {
    target.protocol.handle(scheme, (request) => handleWebRequest(target, request));
  }
}

async function handleWebRequest(target: Session, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const configuredOrigin = settings.serverUrl ? new URL(settings.serverUrl).origin : null;
  const isServerRequest = configuredOrigin !== null && url.origin === configuredOrigin;
  const developmentOrigin = DEVELOPMENT_URL ? new URL(DEVELOPMENT_URL).origin : null;
  if (developmentOrigin && url.origin === developmentOrigin) {
    return target.fetch(request, { bypassCustomProtocolHandlers: true });
  }
  if (!isServerRequest) return response(403, 'Forbidden');
  const backendPath = isBackendPath(url.pathname);
  if (!backendPath && ['GET', 'HEAD'].includes(request.method)) {
    return serveBundledUi(request);
  }
  if (!backendPath) return response(405, 'Method not allowed');
  if (!isAllowedBackendRequestDestination(request.destination, request.headers.get('sec-fetch-dest'))) {
    return response(403, 'Forbidden');
  }
  return target.fetch(withBackendRequestOrigin(request, configuredOrigin), {
    bypassCustomProtocolHandlers: true,
    redirect: 'manual',
  });
}

async function serveAppRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.hostname !== APP_HOST || !['GET', 'HEAD'].includes(request.method)) return response(404, 'Not found');
  return serveBundledUi(request);
}

async function serveBundledUi(request: Request): Promise<Response> {
  const root = rendererRoot();
  const url = new URL(request.url);
  let filename = url.pathname === '/' ? path.join(root, 'index.html') : resolveBundledPath(root, url.pathname);
  if (!filename) return response(400, 'Bad request');

  try {
    const info = await stat(filename);
    if (!info.isFile()) throw new Error('not-file');
  } catch {
    if (path.posix.extname(url.pathname)) return response(404, 'Not found');
    filename = path.join(root, 'index.html');
  }

  const source = await net.fetch(pathToFileURL(filename).toString());
  if (!source.ok) return response(404, 'Not found');
  const headers = new Headers(source.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Permissions-Policy', 'camera=(), display-capture=(), geolocation=(), microphone=(self)');
  if (filename.endsWith('index.html')) {
    headers.set('Cache-Control', 'no-store');
    headers.set('Content-Security-Policy', [
      "default-src 'self'",
      "base-uri 'none'",
      "object-src 'none'",
      "frame-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "media-src 'self' blob:",
      "connect-src 'self'",
      // The login work proof runs in a same-origin worker from the bundle.
      "worker-src 'self'",
    ].join('; '));
  } else {
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  }
  return new Response(request.method === 'HEAD' ? null : source.body, {
    status: source.status,
    headers,
  });
}

function response(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

function rendererRoot(): string {
  return app.isPackaged
    ? path.join(process.resourcesPath, 'renderer')
    : fileURLToPath(new URL('../../client/dist/', import.meta.url));
}

function applicationIconPath(): string {
  return app.isPackaged
    ? path.join(process.resourcesPath, 'desktop-icon.png')
    : DEVELOPMENT_ICON_PATH;
}

function registerIpcHandlers(): void {
  ipcMain.handle('desktop:get-info', checked(async () => desktopInfo()));
  ipcMain.handle('desktop:configure-server', checked(async (_event, value: unknown) => {
    if (MANAGED_SERVER_URL) throw new Error('SERVER_MANAGED');
    const serverUrl = normalizeServerUrl(value);
    const previous = settings.serverUrl;
    if (previous !== serverUrl && previous) {
      await desktopSession.clearStorageData({ origin: previous });
      await vault.deleteNamespace(deploymentNamespace(previous));
    }
    settings = { ...settings, serverUrl };
    await settingsStore.save(settings);
    setTimeout(() => {
      if (mainWindow && !mainWindow.isDestroyed()) void loadApplication(mainWindow).catch(() => undefined);
    }, 50);
    return desktopInfo();
  }));
  ipcMain.handle('desktop:set-idle-lock', checked(async (_event, value: unknown) => {
    settings = { ...settings, idleLockMinutes: normalizeIdleLockMinutes(value) };
    await settingsStore.save(settings);
    return settings.idleLockMinutes;
  }));
  ipcMain.handle('desktop:lock-now', checked(async () => {
    setImmediate(triggerLock);
    return true;
  }));
  ipcMain.handle('desktop:clear-http-cache', checked(async () => {
    // Device keys live in IndexedDB and must survive a sign-out; only the
    // HTTP-level caches are dropped here.
    await desktopSession.clearCache();
    await desktopSession.clearStorageData({ storages: ['cachestorage', 'serviceworkers', 'shadercache'] });
    return true;
  }));
  ipcMain.handle('desktop:unlock-complete', checked(async () => {
    lockTriggered = false;
    return true;
  }));
  ipcMain.handle('desktop:set-language', checked(async (_event, value: unknown) => {
    const next = normalizeDesktopLocale(value);
    if (next !== locale) {
      locale = next;
      installApplicationMenu();
    }
    return true;
  }));
  ipcMain.handle('desktop:show-connection-settings', checked(async () => {
    mainWindow?.webContents.send('desktop:show-connection-settings');
    return true;
  }));
  ipcMain.handle('desktop:secret-get', checked(async (_event, name: unknown) => {
    return vault.get(requiredNamespace(), name);
  }));
  ipcMain.handle('desktop:secret-set', checked(async (_event, name: unknown, value: unknown) => {
    await vault.set(requiredNamespace(), name, value);
    return true;
  }));
  ipcMain.handle('desktop:secret-delete', checked(async (_event, name: unknown) => {
    await vault.delete(requiredNamespace(), name);
    return true;
  }));
  ipcMain.handle('desktop:file-save-begin', checked(async (
    _event,
    suggestedName: unknown,
    expectedBytes: unknown,
    dangerous: unknown,
  ) => fileSaves.begin(suggestedName, expectedBytes, dangerous)));
  ipcMain.handle('desktop:file-save-write', checked(async (_event, token: unknown, chunk: unknown) => {
    return fileSaves.write(token, chunk);
  }));
  ipcMain.handle('desktop:file-save-finish', checked(async (_event, token: unknown) => {
    return fileSaves.finish(token);
  }));
  ipcMain.handle('desktop:file-save-cancel', checked(async (_event, token: unknown) => {
    return fileSaves.cancel(token);
  }));
}

function checked<T extends unknown[], R>(
  handler: (event: IpcMainInvokeEvent, ...args: T) => Promise<R>,
): (event: IpcMainInvokeEvent, ...args: T) => Promise<R> {
  return async (event, ...args) => {
    const frame = event.senderFrame;
    if (
      !mainWindow
      || !frame
      || event.sender.id !== mainWindow.webContents.id
      || frame !== frame.top
      || !trustedFrame(frame.url)
    ) throw new Error('IPC_FORBIDDEN');
    return handler(event, ...args);
  };
}

function requiredNamespace(): string {
  if (!settings.serverUrl) throw new Error('SERVER_NOT_CONFIGURED');
  return deploymentNamespace(settings.serverUrl);
}

async function desktopInfo() {
  return {
    platform: process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux',
    version: app.getVersion(),
    serverUrl: settings.serverUrl,
    idleLockMinutes: settings.idleLockMinutes,
    locked: lockTriggered,
    secureStorageReady: await vault.available(),
    serverManaged: Boolean(MANAGED_SERVER_URL),
  } as const;
}

function electronVaultCrypto(): VaultCrypto {
  return {
    async available() {
      if (!await safeStorage.isAsyncEncryptionAvailable()) return false;
      return process.platform !== 'linux' || safeStorage.getSelectedStorageBackend() !== 'basic_text';
    },
    async encrypt(value) {
      if (!await this.available()) throw new Error('SECURE_STORAGE_UNAVAILABLE');
      return safeStorage.encryptStringAsync(value);
    },
    async decrypt(value) {
      if (!await this.available()) throw new Error('SECURE_STORAGE_UNAVAILABLE');
      return safeStorage.decryptStringAsync(value);
    },
  };
}

function installLockMonitoring(): void {
  const lock = () => triggerLock();
  powerMonitor.on('lock-screen', lock);
  powerMonitor.on('suspend', lock);
  idleTimer = setInterval(() => {
    if (!lockTriggered && powerMonitor.getSystemIdleTime() >= settings.idleLockMinutes * 60) triggerLock();
  }, 15_000);
  idleTimer.unref();
}

function triggerLock(): void {
  if (lockTriggered) return;
  lockTriggered = true;
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('desktop:lock');
}

function installApplicationMenu(): void {
  const text = desktopStrings(locale);
  const template: Electron.MenuItemConstructorOptions[] = [
    ...(process.platform === 'darwin' ? [{
      label: app.name,
      submenu: [
        { role: 'about' as const },
        { type: 'separator' as const },
        { role: 'hide' as const },
        { role: 'hideOthers' as const },
        { role: 'unhide' as const },
        { type: 'separator' as const },
        { role: 'quit' as const },
      ],
    }] : []),
    {
      label: text.appMenu,
      submenu: [
        { label: text.lock, accelerator: 'CmdOrCtrl+Shift+L', click: triggerLock },
        {
          label: text.changeServer,
          enabled: !MANAGED_SERVER_URL,
          click: () => mainWindow?.webContents.send('desktop:show-connection-settings'),
        },
        { type: 'separator' },
        process.platform === 'darwin' ? { role: 'close' } : { role: 'quit' },
      ],
    },
    { label: text.editMenu, submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    { label: text.viewMenu, submenu: [{ role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'togglefullscreen' }] },
    { label: text.windowMenu, submenu: [{ role: 'minimize' }, { role: 'close' }] },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function readDevelopmentUrl(): string | null {
  if (app.isPackaged) return null;
  const value = process.env.ALPARTS_DESKTOP_DEV_URL?.trim();
  if (!value) return null;
  const normalized = normalizeServerUrl(value);
  if (!new URL(normalized).hostname.match(/^(?:localhost|127\.0\.0\.1|\[::1\])$/)) {
    throw new Error('Development UI must be loopback-only');
  }
  return normalized;
}

function readManagedServerUrl(): string | null {
  const value = process.env.ALPARTS_SERVER_URL?.trim();
  return value ? normalizeServerUrl(value) : null;
}
