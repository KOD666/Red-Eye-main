import { app, BrowserWindow } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.env['ELECTRON_DISABLE_SECURITY_WARNINGS'] = 'true';
app.commandLine.appendSwitch('disable-features', 'AutofillServerCommunication');

function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    icon: path.join(__dirname, 'public/logo.png'),
    title: 'RedEye Command & Control Dashboard',
    backgroundColor: '#070101'
  });

  // Simple dev check with build fallback
  const isDev = !app.isPackaged;

  // Open Chrome developer tools for diagnostic logs
  win.webContents.openDevTools();

  // Prioritize live dev server for instant updates, fallback to dist
  win.loadURL('http://localhost:5173').catch(() => {
    win.loadFile(path.join(__dirname, 'dist/index.html')).catch((err) => {
      console.error("Failed to load both dev server and production package:", err);
    });
  });

  // Remove default menu bar for standard UI look
  win.setMenuBarVisibility(false);
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
