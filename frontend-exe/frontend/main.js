import { app, BrowserWindow, ipcMain, dialog } from 'electron';
import path from 'path';
import fs from 'fs';
import https from 'https';
import http from 'http';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.env.ELECTRON_DISABLE_SECURITY_WARNINGS = 'true';

app.commandLine.appendSwitch(
  'disable-features',
  'AutofillServerCommunication'
);

ipcMain.handle('download-file-save', async (event, { url, defaultPath }) => {
  const window = BrowserWindow.getFocusedWindow();
  const { canceled, filePath } = await dialog.showSaveDialog(window, {
    title: 'Save Agent Stager File',
    defaultPath: defaultPath,
    filters: [
      { name: 'Agent Files', extensions: ['exe', 'apk', 'py', 'sh', '*'] }
    ]
  });

  if (canceled || !filePath) return null;

  return new Promise((resolve) => {
    const file = fs.createWriteStream(filePath);
    const client = url.startsWith('https') ? https : http;
    client.get(url, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        // Handle redirect
        client.get(response.headers.location, (redResp) => {
          redResp.pipe(file);
          file.on('finish', () => {
            file.close(() => resolve(filePath));
          });
        });
      } else {
        response.pipe(file);
        file.on('finish', () => {
          file.close(() => resolve(filePath));
        });
      }
    }).on('error', (err) => {
      fs.unlink(filePath, () => {});
      resolve(null);
    });
  });
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    title: 'RedEye Command & Control Dashboard',
    backgroundColor: '#070101',

    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });

  // Development
  if (!app.isPackaged) {
    win.loadURL('http://localhost:5173');
    win.webContents.openDevTools();
  }

  // Production / packaged EXE
  else {
    win.loadFile(
      path.join(__dirname, 'dist', 'index.html')
    );
  }

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