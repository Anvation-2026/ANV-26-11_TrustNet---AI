import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { spawn } from "node:child_process";
import { Socket } from "node:net";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const frontendDir = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(frontendDir, "../backend");

function autoStartBackend() {
  let backendProcess;

  return {
    name: "trustnet-auto-start-backend",
    apply: "serve",
    configureServer(server) {
      let started = false;
      const stopBackend = () => {
        if (backendProcess && !backendProcess.killed) backendProcess.kill();
      };
      const launchBackend = () => {
        if (started) return;
        started = true;

        const windowsPython = path.join(backendDir, ".venv", "Scripts", "python.exe");
        const unixPython = path.join(backendDir, ".venv", "bin", "python");
        const python = existsSync(windowsPython) ? windowsPython
          : existsSync(unixPython) ? unixPython
            : process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
        const args = ["-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"];
        if (existsSync(path.join(backendDir, ".env"))) args.push("--env-file", ".env");

        backendProcess = spawn(python, args, {
          cwd: backendDir,
          stdio: "inherit",
          windowsHide: true,
        });
        backendProcess.once("error", (error) => {
          console.error(`[TrustNet-AI] Could not start the backend: ${error.message}`);
          console.error("Install backend/requirements.txt in the selected Python environment.");
        });
        backendProcess.once("exit", (code) => {
          if (code && code !== 0) console.error(`[TrustNet-AI] Backend stopped with exit code ${code}.`);
        });
      };

      const probe = new Socket();
      probe.setTimeout(500);
      probe.once("connect", () => probe.destroy());
      probe.once("error", launchBackend);
      probe.once("timeout", () => {
        probe.destroy();
        launchBackend();
      });
      probe.connect(8000, "127.0.0.1");

      server.httpServer?.once("close", stopBackend);
      process.once("exit", stopBackend);
    },
  };
}

export default defineConfig({
  plugins: [autoStartBackend(), react(), tailwindcss()],
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
