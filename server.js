const express = require("express");
const http = require("http");
const https = require("https");
const fs = require("fs");
const { spawn } = require("child_process");
const dns = require("dns").promises;

const config = JSON.parse(fs.readFileSync("./config.json", "utf8"));

const app = express();

// Parse incoming JSON request bodies(host, user, pass etc.)
app.use(express.json({ limit: "10kb" }));

// Serve static files from the public directory
app.use(express.static("public"));

// Rate limit, one user can run a maximum of 5 synchronizations every 15 minutes
const rateLimitMap = new Map();
const rate_limit_interval = config.rateLimit.interval;
const rate_limit_max = config.rateLimit.max;

// Getting the user's IP address from an HTTP request
function getRateLimitKey(req) {
  return req.socket.remoteAddress;
}

// Checking whether a given IP has not exceeded the request limit.
function checkRateLimit(req) {
  const key = getRateLimitKey(req);
  const now = Date.now();
  const entry = rateLimitMap.get(key) || { count: 0, resetAt: now + rate_limit_interval };

  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + rate_limit_interval;
  }

  if (entry.count >= rate_limit_max) {
    rateLimitMap.set(key, entry);
    return false;
  }

  entry.count++;
  rateLimitMap.set(key, entry);
  return true;
}

// Clearing old entries every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap.entries()) {
    if (now > entry.resetAt) rateLimitMap.delete(key);
  }
}, 30 * 60 * 1000);

// SSRF SAFE CHECK
function isPrivateIP(ip) {
  // IPv4
  if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.") || (ip.startsWith("172.") && (() => {const second = parseInt(ip.split(".")[1], 10); return second >= 16 && second <= 31; })()) || ip === "0.0.0.0" || ip.startsWith("169.254.")) return true;

  // IPv6
  if (ip === "::1" || ip.startsWith("fc") || ip.startsWith("fe80")) return true;

  return false;
}

// Regex-only SSRF filtering with real DNS-based validation
async function isBlockedHost(host) {
  try {
    // quick reject for obvious cases
    if (/localhost/i.test(host) || /metadata/i.test(host)) {
      return true;
    }

    // DNS resolve (critical SSRF protection layer)
    const records = await dns.lookup(host, { all: true });

    // block if ANY resolved IP is private/internal
    for (const r of records) {
      if (isPrivateIP(r.address)) {
        return true;
      }
    }

    return false;
  } catch {
    // fail closed = block on DNS errors
    return true;
  }
}

// Input Field Validation, Allows safe characters in text fields
function isValidField(value) {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 255) return false;
  
  // Rejects newlines, nulls, and other control characters
  return !/[\x00-\x1F\x7F]/.test(value);
}

// Limits
const max_jobs = config.jobs.maxConcurrent;
const max_logs_entries = config.jobs.maxLogEntries;
const job_timeout = config.jobs.timeoutMs;
const job_cleanup =config.jobs.cleanupMs; 

// Job storage
const jobs = {};

// Sync
app.post("/sync", async (req, res) => {
  // Rate limit per IP
  if (!checkRateLimit(req)) {
    return res.status(429).json({
      ok: false,
      message: `Too many requests. Max ${rate_limit_max} jobs per 15 minutes per IP.`,
    });
  }

  // Limit of simultaneous jobs globally
  const activeCount = Object.values(jobs).filter(j => j.running).length;
  if (activeCount >= max_jobs) {
    return res.status(429).json({
      ok: false,
      message: `Server busy. Max ${max_jobs} concurrent jobs.`,
    });
  }

  const { host1, user1, pass1, host2, user2, pass2, ssl1, ssl2 } = req.body;

  // Validation of required fields
  const fields = { host1, user1, pass1, host2, user2, pass2 };
  for (const [name, value] of Object.entries(fields)) {
    if (!value) {
      return res.status(400).json({ ok: false, message: `Missing field: ${name}` });
    }
    if (!isValidField(value)) {
      return res.status(400).json({ ok: false, message: `Invalid characters in field: ${name}` });
    }
  }

  // SSRF Blocking, reject private hosts
  if (await isBlockedHost(host1)) {
    return res.status(400).json({ ok: false, message: "host source: address not allowed" });
  }
  if (await isBlockedHost(host2)) {
    return res.status(400).json({ ok: false, message: "host target: address not allowed" });
  }

  // Uniquee job ID
  const jobId = require("crypto").randomUUID();

  // Saving passwords to temporary files
  const tmpPass1 = `/tmp/imapsync_pass1_${jobId}`;
  const tmpPass2 = `/tmp/imapsync_pass2_${jobId}`;
  try {
    fs.writeFileSync(tmpPass1, pass1, { mode: 0o600 });
    fs.writeFileSync(tmpPass2, pass2, { mode: 0o600 });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Failed to create temp password files: " + err.message,
    });
  }

  // Imapsync arguments
  const args = [
    "--host1", host1,
    "--user1", user1,
    "--passfile1", tmpPass1,
    "--host2", host2,
    "--user2", user2,
    "--passfile2", tmpPass2,
  ];
  if (ssl1 === true) args.push("--ssl1");
  if (ssl2 === true) args.push("--ssl2");

  const proc = spawn("imapsync", args);

  jobs[jobId] = {
    logs: ["Starting...\n"],
    running: true,
    proc,
    startedAt: Date.now(),
  };

  const appendLog = (text) => {
    jobs[jobId].logs.push(text);
    if (jobs[jobId].logs.length > max_logs_entries) {
      jobs[jobId].logs.shift();
    }
  };
	
  // Limit each output chunk to 1000 characters to prevent excessive memory usage
  proc.stdout.on("data", data => appendLog(data.toString().slice(0, 1000)));
  proc.stderr.on("data", data => appendLog(data.toString().slice(0, 1000)));

  const cleanupTempFiles = () => {
    try { fs.unlinkSync(tmpPass1); } catch (_) {}
    try { fs.unlinkSync(tmpPass2); } catch (_) {}
  };

  // Timeout – kill after 2 hours
  const jobTimeout = setTimeout(() => {
    if (jobs[jobId]?.proc) {
      appendLog("\nTimeout: job killed after 2 hours\n");
      jobs[jobId].proc.kill("SIGTERM");
    }
  }, job_timeout);

  proc.on("error", err => {
    clearTimeout(jobTimeout);
    appendLog("\nError: " + err.message + "\n");
    jobs[jobId].running = false;
    jobs[jobId].proc = null;
    cleanupTempFiles();
    setTimeout(() => delete jobs[jobId], job_cleanup);
  });

  proc.on("close", (code, signal) => {
    clearTimeout(jobTimeout);
    appendLog(signal ? `\nStopped: ${signal}\n` : `\nFinished: ${code}\n`);
    jobs[jobId].running = false;
    jobs[jobId].proc = null;
    cleanupTempFiles();
    setTimeout(() => delete jobs[jobId], job_cleanup);
  });

  res.json({ ok: true, jobId });
});

// Stop
app.post("/stop", (req, res) => {
  const { jobId } = req.body;
  const job = jobs[jobId];

  if (!job || !job.proc) {
    return res.status(400).json({ ok: false, message: "No active process" });
  }

  job.logs.push("\nStopping...\n");
  job.proc.kill("SIGTERM");

  // Fallback: SIGKILL after 5 seconds if the process does not terminate itself
  const fallback = setTimeout(() => {
    if (job.proc && !job.proc.killed) {
      job.proc.kill("SIGKILL");
      job.logs.push("\nForce killed (SIGKILL)\n");
    }
  }, 5000);

  job.proc.on("close", () => clearTimeout(fallback));

  res.json({ ok: true });
});

// logs
app.get("/logs", (req, res) => {
  const { jobId } = req.query;
  const job = jobs[jobId];

  if (!job) {
    return res.status(404).json({ ok: false, message: "Job not found or expired" });
  }

  res.json({
    running: job.running,
    logs: job.logs,
  });
});
 
// Check HTTPS
if (config.https) {
  const options = {
    key:  fs.readFileSync(config.ssl.key),
    cert: fs.readFileSync(config.ssl.cert),
  };
  https.createServer(options, app).listen(config.port);
  console.log(`Running HTTPS on port ${config.port}`);
} else {
  http.createServer(app).listen(config.port);
  console.log(`Running HTTP on port ${config.port}`);
}