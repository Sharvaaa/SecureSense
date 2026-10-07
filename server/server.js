const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3000;

const overridesFile = path.join(
  __dirname,
  "data",
  "overrides.json"
);

const historyFile = path.join(
  __dirname,
  "data",
  "history.json"
);

app.use(cors());
app.use(express.json());

/* =========================
   FILE HELPERS
========================= */

function readJsonFile(file, fallback = []) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(
        file,
        JSON.stringify(
          fallback,
          null,
          2
        )
      );

      return fallback;
    }

    const content =
      fs.readFileSync(
        file,
        "utf-8"
      );

    if (!content.trim()) {
      return fallback;
    }

    return JSON.parse(content);
  } catch {
    return fallback;
  }
}

function saveJsonFile(
  file,
  data
) {
  fs.writeFileSync(
    file,
    JSON.stringify(
      data,
      null,
      2
    )
  );
}

function readOverrides() {
  return readJsonFile(
    overridesFile,
    []
  );
}

function saveOverrides(
  overrides
) {
  saveJsonFile(
    overridesFile,
    overrides
  );
}

function readHistory() {
  return readJsonFile(
    historyFile,
    []
  );
}

function saveHistory(
  history
) {
  saveJsonFile(
    historyFile,
    history
  );
}

/* =========================
   URL HELPERS
========================= */

function normalizeUrl(url) {
  try {
    const parsedUrl =
      new URL(url);

    return (
      parsedUrl.protocol +
      "//" +
      parsedUrl.hostname.toLowerCase()
    );
  } catch {
    return String(url)
      .trim()
      .toLowerCase()
      .replace(/\/+$/, "");
  }
}

function isValidHttpUrl(url) {
  try {
    const parsedUrl =
      new URL(url);

    return (
      ["http:", "https:"].includes(
        parsedUrl.protocol
      ) &&
      Boolean(parsedUrl.hostname)
    );
  } catch {
    return false;
  }
}

function uniqueReasons(
  reasons
) {
  return [
    ...new Set(reasons),
  ];
}

function createHistoryId() {
  return (
    Date.now().toString() +
    "-" +
    Math.random()
      .toString(36)
      .slice(2, 8)
  );
}

/* =========================
   HEALTH CHECK
========================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      status: "ok",
      service:
        "SecureSense backend",
      timestamp:
        new Date().toISOString(),
    });
  }
);

/* =========================
   ROOT
========================= */

app.get("/", (req, res) => {
  res.json({
    message:
      "SecureSense backend is running",
  });
});

/* =========================
   OVERRIDES
========================= */

app.get(
  "/api/overrides",
  (req, res) => {
    res.json(
      readOverrides()
    );
  }
);

app.post(
  "/api/overrides",
  (req, res) => {
    const {
      url,
      status,
    } = req.body;

    if (
      typeof url !==
        "string" ||
      !url.trim() ||
      !status
    ) {
      return res.status(400).json({
        error:
          "URL and status are required",
      });
    }

    if (
      !isValidHttpUrl(url)
    ) {
      return res.status(400).json({
        error:
          "Only valid HTTP and HTTPS website URLs are supported",
      });
    }

    const allowedStatuses = [
      "trusted",
      "suspicious",
      "dangerous",
    ];

    if (
      !allowedStatuses.includes(
        status
      )
    ) {
      return res.status(400).json({
        error:
          "Status must be trusted, suspicious, or dangerous",
      });
    }

    const overrides =
      readOverrides();

    const normalizedUrl =
      normalizeUrl(url);

    const existingIndex =
      overrides.findIndex(
        (item) =>
          item.url ===
          normalizedUrl
      );

    const entry = {
      url: normalizedUrl,
      status,
      updatedAt:
        new Date().toISOString(),
    };

    if (
      existingIndex !== -1
    ) {
      overrides[
        existingIndex
      ] = entry;
    } else {
      overrides.push(
        entry
      );
    }

    saveOverrides(
      overrides
    );

    res.json({
      message:
        "Website override saved",
      override: entry,
    });
  }
);

app.delete(
  "/api/overrides/:url",
  (req, res) => {
    const url =
      decodeURIComponent(
        req.params.url
      );

    const normalizedUrl =
      normalizeUrl(url);

    const overrides =
      readOverrides();

    const filteredOverrides =
      overrides.filter(
        (item) =>
          item.url !==
          normalizedUrl
      );

    saveOverrides(
      filteredOverrides
    );

    res.json({
      message:
        "Website override removed",
    });
  }
);

/* =========================
   URL ANALYSIS
========================= */

app.post(
  "/api/analyze",
  (req, res) => {
    const { url } =
      req.body;

    if (
      typeof url !==
        "string" ||
      !url.trim()
    ) {
      return res.status(400).json({
        error:
          "URL is required",
      });
    }

    if (
      !isValidHttpUrl(url)
    ) {
      return res.status(400).json({
        error:
          "Only valid HTTP and HTTPS website URLs are supported",
      });
    }

    let parsedUrl;

    try {
      parsedUrl =
        new URL(url);
    } catch {
      return res.status(400).json({
        error:
          "Invalid URL",
      });
    }

    const overrides =
      readOverrides();

    const normalizedUrl =
      normalizeUrl(url);

    const override =
      overrides.find(
        (item) =>
          item.url ===
          normalizedUrl
      );

    /* =========================
       SAVED OVERRIDE
    ========================= */

    if (override) {
      let riskLevel;
      let score;

      if (
        override.status ===
        "trusted"
      ) {
        riskLevel =
          "safe";
        score = 0;
      } else if (
        override.status ===
        "dangerous"
      ) {
        riskLevel =
          "dangerous";
        score = 90;
      } else {
        riskLevel =
          "suspicious";
        score = 60;
      }

      return res.json({
        url,
        riskLevel,
        score,
        reasons: [
          "Website has a saved user override: " +
            override.status,
        ],
        source:
          "override",
      });
    }

    /* =========================
       HEURISTIC ANALYSIS
    ========================= */

    let score = 0;
    let reasons = [];

    /* HTTPS */

    if (
      parsedUrl.protocol !==
      "https:"
    ) {
      score += 30;

      reasons.push(
        "Website is not using HTTPS"
      );
    }

    /* SUSPICIOUS KEYWORDS */

    const suspiciousKeywords = [
      "login",
      "verify",
      "account",
      "password",
      "secure",
      "update",
      "confirm",
      "signin",
      "payment",
      "wallet",
      "recovery",
    ];

    const completeUrl =
      (
        parsedUrl.pathname +
        "?" +
        parsedUrl.searchParams.toString()
      ).toLowerCase();

    const matchedKeywords =
      suspiciousKeywords.filter(
        (keyword) =>
          completeUrl.includes(
            keyword
          )
      );

    if (
      matchedKeywords.length >
      0
    ) {
      score += 20;

      reasons.push(
        "URL contains potentially sensitive keywords"
      );
    }

    /* IP ADDRESS */

    const ipPattern =
      /^(\d{1,3}\.){3}\d{1,3}$/;

    if (
      ipPattern.test(
        parsedUrl.hostname
      )
    ) {
      score += 40;

      reasons.push(
        "Website uses an IP address instead of a domain name"
      );
    }

    /* SUSPICIOUS TLD */

    const suspiciousTlds = [
      ".zip",
      ".mov",
      ".top",
      ".click",
      ".xyz",
      ".work",
      ".gq",
      ".tk",
      ".ml",
      ".cf",
      ".ga",
    ];

    const hostname =
      parsedUrl.hostname.toLowerCase();

    const hasSuspiciousTld =
      suspiciousTlds.some(
        (tld) =>
          hostname.endsWith(
            tld
          )
      );

    if (
      hasSuspiciousTld
    ) {
      score += 15;

      reasons.push(
        "Website uses a domain extension commonly associated with higher-risk URLs"
      );
    }

    /* MANY SUBDOMAINS */

    const hostnameParts =
      hostname
        .split(".")
        .filter(Boolean);

    if (
      hostnameParts.length >
      4
    ) {
      score += 10;

      reasons.push(
        "Website uses an unusually deep subdomain structure"
      );
    }

    /* USER INFO */

    if (
      parsedUrl.username ||
      parsedUrl.password
    ) {
      score += 25;

      reasons.push(
        "URL contains embedded user information"
      );
    }

    /* NON-STANDARD PORT */

    if (
      parsedUrl.port &&
      parsedUrl.port !==
        "80" &&
      parsedUrl.port !==
        "443"
    ) {
      score += 15;

      reasons.push(
        "Website uses a non-standard network port"
      );
    }

    /* ENCODED URL */

    if (
      parsedUrl.pathname.includes(
        "%"
      ) ||
      parsedUrl.search.includes(
        "%"
      )
    ) {
      score += 10;

      reasons.push(
        "URL contains encoded characters that require additional inspection"
      );
    }

    /* LONG HOSTNAME */

    if (
      hostname.length >
      63
    ) {
      score += 10;

      reasons.push(
        "Website hostname is unusually long"
      );
    }

    /* LONG URL */

    if (
      url.length > 200
    ) {
      score += 5;

      reasons.push(
        "URL is unusually long"
      );
    }

    /* SCORE */

    score = Math.min(
      Math.max(score, 0),
      100
    );

    /* RISK */

    let riskLevel;

    if (score >= 70) {
      riskLevel =
        "dangerous";
    } else if (
      score >= 40
    ) {
      riskLevel =
        "suspicious";
    } else {
      riskLevel =
        "safe";
    }

    reasons =
      uniqueReasons(
        reasons
      );

    if (
      reasons.length ===
      0
    ) {
      reasons.push(
        "No obvious URL-based threats detected"
      );
    }

    res.json({
      url,
      riskLevel,
      score,
      reasons,
      source:
        "url-analysis",
    });
  }
);

/* =========================
   SCAN HISTORY
========================= */

app.get(
  "/api/history",
  (req, res) => {
    res.json(
      readHistory()
    );
  }
);

app.post(
  "/api/history",
  (req, res) => {
    const {
      url,
      analyzedUrl,
      status,
      score,
      reasons,
      scannedAt,
    } = req.body;

    if (
      typeof url !==
        "string" ||
      !url.trim()
    ) {
      return res.status(400).json({
        error:
          "A valid URL is required",
      });
    }

    const allowedStatuses = [
      "safe",
      "suspicious",
      "dangerous",
    ];

    if (
      !allowedStatuses.includes(
        status
      )
    ) {
      return res.status(400).json({
        error:
          "Status must be safe, suspicious, or dangerous",
      });
    }

    const numericScore =
      Number(score);

    if (
      !Number.isFinite(
        numericScore
      ) ||
      numericScore < 0 ||
      numericScore > 100
    ) {
      return res.status(400).json({
        error:
          "Score must be a number between 0 and 100",
      });
    }

    const history =
      readHistory();

    const entry = {
      id:
        createHistoryId(),

      url,

      analyzedUrl:
        typeof analyzedUrl ===
          "string" &&
        analyzedUrl.trim()
          ? analyzedUrl
          : url,

      status,

      score:
        numericScore,

      reasons:
        Array.isArray(
          reasons
        )
          ? reasons
          : [],

      scannedAt:
        scannedAt ||
        new Date().toISOString(),
    };

    history.unshift(
      entry
    );

    saveHistory(
      history.slice(
        0,
        50
      )
    );

    res.json({
      message:
        "Scan history saved",
      scan: entry,
    });
  }
);

app.delete(
  "/api/history",
  (req, res) => {
    saveHistory([]);

    res.json({
      message:
        "Scan history cleared",
    });
  }
);

/* =========================
   DASHBOARD STATS
========================= */

app.get(
  "/api/stats",
  (req, res) => {
    const history =
      readHistory();

    const latestByUrl =
      new Map();

    history.forEach(
      (item) => {
        const normalizedUrl =
          normalizeUrl(
            item.analyzedUrl ||
              item.url
          );

        if (
          !latestByUrl.has(
            normalizedUrl
          )
        ) {
          latestByUrl.set(
            normalizedUrl,
            item
          );
        }
      }
    );

    const scanned =
      latestByUrl.size;

    let threats = 0;
    let protectedWebsites = 0;

    latestByUrl.forEach(
      (item) => {
        if (
          item.status ===
            "suspicious" ||
          item.status ===
            "dangerous"
        ) {
          threats++;
        }

        if (
          item.status ===
          "safe"
        ) {
          protectedWebsites++;
        }
      }
    );

    res.json({
      scanned,
      threats,
      protected:
        protectedWebsites,
    });
  }
);

/* =========================
   ERROR HANDLING
========================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    if (
      error instanceof
        SyntaxError &&
      error.status ===
        400 &&
      "body" in error
    ) {
      return res
        .status(400)
        .json({
          error:
            "Invalid JSON request body",
        });
    }

    console.error(
      "Server error:",
      error
    );

    res.status(500).json({
      error:
        "Internal SecureSense server error",
    });
  }
);

/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  () => {
    console.log(
      `SecureSense backend running at http://localhost:${PORT}`
    );
  }
);