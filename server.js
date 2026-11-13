import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import db, {
  initDatabase,
  dbRun,
  dbGet,
  dbAll,
  createSessionToken,
  getUserBySessionToken,
  removeSessionToken,
} from "./database.js";
import { generateOTP, sendOTPEmail } from "./emailService.js";

// Load environment variables from .env if present
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;



// Trust proxy for secure cookies behind reverse proxy / iframe environments
app.set("trust proxy", 1);

// Initialize database schema
await initDatabase();

// Template engine setup
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use("/static", express.static(path.join(__dirname, "static")));

// Session management
app.use(
  session({
    secret: process.env.SESSION_SECRET || "expense-tracker-secure-session-key-2026",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 14, // 14 days
      httpOnly: true,
      secure: true,
      sameSite: "none",
    },
  })
);

// Unified Authentication & Context Middleware (supports cookies, tokens, sessions & iframes)
app.use(async (req, res, next) => {
  try {
    let user = null;
    const tokenFromCookie = req.cookies?.auth_token;
    const tokenFromBody = req.body?.auth_token;
    const tokenFromQuery = req.query?.token || req.query?.auth_token;
    const tokenFromHeader = req.headers?.["x-auth-token"] || (req.headers?.authorization ? req.headers.authorization.replace("Bearer ", "") : null);

    const activeToken = tokenFromQuery || tokenFromCookie || tokenFromBody || tokenFromHeader;

    if (activeToken) {
      user = await getUserBySessionToken(activeToken);
    }

    // Fallback to express-session
    if (!user && req.session?.userId) {
      user = await dbGet("SELECT id, name, email FROM users WHERE id = ?", [req.session.userId]);
    }

    if (user) {
      req.user = user;
      req.session.userId = user.id;
      req.session.userName = user.name;
      req.session.userEmail = user.email;
      res.locals.currentUser = user;
      res.locals.authToken = activeToken || "";

      // Ensure browser cookie is stored with sameSite none + secure
      if (activeToken && (!req.cookies?.auth_token || req.cookies.auth_token !== activeToken)) {
        res.cookie("auth_token", activeToken, {
          maxAge: 1000 * 60 * 60 * 24 * 14,
          httpOnly: true,
          secure: true,
          sameSite: "none",
          path: "/",
        });
      }
    } else {
      req.user = null;
      res.locals.currentUser = null;
      res.locals.authToken = "";
    }

    // Flash message transport
    res.locals.success_msg = req.session.success_msg || req.query.success_msg || null;
    res.locals.error_msg = req.session.error_msg || req.query.error_msg || null;
    res.locals.info_msg = req.session.info_msg || req.query.info_msg || null;
    res.locals.dev_otp_preview = req.session.dev_otp_preview || req.query.otp_preview || null;

    delete req.session.success_msg;
    delete req.session.error_msg;
    delete req.session.info_msg;
    delete req.session.dev_otp_preview;

    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    next();
  }
});

// Authentication Guards
function requireAuth(req, res, next) {
  if (!req.user) {
    req.session.error_msg = "Please sign in to access your dashboard.";
    return req.session.save(() => res.redirect("/login"));
  }
  next();
}

function requireGuest(req, res, next) {
  if (req.user) {
    return res.redirect("/");
  }
  next();
}

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

// GET /login
app.get("/login", requireGuest, (req, res) => {
  if (req.query.logged_out) {
    res.locals.info_msg = "You have been logged out successfully.";
  }
  res.render("login", { email: req.query.email || "" });
});

// POST /login (Sign in with Email and Password - no OTP required)
app.post("/login", requireGuest, async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();

    if (!cleanEmail || !password) {
      return res.render("login", {
        email: cleanEmail,
        error_msg: "Please enter both your email address and password.",
      });
    }

    const user = await dbGet("SELECT * FROM users WHERE LOWER(email) = ?", [cleanEmail]);
    if (!user) {
      return res.render("login", {
        email: cleanEmail,
        error_msg: "Invalid email or password. Please verify your credentials or create an account.",
      });
    }

    // Verify password hash
    let passwordMatches = false;
    if (user.password_hash) {
      passwordMatches = await bcrypt.compare(password, user.password_hash);
    }

    if (!passwordMatches) {
      return res.render("login", {
        email: cleanEmail,
        error_msg: "Incorrect password. Please check and try again or use Forgot Password.",
      });
    }

    // Success! Create session token and log in directly without OTP
    const token = await createSessionToken(user.id);
    res.cookie("auth_token", token, {
      maxAge: 1000 * 60 * 60 * 24 * 14,
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    });

    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.userEmail = user.email;
    req.session.success_msg = `Welcome back, ${user.name}!`;

    return req.session.save((err) => {
      if (err) console.error("Session save error:", err);
      res.redirect(`/?token=${token}`);
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.render("login", {
      email: req.body?.email || "",
      error_msg: "An error occurred during sign in. Please try again.",
    });
  }
});

// GET /register
app.get("/register", requireGuest, (req, res) => {
  res.render("register", { name: "", email: "" });
});

// POST /register (Step 1: Validate Name, Email, Password -> Send OTP -> Redirect to Verify OTP)
app.post("/register", requireGuest, async (req, res) => {
  try {
    const { name, email, password, confirm_password } = req.body;
    const cleanName = (name || "").trim();
    const cleanEmail = (email || "").trim().toLowerCase();

    if (!cleanName || !cleanEmail || !password || !confirm_password) {
      return res.render("register", {
        name: cleanName,
        email: cleanEmail,
        error_msg: "Please fill in all fields (Name, Email, and Password).",
      });
    }

    if (password.length < 6) {
      return res.render("register", {
        name: cleanName,
        email: cleanEmail,
        error_msg: "Password must be at least 6 characters long.",
      });
    }

    if (password !== confirm_password) {
      return res.render("register", {
        name: cleanName,
        email: cleanEmail,
        error_msg: "Passwords do not match. Please verify.",
      });
    }

    // Check if user already exists
    const existingUser = await dbGet("SELECT id, name FROM users WHERE LOWER(email) = ?", [cleanEmail]);
    if (existingUser) {
      return res.render("register", {
        name: cleanName,
        email: cleanEmail,
        error_msg: "An account with this email already exists. Please Sign In.",
      });
    }

    // Hash password for storing in OTP payload
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    const purpose = "register";
    const payload = { name: cleanName, email: cleanEmail, passwordHash };

    await dbRun("DELETE FROM otps WHERE LOWER(email) = ?", [cleanEmail]);
    await dbRun(
      "INSERT INTO otps (email, otp, purpose, payload, expires_at) VALUES (?, ?, ?, ?, ?)",
      [cleanEmail, otp, purpose, JSON.stringify(payload), expiresAt]
    );

    // Send email notification with OTP
    const emailResult = await sendOTPEmail({
      email: cleanEmail,
      name: cleanName,
      otp,
      purpose,
    });

    req.session.pendingAuth = {
      email: cleanEmail,
      name: cleanName,
      purpose,
    };

    let redirectUrl = `/verify-otp?email=${encodeURIComponent(cleanEmail)}&purpose=${purpose}`;

    if (emailResult.deliveredVia === "dev-preview") {
      req.session.dev_otp_preview = otp;
      redirectUrl += `&otp_preview=${otp}`;
    }

    req.session.success_msg = `Verification code sent to ${cleanEmail}. Enter the 6-digit code to complete registration.`;
    return req.session.save(() => res.redirect(redirectUrl));
  } catch (err) {
    console.error("Register error:", err);
    return res.render("register", {
      name: req.body?.name || "",
      email: req.body?.email || "",
      error_msg: "Registration failed. Please try again.",
    });
  }
});

// GET /forgot-password
app.get("/forgot-password", requireGuest, (req, res) => {
  res.render("forgot-password", { email: req.query.email || "" });
});

// POST /forgot-password
app.post("/forgot-password", requireGuest, async (req, res) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    if (!email) {
      return res.render("forgot-password", { email, error_msg: "Please enter your registered email address." });
    }

    const user = await dbGet("SELECT * FROM users WHERE LOWER(email) = ?", [email]);
    if (!user) {
      return res.render("forgot-password", {
        email,
        error_msg: "No account found with this email. Please check your email or register for a new account.",
      });
    }

    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    await dbRun("DELETE FROM otps WHERE LOWER(email) = ?", [email]);
    await dbRun(
      "INSERT INTO otps (email, otp, purpose, payload, expires_at) VALUES (?, ?, ?, ?, ?)",
      [email, otp, "reset_password", JSON.stringify({ userId: user.id, name: user.name }), expiresAt]
    );

    const emailResult = await sendOTPEmail({
      email,
      name: user.name,
      otp,
      purpose: "reset_password",
    });

    let redirectUrl = `/reset-password?email=${encodeURIComponent(email)}`;
    if (emailResult.deliveredVia === "dev-preview") {
      req.session.dev_otp_preview = otp;
      redirectUrl += `&otp_preview=${otp}`;
    }

    req.session.success_msg = `A 6-digit reset code has been sent to ${email}.`;
    return req.session.save(() => res.redirect(redirectUrl));
  } catch (err) {
    console.error("Forgot password error:", err);
    res.render("forgot-password", { email: req.body?.email || "", error_msg: "An error occurred. Please try again." });
  }
});

// GET /reset-password
app.get("/reset-password", requireGuest, (req, res) => {
  const email = req.query.email || "";
  const devOtp = req.query.otp_preview || res.locals.dev_otp_preview || "";

  if (!email) {
    return res.redirect("/forgot-password");
  }

  res.render("reset-password", {
    email,
    dev_otp_preview: devOtp,
    error_msg: res.locals.error_msg,
    success_msg: res.locals.success_msg,
  });
});

// POST /reset-password
app.post("/reset-password", requireGuest, async (req, res) => {
  try {
    const { email, otp, password, confirm_password } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();
    const cleanOTP = (otp || "").trim();

    if (!cleanEmail) {
      return res.redirect("/forgot-password");
    }

    if (!cleanOTP || cleanOTP.length !== 6) {
      return res.render("reset-password", {
        email: cleanEmail,
        dev_otp_preview: req.body?.dev_otp_preview || "",
        error_msg: "Please enter a valid 6-digit OTP code.",
      });
    }

    if (!password || password.length < 6) {
      return res.render("reset-password", {
        email: cleanEmail,
        dev_otp_preview: "",
        error_msg: "New password must be at least 6 characters long.",
      });
    }

    if (password !== confirm_password) {
      return res.render("reset-password", {
        email: cleanEmail,
        dev_otp_preview: "",
        error_msg: "Passwords do not match. Please verify.",
      });
    }

    const record = await dbGet(
      "SELECT * FROM otps WHERE LOWER(email) = ? AND otp = ? AND purpose = 'reset_password' ORDER BY id DESC LIMIT 1",
      [cleanEmail, cleanOTP]
    );

    if (!record) {
      return res.render("reset-password", {
        email: cleanEmail,
        dev_otp_preview: "",
        error_msg: "Invalid verification code. Please check and try again.",
      });
    }

    if (Date.now() > record.expires_at) {
      return res.render("reset-password", {
        email: cleanEmail,
        dev_otp_preview: "",
        error_msg: "This verification code has expired. Please request a new one.",
      });
    }

    const user = await dbGet("SELECT * FROM users WHERE LOWER(email) = ?", [cleanEmail]);
    if (!user) {
      return res.render("reset-password", {
        email: cleanEmail,
        dev_otp_preview: "",
        error_msg: "Account not found. Please register first.",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    await dbRun("UPDATE users SET password_hash = ? WHERE id = ?", [passwordHash, user.id]);
    await dbRun("DELETE FROM otps WHERE LOWER(email) = ?", [cleanEmail]);

    // Create session token & auto log in
    const token = await createSessionToken(user.id);
    res.cookie("auth_token", token, {
      maxAge: 1000 * 60 * 60 * 24 * 14,
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    });

    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.userEmail = user.email;
    req.session.success_msg = "Password updated successfully! Welcome back.";

    return req.session.save((err) => {
      if (err) console.error("Session save error:", err);
      res.redirect(`/?token=${token}`);
    });
  } catch (err) {
    console.error("Reset password error:", err);
    res.render("reset-password", {
      email: req.body?.email || "",
      dev_otp_preview: "",
      error_msg: "Failed to reset password. Please try again.",
    });
  }
});

// POST /send-login-otp (Sign in with OTP alternative)
app.post("/send-login-otp", async (req, res) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    if (!email) {
      return res.render("login", { email, error_msg: "Please enter your email to receive an OTP." });
    }

    const user = await dbGet("SELECT * FROM users WHERE LOWER(email) = ?", [email]);
    if (!user) {
      return res.render("login", {
        email,
        error_msg: "No account found with this email. Please register first.",
      });
    }

    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    await dbRun("DELETE FROM otps WHERE LOWER(email) = ?", [email]);
    await dbRun(
      "INSERT INTO otps (email, otp, purpose, payload, expires_at) VALUES (?, ?, ?, ?, ?)",
      [email, otp, "login", JSON.stringify({ userId: user.id, name: user.name }), expiresAt]
    );

    const emailResult = await sendOTPEmail({
      email,
      name: user.name,
      otp,
      purpose: "login",
    });

    let redirectUrl = `/verify-otp?email=${encodeURIComponent(email)}&purpose=login`;
    if (emailResult.deliveredVia === "dev-preview") {
      req.session.dev_otp_preview = otp;
      redirectUrl += `&otp_preview=${otp}`;
    }

    req.session.success_msg = `Login verification code sent to ${email}.`;
    return req.session.save(() => res.redirect(redirectUrl));
  } catch (err) {
    console.error("Send login OTP error:", err);
    res.redirect("/login");
  }
});

// GET /verify-otp
app.get("/verify-otp", (req, res) => {
  const email = req.query.email || req.session.pendingAuth?.email || "";
  const purpose = req.query.purpose || req.session.pendingAuth?.purpose || "register";
  const devOtp = req.query.otp_preview || res.locals.dev_otp_preview || "";

  if (!email) {
    return res.redirect("/register");
  }

  res.render("verify-otp", {
    email,
    purpose,
    dev_otp_preview: devOtp,
    error_msg: res.locals.error_msg,
    success_msg: res.locals.success_msg,
  });
});

// POST /verify-otp (Step 2: Verify OTP -> Create Account / Sign In -> Dashboard)
app.post("/verify-otp", async (req, res) => {
  try {
    const { otp, email, purpose } = req.body;
    const targetEmail = (email || req.session.pendingAuth?.email || "").trim().toLowerCase();
    const cleanOTP = (otp || "").trim();

    if (!targetEmail) {
      req.session.error_msg = "Verification session expired. Please start again.";
      return req.session.save(() => res.redirect("/register"));
    }

    if (!cleanOTP || cleanOTP.length !== 6) {
      return res.render("verify-otp", {
        email: targetEmail,
        purpose: purpose || "register",
        dev_otp_preview: req.body?.dev_otp_preview || "",
        error_msg: "Please enter a valid 6-digit OTP code.",
      });
    }

    const record = await dbGet(
      "SELECT * FROM otps WHERE LOWER(email) = ? AND otp = ? ORDER BY id DESC LIMIT 1",
      [targetEmail, cleanOTP]
    );

    if (!record) {
      return res.render("verify-otp", {
        email: targetEmail,
        purpose: purpose || "register",
        dev_otp_preview: "",
        error_msg: "Incorrect OTP code. Please check and try again.",
      });
    }

    if (Date.now() > record.expires_at) {
      return res.render("verify-otp", {
        email: targetEmail,
        purpose: purpose || "register",
        dev_otp_preview: "",
        error_msg: "This OTP has expired. Please click Resend OTP to get a new code.",
      });
    }

    // OTP Verified successfully!
    const payload = JSON.parse(record.payload || "{}");
    let authenticatedUser = null;

    if (record.purpose === "register") {
      // Check if user was already inserted
      let existing = await dbGet("SELECT * FROM users WHERE LOWER(email) = ?", [targetEmail]);
      if (!existing) {
        const result = await dbRun(
          "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
          [payload.name || "User", targetEmail, payload.passwordHash || ""]
        );
        const newUserId = result.lastID;

        // Initialize user settings
        await dbRun(
          "INSERT INTO user_settings (user_id, available_money, currency) VALUES (?, ?, ?)",
          [newUserId, 0, "₹"]
        );

        // Create welcome notification
        await dbRun(
          "INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
          [
            newUserId,
            "Welcome to Expense Tracker! 🎉",
            "Set your available money and start logging your expenses to track your spending effortlessly.",
            "success",
          ]
        );

        authenticatedUser = { id: newUserId, name: payload.name || "User", email: targetEmail };
      } else {
        authenticatedUser = existing;
      }
    } else {
      // Login purpose
      authenticatedUser = await dbGet("SELECT * FROM users WHERE LOWER(email) = ?", [targetEmail]);
    }

    if (!authenticatedUser) {
      req.session.error_msg = "Account not found. Please register first.";
      return req.session.save(() => res.redirect("/register"));
    }

    // Remove OTP from database
    await dbRun("DELETE FROM otps WHERE LOWER(email) = ?", [targetEmail]);
    delete req.session.pendingAuth;

    // Create session token in database & set cookie
    const token = await createSessionToken(authenticatedUser.id);

    res.cookie("auth_token", token, {
      maxAge: 1000 * 60 * 60 * 24 * 14,
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    });

    req.session.userId = authenticatedUser.id;
    req.session.userName = authenticatedUser.name;
    req.session.userEmail = authenticatedUser.email;
    req.session.success_msg = `Welcome, ${authenticatedUser.name}! Your account is verified and ready.`;

    return req.session.save((err) => {
      if (err) console.error("Session save error:", err);
      res.redirect(`/?token=${token}`);
    });
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.redirect("/login");
  }
});

// POST /resend-otp
app.post("/resend-otp", async (req, res) => {
  try {
    const email = (req.body.email || req.session.pendingAuth?.email || "").trim().toLowerCase();
    if (!email) {
      req.session.error_msg = "Please start the verification process again.";
      return req.session.save(() => res.redirect("/login"));
    }

    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    const existing = await dbGet("SELECT payload, purpose FROM otps WHERE LOWER(email) = ?", [email]);
    const purpose = existing?.purpose || "register";
    const payload = existing?.payload || "{}";

    await dbRun("DELETE FROM otps WHERE LOWER(email) = ?", [email]);
    await dbRun(
      "INSERT INTO otps (email, otp, purpose, payload, expires_at) VALUES (?, ?, ?, ?, ?)",
      [email, otp, purpose, payload, expiresAt]
    );

    const emailResult = await sendOTPEmail({
      email,
      name: "User",
      otp,
      purpose,
    });

    let redirectUrl = `/verify-otp?email=${encodeURIComponent(email)}&purpose=${purpose}`;
    if (emailResult.deliveredVia === "dev-preview") {
      req.session.dev_otp_preview = otp;
      redirectUrl += `&otp_preview=${otp}`;
    }

    req.session.info_msg = `A fresh 6-digit verification code was sent to ${email}.`;
    return req.session.save(() => res.redirect(redirectUrl));
  } catch (err) {
    console.error("Resend OTP error:", err);
    res.redirect("/login");
  }
});

// POST /demo-login (Instant 1-Click Demo Login with 5 recent expenses and clean salary balance)
app.post("/demo-login", async (req, res) => {
  try {
    const demoEmail = "demo@expensetracker.app";
    let demoUser = await dbGet("SELECT * FROM users WHERE LOWER(email) = ?", [demoEmail]);

    if (!demoUser) {
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash("demo1234", salt);
      const resUser = await dbRun(
        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
        ["Demo User", demoEmail, hash]
      );
      const userId = resUser.lastID;
      await dbRun(
        "INSERT INTO user_settings (user_id, available_money, currency) VALUES (?, ?, ?)",
        [userId, 45000, "₹"]
      );
      demoUser = { id: userId, name: "Demo User", email: demoEmail };
    }

    const userId = demoUser.id;

    // Reset and ensure Demo User has 45,000 salary and clean 5 recent transactions
    await dbRun(
      "INSERT INTO user_settings (user_id, available_money, currency) VALUES (?, 45000, '₹') ON CONFLICT(user_id) DO UPDATE SET available_money = 45000",
      [userId]
    );

    // Refresh demo expenses to exactly 5 current-month entries
    await dbRun("DELETE FROM expenses WHERE user_id = ?", [userId]);

    const today = new Date();
    const currentYear = today.getFullYear();
    const currentMonth = String(today.getMonth() + 1).padStart(2, "0");

    const demoExpenses = [
      { name: "Monthly Grocery & Supermarket", amount: 4500, category: "Food", date: `${currentYear}-${currentMonth}-02`, desc: "Organic groceries, fresh produce, and dairy supplies" },
      { name: "Family Weekend Dinner", amount: 2200, category: "Food", date: `${currentYear}-${currentMonth}-06`, desc: "Dinner with family at local restaurant" },
      { name: "Metro & City Commute Pass", amount: 1500, category: "Travel", date: `${currentYear}-${currentMonth}-09`, desc: "Monthly metro card pass & city cabs" },
      { name: "High-Speed Fiber Internet", amount: 999, category: "Bills", date: `${currentYear}-${currentMonth}-12`, desc: "300 Mbps unlimited fiber optic broadband" },
      { name: "Streaming & OTT Subscriptions", amount: 799, category: "Entertainment", date: `${currentYear}-${currentMonth}-15`, desc: "Netflix 4K and Spotify family music plan" },
    ];

    for (const item of demoExpenses) {
      await dbRun(
        "INSERT INTO expenses (user_id, expense_name, amount, category, date, description) VALUES (?, ?, ?, ?, ?, ?)",
        [userId, item.name, item.amount, item.category, item.date, item.desc]
      );
    }

    // Seed Category Budgets
    await dbRun("DELETE FROM budgets WHERE user_id = ?", [userId]);
    await dbRun("INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?, ?, ?)", [userId, "Food", 10000]);
    await dbRun("INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?, ?, ?)", [userId, "Travel", 4000]);
    await dbRun("INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?, ?, ?)", [userId, "Bills", 3000]);
    await dbRun("INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?, ?, ?)", [userId, "Entertainment", 2000]);
    await dbRun("INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?, ?, ?)", [userId, "Shopping", 5000]);

    // Seed Notifications
    await dbRun("DELETE FROM notifications WHERE user_id = ?", [userId]);
    await dbRun(
      "INSERT INTO notifications (user_id, title, message, type, is_read) VALUES (?, ?, ?, ?, ?)",
      [
        userId,
        "Welcome to your Demo Dashboard! 🎉",
        "You are exploring a loaded demo account with ₹45,000 salary, 5 recent transactions, and healthy savings.",
        "success",
        0,
      ]
    );
    await dbRun(
      "INSERT INTO notifications (user_id, title, message, type, is_read) VALUES (?, ?, ?, ?, ?)",
      [
        userId,
        "Healthy 78% Savings Rate 💡",
        "You have saved ₹35,002 out of your ₹45,000 budget this month! Keep up the disciplined budgeting.",
        "info",
        0,
      ]
    );
    await dbRun(
      "INSERT INTO notifications (user_id, title, message, type, is_read) VALUES (?, ?, ?, ?, ?)",
      [
        userId,
        "Food Budget on Track 📊",
        "You have spent ₹6,700 of your ₹10,000 Food budget limit for this month (67%).",
        "warning",
        0,
      ]
    );

    const token = await createSessionToken(demoUser.id);

    res.cookie("auth_token", token, {
      maxAge: 1000 * 60 * 60 * 24 * 14,
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    });

    req.session.userId = demoUser.id;
    req.session.userName = demoUser.name;
    req.session.userEmail = demoUser.email;
    req.session.success_msg = "Logged in as Demo User with 5 recent expenses, ₹45,000 salary, and charts!";

    return req.session.save(() => res.redirect(`/?token=${token}`));
  } catch (err) {
    console.error("Demo login error:", err);
    res.redirect("/login");
  }
});

// GET /logout
app.get("/logout", async (req, res) => {
  try {
    const token = req.cookies?.auth_token || req.query?.token;
    if (token) {
      await removeSessionToken(token);
    }
    res.clearCookie("auth_token", { sameSite: "none", secure: true, path: "/" });
    req.session.destroy((err) => {
      if (err) console.error("Logout session error:", err);
      res.redirect("/login?logged_out=1");
    });
  } catch (err) {
    console.error("Logout error:", err);
    res.redirect("/login");
  }
});

// ==========================================
// PROTECTED DASHBOARD & FINANCE ROUTES
// ==========================================

// Helper: Calculate months list for dropdown
function getAvailableMonths(expenses) {
  const current = new Date();
  const monthsMap = new Map();

  // Always include current month
  const curKey = `${current.getFullYear()}-${String(current.getMonth() + 1).padStart(2, "0")}`;
  const curLabel = current.toLocaleString("default", { month: "long", year: "numeric" });
  monthsMap.set(curKey, curLabel);

  // Add all months from expenses
  for (const exp of expenses) {
    if (exp.date && exp.date.length >= 7) {
      const key = exp.date.slice(0, 7);
      if (!monthsMap.has(key)) {
        const [y, m] = key.split("-");
        const dateObj = new Date(parseInt(y), parseInt(m) - 1, 1);
        monthsMap.set(key, dateObj.toLocaleString("default", { month: "long", year: "numeric" }));
      }
    }
  }

  return Array.from(monthsMap.entries()).map(([value, label]) => ({ value, label }));
}

// GET / (Main Dashboard)
app.get("/", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    // 1. Fetch user profile & settings
    const user = await dbGet("SELECT id, name, email FROM users WHERE id = ?", [userId]);
    let settings = await dbGet("SELECT * FROM user_settings WHERE user_id = ?", [userId]);
    if (!settings) {
      await dbRun("INSERT INTO user_settings (user_id, available_money) VALUES (?, 0)", [userId]);
      settings = { available_money: 0, currency: "₹" };
    }

    const availableMoney = Number(settings.available_money) || 0;

    // 2. Fetch all user expenses (sorted latest first)
    const allExpenses = await dbAll(
      "SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC, id DESC",
      [userId]
    );

    // 3. Search & Filter Parameters
    const searchQuery = (req.query.q || "").trim().toLowerCase();
    const selectedCategory = (req.query.category || "").trim();
    const now = new Date();
    const currentMonthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
    const selectedMonth = req.query.month || currentMonthKey;

    // Filtered list for Recent Expenses table
    let filteredExpenses = allExpenses;

    if (searchQuery) {
      filteredExpenses = filteredExpenses.filter((exp) =>
        exp.expense_name.toLowerCase().includes(searchQuery) ||
        (exp.description && exp.description.toLowerCase().includes(searchQuery))
      );
    }

    if (selectedCategory) {
      filteredExpenses = filteredExpenses.filter((exp) => exp.category === selectedCategory);
    }

    if (req.query.month) {
      filteredExpenses = filteredExpenses.filter((exp) => exp.date && exp.date.startsWith(selectedMonth));
    }

    // 4. Overall Statistics
    const totalExpenses = allExpenses.reduce((sum, exp) => sum + (Number(exp.amount) || 0), 0);
    const balance = availableMoney - totalExpenses;
    const uniqueCategories = new Set(allExpenses.map((exp) => exp.category).filter(Boolean));
    const categoriesCount = uniqueCategories.size;

    // 5. Monthly Report Calculations
    const currentMonthExpenses = allExpenses.filter(
      (exp) => exp.date && exp.date.startsWith(selectedMonth)
    );
    const monthTotalExpenses = currentMonthExpenses.reduce(
      (sum, exp) => sum + (Number(exp.amount) || 0),
      0
    );
    const monthSavings = Math.max(0, availableMoney - monthTotalExpenses);
    const savingsRate =
      availableMoney > 0
        ? Math.max(0, ((availableMoney - monthTotalExpenses) / availableMoney) * 100).toFixed(1)
        : "0.0";

    // Category Spending map for selected month
    const categoryTotals = {};
    for (const exp of currentMonthExpenses) {
      categoryTotals[exp.category] = (categoryTotals[exp.category] || 0) + Number(exp.amount);
    }

    let topCategory = "None";
    let maxSpend = 0;
    for (const [cat, amt] of Object.entries(categoryTotals)) {
      if (amt > maxSpend) {
        maxSpend = amt;
        topCategory = `${cat} (₹${Math.round(amt).toLocaleString("en-IN")})`;
      }
    }

    const monthlyReport = {
      month: selectedMonth,
      income: availableMoney,
      expenses: monthTotalExpenses,
      savings: monthSavings,
      savingsRate,
      topCategory,
      count: currentMonthExpenses.length,
    };

    // 6. Budgets & Alert Progress
    const userBudgets = await dbAll("SELECT * FROM budgets WHERE user_id = ?", [userId]);
    const budgetProgress = userBudgets.map((b) => {
      const spent = categoryTotals[b.category] || 0;
      const limit = Number(b.monthly_limit) || 1;
      const percent = (spent / limit) * 100;
      return {
        id: b.id,
        category: b.category,
        limit,
        spent,
        percent,
      };
    });

    // 7. End of Month Financial Summary Message
    let eomSummary = null;
    if (monthTotalExpenses > 0 || availableMoney > 0) {
      if (availableMoney > monthTotalExpenses) {
        eomSummary = {
          isGood: true,
          title: "Great job on your finances! 🎉",
          message: `You have saved ₹${Math.round(
            monthSavings
          ).toLocaleString("en-IN")} so far this period (${savingsRate}% savings rate). Your spending is well managed!`,
        };
      } else {
        eomSummary = {
          isGood: false,
          title: "Spending Alert ⚠️",
          message: `Your total expenses (₹${Math.round(
            monthTotalExpenses
          ).toLocaleString("en-IN")}) have reached or exceeded your available funds. Consider reviewing non-essential spending.`,
        };
      }
    }

    // 8. Notifications
    const notifications = await dbAll(
      "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 10",
      [userId]
    );
    const unreadNotificationsCount = notifications.filter((n) => !n.is_read).length;

    // 9. Chart.js Category breakdown data
    const chartCategoryData = {
      labels: Object.keys(categoryTotals),
      values: Object.values(categoryTotals),
    };

    // Available months list for filter dropdown
    const availableMonths = getAvailableMonths(allExpenses);
    const todayDate = new Date().toISOString().split("T")[0];

    res.render("index", {
      user,
      currency: settings.currency || "₹",
      settings,
      available_money: availableMoney,
      total_expenses: totalExpenses,
      balance,
      categories_count: categoriesCount,
      expenses: filteredExpenses,
      allExpensesCount: allExpenses.length,
      searchQuery,
      selectedCategory,
      selectedMonth,
      availableMonths,
      monthlyReport,
      budgetProgress,
      eomSummary,
      notifications,
      unreadNotificationsCount,
      chartCategoryData,
      todayDate,
    });
  } catch (err) {
    console.error("Dashboard render error:", err);
    res.status(500).send("A server error occurred loading your dashboard.");
  }
});

// POST /set-money (Update available funds)
app.post("/set-money", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const money = parseFloat(req.body.available_money);
    const cleanMoney = isNaN(money) || money < 0 ? 0 : money;

    await dbRun(
      "INSERT INTO user_settings (user_id, available_money, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET available_money = ?, updated_at = CURRENT_TIMESTAMP",
      [userId, cleanMoney, cleanMoney]
    );

    req.session.success_msg = `Available money updated to ₹${Math.round(cleanMoney).toLocaleString("en-IN")}.`;
    res.redirect("/");
  } catch (err) {
    console.error("Set money error:", err);
    req.session.error_msg = "Failed to update available funds.";
    res.redirect("/");
  }
});

// POST /add (Add Expense with validation and budget checks)
app.post("/add", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { expense_name, amount, category, date, description } = req.body;

    const cleanName = (expense_name || "").trim();
    const parsedAmount = parseFloat(amount);
    const cleanCategory = (category || "Other").trim();
    const cleanDate = date || new Date().toISOString().split("T")[0];
    const cleanDesc = (description || "").trim();

    if (!cleanName) {
      req.session.error_msg = "Please enter an expense name.";
      return res.redirect("/");
    }

    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      req.session.error_msg = "Please enter a valid positive amount.";
      return res.redirect("/");
    }

    // Insert expense
    await dbRun(
      "INSERT INTO expenses (user_id, expense_name, amount, category, date, description) VALUES (?, ?, ?, ?, ?, ?)",
      [userId, cleanName, parsedAmount, cleanCategory, cleanDate, cleanDesc]
    );

    // Check budget limit for this category
    const budget = await dbGet(
      "SELECT monthly_limit FROM budgets WHERE user_id = ? AND category = ?",
      [userId, cleanCategory]
    );

    if (budget) {
      const monthPrefix = cleanDate.slice(0, 7);
      const totalInCatRow = await dbGet(
        "SELECT SUM(amount) as total FROM expenses WHERE user_id = ? AND category = ? AND date LIKE ?",
        [userId, cleanCategory, `${monthPrefix}%`]
      );
      const totalInCat = totalInCatRow?.total || 0;
      const limit = Number(budget.monthly_limit);

      if (totalInCat > limit) {
        await dbRun(
          "INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
          [
            userId,
            `⚠️ ${cleanCategory} Budget Exceeded!`,
            `You spent ₹${Math.round(totalInCat)} in ${cleanCategory}, exceeding your ₹${Math.round(limit)} budget.`,
            "warning",
          ]
        );
      } else if (totalInCat >= limit * 0.8) {
        await dbRun(
          "INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
          [
            userId,
            `⚠️ ${cleanCategory} Budget Warning`,
            `You have used ${(totalInCat / limit * 100).toFixed(0)}% of your ${cleanCategory} budget (₹${Math.round(totalInCat)} of ₹${Math.round(limit)}).`,
            "warning",
          ]
        );
      }
    }

    req.session.success_msg = `Expense "${cleanName}" of ₹${Math.round(parsedAmount).toLocaleString("en-IN")} added successfully!`;
    res.redirect("/");
  } catch (err) {
    console.error("Add expense error:", err);
    req.session.error_msg = "Failed to add expense.";
    res.redirect("/");
  }
});

// GET /edit/:id (Edit Expense page with user ownership check)
app.get("/edit/:id", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const id = parseInt(req.params.id, 10);

    const expense = await dbGet("SELECT * FROM expenses WHERE id = ? AND user_id = ?", [id, userId]);

    if (!expense) {
      req.session.error_msg = "Expense transaction not found or access denied.";
      return res.redirect("/");
    }

    res.render("edit", { expense });
  } catch (err) {
    console.error("Get edit expense error:", err);
    req.session.error_msg = "Error loading expense details.";
    res.redirect("/");
  }
});

// POST /update/:id (Update Expense with user ownership check)
app.post("/update/:id", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const id = parseInt(req.params.id, 10);
    const { expense_name, amount, category, date, description } = req.body;

    const cleanName = (expense_name || "").trim();
    const parsedAmount = parseFloat(amount);
    const cleanCategory = (category || "Other").trim();
    const cleanDate = date || "";
    const cleanDesc = (description || "").trim();

    if (!cleanName || isNaN(parsedAmount) || parsedAmount <= 0) {
      req.session.error_msg = "Please provide valid expense details and amount.";
      return res.redirect(`/edit/${id}`);
    }

    const result = await dbRun(
      "UPDATE expenses SET expense_name = ?, amount = ?, category = ?, date = ?, description = ? WHERE id = ? AND user_id = ?",
      [cleanName, parsedAmount, cleanCategory, cleanDate, cleanDesc, id, userId]
    );

    if (result.changes === 0) {
      req.session.error_msg = "Expense not found or unauthorized.";
      return res.redirect("/");
    }

    req.session.success_msg = `Expense "${cleanName}" updated successfully.`;
    res.redirect("/");
  } catch (err) {
    console.error("Update expense error:", err);
    req.session.error_msg = "Failed to update expense.";
    res.redirect("/");
  }
});

// POST /delete/:id (Delete Expense with user ownership check)
app.post("/delete/:id", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const id = parseInt(req.params.id, 10);

    const result = await dbRun("DELETE FROM expenses WHERE id = ? AND user_id = ?", [id, userId]);

    if (result.changes > 0) {
      req.session.success_msg = "Expense deleted successfully.";
    } else {
      req.session.error_msg = "Expense not found or unauthorized.";
    }

    res.redirect("/");
  } catch (err) {
    console.error("Delete expense error:", err);
    req.session.error_msg = "Failed to delete expense.";
    res.redirect("/");
  }
});

// POST /budgets/set (Set Category Budget limit)
app.post("/budgets/set", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { category, monthly_limit } = req.body;
    const cleanCategory = (category || "").trim();
    const limit = parseFloat(monthly_limit);

    if (!cleanCategory || isNaN(limit) || limit <= 0) {
      req.session.error_msg = "Please specify a valid category and budget limit.";
      return res.redirect("/");
    }

    await dbRun(
      `INSERT INTO budgets (user_id, category, monthly_limit)
       VALUES (?, ?, ?)
       ON CONFLICT(user_id, category) DO UPDATE SET monthly_limit = ?`,
      [userId, cleanCategory, limit, limit]
    );

    req.session.success_msg = `Budget of ₹${Math.round(limit).toLocaleString("en-IN")}/month set for ${cleanCategory}.`;
    res.redirect("/");
  } catch (err) {
    console.error("Set budget error:", err);
    req.session.error_msg = "Failed to save category budget.";
    res.redirect("/");
  }
});

// POST /notifications/read-all (Mark notifications as read)
app.post("/notifications/read-all", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    await dbRun("UPDATE notifications SET is_read = 1 WHERE user_id = ?", [userId]);
    res.redirect("/");
  } catch (err) {
    console.error("Read all notifications error:", err);
    res.redirect("/");
  }
});

// POST /profile/update (Update user profile name and email)
app.post("/profile/update", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, email } = req.body;
    const cleanName = (name || "").trim();
    const cleanEmail = (email || "").trim().toLowerCase();

    if (!cleanName || !cleanEmail) {
      req.session.error_msg = "Name and email cannot be empty.";
      return res.redirect("/");
    }

    // Check if email taken by another user
    const existing = await dbGet("SELECT id FROM users WHERE LOWER(email) = ? AND id != ?", [cleanEmail, userId]);
    if (existing) {
      req.session.error_msg = "This email is already in use by another account.";
      return res.redirect("/");
    }

    await dbRun("UPDATE users SET name = ?, email = ? WHERE id = ?", [cleanName, cleanEmail, userId]);
    req.session.userName = cleanName;
    req.session.userEmail = cleanEmail;
    req.session.success_msg = "Profile details updated successfully!";
    res.redirect("/");
  } catch (err) {
    console.error("Profile update error:", err);
    req.session.error_msg = "Failed to update profile details.";
    res.redirect("/");
  }
});

// POST /settings/update (Update user currency and preferences)
app.post("/settings/update", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { currency } = req.body;
    const cleanCurrency = (currency || "₹").trim();

    await dbRun(
      `INSERT INTO user_settings (user_id, currency, updated_at)
       VALUES (?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(user_id) DO UPDATE SET currency = ?, updated_at = CURRENT_TIMESTAMP`,
      [userId, cleanCurrency, cleanCurrency]
    );

    req.session.success_msg = `Settings updated. Currency set to ${cleanCurrency}.`;
    res.redirect("/");
  } catch (err) {
    console.error("Settings update error:", err);
    req.session.error_msg = "Failed to update settings.";
    res.redirect("/");
  }
});

// GET /export-csv (Export expenses as CSV file)
app.get("/export-csv", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const expenses = await dbAll(
      "SELECT expense_name, amount, category, date, description FROM expenses WHERE user_id = ? ORDER BY date DESC",
      [userId]
    );

    let csv = "Expense Name,Amount,Category,Date,Description\n";
    for (const exp of expenses) {
      const name = `"${(exp.expense_name || "").replace(/"/g, '""')}"`;
      const amt = exp.amount || 0;
      const cat = `"${(exp.category || "").replace(/"/g, '""')}"`;
      const date = `"${(exp.date || "").replace(/"/g, '""')}"`;
      const desc = `"${(exp.description || "").replace(/"/g, '""')}"`;
      csv += `${name},${amt},${cat},${date},${desc}\n`;
    }

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="expenses_${new Date().toISOString().split("T")[0]}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error("Export CSV error:", err);
    req.session.error_msg = "Failed to export CSV.";
    res.redirect("/");
  }
});

// Start Server on 0.0.0.0:3000
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Expense Tracker running at http://0.0.0.0:${PORT}`);
});
