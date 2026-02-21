// ==================== IMPORTS & APP SETUP ====================

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import logger from "./utils/logger.js";
import { initializeApp as initFirebaseAdmin, cert } from "firebase-admin/app";
import { getAuth as getAdminAuth } from "firebase-admin/auth";

dotenv.config();

// ==================== FIREBASE ADMIN SDK ====================

if (!process.env.FIREBASE_PROJECT_ID || !process.env.FIREBASE_CLIENT_EMAIL || !process.env.FIREBASE_PRIVATE_KEY) {
  console.error("❌ Missing Firebase Admin env vars: FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY");
  console.error("   Add them to your .env file. Get them from Firebase Console → Project Settings → Service Accounts → Generate New Private Key");
  process.exit(1);
}

const firebaseAdminApp = initFirebaseAdmin({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  }),
});
const adminAuth = getAdminAuth(firebaseAdminApp);

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5174",
      "https://rootx-school-ms.vercel.app",
      "https://rootx-school-ms.web.app",
    ],
    credentials: true,
  })
);

// ==================== DATABASE CONNECTION ====================

const user = encodeURIComponent(process.env.DB_USER);
const pass = encodeURIComponent(process.env.DB_PASS);
const uri = `mongodb+srv://${user}:${pass}@cluster0.izyiyn6.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  tls: true,
  tlsAllowInvalidCertificates: false,
  serverSelectionTimeoutMS: 10000,
  connectTimeoutMS: 10000,
});

let db;
let isConnected = false;

// Phase 1 Collections
let organizationsCollection;
let usersCollection;
let subscriptionsCollection;
let subscriptionPlansCollection;
let platformSettingsCollection;
let activityLogsCollection;

// Phase 2 Collections
let classesCollection;
let sectionsCollection;
let subjectsCollection;
let studentsCollection;
let teachersCollection;
let parentsCollection;
let documentsCollection;

// Phase 3 Collections
let attendanceCollection;

// Phase 4 Collections
let examsCollection;
let gradeSubmissionsCollection;
let notificationsCollection;

// Phase 5 Collections
let monthlyFeeStructuresCollection;
let studentMonthlyFeesCollection;
let paymentsCollection;
let expensesCollection;
let salariesCollection;

// Phase 6 Collections
let announcementsCollection;

// Phase 7 Collections - Super Admin
let subscriptionRequestsCollection;
let reactivationRequestsCollection;

async function connectDB() {
  if (isConnected && db) {
    return;
  }

  try {
    await client.connect();
    db = client.db("rootx_school_management");

    organizationsCollection = db.collection("organizations");
    usersCollection = db.collection("users");
    subscriptionsCollection = db.collection("subscriptions");
    subscriptionPlansCollection = db.collection("subscription_plans");
    platformSettingsCollection = db.collection("platform_settings");
    activityLogsCollection = db.collection("activity_logs");

    // Phase 2 Collections
    classesCollection = db.collection("classes");
    sectionsCollection = db.collection("sections");
    subjectsCollection = db.collection("subjects");
    studentsCollection = db.collection("students");
    teachersCollection = db.collection("teachers");
    parentsCollection = db.collection("parents");
    documentsCollection = db.collection("documents");

    // Phase 3 Collections
    attendanceCollection = db.collection("attendance");

    // Phase 4 Collections
    examsCollection = db.collection("exams");
    gradeSubmissionsCollection = db.collection("grade_submissions");
    notificationsCollection = db.collection("notifications");

    // Phase 5 Collections
    monthlyFeeStructuresCollection = db.collection("monthly_fee_structures");
    studentMonthlyFeesCollection = db.collection("student_monthly_fees");
    paymentsCollection = db.collection("payments");
    expensesCollection = db.collection("expenses");
    salariesCollection = db.collection("salaries");

    // Phase 6 Collections
    announcementsCollection = db.collection("announcements");

    // Phase 7 Collections - Super Admin
    subscriptionRequestsCollection = db.collection("subscription_requests");
    reactivationRequestsCollection = db.collection("reactivation_requests");

    isConnected = true;
    logger.info("Connected to MongoDB");

    await createIndexes();
  } catch (err) {
    logger.error("MongoDB connection error:", {
      error: err.message,
      stack: err.stack,
    });
    isConnected = false;
    throw err;
  }
}

// ==================== INDEX CREATION ====================

async function createIndexes() {
  try {
    // Cleanup: remove firebaseUid field from documents with empty string or null
    // (sparse unique index only skips documents where the field is missing/undefined)
    await usersCollection.updateMany(
      { $or: [{ firebaseUid: "" }, { firebaseUid: null }] },
      { $unset: { firebaseUid: "" } }
    );

    // organizations
    await organizationsCollection.createIndex({ slug: 1 }, { unique: true });
    await organizationsCollection.createIndex({ email: 1 }, { unique: true });
    await organizationsCollection.createIndex({ subscriptionStatus: 1 });
    await organizationsCollection.createIndex({ ownerId: 1 });
    await organizationsCollection.createIndex({ status: 1 });
    await organizationsCollection.createIndex({ createdAt: -1 });

    // users
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    await usersCollection.createIndex(
      { firebaseUid: 1 },
      { unique: true, sparse: true }
    );
    await usersCollection.createIndex({ organizationId: 1 });
    await usersCollection.createIndex({ organizationId: 1, role: 1 });
    await usersCollection.createIndex({ isSuperAdmin: 1 });

    // subscriptions
    await subscriptionsCollection.createIndex(
      { organizationId: 1 },
      { unique: true }
    );
    await subscriptionsCollection.createIndex({ status: 1 });
    await subscriptionsCollection.createIndex({ nextBillingDate: 1 });

    // subscription_plans
    await subscriptionPlansCollection.createIndex(
      { tier: 1 },
      { unique: true }
    );

    // platform_settings
    await platformSettingsCollection.createIndex(
      { key: 1 },
      { unique: true }
    );
    await platformSettingsCollection.createIndex({ category: 1 });

    // activity_logs
    await activityLogsCollection.createIndex({
      organizationId: 1,
      createdAt: -1,
    });
    await activityLogsCollection.createIndex({ userId: 1, createdAt: -1 });
    await activityLogsCollection.createIndex({
      resource: 1,
      resourceId: 1,
    });
    await activityLogsCollection.createIndex({ createdAt: -1 });

    // ---- Phase 2 Indexes ----

    // classes
    await classesCollection.createIndex({ organizationId: 1, academicYear: 1 });

    // sections
    await sectionsCollection.createIndex({ organizationId: 1, classId: 1 });

    // subjects
    await subjectsCollection.createIndex({ organizationId: 1, classId: 1 });
    await subjectsCollection.createIndex({ organizationId: 1, teacherId: 1 });

    // students
    await studentsCollection.createIndex(
      { organizationId: 1, admissionNumber: 1 },
      { unique: true }
    );
    await studentsCollection.createIndex({ organizationId: 1, classId: 1 });
    await studentsCollection.createIndex({ organizationId: 1, sectionId: 1 });
    await studentsCollection.createIndex({ organizationId: 1, parentId: 1 });
    await studentsCollection.createIndex({ organizationId: 1, status: 1 });

    // teachers
    await teachersCollection.createIndex({ organizationId: 1, status: 1 });
    await teachersCollection.createIndex({ organizationId: 1, userId: 1 });

    // parents
    await parentsCollection.createIndex({ organizationId: 1, userId: 1 });

    // documents
    await documentsCollection.createIndex({
      organizationId: 1,
      ownerId: 1,
      ownerType: 1,
    });

    // ---- Phase 3 Indexes ----

    // attendance - unique: one attendance record per class+section+date
    await attendanceCollection.createIndex(
      { organizationId: 1, classId: 1, sectionId: 1, date: 1 },
      { unique: true }
    );
    await attendanceCollection.createIndex({ organizationId: 1, date: -1 });
    await attendanceCollection.createIndex({
      organizationId: 1,
      classId: 1,
      date: -1,
    });

    // ---- Phase 4 Indexes ----

    // exams
    await examsCollection.createIndex({ organizationId: 1, classId: 1 });
    await examsCollection.createIndex({
      organizationId: 1,
      academicYear: 1,
    });

    // grade_submissions - unique: one submission per exam+class+section+subject
    await gradeSubmissionsCollection.createIndex(
      {
        organizationId: 1,
        examId: 1,
        classId: 1,
        sectionId: 1,
        subjectId: 1,
      },
      { unique: true }
    );
    await gradeSubmissionsCollection.createIndex({
      organizationId: 1,
      status: 1,
    });
    await gradeSubmissionsCollection.createIndex({
      organizationId: 1,
      teacherId: 1,
    });
    await gradeSubmissionsCollection.createIndex({
      organizationId: 1,
      moderatorId: 1,
      status: 1,
    });
    await gradeSubmissionsCollection.createIndex({
      organizationId: 1,
      examId: 1,
    });

    // notifications
    await notificationsCollection.createIndex({ userId: 1, isRead: 1 });
    await notificationsCollection.createIndex({
      organizationId: 1,
      createdAt: -1,
    });

    // ---- Phase 5 Indexes ----

    // monthly_fee_structures
    await monthlyFeeStructuresCollection.createIndex({
      organizationId: 1,
      classId: 1,
    });
    await monthlyFeeStructuresCollection.createIndex({
      organizationId: 1,
      academicYear: 1,
    });

    // student_monthly_fees - unique: one fee record per student per month
    await studentMonthlyFeesCollection.createIndex(
      { organizationId: 1, studentId: 1, month: 1 },
      { unique: true }
    );
    await studentMonthlyFeesCollection.createIndex({
      organizationId: 1,
      status: 1,
    });
    await studentMonthlyFeesCollection.createIndex({
      organizationId: 1,
      studentId: 1,
    });
    await studentMonthlyFeesCollection.createIndex({
      organizationId: 1,
      month: 1,
    });

    // payments
    await paymentsCollection.createIndex({
      organizationId: 1,
      paymentDate: -1,
    });
    await paymentsCollection.createIndex({
      organizationId: 1,
      studentId: 1,
    });
    await paymentsCollection.createIndex(
      { organizationId: 1, receiptNumber: 1 },
      { unique: true, sparse: true }
    );

    // expenses
    await expensesCollection.createIndex({
      organizationId: 1,
      expenseMonth: 1,
    });
    await expensesCollection.createIndex({
      organizationId: 1,
      category: 1,
    });

    // salaries - unique: one salary per staff per month
    await salariesCollection.createIndex(
      { organizationId: 1, staffId: 1, month: 1 },
      { unique: true }
    );
    await salariesCollection.createIndex({
      organizationId: 1,
      month: 1,
    });
    await salariesCollection.createIndex({
      organizationId: 1,
      status: 1,
    });

    // Phase 6: announcements
    await announcementsCollection.createIndex({
      organizationId: 1,
      createdAt: -1,
    });
    await announcementsCollection.createIndex({
      organizationId: 1,
      target: 1,
    });

    // Phase 7: subscription_requests
    await subscriptionRequestsCollection.createIndex(
      { organizationId: 1 },
      { unique: true }
    );
    await subscriptionRequestsCollection.createIndex({
      status: 1,
      createdAt: -1,
    });
    await subscriptionRequestsCollection.createIndex({ requestedTier: 1 });

    // Phase 7: reactivation_requests
    await reactivationRequestsCollection.createIndex({
      organizationId: 1,
      status: 1,
    });
    await reactivationRequestsCollection.createIndex({
      status: 1,
      createdAt: -1,
    });

    logger.info("Indexes created successfully");
  } catch (error) {
    logger.error("Error creating indexes:", { error: error.message });
  }
}

// ==================== ROLE PERMISSIONS ====================

const ROLE_PERMISSIONS = {
  super_admin: ["all"],
  org_owner: ["all"],
  admin: [
    "manage_org_settings",
    "manage_users",
    "invite_users",
    "view_students",
    "create_student",
    "update_student",
    "delete_student",
    "view_teachers",
    "create_teacher",
    "update_teacher",
    "delete_teacher",
    "manage_classes",
    "manage_sections",
    "manage_subjects",
    "view_attendance",
    "mark_attendance",
    "manage_exams",
    "create_exam",
    "review_grades",
    "approve_grades",
    "reject_grades",
    "publish_grades",
    "view_published_grades",
    "manage_fee_structures",
    "collect_payment",
    "view_fees",
    "manage_expenses",
    "manage_salaries",
    "create_announcement",
    "view_announcements",
    "manage_documents",
    "view_reports",
    "export_data",
    "view_activity_logs",
  ],
  moderator: [
    "view_classes",
    "view_sections",
    "view_subjects",
    "view_students",
    "view_teachers",
    "view_attendance",
    "review_grades",
    "approve_grades",
    "reject_grades",
    "view_published_grades",
    "view_announcements",
    "view_reports",
  ],
  teacher: [
    "view_classes",
    "view_sections",
    "view_subjects",
    "view_students",
    "view_attendance",
    "mark_attendance",
    "create_exam",
    "create_grade_draft",
    "submit_grades",
    "view_published_grades",
    "create_announcement",
    "view_announcements",
    "upload_own_documents",
    "view_reports",
  ],
  student: [
    "view_classes",
    "view_sections",
    "view_subjects",
    "view_attendance",
    "view_published_grades",
    "view_fees",
    "view_announcements",
    "upload_own_documents",
  ],
  parent: [
    "view_classes",
    "view_sections",
    "view_attendance",
    "view_published_grades",
    "view_fees",
    "view_announcements",
  ],
};

// ==================== MIDDLEWARE ====================

const ensureDBConnection = async (req, res, next) => {
  try {
    if (!isConnected) {
      await connectDB();
    }
    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Database connection failed",
      error: error.message,
    });
  }
};

const authenticateUser = async (req, res, next) => {
  try {
    const email = req.headers["x-user-email"];

    if (!email) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    const userDoc = await usersCollection.findOne({ email });

    if (!userDoc) {
      return res.status(401).json({
        success: false,
        message: "User not found",
      });
    }

    req.user = userDoc;
    req.userId = userDoc._id;
    req.organizationId = userDoc.organizationId;
    req.userRole = userDoc.role;

    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Authentication failed",
      error: error.message,
    });
  }
};

const enforceOrganizationIsolation = (req, res, next) => {
  if (req.userRole === "super_admin" || req.user?.isSuperAdmin) {
    req.isSuperAdmin = true;
    return next();
  }

  if (!req.organizationId) {
    return res.status(403).json({
      success: false,
      message: "Organization context required",
    });
  }

  next();
};

const checkOrganizationSuspension = async (req, res, next) => {
  try {
    if (req.isSuperAdmin || req.userRole === "super_admin") {
      return next();
    }

    if (!req.organizationId) {
      return next();
    }

    const organization = await organizationsCollection.findOne({
      _id: new ObjectId(req.organizationId),
    });

    if (!organization) {
      return res.status(404).json({
        success: false,
        message: "Organization not found",
      });
    }

    if (organization.status === "suspended") {
      return res.status(403).json({
        success: false,
        suspended: true,
        message:
          "Your organization has been suspended. Please contact support.",
        suspensionData: {
          reason: organization.suspensionReason || "No reason provided",
          suspendedAt: organization.suspendedAt,
          organizationName: organization.name,
        },
      });
    }

    next();
  } catch (error) {
    logger.error("Error checking organization suspension:", {
      error: error.message,
    });
    return res.status(500).json({
      success: false,
      message: "Error checking organization status",
    });
  }
};

const requirePermission = (permission) => {
  return (req, res, next) => {
    const { userRole } = req;

    if (userRole === "super_admin" || req.user?.isSuperAdmin) {
      return next();
    }

    const userPermissions = ROLE_PERMISSIONS[userRole] || [];

    if (
      userPermissions.includes("all") ||
      userPermissions.includes(permission)
    ) {
      return next();
    }

    res.status(403).json({
      success: false,
      message: "Insufficient permissions",
      required: permission,
    });
  };
};

const requireSuperAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: "Authentication required",
    });
  }

  if (req.user.role !== "super_admin" && !req.user.isSuperAdmin) {
    return res.status(403).json({
      success: false,
      message: "Super admin access required",
    });
  }

  req.isSuperAdmin = true;
  next();
};

// ==================== UTILITY FUNCTIONS ====================

async function logActivity(
  userId,
  organizationId,
  action,
  resource,
  resourceId,
  changes = null,
  req = null
) {
  try {
    const userDoc = await usersCollection.findOne({
      _id: new ObjectId(userId),
    });

    await activityLogsCollection.insertOne({
      organizationId: organizationId
        ? new ObjectId(organizationId)
        : null,
      userId: new ObjectId(userId),
      userName: userDoc?.name || "Unknown",
      action,
      resource,
      resourceId: resourceId ? String(resourceId) : null,
      changes,
      ipAddress:
        req?.ip || req?.headers?.["x-forwarded-for"] || null,
      userAgent: req?.headers?.["user-agent"] || null,
      isSuperAdminAction:
        req?.isSuperAdmin === true || req?.userRole === "super_admin",
      createdAt: new Date(),
    });
  } catch (error) {
    logger.error("Error logging activity:", { error: error.message });
  }
}

async function checkUsageLimits(organizationId, resourceType) {
  try {
    const org = await organizationsCollection.findOne({
      _id: new ObjectId(organizationId),
    });

    if (!org) {
      return { allowed: false, message: "Organization not found" };
    }

    const limitMap = {
      students: { current: "currentStudents", max: "maxStudents" },
      classes: { current: "currentClasses", max: "maxClasses" },
      teachers: { current: "currentTeachers", max: "maxTeachers" },
    };

    const mapping = limitMap[resourceType];
    if (!mapping) return { allowed: true };

    const current = org.usage?.[mapping.current] || 0;
    const max = org.limits?.[mapping.max];

    if (max === -1) return { allowed: true, current, max: "unlimited" };

    if (current >= max) {
      return {
        allowed: false,
        current,
        max,
        message: `${resourceType} limit reached (${current}/${max}). Upgrade your plan.`,
      };
    }

    return { allowed: true, current, max };
  } catch (error) {
    logger.error("Error checking usage limits:", {
      error: error.message,
    });
    return { allowed: false, message: "Error checking limits" };
  }
}

// ==================== PHASE 4 HELPERS ====================

function calculateGrade(marks, fullMarks = 100) {
  const percentage = (marks / fullMarks) * 100;
  if (percentage >= 90) return { grade: "A+", gradePoint: 5.0 };
  if (percentage >= 80) return { grade: "A", gradePoint: 4.0 };
  if (percentage >= 70) return { grade: "A-", gradePoint: 3.5 };
  if (percentage >= 60) return { grade: "B", gradePoint: 3.0 };
  if (percentage >= 50) return { grade: "C", gradePoint: 2.0 };
  if (percentage >= 40) return { grade: "D", gradePoint: 1.0 };
  return { grade: "F", gradePoint: 0.0 };
}

async function createNotification(
  userId,
  organizationId,
  type,
  title,
  message,
  data = {}
) {
  try {
    await notificationsCollection.insertOne({
      userId: new ObjectId(userId),
      organizationId: organizationId
        ? new ObjectId(organizationId)
        : null,
      type,
      title,
      message,
      data,
      isRead: false,
      createdAt: new Date(),
    });
  } catch (error) {
    logger.error("Error creating notification:", {
      error: error.message,
    });
  }
}

async function createBulkNotifications(
  userIds,
  organizationId,
  type,
  title,
  message,
  data = {}
) {
  try {
    if (!userIds || userIds.length === 0) return;
    const notifications = userIds.map((uid) => ({
      userId: new ObjectId(uid),
      organizationId: organizationId
        ? new ObjectId(organizationId)
        : null,
      type,
      title,
      message,
      data,
      isRead: false,
      createdAt: new Date(),
    }));
    await notificationsCollection.insertMany(notifications);
  } catch (error) {
    logger.error("Error creating bulk notifications:", {
      error: error.message,
    });
  }
}

async function getTeacherDocForCurrentUser(organizationId, userId) {
  return await teachersCollection.findOne({
    organizationId,
    userId,
    status: "active",
  });
}

// ==================== PHASE 5 HELPERS ====================

async function generateReceiptNumber(organizationId) {
  try {
    const org = await organizationsCollection.findOne({
      _id: new ObjectId(organizationId),
    });
    const slug = (org?.slug || "ORG").toUpperCase();
    const year = new Date().getFullYear();

    const lastPayment = await paymentsCollection
      .find({
        organizationId: new ObjectId(organizationId),
        receiptNumber: { $regex: `^${slug}-${year}-` },
      })
      .sort({ createdAt: -1 })
      .limit(1)
      .toArray();

    let nextNum = 1;
    if (lastPayment.length > 0) {
      const lastReceipt = lastPayment[0].receiptNumber;
      const parts = lastReceipt.split("-");
      const lastNum = parseInt(parts[parts.length - 1], 10);
      if (!isNaN(lastNum)) nextNum = lastNum + 1;
    }

    return `${slug}-${year}-${String(nextNum).padStart(5, "0")}`;
  } catch (error) {
    logger.error("Error generating receipt number:", {
      error: error.message,
    });
    return `REC-${Date.now()}`;
  }
}

function calculateFeeStatus(payableAmount, paidAmount, dueDate) {
  if (paidAmount >= payableAmount) return "paid";
  if (paidAmount > 0) return "partial";
  if (dueDate && new Date(dueDate) < new Date()) return "overdue";
  return "pending";
}

// ==================== PHASE 6 HELPERS ====================

function escapeCsvField(field) {
  if (field === null || field === undefined) return "";
  const str = String(field);
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function buildCsvString(headers, rows) {
  const headerLine = headers.map(escapeCsvField).join(",");
  const dataLines = rows.map((row) =>
    row.map(escapeCsvField).join(",")
  );
  return [headerLine, ...dataLines].join("\n");
}

// ==================== FIREBASE HELPER ====================

// Creates a Firebase Auth account for new users.
// If the email already exists in Firebase, returns the existing UID.
const createFirebaseUser = async (email, password, displayName) => {
  try {
    const userRecord = await adminAuth.createUser({
      email,
      password,
      displayName,
      emailVerified: false,
    });
    return { uid: userRecord.uid, alreadyExisted: false };
  } catch (err) {
    if (err.code === "auth/email-already-exists") {
      const existing = await adminAuth.getUserByEmail(email);
      return { uid: existing.uid, alreadyExisted: true };
    }
    throw err;
  }
};

// ==================== INITIALIZE DATABASE ====================

connectDB().catch((err) => {
  logger.error("Initial DB connection failed:", {
    error: err.message,
    hint: "Check MongoDB Atlas IP whitelist and credentials",
  });
});

// ==================== API ROUTES ====================

// --- Health Check ---

app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "RootX School Management System API is healthy",
    timestamp: new Date().toISOString(),
    dbConnected: isConnected,
  });
});

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "RootX School Management System API",
    version: "1.0.0",
    status: "running",
  });
});

// --- Subscription Plans (Public) ---

app.get("/subscriptions/plans", ensureDBConnection, async (req, res) => {
  try {
    const plans = await subscriptionPlansCollection
      .find({ isActive: true })
      .sort({ displayOrder: 1 })
      .toArray();

    res.json({
      success: true,
      data: plans,
    });
  } catch (error) {
    logger.error("Error fetching plans:", { error: error.message });
    res.status(500).json({
      success: false,
      message: "Failed to fetch subscription plans",
      error: error.message,
    });
  }
});

// GET /subscriptions/organization/:orgId - Get subscription for an organization
app.get(
  "/subscriptions/organization/:orgId",
  ensureDBConnection,
  authenticateUser,
  async (req, res) => {
    try {
      const { orgId } = req.params;

      if (!ObjectId.isValid(orgId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid organization ID",
        });
      }

      const subscription = await subscriptionsCollection.findOne({
        organizationId: new ObjectId(orgId),
      });

      if (!subscription) {
        return res.status(404).json({
          success: false,
          message: "Subscription not found for this organization",
        });
      }

      // Enrich with plan details
      const plan = await subscriptionPlansCollection.findOne({
        tier: subscription.tier,
      });

      res.json({
        success: true,
        data: {
          ...subscription,
          planDetails: plan || null,
        },
      });
    } catch (error) {
      logger.error("Error fetching organization subscription:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch subscription",
        error: error.message,
      });
    }
  }
);

// GET /subscriptions/my-request - Get the current org's pending subscription request
app.get(
  "/subscriptions/my-request",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  async (req, res) => {
    try {
      if (req.userRole !== "org_owner") {
        return res.status(403).json({
          success: false,
          message: "Only organization owners can access subscription requests",
        });
      }

      const request = await subscriptionRequestsCollection.findOne(
        { organizationId: new ObjectId(req.organizationId) },
        { sort: { createdAt: -1 } }
      );

      res.json({
        success: true,
        data: request || null,
      });
    } catch (error) {
      logger.error("Error fetching subscription request:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch subscription request",
        error: error.message,
      });
    }
  }
);

// POST /subscriptions/request - Submit a subscription upgrade/downgrade request
app.post(
  "/subscriptions/request",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  async (req, res) => {
    try {
      if (req.userRole !== "org_owner") {
        return res.status(403).json({
          success: false,
          message: "Only organization owners can request subscription changes",
        });
      }

      const { requestedTier, requestedBillingCycle = "monthly", reason } =
        req.body;

      if (!requestedTier) {
        return res.status(400).json({
          success: false,
          message: "Requested tier is required",
        });
      }

      const validTiers = ["free", "basic", "professional", "enterprise"];
      if (!validTiers.includes(requestedTier)) {
        return res.status(400).json({
          success: false,
          message: "Invalid tier. Must be one of: free, basic, professional, enterprise",
        });
      }

      const validCycles = ["monthly", "yearly"];
      if (!validCycles.includes(requestedBillingCycle)) {
        return res.status(400).json({
          success: false,
          message: "Invalid billing cycle. Must be monthly or yearly",
        });
      }

      // Get current subscription
      const subscription = await subscriptionsCollection.findOne({
        organizationId: new ObjectId(req.organizationId),
      });

      if (!subscription) {
        return res.status(404).json({
          success: false,
          message: "Current subscription not found",
        });
      }

      if (subscription.tier === requestedTier) {
        return res.status(400).json({
          success: false,
          message: "You are already on this plan",
        });
      }

      // Check if there's already a pending request
      const existingRequest = await subscriptionRequestsCollection.findOne({
        organizationId: new ObjectId(req.organizationId),
        status: "pending",
      });

      if (existingRequest) {
        return res.status(400).json({
          success: false,
          message:
            "You already have a pending subscription request. Please wait for it to be reviewed.",
        });
      }

      const request = {
        organizationId: new ObjectId(req.organizationId),
        requestedBy: new ObjectId(req.userId),
        currentTier: subscription.tier,
        requestedTier,
        requestedBillingCycle,
        status: "pending",
        reason: reason || "",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // Use replaceOne + upsert to handle the unique index on organizationId.
      // An org can only have one request document at a time; approved/rejected
      // requests get replaced when a new request is submitted.
      const result = await subscriptionRequestsCollection.findOneAndReplace(
        { organizationId: req.organizationObjectId },
        request,
        { upsert: true, returnDocument: "after" }
      );

      const savedId = result?._id || new ObjectId(req.organizationId);

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "subscription_request",
        savedId,
        { currentTier: subscription.tier, requestedTier, requestedBillingCycle },
        req
      );

      res.status(201).json({
        success: true,
        message:
          "Subscription request submitted successfully. Our team will review it shortly.",
        data: { _id: savedId, ...request },
      });
    } catch (error) {
      logger.error("Error creating subscription request:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to submit subscription request",
        error: error.message,
      });
    }
  }
);

// --- Organization Endpoints ---

// POST /organizations - Public signup
app.post("/organizations", ensureDBConnection, async (req, res) => {
  try {
    const {
      name,
      slug,
      email,
      phone,
      address,
      ownerName,
      ownerEmail,
      ownerPassword,
      ownerPhotoURL,
      ownerFirebaseUid,
    } = req.body;

    if (!name || !slug || !email || !ownerEmail) {
      return res.status(400).json({
        success: false,
        message:
          "Required fields missing: name, slug, email, ownerEmail",
      });
    }

    // Check uniqueness
    const existing = await organizationsCollection.findOne({
      $or: [{ slug }, { email }],
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message:
          "Organization with this slug or email already exists",
      });
    }

    // Create organization
    const organization = {
      name,
      slug,
      email,
      phone: phone || "",
      address: address || "",
      logo: "",
      subscriptionStatus: "trial",
      subscriptionTier: "free",
      limits: {
        maxStudents: 50,
        maxClasses: 5,
        maxTeachers: 3,
        maxStorage: 100,
      },
      usage: {
        currentStudents: 0,
        currentClasses: 0,
        currentTeachers: 0,
        storageUsed: 0,
      },
      settings: {
        timezone: "Asia/Dhaka",
        currency: "BDT",
        language: "en",
        dateFormat: "DD/MM/YYYY",
        academicYearStart: "January",
      },
      branding: {
        primaryColor: "#3B82F6",
        secondaryColor: "#10B981",
      },
      ownerId: null,
      status: "active",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const orgResult = await organizationsCollection.insertOne(organization);
    const organizationId = orgResult.insertedId;

    // Check if owner user already exists
    let existingUser = await usersCollection.findOne({
      email: ownerEmail,
    });
    let ownerId;

    if (existingUser) {
      await usersCollection.updateOne(
        { _id: existingUser._id },
        {
          $set: {
            organizationId,
            role: "org_owner",
            permissions: ["all"],
            photoURL:
              ownerPhotoURL || existingUser.photoURL || "",
            ...(ownerFirebaseUid && { firebaseUid: ownerFirebaseUid }),
            status: "active",
            updatedAt: new Date(),
          },
        }
      );
      ownerId = existingUser._id;
    } else {
      const owner = {
        name: ownerName || "Owner",
        email: ownerEmail,
        phone: phone || "",
        password: ownerPassword || "",
        photoURL: ownerPhotoURL || "",
        ...(ownerFirebaseUid && { firebaseUid: ownerFirebaseUid }),
        organizationId,
        role: "org_owner",
        permissions: ["all"],
        isSuperAdmin: false,
        status: "active",
        emailVerified: false,
        lastLogin: null,
        lastActivity: new Date(),
        preferences: {
          language: "en",
          theme: "light",
          notifications: {
            email: true,
            sms: false,
            push: true,
          },
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const userResult = await usersCollection.insertOne(owner);
      ownerId = userResult.insertedId;
    }

    // Update organization with ownerId
    await organizationsCollection.updateOne(
      { _id: organizationId },
      { $set: { ownerId } }
    );

    // Create trial subscription
    const subscription = {
      organizationId,
      tier: "free",
      status: "trial",
      billingCycle: "monthly",
      amount: 0,
      currency: "BDT",
      trialStartDate: new Date(),
      trialEndDate: new Date(
        Date.now() + 14 * 24 * 60 * 60 * 1000
      ),
      isTrialUsed: true,
      currentPeriodStart: new Date(),
      currentPeriodEnd: new Date(
        Date.now() + 14 * 24 * 60 * 60 * 1000
      ),
      nextBillingDate: new Date(
        Date.now() + 14 * 24 * 60 * 60 * 1000
      ),
      cancelAtPeriodEnd: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    await subscriptionsCollection.insertOne(subscription);

    logger.info("Organization created:", { organizationId, slug });

    res.status(201).json({
      success: true,
      message: "Organization created successfully",
      data: {
        organizationId,
        slug,
        ownerId,
      },
    });
  } catch (error) {
    logger.error("Error creating organization:", {
      error: error.message,
      stack: error.stack,
    });
    res.status(500).json({
      success: false,
      message: "Failed to create organization",
      error: error.message,
    });
  }
});

// GET /organizations/:id
app.get(
  "/organizations/:id",
  ensureDBConnection,
  authenticateUser,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid organization ID",
        });
      }

      const organization = await organizationsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!organization) {
        return res.status(404).json({
          success: false,
          message: "Organization not found",
        });
      }

      // Verify access
      if (
        !req.user.isSuperAdmin &&
        req.userRole !== "super_admin" &&
        String(req.organizationId) !== String(organization._id)
      ) {
        return res.status(403).json({
          success: false,
          message: "Access denied",
        });
      }

      res.json({
        success: true,
        data: organization,
      });
    } catch (error) {
      logger.error("Error fetching organization:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch organization",
        error: error.message,
      });
    }
  }
);

// PATCH /organizations/:id
app.patch(
  "/organizations/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_org_settings"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid organization ID",
        });
      }

      // Only allow specific fields to be updated
      const allowedFields = [
        "name",
        "phone",
        "address",
        "logo",
        "settings",
        "branding",
      ];
      const updates = {};

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      updates.updatedAt = new Date();

      const result = await organizationsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Organization not found",
        });
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "organization",
        id,
        { after: updates },
        req
      );

      const updated = await organizationsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Organization updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating organization:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to update organization",
        error: error.message,
      });
    }
  }
);

// GET /organizations/:id/stats
app.get(
  "/organizations/:id/stats",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  async (req, res) => {
    try {
      const { id } = req.params;

      const organization = await organizationsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!organization) {
        return res.status(404).json({
          success: false,
          message: "Organization not found",
        });
      }

      const orgObjectId = new ObjectId(id);

      // Fetch real counts from Phase 2 collections in parallel
      const [
        userCount,
        studentCount,
        teacherCount,
        classCount,
        sectionCount,
        subjectCount,
        parentCount,
      ] = await Promise.all([
        usersCollection.countDocuments({
          organizationId: orgObjectId,
          status: "active",
        }),
        studentsCollection.countDocuments({
          organizationId: orgObjectId,
          status: { $in: ["active"] },
        }),
        teachersCollection.countDocuments({
          organizationId: orgObjectId,
          status: "active",
        }),
        classesCollection.countDocuments({
          organizationId: orgObjectId,
          status: "active",
        }),
        sectionsCollection.countDocuments({
          organizationId: orgObjectId,
        }),
        subjectsCollection.countDocuments({
          organizationId: orgObjectId,
        }),
        parentsCollection.countDocuments({
          organizationId: orgObjectId,
        }),
      ]);

      res.json({
        success: true,
        data: {
          usage: organization.usage,
          limits: organization.limits,
          totalUsers: userCount,
          totalStudents: studentCount,
          totalTeachers: teacherCount,
          totalClasses: classCount,
          totalSections: sectionCount,
          totalSubjects: subjectCount,
          totalParents: parentCount,
          subscriptionStatus: organization.subscriptionStatus,
          subscriptionTier: organization.subscriptionTier,
        },
      });
    } catch (error) {
      logger.error("Error fetching org stats:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch organization statistics",
        error: error.message,
      });
    }
  }
);

// --- User Endpoints ---

// POST /users/register - Public registration
app.post("/users/register", ensureDBConnection, async (req, res) => {
  try {
    const { name, email, password, phone, firebaseUid, photoURL } =
      req.body;

    if (!name || !email) {
      return res.status(400).json({
        success: false,
        message: "Name and email are required",
      });
    }

    // Check if user already exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(200).json({
        success: true,
        data: existingUser,
        message: "User already exists",
      });
    }

    const newUser = {
      name,
      email,
      password: password || "",
      phone: phone || "",
      ...(firebaseUid && { firebaseUid }),
      photoURL: photoURL || "",
      organizationId: null,
      role: null,
      permissions: [],
      isSuperAdmin: false,
      status: "active",
      emailVerified: false,
      lastLogin: new Date(),
      lastActivity: new Date(),
      preferences: {
        language: "en",
        theme: "light",
        notifications: {
          email: true,
          sms: false,
          push: true,
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await usersCollection.insertOne(newUser);
    const createdUser = await usersCollection.findOne({
      _id: result.insertedId,
    });

    logger.info("User registered:", { email });

    res.status(201).json({
      success: true,
      data: createdUser,
      message: "User registered successfully",
    });
  } catch (error) {
    logger.error("Registration error:", {
      error: error.message,
      stack: error.stack,
    });
    res.status(500).json({
      success: false,
      message: "Failed to register user",
      error: error.message,
    });
  }
});

// GET /users/me - Get current user
app.get(
  "/users/me",
  ensureDBConnection,
  authenticateUser,
  async (req, res) => {
    try {
      // Update lastActivity
      await usersCollection.updateOne(
        { _id: req.userId },
        { $set: { lastActivity: new Date() } }
      );

      // Exclude password from response
      const { password, ...userData } = req.user;

      res.json({
        success: true,
        data: userData,
      });
    } catch (error) {
      logger.error("Error fetching current user:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch user data",
        error: error.message,
      });
    }
  }
);

// GET /users - List organization users
app.get(
  "/users",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_users"),
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 10,
        role,
        status,
        search,
      } = req.query;

      const query = {
        organizationId: req.organizationId,
        status: { $ne: "deleted" },
      };

      if (role) query.role = role;
      if (status) query.status = status;
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
        ];
      }

      const users = await usersCollection
        .find(query)
        .project({ password: 0 })
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ createdAt: -1 })
        .toArray();

      const total = await usersCollection.countDocuments(query);

      res.json({
        success: true,
        data: users,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching users:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch users",
        error: error.message,
      });
    }
  }
);

// POST /users/invite - Invite user to organization
app.post(
  "/users/invite",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("invite_users"),
  async (req, res) => {
    try {
      const { email, role, name } = req.body;

      if (!email || !role) {
        return res.status(400).json({
          success: false,
          message: "Email and role are required",
        });
      }

      const validRoles = [
        "admin",
        "moderator",
        "teacher",
        "student",
        "parent",
      ];
      if (!validRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          message: `Invalid role. Must be one of: ${validRoles.join(", ")}`,
        });
      }

      // Check usage limits for teachers
      if (role === "teacher") {
        const limitCheck = await checkUsageLimits(
          req.organizationId,
          "teachers"
        );
        if (!limitCheck.allowed) {
          return res.status(403).json({
            success: false,
            message: limitCheck.message,
          });
        }
      }

      // Check if user exists
      let existingUser = await usersCollection.findOne({ email });

      if (existingUser) {
        if (existingUser.organizationId) {
          return res.status(409).json({
            success: false,
            message:
              "User already belongs to an organization",
          });
        }

        // Assign to this organization
        await usersCollection.updateOne(
          { _id: existingUser._id },
          {
            $set: {
              organizationId: req.organizationId,
              role,
              permissions: ROLE_PERMISSIONS[role] || [],
              status: "active",
              updatedAt: new Date(),
            },
          }
        );

        // Update usage counter for teachers
        if (role === "teacher") {
          await organizationsCollection.updateOne(
            { _id: new ObjectId(req.organizationId) },
            { $inc: { "usage.currentTeachers": 1 } }
          );
        }

        await logActivity(
          req.userId,
          req.organizationId,
          "invited",
          "user",
          existingUser._id,
          { role },
          req
        );

        const updatedUser = await usersCollection.findOne({
          _id: existingUser._id,
        });

        return res.json({
          success: true,
          message: "User invited successfully",
          data: updatedUser,
        });
      }

      // Create new user with organization
      const newUser = {
        name: name || "Invited User",
        email,
        password: "",
        phone: "",
        // firebaseUid omitted - sparse index will skip this document
        photoURL: "",
        organizationId: req.organizationId,
        role,
        permissions: ROLE_PERMISSIONS[role] || [],
        isSuperAdmin: false,
        status: "active",
        emailVerified: false,
        lastLogin: null,
        lastActivity: null,
        preferences: {
          language: "en",
          theme: "light",
          notifications: {
            email: true,
            sms: false,
            push: true,
          },
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await usersCollection.insertOne(newUser);

      // Update usage counter for teachers
      if (role === "teacher") {
        await organizationsCollection.updateOne(
          { _id: new ObjectId(req.organizationId) },
          { $inc: { "usage.currentTeachers": 1 } }
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "invited",
        "user",
        result.insertedId,
        { role, email },
        req
      );

      const createdUser = await usersCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "User invited successfully",
        data: createdUser,
      });
    } catch (error) {
      logger.error("Error inviting user:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to invite user",
        error: error.message,
      });
    }
  }
);

// PATCH /users/:id/role - Update user role
app.patch(
  "/users/:id/role",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_users"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid user ID",
        });
      }

      if (!role) {
        return res.status(400).json({
          success: false,
          message: "Role is required",
        });
      }

      const validRoles = [
        "admin",
        "moderator",
        "teacher",
        "student",
        "parent",
      ];
      if (!validRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          message: `Invalid role. Must be one of: ${validRoles.join(", ")}`,
        });
      }

      // Cannot change own role
      if (String(req.userId) === id) {
        return res.status(400).json({
          success: false,
          message: "Cannot change your own role",
        });
      }

      const targetUser = await usersCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: "User not found in your organization",
        });
      }

      // Cannot change org_owner role unless you are org_owner
      if (
        targetUser.role === "org_owner" &&
        req.userRole !== "org_owner"
      ) {
        return res.status(403).json({
          success: false,
          message: "Cannot change organization owner role",
        });
      }

      const previousRole = targetUser.role;

      await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            role,
            permissions: ROLE_PERMISSIONS[role] || [],
            updatedAt: new Date(),
          },
        }
      );

      // Update usage counters
      if (previousRole === "teacher" && role !== "teacher") {
        await organizationsCollection.updateOne(
          { _id: new ObjectId(req.organizationId) },
          { $inc: { "usage.currentTeachers": -1 } }
        );
      } else if (previousRole !== "teacher" && role === "teacher") {
        const limitCheck = await checkUsageLimits(
          req.organizationId,
          "teachers"
        );
        if (!limitCheck.allowed) {
          // Revert
          await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            {
              $set: {
                role: previousRole,
                permissions:
                  ROLE_PERMISSIONS[previousRole] || [],
                updatedAt: new Date(),
              },
            }
          );
          return res.status(403).json({
            success: false,
            message: limitCheck.message,
          });
        }
        await organizationsCollection.updateOne(
          { _id: new ObjectId(req.organizationId) },
          { $inc: { "usage.currentTeachers": 1 } }
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "user",
        id,
        {
          before: { role: previousRole },
          after: { role },
        },
        req
      );

      const updatedUser = await usersCollection.findOne({
        _id: new ObjectId(id),
      });
      const { password, ...userData } = updatedUser;

      res.json({
        success: true,
        message: "User role updated successfully",
        data: userData,
      });
    } catch (error) {
      logger.error("Error updating user role:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to update user role",
        error: error.message,
      });
    }
  }
);

// DELETE /users/:id - Remove user from organization
app.delete(
  "/users/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_users"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid user ID",
        });
      }

      // Cannot delete self
      if (String(req.userId) === id) {
        return res.status(400).json({
          success: false,
          message: "Cannot remove yourself",
        });
      }

      const targetUser = await usersCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: "User not found in your organization",
        });
      }

      // Cannot delete org_owner
      if (targetUser.role === "org_owner") {
        return res.status(403).json({
          success: false,
          message: "Cannot remove the organization owner",
        });
      }

      // Remove from organization
      await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            organizationId: null,
            role: null,
            permissions: [],
            status: "inactive",
            updatedAt: new Date(),
          },
        }
      );

      // Decrement usage counters
      if (targetUser.role === "teacher") {
        await organizationsCollection.updateOne(
          { _id: new ObjectId(req.organizationId) },
          { $inc: { "usage.currentTeachers": -1 } }
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "removed",
        "user",
        id,
        {
          before: {
            role: targetUser.role,
            email: targetUser.email,
          },
        },
        req
      );

      res.json({
        success: true,
        message: "User removed from organization",
      });
    } catch (error) {
      logger.error("Error removing user:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to remove user",
        error: error.message,
      });
    }
  }
);

// ==================== PHASE 2: ACADEMIC STRUCTURE & PEOPLE MANAGEMENT ====================

// --- Classes Endpoints ---

// GET /classes - List classes (org-scoped)
app.get(
  "/classes",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_classes"),
  async (req, res) => {
    try {
      const { academicYear, status, search } = req.query;

      const query = {
        organizationId: req.organizationId,
      };

      if (academicYear) query.academicYear = academicYear;
      if (status) query.status = status;
      if (search) {
        query.name = { $regex: search, $options: "i" };
      }

      const classes = await classesCollection
        .find(query)
        .sort({ numericLevel: 1 })
        .toArray();

      res.json({
        success: true,
        data: classes,
      });
    } catch (error) {
      logger.error("Error fetching classes:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch classes",
        error: error.message,
      });
    }
  }
);

// POST /classes - Create class
app.post(
  "/classes",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_classes"),
  async (req, res) => {
    try {
      const { name, numericLevel, academicYear, status } = req.body;

      if (!name || numericLevel === undefined || !academicYear) {
        return res.status(400).json({
          success: false,
          message: "Required fields: name, numericLevel, academicYear",
        });
      }

      // Check usage limits
      const limitCheck = await checkUsageLimits(
        req.organizationId,
        "classes"
      );
      if (!limitCheck.allowed) {
        return res.status(403).json({
          success: false,
          message: limitCheck.message,
        });
      }

      // Check duplicate class name in same org and academic year
      const existing = await classesCollection.findOne({
        organizationId: req.organizationId,
        name,
        academicYear,
      });

      if (existing) {
        return res.status(409).json({
          success: false,
          message: "A class with this name already exists for this academic year",
        });
      }

      const newClass = {
        organizationId: req.organizationId,
        name,
        numericLevel: Number(numericLevel),
        academicYear,
        status: status || "active",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await classesCollection.insertOne(newClass);

      // Increment usage counter
      await organizationsCollection.updateOne(
        { _id: new ObjectId(req.organizationId) },
        { $inc: { "usage.currentClasses": 1 } }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "class",
        result.insertedId,
        { after: newClass },
        req
      );

      const created = await classesCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "Class created successfully",
        data: created,
      });
    } catch (error) {
      logger.error("Error creating class:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to create class",
        error: error.message,
      });
    }
  }
);

// PATCH /classes/:id - Update class
app.patch(
  "/classes/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_classes"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid class ID",
        });
      }

      const allowedFields = ["name", "numericLevel", "academicYear", "status"];
      const updates = {};

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = field === "numericLevel"
            ? Number(req.body[field])
            : req.body[field];
        }
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      updates.updatedAt = new Date();

      const result = await classesCollection.updateOne(
        { _id: new ObjectId(id), organizationId: req.organizationId },
        { $set: updates }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Class not found",
        });
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "class",
        id,
        { after: updates },
        req
      );

      const updated = await classesCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Class updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating class:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update class",
        error: error.message,
      });
    }
  }
);

// DELETE /classes/:id - Delete class (CASCADE)
app.delete(
  "/classes/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_classes"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid class ID",
        });
      }

      const classDoc = await classesCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!classDoc) {
        return res.status(404).json({
          success: false,
          message: "Class not found",
        });
      }

      // Count students in this class for usage decrement
      const studentCount = await studentsCollection.countDocuments({
        organizationId: req.organizationId,
        classId: new ObjectId(id),
        status: { $ne: "dropped" },
      });

      // Cascade: soft-delete students in this class
      if (studentCount > 0) {
        await studentsCollection.updateMany(
          {
            organizationId: req.organizationId,
            classId: new ObjectId(id),
            status: { $ne: "dropped" },
          },
          {
            $set: { status: "dropped", updatedAt: new Date() },
          }
        );
      }

      // Cascade: delete sections
      await sectionsCollection.deleteMany({
        organizationId: req.organizationId,
        classId: new ObjectId(id),
      });

      // Cascade: delete subjects and clean up teacher references
      const subjects = await subjectsCollection
        .find({
          organizationId: req.organizationId,
          classId: new ObjectId(id),
        })
        .toArray();

      for (const subject of subjects) {
        if (subject.teacherId) {
          await teachersCollection.updateOne(
            { _id: new ObjectId(subject.teacherId) },
            {
              $pull: {
                subjects: new ObjectId(subject._id),
                classes: new ObjectId(id),
              },
            }
          );
        }
      }

      await subjectsCollection.deleteMany({
        organizationId: req.organizationId,
        classId: new ObjectId(id),
      });

      // Delete the class
      await classesCollection.deleteOne({ _id: new ObjectId(id) });

      // Decrement usage counters
      await organizationsCollection.updateOne(
        { _id: new ObjectId(req.organizationId) },
        {
          $inc: {
            "usage.currentClasses": -1,
            "usage.currentStudents": -studentCount,
          },
        }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "class",
        id,
        { before: { name: classDoc.name, studentCount } },
        req
      );

      res.json({
        success: true,
        message: `Class deleted. Cascaded: ${studentCount} students dropped, sections and subjects removed.`,
      });
    } catch (error) {
      logger.error("Error deleting class:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to delete class",
        error: error.message,
      });
    }
  }
);

// --- Sections Endpoints ---

// GET /sections - List sections
app.get(
  "/sections",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_sections"),
  async (req, res) => {
    try {
      const { classId, status } = req.query;

      const query = {
        organizationId: req.organizationId,
      };

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid classId",
          });
        }
        query.classId = new ObjectId(classId);
      }

      if (status) {
        query.status = status;
      }

      const sections = await sectionsCollection
        .find(query)
        .sort({ name: 1 })
        .toArray();

      // Populate class names
      const classIds = [...new Set(sections.map((s) => String(s.classId)))];
      const classes = await classesCollection
        .find({
          _id: { $in: classIds.map((cid) => new ObjectId(cid)) },
        })
        .toArray();

      const classMap = {};
      classes.forEach((c) => {
        classMap[String(c._id)] = c.name;
      });

      const enrichedSections = sections.map((s) => ({
        ...s,
        className: classMap[String(s.classId)] || "Unknown",
      }));

      res.json({
        success: true,
        data: enrichedSections,
      });
    } catch (error) {
      logger.error("Error fetching sections:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch sections",
        error: error.message,
      });
    }
  }
);

// POST /sections - Create section
app.post(
  "/sections",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_sections"),
  async (req, res) => {
    try {
      const { name, classId, capacity, classTeacherId, status } = req.body;

      if (!name || !classId) {
        return res.status(400).json({
          success: false,
          message: "Required fields: name, classId",
        });
      }

      if (!ObjectId.isValid(classId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid classId",
        });
      }

      // Validate class exists in org
      const classDoc = await classesCollection.findOne({
        _id: new ObjectId(classId),
        organizationId: req.organizationId,
      });

      if (!classDoc) {
        return res.status(404).json({
          success: false,
          message: "Class not found in your organization",
        });
      }

      // Check duplicate section name in same class
      const existing = await sectionsCollection.findOne({
        organizationId: req.organizationId,
        classId: new ObjectId(classId),
        name,
      });

      if (existing) {
        return res.status(409).json({
          success: false,
          message: "A section with this name already exists in this class",
        });
      }

      // Validate classTeacherId if provided
      if (classTeacherId) {
        if (!ObjectId.isValid(classTeacherId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid classTeacherId",
          });
        }
        const teacher = await teachersCollection.findOne({
          _id: new ObjectId(classTeacherId),
          organizationId: req.organizationId,
        });
        if (!teacher) {
          return res.status(404).json({
            success: false,
            message: "Teacher not found in your organization",
          });
        }
      }

      const newSection = {
        organizationId: req.organizationId,
        name,
        classId: new ObjectId(classId),
        capacity: capacity ? Number(capacity) : 40,
        classTeacherId: classTeacherId ? new ObjectId(classTeacherId) : null,
        status: status || "active",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await sectionsCollection.insertOne(newSection);

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "section",
        result.insertedId,
        { after: { name, classId, className: classDoc.name } },
        req
      );

      const created = await sectionsCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "Section created successfully",
        data: { ...created, className: classDoc.name },
      });
    } catch (error) {
      logger.error("Error creating section:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to create section",
        error: error.message,
      });
    }
  }
);

// PATCH /sections/:id - Update section
app.patch(
  "/sections/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_sections"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid section ID",
        });
      }

      const allowedFields = ["name", "capacity", "classTeacherId", "status"];
      const updates = {};

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          if (field === "classTeacherId") {
            if (req.body[field] === null || req.body[field] === "") {
              updates[field] = null;
            } else {
              if (!ObjectId.isValid(req.body[field])) {
                return res.status(400).json({
                  success: false,
                  message: "Invalid classTeacherId",
                });
              }
              updates[field] = new ObjectId(req.body[field]);
            }
          } else if (field === "capacity") {
            updates[field] = Number(req.body[field]);
          } else {
            updates[field] = req.body[field];
          }
        }
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      updates.updatedAt = new Date();

      const result = await sectionsCollection.updateOne(
        { _id: new ObjectId(id), organizationId: req.organizationId },
        { $set: updates }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Section not found",
        });
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "section",
        id,
        { after: updates },
        req
      );

      const updated = await sectionsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Section updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating section:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update section",
        error: error.message,
      });
    }
  }
);

// DELETE /sections/:id - Delete section
app.delete(
  "/sections/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_sections"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid section ID",
        });
      }

      const section = await sectionsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!section) {
        return res.status(404).json({
          success: false,
          message: "Section not found",
        });
      }

      // Check for students in this section
      const studentCount = await studentsCollection.countDocuments({
        organizationId: req.organizationId,
        sectionId: new ObjectId(id),
        status: { $ne: "dropped" },
      });

      if (studentCount > 0) {
        return res.status(400).json({
          success: false,
          message: `Cannot delete section with ${studentCount} active students. Reassign or remove students first.`,
        });
      }

      await sectionsCollection.deleteOne({ _id: new ObjectId(id) });

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "section",
        id,
        { before: { name: section.name, classId: section.classId } },
        req
      );

      res.json({
        success: true,
        message: "Section deleted successfully",
      });
    } catch (error) {
      logger.error("Error deleting section:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to delete section",
        error: error.message,
      });
    }
  }
);

// --- Subjects Endpoints ---

// GET /subjects - List subjects
app.get(
  "/subjects",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_subjects"),
  async (req, res) => {
    try {
      const { classId, teacherId } = req.query;

      const query = {
        organizationId: req.organizationId,
      };

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid classId",
          });
        }
        query.classId = new ObjectId(classId);
      }

      if (teacherId) {
        if (!ObjectId.isValid(teacherId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid teacherId",
          });
        }
        query.teacherId = new ObjectId(teacherId);
      }

      const subjects = await subjectsCollection
        .find(query)
        .sort({ name: 1 })
        .toArray();

      // Populate class and teacher names
      const classIds = [...new Set(subjects.map((s) => String(s.classId)))];
      const teacherIds = [
        ...new Set(
          subjects.filter((s) => s.teacherId).map((s) => String(s.teacherId))
        ),
      ];

      const classes = await classesCollection
        .find({
          _id: { $in: classIds.map((cid) => new ObjectId(cid)) },
        })
        .toArray();

      const teachers = teacherIds.length
        ? await teachersCollection
            .find({
              _id: { $in: teacherIds.map((tid) => new ObjectId(tid)) },
            })
            .toArray()
        : [];

      // Get user names for teachers
      const teacherUserIds = teachers
        .filter((t) => t.userId)
        .map((t) => new ObjectId(t.userId));
      const teacherUsers = teacherUserIds.length
        ? await usersCollection
            .find({ _id: { $in: teacherUserIds } })
            .project({ name: 1 })
            .toArray()
        : [];

      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));

      const teacherUserMap = {};
      teacherUsers.forEach((u) => (teacherUserMap[String(u._id)] = u.name));

      const teacherMap = {};
      teachers.forEach((t) => {
        teacherMap[String(t._id)] =
          teacherUserMap[String(t.userId)] || "Unknown";
      });

      const enrichedSubjects = subjects.map((s) => ({
        ...s,
        className: classMap[String(s.classId)] || "Unknown",
        teacherName: s.teacherId
          ? teacherMap[String(s.teacherId)] || "Unassigned"
          : "Unassigned",
      }));

      res.json({
        success: true,
        data: enrichedSubjects,
      });
    } catch (error) {
      logger.error("Error fetching subjects:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch subjects",
        error: error.message,
      });
    }
  }
);

// POST /subjects - Create subject
app.post(
  "/subjects",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_subjects"),
  async (req, res) => {
    try {
      const {
        name,
        subjectCode,
        classId,
        teacherId,
        type,
        fullMarks,
        passMarks,
      } = req.body;

      if (!name || !classId) {
        return res.status(400).json({
          success: false,
          message: "Required fields: name, classId",
        });
      }

      if (!ObjectId.isValid(classId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid classId",
        });
      }

      // Validate class exists
      const classDoc = await classesCollection.findOne({
        _id: new ObjectId(classId),
        organizationId: req.organizationId,
      });

      if (!classDoc) {
        return res.status(404).json({
          success: false,
          message: "Class not found in your organization",
        });
      }

      // Validate teacher if provided
      let teacherDoc = null;
      if (teacherId) {
        if (!ObjectId.isValid(teacherId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid teacherId",
          });
        }
        teacherDoc = await teachersCollection.findOne({
          _id: new ObjectId(teacherId),
          organizationId: req.organizationId,
        });
        if (!teacherDoc) {
          return res.status(404).json({
            success: false,
            message: "Teacher not found in your organization",
          });
        }
      }

      // Check duplicate subject code in same class
      if (subjectCode) {
        const existing = await subjectsCollection.findOne({
          organizationId: req.organizationId,
          classId: new ObjectId(classId),
          subjectCode,
        });
        if (existing) {
          return res.status(409).json({
            success: false,
            message: "A subject with this code already exists in this class",
          });
        }
      }

      const newSubject = {
        organizationId: req.organizationId,
        name,
        subjectCode: subjectCode || "",
        classId: new ObjectId(classId),
        teacherId: teacherId ? new ObjectId(teacherId) : null,
        type: type || "mandatory",
        fullMarks: fullMarks ? Number(fullMarks) : 100,
        passMarks: passMarks ? Number(passMarks) : 33,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await subjectsCollection.insertOne(newSubject);

      // Update teacher's subjects[] and classes[] arrays
      if (teacherId && teacherDoc) {
        const updateOps = {
          $addToSet: {
            subjects: result.insertedId,
          },
        };
        // Add class to teacher's classes if not already there
        if (
          !teacherDoc.classes ||
          !teacherDoc.classes.some(
            (c) => String(c) === String(classId)
          )
        ) {
          updateOps.$addToSet.classes = new ObjectId(classId);
        }
        await teachersCollection.updateOne(
          { _id: new ObjectId(teacherId) },
          updateOps
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "subject",
        result.insertedId,
        { after: { name, classId, teacherId } },
        req
      );

      const created = await subjectsCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "Subject created successfully",
        data: { ...created, className: classDoc.name },
      });
    } catch (error) {
      logger.error("Error creating subject:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to create subject",
        error: error.message,
      });
    }
  }
);

// PATCH /subjects/:id - Update subject
app.patch(
  "/subjects/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_subjects"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid subject ID",
        });
      }

      const existingSubject = await subjectsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!existingSubject) {
        return res.status(404).json({
          success: false,
          message: "Subject not found",
        });
      }

      const allowedFields = [
        "name",
        "subjectCode",
        "teacherId",
        "type",
        "fullMarks",
        "passMarks",
      ];
      const updates = {};

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          if (field === "teacherId") {
            if (req.body[field] === null || req.body[field] === "") {
              updates[field] = null;
            } else {
              if (!ObjectId.isValid(req.body[field])) {
                return res.status(400).json({
                  success: false,
                  message: "Invalid teacherId",
                });
              }
              // Validate new teacher exists
              const newTeacher = await teachersCollection.findOne({
                _id: new ObjectId(req.body[field]),
                organizationId: req.organizationId,
              });
              if (!newTeacher) {
                return res.status(404).json({
                  success: false,
                  message: "Teacher not found in your organization",
                });
              }
              updates[field] = new ObjectId(req.body[field]);
            }
          } else if (field === "fullMarks" || field === "passMarks") {
            updates[field] = Number(req.body[field]);
          } else {
            updates[field] = req.body[field];
          }
        }
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      // Handle teacher change: update old and new teacher arrays
      if (
        updates.teacherId !== undefined &&
        String(updates.teacherId) !== String(existingSubject.teacherId)
      ) {
        // Remove from old teacher
        if (existingSubject.teacherId) {
          await teachersCollection.updateOne(
            { _id: new ObjectId(existingSubject.teacherId) },
            { $pull: { subjects: new ObjectId(id) } }
          );
          // Check if old teacher still has subjects in this class
          const oldTeacherSubjectsInClass =
            await subjectsCollection.countDocuments({
              organizationId: req.organizationId,
              classId: existingSubject.classId,
              teacherId: existingSubject.teacherId,
              _id: { $ne: new ObjectId(id) },
            });
          if (oldTeacherSubjectsInClass === 0) {
            await teachersCollection.updateOne(
              { _id: new ObjectId(existingSubject.teacherId) },
              { $pull: { classes: existingSubject.classId } }
            );
          }
        }
        // Add to new teacher
        if (updates.teacherId) {
          await teachersCollection.updateOne(
            { _id: new ObjectId(updates.teacherId) },
            {
              $addToSet: {
                subjects: new ObjectId(id),
                classes: existingSubject.classId,
              },
            }
          );
        }
      }

      updates.updatedAt = new Date();

      await subjectsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "subject",
        id,
        { after: updates },
        req
      );

      const updated = await subjectsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Subject updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating subject:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update subject",
        error: error.message,
      });
    }
  }
);

// DELETE /subjects/:id - Delete subject
app.delete(
  "/subjects/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_subjects"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid subject ID",
        });
      }

      const subject = await subjectsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!subject) {
        return res.status(404).json({
          success: false,
          message: "Subject not found",
        });
      }

      // Remove from teacher's subjects[] array
      if (subject.teacherId) {
        await teachersCollection.updateOne(
          { _id: new ObjectId(subject.teacherId) },
          { $pull: { subjects: new ObjectId(id) } }
        );
        // Check if teacher still has other subjects in this class
        const teacherSubjectsInClass =
          await subjectsCollection.countDocuments({
            organizationId: req.organizationId,
            classId: subject.classId,
            teacherId: subject.teacherId,
            _id: { $ne: new ObjectId(id) },
          });
        if (teacherSubjectsInClass === 0) {
          await teachersCollection.updateOne(
            { _id: new ObjectId(subject.teacherId) },
            { $pull: { classes: subject.classId } }
          );
        }
      }

      await subjectsCollection.deleteOne({ _id: new ObjectId(id) });

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "subject",
        id,
        { before: { name: subject.name, classId: subject.classId } },
        req
      );

      res.json({
        success: true,
        message: "Subject deleted successfully",
      });
    } catch (error) {
      logger.error("Error deleting subject:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to delete subject",
        error: error.message,
      });
    }
  }
);

// --- Students Endpoints ---

// GET /students - List students
app.get(
  "/students",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_students"),
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 10,
        classId,
        sectionId,
        status,
        academicYear,
        search,
      } = req.query;

      const query = {
        organizationId: req.organizationId,
      };

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid classId",
          });
        }
        query.classId = new ObjectId(classId);
      }
      if (sectionId) {
        if (!ObjectId.isValid(sectionId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid sectionId",
          });
        }
        query.sectionId = new ObjectId(sectionId);
      }
      if (status) query.status = status;
      if (academicYear) query.academicYear = academicYear;

      // For search, we need to join with users
      let studentDocs;
      let total;

      if (search) {
        // Find matching user IDs first
        const matchingUsers = await usersCollection
          .find({
            organizationId: req.organizationId,
            $or: [
              { name: { $regex: search, $options: "i" } },
              { email: { $regex: search, $options: "i" } },
            ],
          })
          .project({ _id: 1 })
          .toArray();

        const matchingUserIds = matchingUsers.map((u) => u._id);

        // Also search by admission number
        query.$or = [
          { userId: { $in: matchingUserIds } },
          { admissionNumber: { $regex: search, $options: "i" } },
        ];
      }

      total = await studentsCollection.countDocuments(query);

      studentDocs = await studentsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ rollNumber: 1 })
        .toArray();

      // Enrich with user data, class, section names
      const userIds = studentDocs
        .filter((s) => s.userId)
        .map((s) => new ObjectId(s.userId));
      const classIds = [
        ...new Set(studentDocs.filter((s) => s.classId).map((s) => String(s.classId))),
      ];
      const sectionIds = [
        ...new Set(
          studentDocs.filter((s) => s.sectionId).map((s) => String(s.sectionId))
        ),
      ];

      const [users, classes, sections] = await Promise.all([
        userIds.length
          ? usersCollection
              .find({ _id: { $in: userIds } })
              .project({ name: 1, email: 1, phone: 1, photoURL: 1 })
              .toArray()
          : [],
        classIds.length
          ? classesCollection
              .find({
                _id: { $in: classIds.map((c) => new ObjectId(c)) },
              })
              .toArray()
          : [],
        sectionIds.length
          ? sectionsCollection
              .find({
                _id: { $in: sectionIds.map((s) => new ObjectId(s)) },
              })
              .toArray()
          : [],
      ]);

      const userMap = {};
      users.forEach((u) => (userMap[String(u._id)] = u));
      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));
      const sectionMap = {};
      sections.forEach((s) => (sectionMap[String(s._id)] = s.name));

      const enrichedStudents = studentDocs.map((s) => ({
        ...s,
        user: userMap[String(s.userId)] || null,
        className: classMap[String(s.classId)] || "Unknown",
        sectionName: sectionMap[String(s.sectionId)] || "Unknown",
      }));

      res.json({
        success: true,
        data: enrichedStudents,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching students:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch students",
        error: error.message,
      });
    }
  }
);

// GET /students/:id - Get student details
app.get(
  "/students/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_students"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid student ID",
        });
      }

      const student = await studentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!student) {
        return res.status(404).json({
          success: false,
          message: "Student not found",
        });
      }

      // Enrich with related data
      const [user, classDoc, section, parent] = await Promise.all([
        student.userId
          ? usersCollection.findOne(
              { _id: new ObjectId(student.userId) },
              { projection: { password: 0 } }
            )
          : null,
        student.classId
          ? classesCollection.findOne({
              _id: new ObjectId(student.classId),
            })
          : null,
        student.sectionId
          ? sectionsCollection.findOne({
              _id: new ObjectId(student.sectionId),
            })
          : null,
        student.parentId
          ? parentsCollection.findOne({
              _id: new ObjectId(student.parentId),
            })
          : null,
      ]);

      // Get parent user info if parent exists
      let parentUser = null;
      if (parent && parent.userId) {
        parentUser = await usersCollection.findOne(
          { _id: new ObjectId(parent.userId) },
          { projection: { name: 1, email: 1, phone: 1 } }
        );
      }

      res.json({
        success: true,
        data: {
          ...student,
          user,
          className: classDoc?.name || "Unknown",
          sectionName: section?.name || "Unknown",
          parent: parent
            ? {
                ...parent,
                user: parentUser,
              }
            : null,
        },
      });
    } catch (error) {
      logger.error("Error fetching student:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch student details",
        error: error.message,
      });
    }
  }
);

// POST /students - Create student
app.post(
  "/students",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_student"),
  async (req, res) => {
    try {
      const {
        name,
        email,
        phone,
        classId,
        sectionId,
        admissionNumber,
        dob,
        gender,
        address,
        bloodGroup,
        parentId,
        academicYear,
        previousInstitute,
        photoURL,
        password,
      } = req.body;

      if (!name || !email || !classId || !sectionId || !admissionNumber) {
        return res.status(400).json({
          success: false,
          message:
            "Required fields: name, email, classId, sectionId, admissionNumber",
        });
      }

      // Check usage limits
      const limitCheck = await checkUsageLimits(
        req.organizationId,
        "students"
      );
      if (!limitCheck.allowed) {
        return res.status(403).json({
          success: false,
          message: limitCheck.message,
        });
      }

      // Validate classId and sectionId
      if (!ObjectId.isValid(classId) || !ObjectId.isValid(sectionId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid classId or sectionId",
        });
      }

      const [classDoc, sectionDoc] = await Promise.all([
        classesCollection.findOne({
          _id: new ObjectId(classId),
          organizationId: req.organizationId,
        }),
        sectionsCollection.findOne({
          _id: new ObjectId(sectionId),
          organizationId: req.organizationId,
          classId: new ObjectId(classId),
        }),
      ]);

      if (!classDoc) {
        return res.status(404).json({
          success: false,
          message: "Class not found in your organization",
        });
      }

      if (!sectionDoc) {
        return res.status(404).json({
          success: false,
          message: "Section not found in this class",
        });
      }

      // Check duplicate admission number
      const existingAdmission = await studentsCollection.findOne({
        organizationId: req.organizationId,
        admissionNumber,
      });

      if (existingAdmission) {
        return res.status(409).json({
          success: false,
          message: "A student with this admission number already exists",
        });
      }

      // Create or link user account
      let userId;
      let createdFirebaseUid = null;
      let existingUser = await usersCollection.findOne({ email });

      if (existingUser) {
        // If user exists but has no org, assign to this org
        if (!existingUser.organizationId) {
          await usersCollection.updateOne(
            { _id: existingUser._id },
            {
              $set: {
                organizationId: req.organizationId,
                role: "student",
                permissions: ROLE_PERMISSIONS.student,
                name: name || existingUser.name,
                photoURL: photoURL || existingUser.photoURL || "",
                status: "active",
                updatedAt: new Date(),
              },
            }
          );
          userId = existingUser._id;
        } else if (
          String(existingUser.organizationId) ===
          String(req.organizationId)
        ) {
          // User already in this org
          userId = existingUser._id;
        } else {
          return res.status(409).json({
            success: false,
            message: "This email is already registered in another organization",
          });
        }
      } else {
        // New user — password required, create Firebase account first
        if (!password) {
          return res.status(400).json({
            success: false,
            message: "password is required when creating a new student account",
          });
        }
        if (password.length < 6) {
          return res.status(400).json({
            success: false,
            message: "password must be at least 6 characters",
          });
        }

        const fbResult = await createFirebaseUser(email, password, name);
        createdFirebaseUid = fbResult.uid;

        const newUser = {
          name,
          email,
          password: "",
          phone: phone || "",
          firebaseUid: createdFirebaseUid,
          photoURL: photoURL || "",
          organizationId: req.organizationId,
          role: "student",
          permissions: ROLE_PERMISSIONS.student,
          isSuperAdmin: false,
          status: "active",
          emailVerified: false,
          lastLogin: null,
          lastActivity: null,
          preferences: {
            language: "en",
            theme: "light",
            notifications: { email: true, sms: false, push: true },
          },
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        let userResult;
        try {
          userResult = await usersCollection.insertOne(newUser);
        } catch (mongoErr) {
          if (createdFirebaseUid && !fbResult.alreadyExisted) {
            try { await adminAuth.deleteUser(createdFirebaseUid); } catch (_) {}
          }
          throw mongoErr;
        }
        userId = userResult.insertedId;
      }

      // Auto roll number: count existing students in class+section + 1
      const existingCount = await studentsCollection.countDocuments({
        organizationId: req.organizationId,
        classId: new ObjectId(classId),
        sectionId: new ObjectId(sectionId),
      });
      const rollNumber = existingCount + 1;

      // Validate parentId if provided
      if (parentId) {
        if (!ObjectId.isValid(parentId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid parentId",
          });
        }
        const parentDoc = await parentsCollection.findOne({
          _id: new ObjectId(parentId),
          organizationId: req.organizationId,
        });
        if (!parentDoc) {
          return res.status(404).json({
            success: false,
            message: "Parent not found in your organization",
          });
        }
      }

      const newStudent = {
        organizationId: req.organizationId,
        userId,
        admissionNumber,
        rollNumber,
        classId: new ObjectId(classId),
        sectionId: new ObjectId(sectionId),
        parentId: parentId ? new ObjectId(parentId) : null,
        dob: dob ? new Date(dob) : null,
        gender: gender || null,
        address: address || "",
        bloodGroup: bloodGroup || "",
        documents: [],
        status: "active",
        academicYear: academicYear || classDoc.academicYear || "",
        admissionDate: new Date(),
        previousInstitute: previousInstitute || "",
        createdBy: req.userId,
        updatedBy: req.userId,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      let result;
      try {
        result = await studentsCollection.insertOne(newStudent);
      } catch (mongoErr) {
        if (createdFirebaseUid && !existingUser) {
          try { await adminAuth.deleteUser(createdFirebaseUid); } catch (_) {}
        }
        throw mongoErr;
      }

      // If parentId is provided, add student to parent's children[]
      if (parentId) {
        await parentsCollection.updateOne(
          { _id: new ObjectId(parentId) },
          { $addToSet: { children: result.insertedId } }
        );
      }

      // Increment usage counter
      await organizationsCollection.updateOne(
        { _id: new ObjectId(req.organizationId) },
        { $inc: { "usage.currentStudents": 1 } }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "student",
        result.insertedId,
        { after: { name, email, admissionNumber, classId, sectionId } },
        req
      );

      const created = await studentsCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "Student created successfully",
        data: {
          ...created,
          className: classDoc.name,
          sectionName: sectionDoc.name,
        },
      });
    } catch (error) {
      logger.error("Error creating student:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to create student",
        error: error.message,
      });
    }
  }
);

// PATCH /students/:id - Update student
app.patch(
  "/students/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("update_student"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid student ID",
        });
      }

      const student = await studentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!student) {
        return res.status(404).json({
          success: false,
          message: "Student not found",
        });
      }

      const allowedFields = [
        "classId",
        "sectionId",
        "parentId",
        "dob",
        "gender",
        "address",
        "bloodGroup",
        "status",
        "academicYear",
        "previousInstitute",
      ];
      const updates = {};

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          if (field === "classId" || field === "sectionId") {
            if (!ObjectId.isValid(req.body[field])) {
              return res.status(400).json({
                success: false,
                message: `Invalid ${field}`,
              });
            }
            updates[field] = new ObjectId(req.body[field]);
          } else if (field === "parentId") {
            if (
              req.body[field] === null ||
              req.body[field] === ""
            ) {
              updates[field] = null;
            } else {
              if (!ObjectId.isValid(req.body[field])) {
                return res.status(400).json({
                  success: false,
                  message: "Invalid parentId",
                });
              }
              updates[field] = new ObjectId(req.body[field]);
            }
          } else if (field === "dob") {
            updates[field] = new Date(req.body[field]);
          } else {
            updates[field] = req.body[field];
          }
        }
      }

      // Also update user-level fields if provided
      const userUpdates = {};
      if (req.body.name) userUpdates.name = req.body.name;
      if (req.body.phone) userUpdates.phone = req.body.phone;
      if (req.body.photoURL) userUpdates.photoURL = req.body.photoURL;

      if (Object.keys(updates).length === 0 && Object.keys(userUpdates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      // Validate new classId/sectionId if provided
      if (updates.classId) {
        const classDoc = await classesCollection.findOne({
          _id: updates.classId,
          organizationId: req.organizationId,
        });
        if (!classDoc) {
          return res.status(404).json({
            success: false,
            message: "Class not found",
          });
        }
      }

      if (updates.sectionId) {
        const targetClassId = updates.classId || student.classId;
        const sectionDoc = await sectionsCollection.findOne({
          _id: updates.sectionId,
          organizationId: req.organizationId,
          classId: targetClassId,
        });
        if (!sectionDoc) {
          return res.status(404).json({
            success: false,
            message: "Section not found in the target class",
          });
        }
      }

      // Handle parentId change: sync bidirectional references
      if (
        updates.parentId !== undefined &&
        String(updates.parentId) !== String(student.parentId)
      ) {
        // Remove from old parent
        if (student.parentId) {
          await parentsCollection.updateOne(
            { _id: new ObjectId(student.parentId) },
            { $pull: { children: new ObjectId(id) } }
          );
        }
        // Add to new parent
        if (updates.parentId) {
          await parentsCollection.updateOne(
            { _id: new ObjectId(updates.parentId) },
            { $addToSet: { children: new ObjectId(id) } }
          );
        }
      }

      updates.updatedBy = req.userId;
      updates.updatedAt = new Date();

      await studentsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      // Update user record if needed
      if (Object.keys(userUpdates).length > 0 && student.userId) {
        userUpdates.updatedAt = new Date();
        await usersCollection.updateOne(
          { _id: new ObjectId(student.userId) },
          { $set: userUpdates }
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "student",
        id,
        { after: updates },
        req
      );

      const updated = await studentsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Student updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating student:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update student",
        error: error.message,
      });
    }
  }
);

// DELETE /students/:id - Soft delete student
app.delete(
  "/students/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("delete_student"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid student ID",
        });
      }

      const student = await studentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!student) {
        return res.status(404).json({
          success: false,
          message: "Student not found",
        });
      }

      if (student.status === "dropped") {
        return res.status(400).json({
          success: false,
          message: "Student already dropped",
        });
      }

      // Soft delete: set status to dropped
      await studentsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: "dropped",
            updatedBy: req.userId,
            updatedAt: new Date(),
          },
        }
      );

      // Remove from parent's children[]
      if (student.parentId) {
        await parentsCollection.updateOne(
          { _id: new ObjectId(student.parentId) },
          { $pull: { children: new ObjectId(id) } }
        );
      }

      // Decrement usage counter
      await organizationsCollection.updateOne(
        { _id: new ObjectId(req.organizationId) },
        { $inc: { "usage.currentStudents": -1 } }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "student",
        id,
        {
          before: {
            admissionNumber: student.admissionNumber,
            classId: student.classId,
          },
        },
        req
      );

      res.json({
        success: true,
        message: "Student removed successfully",
      });
    } catch (error) {
      logger.error("Error deleting student:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to remove student",
        error: error.message,
      });
    }
  }
);

// GET /students/:id/attendance - Student attendance history
app.get(
  "/students/:id/attendance",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_attendance"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { startDate, endDate, month } = req.query;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid student ID",
        });
      }

      const student = await studentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!student) {
        return res.status(404).json({
          success: false,
          message: "Student not found",
        });
      }

      const studentObjectId = new ObjectId(id);

      // Build date filter
      const dateFilter = {};
      if (month) {
        // month format: YYYY-MM
        const [year, mon] = month.split("-").map(Number);
        dateFilter.$gte = new Date(year, mon - 1, 1);
        dateFilter.$lt = new Date(year, mon, 1);
      } else {
        if (startDate) dateFilter.$gte = new Date(startDate);
        if (endDate) {
          const end = new Date(endDate);
          end.setHours(23, 59, 59, 999);
          dateFilter.$lte = end;
        }
      }

      // Query attendance records containing this student
      const query = {
        organizationId: req.organizationId,
        classId: student.classId,
        sectionId: student.sectionId,
        "records.studentId": studentObjectId,
      };

      if (Object.keys(dateFilter).length > 0) {
        query.date = dateFilter;
      }

      const attendanceDocs = await attendanceCollection
        .find(query)
        .sort({ date: -1 })
        .toArray();

      // Extract this student's status from each record
      const entries = attendanceDocs.map((doc) => {
        const record = doc.records.find(
          (r) => String(r.studentId) === String(studentObjectId)
        );
        return {
          date: doc.date,
          status: record ? record.status : "absent",
          classId: doc.classId,
          sectionId: doc.sectionId,
        };
      });

      // Compute summary
      const totalDays = entries.length;
      const present = entries.filter((e) => e.status === "present").length;
      const absent = entries.filter((e) => e.status === "absent").length;
      const late = entries.filter((e) => e.status === "late").length;
      const excused = entries.filter((e) => e.status === "excused").length;
      const attendancePercentage =
        totalDays > 0
          ? Math.round(((present + late) / totalDays) * 100 * 100) / 100
          : 0;

      res.json({
        success: true,
        data: {
          entries,
          summary: {
            totalDays,
            present,
            absent,
            late,
            excused,
            attendancePercentage,
          },
        },
      });
    } catch (error) {
      logger.error("Error fetching student attendance:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch attendance",
        error: error.message,
      });
    }
  }
);

// GET /students/:id/grades - Student published grades
app.get(
  "/students/:id/grades",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_published_grades"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { examId } = req.query;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid student ID",
        });
      }

      const student = await studentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!student) {
        return res.status(404).json({
          success: false,
          message: "Student not found",
        });
      }

      const query = {
        organizationId: req.organizationId,
        status: "published",
        "grades.studentId": new ObjectId(id),
      };
      if (examId && ObjectId.isValid(examId)) {
        query.examId = new ObjectId(examId);
      }

      const submissions = await gradeSubmissionsCollection
        .find(query)
        .sort({ publishedAt: -1 })
        .toArray();

      if (submissions.length === 0) {
        return res.json({ success: true, data: [] });
      }

      // Collect unique IDs for enrichment
      const examIds = [
        ...new Set(submissions.map((s) => String(s.examId))),
      ];
      const subjectIds = [
        ...new Set(submissions.map((s) => String(s.subjectId))),
      ];

      const [exams, subjects] = await Promise.all([
        examsCollection
          .find({
            _id: { $in: examIds.map((e) => new ObjectId(e)) },
          })
          .toArray(),
        subjectsCollection
          .find({
            _id: { $in: subjectIds.map((s) => new ObjectId(s)) },
          })
          .toArray(),
      ]);

      const examMap = {};
      exams.forEach((e) => (examMap[String(e._id)] = e));
      const subjectMap = {};
      subjects.forEach((s) => (subjectMap[String(s._id)] = s));

      const grades = submissions.map((sub) => {
        const studentGrade = sub.grades.find(
          (g) => String(g.studentId) === id
        );
        const subject = subjectMap[String(sub.subjectId)];
        return {
          submissionId: sub._id,
          examId: sub.examId,
          examName: examMap[String(sub.examId)]?.name || "Unknown",
          subjectId: sub.subjectId,
          subjectName: subject?.name || "Unknown",
          subjectCode: subject?.subjectCode || "",
          fullMarks: subject?.fullMarks || 100,
          passMarks: subject?.passMarks || 33,
          obtainedMarks: studentGrade?.marks ?? null,
          grade: studentGrade?.grade || null,
          gradePoint: studentGrade?.gradePoint ?? null,
          passed: studentGrade
            ? studentGrade.marks >= (subject?.passMarks || 33)
            : null,
          remarks: studentGrade?.remarks || "",
          publishedAt: sub.publishedAt,
        };
      });

      res.json({
        success: true,
        data: grades,
      });
    } catch (error) {
      logger.error("Error fetching student grades:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch grades",
        error: error.message,
      });
    }
  }
);

// GET /students/:id/fees - Student fee history (Phase 5 - replaced stub)
app.get(
  "/students/:id/fees",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_fees"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { month, status } = req.query;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid student ID",
        });
      }

      // Students can only view their own fees, parents can view their children's
      if (req.userRole === "student") {
        const studentDoc = await studentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
        });
        if (!studentDoc || studentDoc._id.toString() !== id) {
          return res.status(403).json({
            success: false,
            message: "You can only view your own fees",
          });
        }
      } else if (req.userRole === "parent") {
        const parentDoc = await parentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
        });
        const childIds = (parentDoc?.children || []).map((c) => c.toString());
        if (!childIds.includes(id)) {
          return res.status(403).json({
            success: false,
            message: "You can only view your children's fees",
          });
        }
      }

      const student = await studentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!student) {
        return res.status(404).json({
          success: false,
          message: "Student not found",
        });
      }

      const query = {
        organizationId: req.organizationId,
        studentId: new ObjectId(id),
      };
      if (month) query.month = month;
      if (status) query.status = status;

      const fees = await studentMonthlyFeesCollection
        .find(query)
        .sort({ month: -1 })
        .toArray();

      // Get payments for these fees
      const feeIds = fees.map((f) => f._id);
      const payments = await paymentsCollection
        .find({
          organizationId: req.organizationId,
          studentMonthlyFeeId: { $in: feeIds },
        })
        .sort({ paymentDate: -1 })
        .toArray();

      // Group payments by fee
      const paymentsByFee = {};
      payments.forEach((p) => {
        const feeId = p.studentMonthlyFeeId.toString();
        if (!paymentsByFee[feeId]) paymentsByFee[feeId] = [];
        paymentsByFee[feeId].push(p);
      });

      const feesWithPayments = fees.map((f) => ({
        ...f,
        payments: paymentsByFee[f._id.toString()] || [],
      }));

      // Summary
      const totalPayable = fees.reduce((sum, f) => sum + (f.payableAmount - (f.discount || 0)), 0);
      const totalPaid = fees.reduce((sum, f) => sum + (f.paidAmount || 0), 0);
      const totalDue = totalPayable - totalPaid;

      res.json({
        success: true,
        data: feesWithPayments,
        summary: {
          totalPayable,
          totalPaid,
          totalDue,
          totalMonths: fees.length,
          paidMonths: fees.filter((f) => f.status === "paid").length,
          pendingMonths: fees.filter((f) => f.status === "pending").length,
          partialMonths: fees.filter((f) => f.status === "partial").length,
          overdueMonths: fees.filter((f) => f.status === "overdue").length,
        },
      });
    } catch (error) {
      logger.error("Error fetching student fees:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch fees",
        error: error.message,
      });
    }
  }
);

// --- Teachers Endpoints ---

// GET /teachers/me - Get current teacher's own profile (used by teacher dashboard)
app.get(
  "/teachers/me",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_grade_draft"),
  async (req, res) => {
    try {
      const teacherDoc = await teachersCollection.findOne({
        organizationId: req.organizationId,
        userId: req.userId,
        status: "active",
      });

      if (!teacherDoc) {
        return res.status(404).json({
          success: false,
          message: "Teacher profile not found for the current user",
        });
      }

      res.json({ success: true, data: teacherDoc });
    } catch (error) {
      logger.error("Error fetching teacher profile:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch teacher profile",
        error: error.message,
      });
    }
  }
);

// GET /teachers - List teachers
app.get(
  "/teachers",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_teachers"),
  async (req, res) => {
    try {
      const { page = 1, limit = 10, status, search } = req.query;

      const query = {
        organizationId: req.organizationId,
      };

      if (status) query.status = status;

      let teacherDocs;
      let total;

      if (search) {
        // Search via user names/emails
        const matchingUsers = await usersCollection
          .find({
            organizationId: req.organizationId,
            role: "teacher",
            $or: [
              { name: { $regex: search, $options: "i" } },
              { email: { $regex: search, $options: "i" } },
            ],
          })
          .project({ _id: 1 })
          .toArray();

        const matchingUserIds = matchingUsers.map((u) => u._id);

        query.$or = [
          { userId: { $in: matchingUserIds } },
          { employeeId: { $regex: search, $options: "i" } },
        ];
      }

      total = await teachersCollection.countDocuments(query);

      teacherDocs = await teachersCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ createdAt: -1 })
        .toArray();

      // Enrich with user data
      const userIds = teacherDocs
        .filter((t) => t.userId)
        .map((t) => new ObjectId(t.userId));

      const users = userIds.length
        ? await usersCollection
            .find({ _id: { $in: userIds } })
            .project({ name: 1, email: 1, phone: 1, photoURL: 1 })
            .toArray()
        : [];

      const userMap = {};
      users.forEach((u) => (userMap[String(u._id)] = u));

      const enrichedTeachers = teacherDocs.map((t) => ({
        ...t,
        user: userMap[String(t.userId)] || null,
      }));

      res.json({
        success: true,
        data: enrichedTeachers,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching teachers:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch teachers",
        error: error.message,
      });
    }
  }
);

// GET /teachers/:id - Get teacher details
app.get(
  "/teachers/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_teachers"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid teacher ID",
        });
      }

      const teacher = await teachersCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!teacher) {
        return res.status(404).json({
          success: false,
          message: "Teacher not found",
        });
      }

      // Get user info
      const user = teacher.userId
        ? await usersCollection.findOne(
            { _id: new ObjectId(teacher.userId) },
            { projection: { password: 0 } }
          )
        : null;

      // Get assigned subjects with class names
      const assignedSubjects = await subjectsCollection
        .find({
          organizationId: req.organizationId,
          teacherId: new ObjectId(id),
        })
        .toArray();

      // Get class names for subjects
      const classIds = [
        ...new Set(assignedSubjects.map((s) => String(s.classId))),
      ];
      const classes = classIds.length
        ? await classesCollection
            .find({
              _id: { $in: classIds.map((c) => new ObjectId(c)) },
            })
            .toArray()
        : [];

      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));

      const enrichedSubjects = assignedSubjects.map((s) => ({
        ...s,
        className: classMap[String(s.classId)] || "Unknown",
      }));

      res.json({
        success: true,
        data: {
          ...teacher,
          user,
          assignedSubjects: enrichedSubjects,
          assignedClasses: classes,
        },
      });
    } catch (error) {
      logger.error("Error fetching teacher:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch teacher details",
        error: error.message,
      });
    }
  }
);

// POST /teachers - Create teacher
app.post(
  "/teachers",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_teacher"),
  async (req, res) => {
    try {
      const {
        name,
        email,
        phone,
        employeeId,
        qualification,
        specialization,
        joiningDate,
        photoURL,
        password,
      } = req.body;

      if (!name || !email) {
        return res.status(400).json({
          success: false,
          message: "Required fields: name, email",
        });
      }

      // Check usage limits
      const limitCheck = await checkUsageLimits(
        req.organizationId,
        "teachers"
      );
      if (!limitCheck.allowed) {
        return res.status(403).json({
          success: false,
          message: limitCheck.message,
        });
      }

      // Create or link user account
      let userId;
      let createdFirebaseUid = null;
      let existingUser = await usersCollection.findOne({ email });

      if (existingUser) {
        if (!existingUser.organizationId) {
          await usersCollection.updateOne(
            { _id: existingUser._id },
            {
              $set: {
                organizationId: req.organizationId,
                role: "teacher",
                permissions: ROLE_PERMISSIONS.teacher,
                name: name || existingUser.name,
                photoURL: photoURL || existingUser.photoURL || "",
                status: "active",
                updatedAt: new Date(),
              },
            }
          );
          userId = existingUser._id;
        } else if (
          String(existingUser.organizationId) ===
          String(req.organizationId)
        ) {
          // Check if teacher profile already exists for this user
          const existingTeacher = await teachersCollection.findOne({
            organizationId: req.organizationId,
            userId: existingUser._id,
          });
          if (existingTeacher) {
            return res.status(409).json({
              success: false,
              message: "A teacher profile already exists for this user",
            });
          }
          userId = existingUser._id;
        } else {
          return res.status(409).json({
            success: false,
            message: "This email is already registered in another organization",
          });
        }
      } else {
        // New user — password required, create Firebase account first
        if (!password) {
          return res.status(400).json({
            success: false,
            message: "password is required when creating a new teacher account",
          });
        }
        if (password.length < 6) {
          return res.status(400).json({
            success: false,
            message: "password must be at least 6 characters",
          });
        }

        const fbResult = await createFirebaseUser(email, password, name);
        createdFirebaseUid = fbResult.uid;

        const newUser = {
          name,
          email,
          password: "",
          phone: phone || "",
          firebaseUid: createdFirebaseUid,
          photoURL: photoURL || "",
          organizationId: req.organizationId,
          role: "teacher",
          permissions: ROLE_PERMISSIONS.teacher,
          isSuperAdmin: false,
          status: "active",
          emailVerified: false,
          lastLogin: null,
          lastActivity: null,
          preferences: {
            language: "en",
            theme: "light",
            notifications: { email: true, sms: false, push: true },
          },
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        let userResult;
        try {
          userResult = await usersCollection.insertOne(newUser);
        } catch (mongoErr) {
          // Clean up Firebase account to avoid orphan
          if (createdFirebaseUid && !fbResult.alreadyExisted) {
            try { await adminAuth.deleteUser(createdFirebaseUid); } catch (_) {}
          }
          throw mongoErr;
        }
        userId = userResult.insertedId;
      }

      const newTeacher = {
        organizationId: req.organizationId,
        userId,
        employeeId: employeeId || "",
        subjects: [],
        classes: [],
        qualification: qualification || "",
        specialization: specialization || "",
        joiningDate: joiningDate ? new Date(joiningDate) : new Date(),
        status: "active",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      let result;
      try {
        result = await teachersCollection.insertOne(newTeacher);
      } catch (mongoErr) {
        // Clean up Firebase account to avoid orphan
        if (createdFirebaseUid && !existingUser) {
          try { await adminAuth.deleteUser(createdFirebaseUid); } catch (_) {}
        }
        throw mongoErr;
      }

      // Increment usage counter
      await organizationsCollection.updateOne(
        { _id: new ObjectId(req.organizationId) },
        { $inc: { "usage.currentTeachers": 1 } }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "teacher",
        result.insertedId,
        { after: { name, email, employeeId } },
        req
      );

      const created = await teachersCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "Teacher created successfully",
        data: created,
      });
    } catch (error) {
      logger.error("Error creating teacher:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to create teacher",
        error: error.message,
      });
    }
  }
);

// PATCH /teachers/:id - Update teacher
app.patch(
  "/teachers/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("update_teacher"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid teacher ID",
        });
      }

      const teacher = await teachersCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!teacher) {
        return res.status(404).json({
          success: false,
          message: "Teacher not found",
        });
      }

      const allowedFields = [
        "employeeId",
        "qualification",
        "specialization",
        "joiningDate",
        "status",
      ];
      const updates = {};

      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          if (field === "joiningDate") {
            updates[field] = new Date(req.body[field]);
          } else {
            updates[field] = req.body[field];
          }
        }
      }

      // Handle user-level updates
      const userUpdates = {};
      if (req.body.name) userUpdates.name = req.body.name;
      if (req.body.phone) userUpdates.phone = req.body.phone;
      if (req.body.photoURL) userUpdates.photoURL = req.body.photoURL;

      if (Object.keys(updates).length === 0 && Object.keys(userUpdates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      updates.updatedAt = new Date();

      await teachersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      // Update user record if needed
      if (Object.keys(userUpdates).length > 0 && teacher.userId) {
        userUpdates.updatedAt = new Date();
        await usersCollection.updateOne(
          { _id: new ObjectId(teacher.userId) },
          { $set: userUpdates }
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "teacher",
        id,
        { after: { ...updates, ...userUpdates } },
        req
      );

      const updated = await teachersCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Teacher updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating teacher:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update teacher",
        error: error.message,
      });
    }
  }
);

// DELETE /teachers/:id - Soft delete teacher
app.delete(
  "/teachers/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("delete_teacher"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid teacher ID",
        });
      }

      const teacher = await teachersCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!teacher) {
        return res.status(404).json({
          success: false,
          message: "Teacher not found",
        });
      }

      if (teacher.status === "inactive") {
        return res.status(400).json({
          success: false,
          message: "Teacher already inactive",
        });
      }

      // Set teacher status to inactive
      await teachersCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: "inactive",
            updatedAt: new Date(),
          },
        }
      );

      // Remove teacher assignment from all subjects
      await subjectsCollection.updateMany(
        {
          organizationId: req.organizationId,
          teacherId: new ObjectId(id),
        },
        { $set: { teacherId: null, updatedAt: new Date() } }
      );

      // Remove teacher from section classTeacher assignments
      await sectionsCollection.updateMany(
        {
          organizationId: req.organizationId,
          classTeacherId: new ObjectId(id),
        },
        { $set: { classTeacherId: null, updatedAt: new Date() } }
      );

      // Decrement usage counter
      await organizationsCollection.updateOne(
        { _id: new ObjectId(req.organizationId) },
        { $inc: { "usage.currentTeachers": -1 } }
      );

      // Update user status
      if (teacher.userId) {
        await usersCollection.updateOne(
          { _id: new ObjectId(teacher.userId) },
          {
            $set: {
              status: "inactive",
              updatedAt: new Date(),
            },
          }
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "teacher",
        id,
        { before: { employeeId: teacher.employeeId, userId: teacher.userId } },
        req
      );

      res.json({
        success: true,
        message: "Teacher removed successfully",
      });
    } catch (error) {
      logger.error("Error deleting teacher:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to remove teacher",
        error: error.message,
      });
    }
  }
);

// GET /teachers/:id/classes - Teacher's assigned classes & subjects
app.get(
  "/teachers/:id/classes",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_teachers"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid teacher ID",
        });
      }

      const teacher = await teachersCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!teacher) {
        return res.status(404).json({
          success: false,
          message: "Teacher not found",
        });
      }

      // Get all subjects assigned to this teacher
      const subjects = await subjectsCollection
        .find({
          organizationId: req.organizationId,
          teacherId: new ObjectId(id),
        })
        .toArray();

      // Get unique class IDs
      const classIds = [
        ...new Set(subjects.map((s) => String(s.classId))),
      ];

      const classes = classIds.length
        ? await classesCollection
            .find({
              _id: { $in: classIds.map((c) => new ObjectId(c)) },
            })
            .sort({ numericLevel: 1 })
            .toArray()
        : [];

      // Group subjects by class
      const classesWithSubjects = classes.map((c) => ({
        ...c,
        subjects: subjects.filter(
          (s) => String(s.classId) === String(c._id)
        ),
      }));

      res.json({
        success: true,
        data: classesWithSubjects,
      });
    } catch (error) {
      logger.error("Error fetching teacher classes:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch teacher classes",
        error: error.message,
      });
    }
  }
);

// GET /teachers/:id/submissions - Teacher's grade submissions
app.get(
  "/teachers/:id/submissions",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_teachers"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { examId, status, page = 1, limit = 20 } = req.query;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid teacher ID",
        });
      }

      const teacher = await teachersCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!teacher) {
        return res.status(404).json({
          success: false,
          message: "Teacher not found",
        });
      }

      const query = {
        organizationId: req.organizationId,
        teacherId: teacher._id,
      };
      if (examId && ObjectId.isValid(examId)) {
        query.examId = new ObjectId(examId);
      }
      if (status) query.status = status;

      const total = await gradeSubmissionsCollection.countDocuments(
        query
      );
      const submissions = await gradeSubmissionsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ updatedAt: -1 })
        .toArray();

      // Enrich with exam, class, section, subject names
      const examIds = [
        ...new Set(submissions.map((s) => String(s.examId))),
      ];
      const classIds = [
        ...new Set(submissions.map((s) => String(s.classId))),
      ];
      const sectionIds = [
        ...new Set(submissions.map((s) => String(s.sectionId))),
      ];
      const subjectIds = [
        ...new Set(submissions.map((s) => String(s.subjectId))),
      ];

      const [exams, classes, sections, subjects] = await Promise.all([
        examIds.length
          ? examsCollection
              .find({
                _id: { $in: examIds.map((e) => new ObjectId(e)) },
              })
              .toArray()
          : [],
        classIds.length
          ? classesCollection
              .find({
                _id: { $in: classIds.map((c) => new ObjectId(c)) },
              })
              .toArray()
          : [],
        sectionIds.length
          ? sectionsCollection
              .find({
                _id: {
                  $in: sectionIds.map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
        subjectIds.length
          ? subjectsCollection
              .find({
                _id: {
                  $in: subjectIds.map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
      ]);

      const examMap = {};
      exams.forEach((e) => (examMap[String(e._id)] = e.name));
      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));
      const sectionMap = {};
      sections.forEach((s) => (sectionMap[String(s._id)] = s.name));
      const subjectMap = {};
      subjects.forEach((s) => (subjectMap[String(s._id)] = s.name));

      const enriched = submissions.map((sub) => ({
        ...sub,
        examName: examMap[String(sub.examId)] || "Unknown",
        className: classMap[String(sub.classId)] || "Unknown",
        sectionName: sectionMap[String(sub.sectionId)] || "Unknown",
        subjectName: subjectMap[String(sub.subjectId)] || "Unknown",
        studentCount: sub.grades ? sub.grades.length : 0,
      }));

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching teacher submissions:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch submissions",
        error: error.message,
      });
    }
  }
);

// --- Parents Endpoints ---

// GET /parents - List parents
app.get(
  "/parents",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_users"),
  async (req, res) => {
    try {
      const { page = 1, limit = 10, search } = req.query;

      const query = {
        organizationId: req.organizationId,
      };

      let parentDocs;
      let total;

      if (search) {
        const matchingUsers = await usersCollection
          .find({
            organizationId: req.organizationId,
            role: "parent",
            $or: [
              { name: { $regex: search, $options: "i" } },
              { email: { $regex: search, $options: "i" } },
            ],
          })
          .project({ _id: 1 })
          .toArray();

        query.userId = {
          $in: matchingUsers.map((u) => u._id),
        };
      }

      total = await parentsCollection.countDocuments(query);

      parentDocs = await parentsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ createdAt: -1 })
        .toArray();

      // Enrich with user data
      const userIds = parentDocs
        .filter((p) => p.userId)
        .map((p) => new ObjectId(p.userId));

      const users = userIds.length
        ? await usersCollection
            .find({ _id: { $in: userIds } })
            .project({ name: 1, email: 1, phone: 1, photoURL: 1 })
            .toArray()
        : [];

      const userMap = {};
      users.forEach((u) => (userMap[String(u._id)] = u));

      const enrichedParents = parentDocs.map((p) => ({
        ...p,
        user: userMap[String(p.userId)] || null,
        childrenCount: p.children ? p.children.length : 0,
      }));

      res.json({
        success: true,
        data: enrichedParents,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching parents:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch parents",
        error: error.message,
      });
    }
  }
);

// GET /parents/:id - Get parent details with children
app.get(
  "/parents/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_users"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid parent ID",
        });
      }

      const parent = await parentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!parent) {
        return res.status(404).json({
          success: false,
          message: "Parent not found",
        });
      }

      // Get user info
      const user = parent.userId
        ? await usersCollection.findOne(
            { _id: new ObjectId(parent.userId) },
            { projection: { password: 0 } }
          )
        : null;

      // Get children details
      let children = [];
      if (parent.children && parent.children.length > 0) {
        const childDocs = await studentsCollection
          .find({
            _id: {
              $in: parent.children.map((c) => new ObjectId(c)),
            },
          })
          .toArray();

        // Get user data and class/section for each child
        const childUserIds = childDocs
          .filter((c) => c.userId)
          .map((c) => new ObjectId(c.userId));
        const childClassIds = [
          ...new Set(
            childDocs.filter((c) => c.classId).map((c) => String(c.classId))
          ),
        ];
        const childSectionIds = [
          ...new Set(
            childDocs
              .filter((c) => c.sectionId)
              .map((c) => String(c.sectionId))
          ),
        ];

        const [childUsers, childClasses, childSections] =
          await Promise.all([
            childUserIds.length
              ? usersCollection
                  .find({ _id: { $in: childUserIds } })
                  .project({ name: 1, email: 1, photoURL: 1 })
                  .toArray()
              : [],
            childClassIds.length
              ? classesCollection
                  .find({
                    _id: {
                      $in: childClassIds.map(
                        (c) => new ObjectId(c)
                      ),
                    },
                  })
                  .toArray()
              : [],
            childSectionIds.length
              ? sectionsCollection
                  .find({
                    _id: {
                      $in: childSectionIds.map(
                        (s) => new ObjectId(s)
                      ),
                    },
                  })
                  .toArray()
              : [],
          ]);

        const childUserMap = {};
        childUsers.forEach(
          (u) => (childUserMap[String(u._id)] = u)
        );
        const childClassMap = {};
        childClasses.forEach(
          (c) => (childClassMap[String(c._id)] = c.name)
        );
        const childSectionMap = {};
        childSections.forEach(
          (s) => (childSectionMap[String(s._id)] = s.name)
        );

        children = childDocs.map((c) => ({
          ...c,
          user: childUserMap[String(c.userId)] || null,
          className: childClassMap[String(c.classId)] || "Unknown",
          sectionName:
            childSectionMap[String(c.sectionId)] || "Unknown",
        }));
      }

      res.json({
        success: true,
        data: {
          ...parent,
          user,
          childrenDetails: children,
        },
      });
    } catch (error) {
      logger.error("Error fetching parent:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch parent details",
        error: error.message,
      });
    }
  }
);

// POST /parents - Create parent
app.post(
  "/parents",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_users"),
  async (req, res) => {
    try {
      const {
        name,
        email,
        phone,
        occupation,
        relationship,
        children,
        photoURL,
        password,
      } = req.body;

      if (!name || !email) {
        return res.status(400).json({
          success: false,
          message: "Required fields: name, email",
        });
      }

      // Create or link user account
      let userId;
      let createdFirebaseUid = null;
      let existingUser = await usersCollection.findOne({ email });

      if (existingUser) {
        if (!existingUser.organizationId) {
          await usersCollection.updateOne(
            { _id: existingUser._id },
            {
              $set: {
                organizationId: req.organizationId,
                role: "parent",
                permissions: ROLE_PERMISSIONS.parent,
                name: name || existingUser.name,
                photoURL: photoURL || existingUser.photoURL || "",
                status: "active",
                updatedAt: new Date(),
              },
            }
          );
          userId = existingUser._id;
        } else if (
          String(existingUser.organizationId) ===
          String(req.organizationId)
        ) {
          // Check if parent profile already exists
          const existingParent = await parentsCollection.findOne({
            organizationId: req.organizationId,
            userId: existingUser._id,
          });
          if (existingParent) {
            return res.status(409).json({
              success: false,
              message: "A parent profile already exists for this user",
            });
          }
          userId = existingUser._id;
        } else {
          return res.status(409).json({
            success: false,
            message: "This email is already registered in another organization",
          });
        }
      } else {
        // New user — password required, create Firebase account first
        if (!password) {
          return res.status(400).json({
            success: false,
            message: "password is required when creating a new parent account",
          });
        }
        if (password.length < 6) {
          return res.status(400).json({
            success: false,
            message: "password must be at least 6 characters",
          });
        }

        const fbResult = await createFirebaseUser(email, password, name);
        createdFirebaseUid = fbResult.uid;

        const newUser = {
          name,
          email,
          password: "",
          phone: phone || "",
          firebaseUid: createdFirebaseUid,
          photoURL: photoURL || "",
          organizationId: req.organizationId,
          role: "parent",
          permissions: ROLE_PERMISSIONS.parent,
          isSuperAdmin: false,
          status: "active",
          emailVerified: false,
          lastLogin: null,
          lastActivity: null,
          preferences: {
            language: "en",
            theme: "light",
            notifications: { email: true, sms: false, push: true },
          },
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        let userResult;
        try {
          userResult = await usersCollection.insertOne(newUser);
        } catch (mongoErr) {
          if (createdFirebaseUid && !fbResult.alreadyExisted) {
            try { await adminAuth.deleteUser(createdFirebaseUid); } catch (_) {}
          }
          throw mongoErr;
        }
        userId = userResult.insertedId;
      }

      // Validate children IDs if provided
      const childrenIds = [];
      if (children && Array.isArray(children) && children.length > 0) {
        for (const childId of children) {
          if (!ObjectId.isValid(childId)) {
            return res.status(400).json({
              success: false,
              message: `Invalid student ID: ${childId}`,
            });
          }
          const student = await studentsCollection.findOne({
            _id: new ObjectId(childId),
            organizationId: req.organizationId,
          });
          if (!student) {
            return res.status(404).json({
              success: false,
              message: `Student not found: ${childId}`,
            });
          }
          childrenIds.push(new ObjectId(childId));
        }
      }

      const newParent = {
        organizationId: req.organizationId,
        userId,
        children: childrenIds,
        occupation: occupation || "",
        relationship: relationship || "guardian",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      let result;
      try {
        result = await parentsCollection.insertOne(newParent);
      } catch (mongoErr) {
        if (createdFirebaseUid && !existingUser) {
          try { await adminAuth.deleteUser(createdFirebaseUid); } catch (_) {}
        }
        throw mongoErr;
      }

      // Update linked students' parentId
      if (childrenIds.length > 0) {
        await studentsCollection.updateMany(
          { _id: { $in: childrenIds } },
          {
            $set: {
              parentId: result.insertedId,
              updatedAt: new Date(),
            },
          }
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "parent",
        result.insertedId,
        { after: { name, email, childrenCount: childrenIds.length } },
        req
      );

      const created = await parentsCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "Parent created successfully",
        data: created,
      });
    } catch (error) {
      logger.error("Error creating parent:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to create parent",
        error: error.message,
      });
    }
  }
);

// PATCH /parents/:id - Update parent
app.patch(
  "/parents/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_users"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid parent ID",
        });
      }

      const parent = await parentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!parent) {
        return res.status(404).json({
          success: false,
          message: "Parent not found",
        });
      }

      const updates = {};

      if (req.body.occupation !== undefined)
        updates.occupation = req.body.occupation;
      if (req.body.relationship !== undefined)
        updates.relationship = req.body.relationship;

      // Handle children update with bidirectional sync
      if (req.body.children !== undefined) {
        const newChildrenIds = [];

        if (
          Array.isArray(req.body.children) &&
          req.body.children.length > 0
        ) {
          for (const childId of req.body.children) {
            if (!ObjectId.isValid(childId)) {
              return res.status(400).json({
                success: false,
                message: `Invalid student ID: ${childId}`,
              });
            }
            const student = await studentsCollection.findOne({
              _id: new ObjectId(childId),
              organizationId: req.organizationId,
            });
            if (!student) {
              return res.status(404).json({
                success: false,
                message: `Student not found: ${childId}`,
              });
            }
            newChildrenIds.push(new ObjectId(childId));
          }
        }

        // Remove parentId from old children not in new list
        const oldChildrenStrings = (parent.children || []).map((c) =>
          String(c)
        );
        const newChildrenStrings = newChildrenIds.map((c) => String(c));

        const removedChildren = oldChildrenStrings.filter(
          (c) => !newChildrenStrings.includes(c)
        );
        const addedChildren = newChildrenStrings.filter(
          (c) => !oldChildrenStrings.includes(c)
        );

        if (removedChildren.length > 0) {
          await studentsCollection.updateMany(
            {
              _id: {
                $in: removedChildren.map((c) => new ObjectId(c)),
              },
            },
            { $set: { parentId: null, updatedAt: new Date() } }
          );
        }

        if (addedChildren.length > 0) {
          await studentsCollection.updateMany(
            {
              _id: {
                $in: addedChildren.map((c) => new ObjectId(c)),
              },
            },
            {
              $set: {
                parentId: new ObjectId(id),
                updatedAt: new Date(),
              },
            }
          );
        }

        updates.children = newChildrenIds;
      }

      // Handle user-level updates
      const userUpdates = {};
      if (req.body.name) userUpdates.name = req.body.name;
      if (req.body.phone) userUpdates.phone = req.body.phone;
      if (req.body.photoURL) userUpdates.photoURL = req.body.photoURL;

      if (Object.keys(updates).length === 0 && Object.keys(userUpdates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      updates.updatedAt = new Date();

      await parentsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      if (Object.keys(userUpdates).length > 0 && parent.userId) {
        userUpdates.updatedAt = new Date();
        await usersCollection.updateOne(
          { _id: new ObjectId(parent.userId) },
          { $set: userUpdates }
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "parent",
        id,
        { after: updates },
        req
      );

      const updated = await parentsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Parent updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating parent:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update parent",
        error: error.message,
      });
    }
  }
);

// DELETE /parents/:id - Remove parent
app.delete(
  "/parents/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_users"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid parent ID",
        });
      }

      const parent = await parentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!parent) {
        return res.status(404).json({
          success: false,
          message: "Parent not found",
        });
      }

      // Remove parentId from all children
      if (parent.children && parent.children.length > 0) {
        await studentsCollection.updateMany(
          {
            _id: {
              $in: parent.children.map((c) => new ObjectId(c)),
            },
          },
          { $set: { parentId: null, updatedAt: new Date() } }
        );
      }

      // Delete parent profile
      await parentsCollection.deleteOne({ _id: new ObjectId(id) });

      // Reset user role
      if (parent.userId) {
        await usersCollection.updateOne(
          { _id: new ObjectId(parent.userId) },
          {
            $set: {
              role: null,
              organizationId: null,
              permissions: [],
              status: "inactive",
              updatedAt: new Date(),
            },
          }
        );
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "parent",
        id,
        { before: { userId: parent.userId, childrenCount: parent.children?.length || 0 } },
        req
      );

      res.json({
        success: true,
        message: "Parent removed successfully",
      });
    } catch (error) {
      logger.error("Error deleting parent:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to remove parent",
        error: error.message,
      });
    }
  }
);

// --- Documents Endpoints ---

// GET /documents - List documents
app.get(
  "/documents",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_documents"),
  async (req, res) => {
    try {
      const { ownerId, ownerType, fileType } = req.query;

      const query = {
        organizationId: req.organizationId,
      };

      if (ownerId) {
        if (!ObjectId.isValid(ownerId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid ownerId",
          });
        }
        query.ownerId = new ObjectId(ownerId);
      }
      if (ownerType) query.ownerType = ownerType;
      if (fileType) query.fileType = fileType;

      const documents = await documentsCollection
        .find(query)
        .sort({ uploadedAt: -1 })
        .toArray();

      res.json({
        success: true,
        data: documents,
      });
    } catch (error) {
      logger.error("Error fetching documents:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch documents",
        error: error.message,
      });
    }
  }
);

// POST /documents - Create document metadata
app.post(
  "/documents",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  async (req, res) => {
    try {
      const { ownerId, ownerType, fileName, fileUrl, fileType, fileSize } =
        req.body;

      if (!ownerId || !ownerType || !fileName || !fileUrl) {
        return res.status(400).json({
          success: false,
          message:
            "Required fields: ownerId, ownerType, fileName, fileUrl",
        });
      }

      if (!ObjectId.isValid(ownerId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid ownerId",
        });
      }

      if (!["student", "teacher"].includes(ownerType)) {
        return res.status(400).json({
          success: false,
          message: "ownerType must be 'student' or 'teacher'",
        });
      }

      // Check permission based on ownerType or if user is admin
      const isAdmin =
        req.userRole === "org_owner" ||
        req.userRole === "admin";
      const isOwnDocument =
        (ownerType === "student" &&
          req.userRole === "student") ||
        (ownerType === "teacher" &&
          req.userRole === "teacher");

      if (!isAdmin && !isOwnDocument) {
        return res.status(403).json({
          success: false,
          message: "Insufficient permissions to upload document",
        });
      }

      // Validate owner exists
      const ownerCollection =
        ownerType === "student"
          ? studentsCollection
          : teachersCollection;
      const owner = await ownerCollection.findOne({
        _id: new ObjectId(ownerId),
        organizationId: req.organizationId,
      });

      if (!owner) {
        return res.status(404).json({
          success: false,
          message: `${ownerType} not found`,
        });
      }

      const newDocument = {
        organizationId: req.organizationId,
        ownerId: new ObjectId(ownerId),
        ownerType,
        fileName,
        fileUrl,
        fileType: fileType || "other",
        fileSize: fileSize ? Number(fileSize) : 0,
        uploadedBy: req.userId,
        uploadedAt: new Date(),
      };

      const result = await documentsCollection.insertOne(newDocument);

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "document",
        result.insertedId,
        { after: { fileName, ownerType, ownerId } },
        req
      );

      const created = await documentsCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "Document uploaded successfully",
        data: created,
      });
    } catch (error) {
      logger.error("Error creating document:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to upload document",
        error: error.message,
      });
    }
  }
);

// DELETE /documents/:id - Delete document
app.delete(
  "/documents/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid document ID",
        });
      }

      const document = await documentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!document) {
        return res.status(404).json({
          success: false,
          message: "Document not found",
        });
      }

      // Check permission: admin can delete any, users can delete their own uploads
      const isAdmin =
        req.userRole === "org_owner" ||
        req.userRole === "admin";
      const isOwnUpload =
        String(document.uploadedBy) === String(req.userId);

      if (!isAdmin && !isOwnUpload) {
        return res.status(403).json({
          success: false,
          message: "Insufficient permissions to delete document",
        });
      }

      await documentsCollection.deleteOne({ _id: new ObjectId(id) });

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "document",
        id,
        { before: { fileName: document.fileName, ownerType: document.ownerType } },
        req
      );

      res.json({
        success: true,
        message: "Document deleted successfully",
      });
    } catch (error) {
      logger.error("Error deleting document:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to delete document",
        error: error.message,
      });
    }
  }
);

// ==================== PHASE 3: ATTENDANCE MANAGEMENT ====================

// POST /attendance - Mark or update daily attendance (upsert)
app.post(
  "/attendance",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("mark_attendance"),
  async (req, res) => {
    try {
      const { classId, sectionId, date, records } = req.body;

      // Validate required fields
      if (!classId || !sectionId || !date || !records) {
        return res.status(400).json({
          success: false,
          message: "Required fields: classId, sectionId, date, records",
        });
      }

      if (!Array.isArray(records) || records.length === 0) {
        return res.status(400).json({
          success: false,
          message: "records must be a non-empty array",
        });
      }

      // Validate ObjectIds
      if (!ObjectId.isValid(classId) || !ObjectId.isValid(sectionId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid classId or sectionId",
        });
      }

      // Validate date is not in the future
      const attendanceDate = new Date(date);
      attendanceDate.setHours(0, 0, 0, 0);
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      if (attendanceDate > today) {
        return res.status(400).json({
          success: false,
          message: "Cannot mark attendance for a future date",
        });
      }

      // Validate class and section exist in org
      const [classDoc, sectionDoc] = await Promise.all([
        classesCollection.findOne({
          _id: new ObjectId(classId),
          organizationId: req.organizationId,
        }),
        sectionsCollection.findOne({
          _id: new ObjectId(sectionId),
          organizationId: req.organizationId,
          classId: new ObjectId(classId),
        }),
      ]);

      if (!classDoc) {
        return res.status(404).json({
          success: false,
          message: "Class not found in your organization",
        });
      }

      if (!sectionDoc) {
        return res.status(404).json({
          success: false,
          message: "Section not found in this class",
        });
      }

      // Teacher restriction: verify teacher is assigned to this class
      if (req.userRole === "teacher") {
        const teacherDoc = await teachersCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
          status: "active",
        });

        if (!teacherDoc) {
          return res.status(403).json({
            success: false,
            message: "Teacher profile not found",
          });
        }

        // Check if teacher has any subject in this class
        const hasSubjectInClass = await subjectsCollection.findOne({
          organizationId: req.organizationId,
          classId: new ObjectId(classId),
          teacherId: teacherDoc._id,
        });

        if (!hasSubjectInClass) {
          return res.status(403).json({
            success: false,
            message: "You are not assigned to this class",
          });
        }
      }

      // Validate each record
      const validStatuses = ["present", "absent", "late", "excused"];
      const validatedRecords = [];

      for (const record of records) {
        if (!record.studentId || !record.status) {
          return res.status(400).json({
            success: false,
            message: "Each record must have studentId and status",
          });
        }

        if (!ObjectId.isValid(record.studentId)) {
          return res.status(400).json({
            success: false,
            message: `Invalid studentId: ${record.studentId}`,
          });
        }

        if (!validStatuses.includes(record.status)) {
          return res.status(400).json({
            success: false,
            message: `Invalid status '${record.status}'. Must be one of: ${validStatuses.join(", ")}`,
          });
        }

        validatedRecords.push({
          studentId: new ObjectId(record.studentId),
          status: record.status,
        });
      }

      // Validate all students exist in the given class+section
      const studentIds = validatedRecords.map((r) => r.studentId);
      const validStudents = await studentsCollection.countDocuments({
        organizationId: req.organizationId,
        _id: { $in: studentIds },
        classId: new ObjectId(classId),
        sectionId: new ObjectId(sectionId),
        status: "active",
      });

      if (validStudents !== studentIds.length) {
        return res.status(400).json({
          success: false,
          message:
            "Some students are not found, not active, or do not belong to the specified class and section",
        });
      }

      // Upsert: find existing record for this org+class+section+date
      const filter = {
        organizationId: req.organizationId,
        classId: new ObjectId(classId),
        sectionId: new ObjectId(sectionId),
        date: attendanceDate,
      };

      const existing = await attendanceCollection.findOne(filter);

      const attendanceData = {
        organizationId: req.organizationId,
        classId: new ObjectId(classId),
        sectionId: new ObjectId(sectionId),
        date: attendanceDate,
        records: validatedRecords,
        markedBy: req.userId,
        updatedAt: new Date(),
      };

      let resultAction;

      if (existing) {
        // Update existing record
        await attendanceCollection.updateOne(filter, {
          $set: {
            records: validatedRecords,
            markedBy: req.userId,
            updatedAt: new Date(),
          },
        });
        resultAction = "updated";
      } else {
        // Insert new record
        attendanceData.createdAt = new Date();
        await attendanceCollection.insertOne(attendanceData);
        resultAction = "created";
      }

      await logActivity(
        req.userId,
        req.organizationId,
        resultAction,
        "attendance",
        existing ? existing._id : null,
        {
          after: {
            classId,
            sectionId,
            date: attendanceDate,
            recordCount: validatedRecords.length,
          },
        },
        req
      );

      const savedRecord = await attendanceCollection.findOne(filter);

      res.status(existing ? 200 : 201).json({
        success: true,
        message: `Attendance ${resultAction} successfully`,
        data: savedRecord,
      });
    } catch (error) {
      logger.error("Error marking attendance:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to mark attendance",
        error: error.message,
      });
    }
  }
);

// GET /attendance/reports - Aggregated attendance reports
// NOTE: This route MUST be defined before GET /attendance to avoid route conflict
app.get(
  "/attendance/reports",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_attendance"),
  async (req, res) => {
    try {
      const { classId, sectionId, studentId, startDate, endDate } = req.query;

      const matchStage = {
        organizationId: req.organizationId,
      };

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid classId",
          });
        }
        matchStage.classId = new ObjectId(classId);
      }

      if (sectionId) {
        if (!ObjectId.isValid(sectionId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid sectionId",
          });
        }
        matchStage.sectionId = new ObjectId(sectionId);
      }

      if (startDate || endDate) {
        matchStage.date = {};
        if (startDate) matchStage.date.$gte = new Date(startDate);
        if (endDate) {
          const end = new Date(endDate);
          end.setHours(23, 59, 59, 999);
          matchStage.date.$lte = end;
        }
      }

      // If studentId is provided, return individual student report
      if (studentId) {
        if (!ObjectId.isValid(studentId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid studentId",
          });
        }

        const studentObjectId = new ObjectId(studentId);

        // Verify student exists
        const student = await studentsCollection.findOne({
          _id: studentObjectId,
          organizationId: req.organizationId,
        });

        if (!student) {
          return res.status(404).json({
            success: false,
            message: "Student not found",
          });
        }

        // Add class/section filter from student if not already provided
        if (!classId) matchStage.classId = student.classId;
        if (!sectionId) matchStage.sectionId = student.sectionId;

        matchStage["records.studentId"] = studentObjectId;

        const attendanceDocs = await attendanceCollection
          .find(matchStage)
          .sort({ date: -1 })
          .toArray();

        let present = 0,
          absent = 0,
          late = 0,
          excused = 0;

        attendanceDocs.forEach((doc) => {
          const record = doc.records.find(
            (r) => String(r.studentId) === String(studentObjectId)
          );
          if (record) {
            if (record.status === "present") present++;
            else if (record.status === "absent") absent++;
            else if (record.status === "late") late++;
            else if (record.status === "excused") excused++;
          }
        });

        const totalDays = attendanceDocs.length;
        const attendancePercentage =
          totalDays > 0
            ? Math.round(((present + late) / totalDays) * 100 * 100) / 100
            : 0;

        // Get student user info
        const studentUser = student.userId
          ? await usersCollection.findOne(
              { _id: new ObjectId(student.userId) },
              { projection: { name: 1, email: 1 } }
            )
          : null;

        return res.json({
          success: true,
          data: {
            student: {
              _id: student._id,
              admissionNumber: student.admissionNumber,
              rollNumber: student.rollNumber,
              name: studentUser?.name || "Unknown",
            },
            summary: {
              totalDays,
              present,
              absent,
              late,
              excused,
              attendancePercentage,
            },
          },
        });
      }

      // Class/section-wide report: per-student summary
      if (!classId || !sectionId) {
        return res.status(400).json({
          success: false,
          message:
            "Either studentId, or both classId and sectionId are required",
        });
      }

      const attendanceDocs = await attendanceCollection
        .find(matchStage)
        .sort({ date: -1 })
        .toArray();

      const totalDays = attendanceDocs.length;

      // Build per-student stats
      const studentStats = {};

      attendanceDocs.forEach((doc) => {
        doc.records.forEach((record) => {
          const sid = String(record.studentId);
          if (!studentStats[sid]) {
            studentStats[sid] = {
              studentId: record.studentId,
              present: 0,
              absent: 0,
              late: 0,
              excused: 0,
            };
          }
          studentStats[sid][record.status]++;
        });
      });

      // Enrich with student names
      const studentIdsForLookup = Object.values(studentStats).map(
        (s) => new ObjectId(s.studentId)
      );

      const students = studentIdsForLookup.length
        ? await studentsCollection
            .find({ _id: { $in: studentIdsForLookup } })
            .toArray()
        : [];

      const studentUserIds = students
        .filter((s) => s.userId)
        .map((s) => new ObjectId(s.userId));

      const studentUsers = studentUserIds.length
        ? await usersCollection
            .find({ _id: { $in: studentUserIds } })
            .project({ name: 1 })
            .toArray()
        : [];

      const userMap = {};
      studentUsers.forEach((u) => (userMap[String(u._id)] = u.name));

      const studentMap = {};
      students.forEach((s) => {
        studentMap[String(s._id)] = {
          admissionNumber: s.admissionNumber,
          rollNumber: s.rollNumber,
          name: userMap[String(s.userId)] || "Unknown",
        };
      });

      const perStudentReport = Object.values(studentStats).map((stats) => {
        const sid = String(stats.studentId);
        const total = stats.present + stats.absent + stats.late + stats.excused;
        return {
          studentId: stats.studentId,
          ...studentMap[sid],
          present: stats.present,
          absent: stats.absent,
          late: stats.late,
          excused: stats.excused,
          totalDays: total,
          attendancePercentage:
            total > 0
              ? Math.round(
                  ((stats.present + stats.late) / total) * 100 * 100
                ) / 100
              : 0,
        };
      });

      // Sort by roll number
      perStudentReport.sort((a, b) => (a.rollNumber || 0) - (b.rollNumber || 0));

      // Overall summary
      const overallPresent = perStudentReport.reduce(
        (sum, s) => sum + s.present,
        0
      );
      const overallAbsent = perStudentReport.reduce(
        (sum, s) => sum + s.absent,
        0
      );
      const overallLate = perStudentReport.reduce(
        (sum, s) => sum + s.late,
        0
      );
      const overallExcused = perStudentReport.reduce(
        (sum, s) => sum + s.excused,
        0
      );
      const overallTotal =
        overallPresent + overallAbsent + overallLate + overallExcused;

      res.json({
        success: true,
        data: {
          totalDaysMarked: totalDays,
          totalStudents: perStudentReport.length,
          overallSummary: {
            present: overallPresent,
            absent: overallAbsent,
            late: overallLate,
            excused: overallExcused,
            total: overallTotal,
            attendancePercentage:
              overallTotal > 0
                ? Math.round(
                    ((overallPresent + overallLate) / overallTotal) * 100 * 100
                  ) / 100
                : 0,
          },
          students: perStudentReport,
        },
      });
    } catch (error) {
      logger.error("Error generating attendance report:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate attendance report",
        error: error.message,
      });
    }
  }
);

// GET /attendance - List attendance records
app.get(
  "/attendance",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_attendance"),
  async (req, res) => {
    try {
      const {
        classId,
        sectionId,
        startDate,
        endDate,
        page = 1,
        limit = 10,
      } = req.query;

      const query = {
        organizationId: req.organizationId,
      };

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid classId",
          });
        }
        query.classId = new ObjectId(classId);
      }

      if (sectionId) {
        if (!ObjectId.isValid(sectionId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid sectionId",
          });
        }
        query.sectionId = new ObjectId(sectionId);
      }

      if (startDate || endDate) {
        query.date = {};
        if (startDate) query.date.$gte = new Date(startDate);
        if (endDate) {
          const end = new Date(endDate);
          end.setHours(23, 59, 59, 999);
          query.date.$lte = end;
        }
      }

      const total = await attendanceCollection.countDocuments(query);

      const attendanceDocs = await attendanceCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ date: -1 })
        .toArray();

      // Enrich with class names, section names, marker names
      const classIds = [
        ...new Set(attendanceDocs.map((a) => String(a.classId))),
      ];
      const sectionIds = [
        ...new Set(attendanceDocs.map((a) => String(a.sectionId))),
      ];
      const markerIds = [
        ...new Set(
          attendanceDocs.filter((a) => a.markedBy).map((a) => String(a.markedBy))
        ),
      ];

      // Collect all unique studentIds from records
      const allStudentIds = new Set();
      attendanceDocs.forEach((doc) => {
        doc.records.forEach((r) => allStudentIds.add(String(r.studentId)));
      });

      const [classes, sections, markers, studentDocs] = await Promise.all([
        classIds.length
          ? classesCollection
              .find({ _id: { $in: classIds.map((c) => new ObjectId(c)) } })
              .toArray()
          : [],
        sectionIds.length
          ? sectionsCollection
              .find({ _id: { $in: sectionIds.map((s) => new ObjectId(s)) } })
              .toArray()
          : [],
        markerIds.length
          ? usersCollection
              .find({ _id: { $in: markerIds.map((m) => new ObjectId(m)) } })
              .project({ name: 1 })
              .toArray()
          : [],
        allStudentIds.size > 0
          ? studentsCollection
              .find({
                _id: {
                  $in: [...allStudentIds].map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
      ]);

      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));

      const sectionMap = {};
      sections.forEach((s) => (sectionMap[String(s._id)] = s.name));

      const markerMap = {};
      markers.forEach((m) => (markerMap[String(m._id)] = m.name));

      // Build student name map (student -> user -> name)
      const studentUserIds = studentDocs
        .filter((s) => s.userId)
        .map((s) => new ObjectId(s.userId));

      const studentUsers = studentUserIds.length
        ? await usersCollection
            .find({ _id: { $in: studentUserIds } })
            .project({ name: 1 })
            .toArray()
        : [];

      const userNameMap = {};
      studentUsers.forEach((u) => (userNameMap[String(u._id)] = u.name));

      const studentNameMap = {};
      studentDocs.forEach((s) => {
        studentNameMap[String(s._id)] = {
          name: userNameMap[String(s.userId)] || "Unknown",
          rollNumber: s.rollNumber,
          admissionNumber: s.admissionNumber,
        };
      });

      const enrichedDocs = attendanceDocs.map((doc) => ({
        ...doc,
        className: classMap[String(doc.classId)] || "Unknown",
        sectionName: sectionMap[String(doc.sectionId)] || "Unknown",
        markedByName: markerMap[String(doc.markedBy)] || "Unknown",
        records: doc.records.map((r) => ({
          ...r,
          studentName:
            studentNameMap[String(r.studentId)]?.name || "Unknown",
          rollNumber:
            studentNameMap[String(r.studentId)]?.rollNumber || null,
        })),
      }));

      res.json({
        success: true,
        data: enrichedDocs,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching attendance:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch attendance records",
        error: error.message,
      });
    }
  }
);

// GET /attendance/student/:studentId - Single student attendance history
app.get(
  "/attendance/student/:studentId",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_attendance"),
  async (req, res) => {
    try {
      const { studentId } = req.params;
      const { startDate, endDate, month } = req.query;

      if (!ObjectId.isValid(studentId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid studentId",
        });
      }

      const student = await studentsCollection.findOne({
        _id: new ObjectId(studentId),
        organizationId: req.organizationId,
      });

      if (!student) {
        return res.status(404).json({
          success: false,
          message: "Student not found",
        });
      }

      const studentObjectId = new ObjectId(studentId);

      // Build date filter
      const dateFilter = {};
      if (month) {
        const [year, mon] = month.split("-").map(Number);
        dateFilter.$gte = new Date(year, mon - 1, 1);
        dateFilter.$lt = new Date(year, mon, 1);
      } else {
        if (startDate) dateFilter.$gte = new Date(startDate);
        if (endDate) {
          const end = new Date(endDate);
          end.setHours(23, 59, 59, 999);
          dateFilter.$lte = end;
        }
      }

      const query = {
        organizationId: req.organizationId,
        classId: student.classId,
        sectionId: student.sectionId,
        "records.studentId": studentObjectId,
      };

      if (Object.keys(dateFilter).length > 0) {
        query.date = dateFilter;
      }

      const attendanceDocs = await attendanceCollection
        .find(query)
        .sort({ date: -1 })
        .toArray();

      const entries = attendanceDocs.map((doc) => {
        const record = doc.records.find(
          (r) => String(r.studentId) === String(studentObjectId)
        );
        return {
          date: doc.date,
          status: record ? record.status : "absent",
        };
      });

      // Compute summary
      const totalDays = entries.length;
      const present = entries.filter((e) => e.status === "present").length;
      const absent = entries.filter((e) => e.status === "absent").length;
      const late = entries.filter((e) => e.status === "late").length;
      const excused = entries.filter((e) => e.status === "excused").length;
      const attendancePercentage =
        totalDays > 0
          ? Math.round(((present + late) / totalDays) * 100 * 100) / 100
          : 0;

      // Get student user info
      const studentUser = student.userId
        ? await usersCollection.findOne(
            { _id: new ObjectId(student.userId) },
            { projection: { name: 1, email: 1 } }
          )
        : null;

      res.json({
        success: true,
        data: {
          student: {
            _id: student._id,
            admissionNumber: student.admissionNumber,
            rollNumber: student.rollNumber,
            name: studentUser?.name || "Unknown",
            classId: student.classId,
            sectionId: student.sectionId,
          },
          entries,
          summary: {
            totalDays,
            present,
            absent,
            late,
            excused,
            attendancePercentage,
          },
        },
      });
    } catch (error) {
      logger.error("Error fetching student attendance:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch student attendance",
        error: error.message,
      });
    }
  }
);

// ==================== PHASE 4: EXAMS & GRADES ====================

// --- Exam Management Endpoints ---

// POST /exams - Create exam
app.post(
  "/exams",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_exam"),
  async (req, res) => {
    try {
      const { name, classId, academicYear, startDate, endDate } =
        req.body;

      if (!name || !classId || !academicYear || !startDate || !endDate) {
        return res.status(400).json({
          success: false,
          message:
            "Required fields: name, classId, academicYear, startDate, endDate",
        });
      }

      if (!ObjectId.isValid(classId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid classId",
        });
      }

      const classDoc = await classesCollection.findOne({
        _id: new ObjectId(classId),
        organizationId: req.organizationId,
      });

      if (!classDoc) {
        return res.status(404).json({
          success: false,
          message: "Class not found in your organization",
        });
      }

      const start = new Date(startDate);
      const end = new Date(endDate);
      if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        return res.status(400).json({
          success: false,
          message: "Invalid date format for startDate or endDate",
        });
      }
      if (start > end) {
        return res.status(400).json({
          success: false,
          message: "startDate must be before or equal to endDate",
        });
      }

      // Determine status based on dates
      const now = new Date();
      let status = "upcoming";
      if (now >= start && now <= end) status = "ongoing";
      else if (now > end) status = "completed";

      const newExam = {
        organizationId: req.organizationId,
        name,
        classId: new ObjectId(classId),
        academicYear,
        startDate: start,
        endDate: end,
        status,
        createdBy: req.userId,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await examsCollection.insertOne(newExam);

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "exam",
        result.insertedId,
        { after: { name, classId, academicYear, startDate, endDate } },
        req
      );

      const created = await examsCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "Exam created successfully",
        data: { ...created, className: classDoc.name },
      });
    } catch (error) {
      logger.error("Error creating exam:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to create exam",
        error: error.message,
      });
    }
  }
);

// GET /exams - List exams
app.get(
  "/exams",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_exam"),
  async (req, res) => {
    try {
      const {
        classId,
        academicYear,
        status,
        page = 1,
        limit = 20,
      } = req.query;

      const query = { organizationId: req.organizationId };

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid classId",
          });
        }
        query.classId = new ObjectId(classId);
      }
      if (academicYear) query.academicYear = academicYear;
      if (status) query.status = status;

      const total = await examsCollection.countDocuments(query);
      const exams = await examsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ startDate: -1 })
        .toArray();

      // Enrich with class names
      const classIds = [
        ...new Set(exams.map((e) => String(e.classId))),
      ];
      const classes = classIds.length
        ? await classesCollection
            .find({
              _id: { $in: classIds.map((c) => new ObjectId(c)) },
            })
            .toArray()
        : [];

      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));

      // Get submission counts per exam
      const examObjIds = exams.map((e) => e._id);
      const submissionCounts = examObjIds.length
        ? await gradeSubmissionsCollection
            .aggregate([
              {
                $match: {
                  organizationId: req.organizationId,
                  examId: { $in: examObjIds },
                },
              },
              {
                $group: {
                  _id: { examId: "$examId", status: "$status" },
                  count: { $sum: 1 },
                },
              },
            ])
            .toArray()
        : [];

      const submissionMap = {};
      submissionCounts.forEach((sc) => {
        const eid = String(sc._id.examId);
        if (!submissionMap[eid]) submissionMap[eid] = {};
        submissionMap[eid][sc._id.status] = sc.count;
      });

      const enriched = exams.map((e) => ({
        ...e,
        className: classMap[String(e.classId)] || "Unknown",
        submissionStatus: submissionMap[String(e._id)] || {},
      }));

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching exams:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch exams",
        error: error.message,
      });
    }
  }
);

// GET /exams/:id - Get exam details with submission status per subject
app.get(
  "/exams/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_exam"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid exam ID",
        });
      }

      const exam = await examsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!exam) {
        return res.status(404).json({
          success: false,
          message: "Exam not found",
        });
      }

      // Get class info
      const classDoc = await classesCollection.findOne({
        _id: exam.classId,
      });

      // Get all sections for this class
      const sections = await sectionsCollection
        .find({
          organizationId: req.organizationId,
          classId: exam.classId,
        })
        .toArray();

      // Get all subjects for this class
      const subjects = await subjectsCollection
        .find({
          organizationId: req.organizationId,
          classId: exam.classId,
        })
        .toArray();

      // Get teacher names for subjects
      const teacherIds = subjects
        .filter((s) => s.teacherId)
        .map((s) => s.teacherId);
      const teachers = teacherIds.length
        ? await teachersCollection
            .find({ _id: { $in: teacherIds } })
            .toArray()
        : [];
      const teacherUserIds = teachers
        .filter((t) => t.userId)
        .map((t) => t.userId);
      const teacherUsers = teacherUserIds.length
        ? await usersCollection
            .find(
              { _id: { $in: teacherUserIds } },
              { projection: { name: 1 } }
            )
            .toArray()
        : [];
      const teacherUserMap = {};
      teacherUsers.forEach(
        (u) => (teacherUserMap[String(u._id)] = u.name)
      );
      const teacherNameMap = {};
      teachers.forEach(
        (t) =>
          (teacherNameMap[String(t._id)] =
            teacherUserMap[String(t.userId)] || "Unknown")
      );

      // Get all submissions for this exam
      const submissions = await gradeSubmissionsCollection
        .find({
          organizationId: req.organizationId,
          examId: new ObjectId(id),
        })
        .toArray();

      // Build submission lookup: sectionId+subjectId -> submission
      const submissionLookup = {};
      submissions.forEach((sub) => {
        const key = `${String(sub.sectionId)}_${String(sub.subjectId)}`;
        submissionLookup[key] = {
          _id: sub._id,
          status: sub.status,
          teacherId: sub.teacherId,
          studentCount: sub.grades ? sub.grades.length : 0,
          submittedAt: sub.submittedAt,
          approvedAt: sub.approvedAt,
          publishedAt: sub.publishedAt,
        };
      });

      // Build per-section, per-subject status grid
      const sectionDetails = sections.map((section) => ({
        _id: section._id,
        name: section.name,
        subjects: subjects.map((subject) => {
          const key = `${String(section._id)}_${String(subject._id)}`;
          const submission = submissionLookup[key];
          return {
            _id: subject._id,
            name: subject.name,
            subjectCode: subject.subjectCode,
            teacherName:
              teacherNameMap[String(subject.teacherId)] || "Unassigned",
            submission: submission || { status: "not_started" },
          };
        }),
      }));

      res.json({
        success: true,
        data: {
          ...exam,
          className: classDoc?.name || "Unknown",
          sections: sectionDetails,
          totalSubmissions: submissions.length,
          totalExpected: sections.length * subjects.length,
        },
      });
    } catch (error) {
      logger.error("Error fetching exam details:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch exam details",
        error: error.message,
      });
    }
  }
);

// PATCH /exams/:id - Update exam
app.patch(
  "/exams/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_exams"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid exam ID",
        });
      }

      const exam = await examsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!exam) {
        return res.status(404).json({
          success: false,
          message: "Exam not found",
        });
      }

      // Block update if published submissions exist
      const publishedCount =
        await gradeSubmissionsCollection.countDocuments({
          organizationId: req.organizationId,
          examId: new ObjectId(id),
          status: "published",
        });

      if (publishedCount > 0) {
        return res.status(400).json({
          success: false,
          message:
            "Cannot update exam with published grade submissions",
        });
      }

      const allowedFields = [
        "name",
        "academicYear",
        "startDate",
        "endDate",
        "status",
      ];
      const updates = {};
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          if (field === "startDate" || field === "endDate") {
            const d = new Date(req.body[field]);
            if (isNaN(d.getTime())) {
              return res.status(400).json({
                success: false,
                message: `Invalid date format for ${field}`,
              });
            }
            updates[field] = d;
          } else if (field === "status") {
            if (
              !["upcoming", "ongoing", "completed"].includes(
                req.body[field]
              )
            ) {
              return res.status(400).json({
                success: false,
                message:
                  "Status must be: upcoming, ongoing, or completed",
              });
            }
            updates[field] = req.body[field];
          } else {
            updates[field] = req.body[field];
          }
        }
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      // Validate startDate <= endDate if either is being updated
      const finalStart = updates.startDate || exam.startDate;
      const finalEnd = updates.endDate || exam.endDate;
      if (finalStart > finalEnd) {
        return res.status(400).json({
          success: false,
          message: "startDate must be before or equal to endDate",
        });
      }

      updates.updatedAt = new Date();

      await examsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "exam",
        id,
        {
          before: Object.fromEntries(
            Object.keys(updates).map((k) => [k, exam[k]])
          ),
          after: updates,
        },
        req
      );

      const updated = await examsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Exam updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating exam:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update exam",
        error: error.message,
      });
    }
  }
);

// DELETE /exams/:id - Delete exam (cascade: grade_submissions)
app.delete(
  "/exams/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_exams"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid exam ID",
        });
      }

      const exam = await examsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!exam) {
        return res.status(404).json({
          success: false,
          message: "Exam not found",
        });
      }

      // Block deletion if published submissions exist
      const publishedCount =
        await gradeSubmissionsCollection.countDocuments({
          organizationId: req.organizationId,
          examId: new ObjectId(id),
          status: "published",
        });

      if (publishedCount > 0) {
        return res.status(400).json({
          success: false,
          message:
            "Cannot delete exam with published grade submissions. Published results must be preserved.",
        });
      }

      // Cascade delete all non-published grade submissions
      const deleteResult =
        await gradeSubmissionsCollection.deleteMany({
          organizationId: req.organizationId,
          examId: new ObjectId(id),
        });

      await examsCollection.deleteOne({ _id: new ObjectId(id) });

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "exam",
        id,
        {
          before: {
            name: exam.name,
            classId: exam.classId,
            academicYear: exam.academicYear,
            submissionsDeleted: deleteResult.deletedCount,
          },
        },
        req
      );

      res.json({
        success: true,
        message: `Exam deleted successfully. ${deleteResult.deletedCount} grade submission(s) also removed.`,
      });
    } catch (error) {
      logger.error("Error deleting exam:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to delete exam",
        error: error.message,
      });
    }
  }
);

// --- Grade Submission Endpoints ---

// IMPORTANT: Static paths MUST come before parameterized /:id paths

// GET /grade-submissions/teacher/my-submissions - Teacher's own submissions
app.get(
  "/grade-submissions/teacher/my-submissions",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_grade_draft"),
  async (req, res) => {
    try {
      const { examId, status, page = 1, limit = 20 } = req.query;

      const teacherDoc = await getTeacherDocForCurrentUser(
        req.organizationId,
        req.userId
      );
      if (!teacherDoc) {
        return res.status(403).json({
          success: false,
          message: "Teacher profile not found or inactive",
        });
      }

      const query = {
        organizationId: req.organizationId,
        teacherId: teacherDoc._id,
      };
      if (examId && ObjectId.isValid(examId)) {
        query.examId = new ObjectId(examId);
      }
      if (status) query.status = status;

      const total = await gradeSubmissionsCollection.countDocuments(
        query
      );
      const submissions = await gradeSubmissionsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ updatedAt: -1 })
        .toArray();

      // Enrich
      const examIds = [
        ...new Set(submissions.map((s) => String(s.examId))),
      ];
      const classIds = [
        ...new Set(submissions.map((s) => String(s.classId))),
      ];
      const sectionIds = [
        ...new Set(submissions.map((s) => String(s.sectionId))),
      ];
      const subjectIds = [
        ...new Set(submissions.map((s) => String(s.subjectId))),
      ];

      const [exams, classes, sections, subjects] = await Promise.all([
        examIds.length
          ? examsCollection
              .find({
                _id: { $in: examIds.map((e) => new ObjectId(e)) },
              })
              .toArray()
          : [],
        classIds.length
          ? classesCollection
              .find({
                _id: { $in: classIds.map((c) => new ObjectId(c)) },
              })
              .toArray()
          : [],
        sectionIds.length
          ? sectionsCollection
              .find({
                _id: {
                  $in: sectionIds.map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
        subjectIds.length
          ? subjectsCollection
              .find({
                _id: {
                  $in: subjectIds.map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
      ]);

      const examMap = {};
      exams.forEach((e) => (examMap[String(e._id)] = e.name));
      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));
      const sectionMap = {};
      sections.forEach((s) => (sectionMap[String(s._id)] = s.name));
      const subjectMap = {};
      subjects.forEach((s) => (subjectMap[String(s._id)] = s.name));

      const enriched = submissions.map((sub) => ({
        ...sub,
        examName: examMap[String(sub.examId)] || "Unknown",
        className: classMap[String(sub.classId)] || "Unknown",
        sectionName: sectionMap[String(sub.sectionId)] || "Unknown",
        subjectName: subjectMap[String(sub.subjectId)] || "Unknown",
        studentCount: sub.grades ? sub.grades.length : 0,
      }));

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching teacher submissions:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch submissions",
        error: error.message,
      });
    }
  }
);

// GET /grade-submissions/moderator/pending - Pending review submissions
app.get(
  "/grade-submissions/moderator/pending",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("review_grades"),
  async (req, res) => {
    try {
      const { examId, classId, page = 1, limit = 20 } = req.query;

      const query = {
        organizationId: req.organizationId,
        status: { $in: ["submitted", "under_review"] },
      };
      if (examId && ObjectId.isValid(examId)) {
        query.examId = new ObjectId(examId);
      }
      if (classId && ObjectId.isValid(classId)) {
        query.classId = new ObjectId(classId);
      }

      const total = await gradeSubmissionsCollection.countDocuments(
        query
      );
      const submissions = await gradeSubmissionsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ submittedAt: -1 })
        .toArray();

      // Enrich
      const examIds = [
        ...new Set(submissions.map((s) => String(s.examId))),
      ];
      const classIds = [
        ...new Set(submissions.map((s) => String(s.classId))),
      ];
      const sectionIds = [
        ...new Set(submissions.map((s) => String(s.sectionId))),
      ];
      const subjectIds = [
        ...new Set(submissions.map((s) => String(s.subjectId))),
      ];
      const teacherIds = [
        ...new Set(
          submissions
            .filter((s) => s.teacherId)
            .map((s) => String(s.teacherId))
        ),
      ];

      const [exams, classes, sections, subjects, teachers] =
        await Promise.all([
          examIds.length
            ? examsCollection
                .find({
                  _id: { $in: examIds.map((e) => new ObjectId(e)) },
                })
                .toArray()
            : [],
          classIds.length
            ? classesCollection
                .find({
                  _id: {
                    $in: classIds.map((c) => new ObjectId(c)),
                  },
                })
                .toArray()
            : [],
          sectionIds.length
            ? sectionsCollection
                .find({
                  _id: {
                    $in: sectionIds.map((s) => new ObjectId(s)),
                  },
                })
                .toArray()
            : [],
          subjectIds.length
            ? subjectsCollection
                .find({
                  _id: {
                    $in: subjectIds.map((s) => new ObjectId(s)),
                  },
                })
                .toArray()
            : [],
          teacherIds.length
            ? teachersCollection
                .find({
                  _id: {
                    $in: teacherIds.map((t) => new ObjectId(t)),
                  },
                })
                .toArray()
            : [],
        ]);

      // Get teacher user names
      const teacherUserIds = teachers
        .filter((t) => t.userId)
        .map((t) => t.userId);
      const teacherUsers = teacherUserIds.length
        ? await usersCollection
            .find(
              { _id: { $in: teacherUserIds } },
              { projection: { name: 1 } }
            )
            .toArray()
        : [];
      const teacherUserMap = {};
      teacherUsers.forEach(
        (u) => (teacherUserMap[String(u._id)] = u.name)
      );

      const examMap = {};
      exams.forEach((e) => (examMap[String(e._id)] = e.name));
      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));
      const sectionMap = {};
      sections.forEach((s) => (sectionMap[String(s._id)] = s.name));
      const subjectMap = {};
      subjects.forEach((s) => (subjectMap[String(s._id)] = s.name));
      const teacherNameMap = {};
      teachers.forEach(
        (t) =>
          (teacherNameMap[String(t._id)] =
            teacherUserMap[String(t.userId)] || "Unknown")
      );

      const enriched = submissions.map((sub) => ({
        ...sub,
        examName: examMap[String(sub.examId)] || "Unknown",
        className: classMap[String(sub.classId)] || "Unknown",
        sectionName: sectionMap[String(sub.sectionId)] || "Unknown",
        subjectName: subjectMap[String(sub.subjectId)] || "Unknown",
        teacherName:
          teacherNameMap[String(sub.teacherId)] || "Unknown",
        studentCount: sub.grades ? sub.grades.length : 0,
      }));

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching pending submissions:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch pending submissions",
        error: error.message,
      });
    }
  }
);

// GET /grade-submissions/admin/approved - Approved submissions ready to publish
app.get(
  "/grade-submissions/admin/approved",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("publish_grades"),
  async (req, res) => {
    try {
      const { examId, classId, page = 1, limit = 20 } = req.query;

      const query = {
        organizationId: req.organizationId,
        status: "approved",
      };
      if (examId && ObjectId.isValid(examId)) {
        query.examId = new ObjectId(examId);
      }
      if (classId && ObjectId.isValid(classId)) {
        query.classId = new ObjectId(classId);
      }

      const total = await gradeSubmissionsCollection.countDocuments(
        query
      );
      const submissions = await gradeSubmissionsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ approvedAt: -1 })
        .toArray();

      // Enrich
      const examIds = [
        ...new Set(submissions.map((s) => String(s.examId))),
      ];
      const classIds = [
        ...new Set(submissions.map((s) => String(s.classId))),
      ];
      const sectionIds = [
        ...new Set(submissions.map((s) => String(s.sectionId))),
      ];
      const subjectIds = [
        ...new Set(submissions.map((s) => String(s.subjectId))),
      ];

      const [exams, classes, sections, subjects] = await Promise.all([
        examIds.length
          ? examsCollection
              .find({
                _id: { $in: examIds.map((e) => new ObjectId(e)) },
              })
              .toArray()
          : [],
        classIds.length
          ? classesCollection
              .find({
                _id: { $in: classIds.map((c) => new ObjectId(c)) },
              })
              .toArray()
          : [],
        sectionIds.length
          ? sectionsCollection
              .find({
                _id: {
                  $in: sectionIds.map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
        subjectIds.length
          ? subjectsCollection
              .find({
                _id: {
                  $in: subjectIds.map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
      ]);

      const examMap = {};
      exams.forEach((e) => (examMap[String(e._id)] = e.name));
      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));
      const sectionMap = {};
      sections.forEach((s) => (sectionMap[String(s._id)] = s.name));
      const subjectMap = {};
      subjects.forEach((s) => (subjectMap[String(s._id)] = s.name));

      const enriched = submissions.map((sub) => ({
        ...sub,
        examName: examMap[String(sub.examId)] || "Unknown",
        className: classMap[String(sub.classId)] || "Unknown",
        sectionName: sectionMap[String(sub.sectionId)] || "Unknown",
        subjectName: subjectMap[String(sub.subjectId)] || "Unknown",
        studentCount: sub.grades ? sub.grades.length : 0,
      }));

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching approved submissions:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch approved submissions",
        error: error.message,
      });
    }
  }
);

// POST /grade-submissions - Create draft grade submission
app.post(
  "/grade-submissions",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_grade_draft"),
  async (req, res) => {
    try {
      const { examId, classId, sectionId, subjectId, grades } =
        req.body;

      if (!examId || !classId || !sectionId || !subjectId) {
        return res.status(400).json({
          success: false,
          message:
            "Required fields: examId, classId, sectionId, subjectId",
        });
      }

      if (
        !ObjectId.isValid(examId) ||
        !ObjectId.isValid(classId) ||
        !ObjectId.isValid(sectionId) ||
        !ObjectId.isValid(subjectId)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid ObjectId format in request",
        });
      }

      // Verify teacher is assigned to this subject
      const teacherDoc = await getTeacherDocForCurrentUser(
        req.organizationId,
        req.userId
      );
      if (!teacherDoc) {
        return res.status(403).json({
          success: false,
          message: "Teacher profile not found or inactive",
        });
      }

      // Validate all referenced entities exist
      const [exam, classDoc, section, subject] = await Promise.all([
        examsCollection.findOne({
          _id: new ObjectId(examId),
          organizationId: req.organizationId,
        }),
        classesCollection.findOne({
          _id: new ObjectId(classId),
          organizationId: req.organizationId,
        }),
        sectionsCollection.findOne({
          _id: new ObjectId(sectionId),
          organizationId: req.organizationId,
          classId: new ObjectId(classId),
        }),
        subjectsCollection.findOne({
          _id: new ObjectId(subjectId),
          organizationId: req.organizationId,
          classId: new ObjectId(classId),
          teacherId: teacherDoc._id,
        }),
      ]);

      if (!exam) {
        return res.status(404).json({
          success: false,
          message: "Exam not found in your organization",
        });
      }
      if (!classDoc) {
        return res.status(404).json({
          success: false,
          message: "Class not found in your organization",
        });
      }
      if (!section) {
        return res.status(404).json({
          success: false,
          message: "Section not found in this class",
        });
      }
      if (!subject) {
        return res.status(403).json({
          success: false,
          message:
            "You are not assigned to teach this subject in this class",
        });
      }

      // Check for existing submission (proactive duplicate check)
      const existing = await gradeSubmissionsCollection.findOne({
        organizationId: req.organizationId,
        examId: new ObjectId(examId),
        classId: new ObjectId(classId),
        sectionId: new ObjectId(sectionId),
        subjectId: new ObjectId(subjectId),
      });

      if (existing) {
        return res.status(409).json({
          success: false,
          message:
            "A grade submission already exists for this exam, class, section, and subject",
          data: { existingId: existing._id, status: existing.status },
        });
      }

      // Build initial grades array if provided, else empty
      let processedGrades = [];
      if (grades && Array.isArray(grades) && grades.length > 0) {
        for (const g of grades) {
          if (!g.studentId || !ObjectId.isValid(g.studentId)) {
            return res.status(400).json({
              success: false,
              message: `Invalid studentId in grades array: ${g.studentId}`,
            });
          }
          const marks =
            g.marks !== undefined && g.marks !== null
              ? Number(g.marks)
              : null;
          if (marks !== null) {
            if (isNaN(marks) || marks < 0 || marks > subject.fullMarks) {
              return res.status(400).json({
                success: false,
                message: `Marks must be between 0 and ${subject.fullMarks} for student ${g.studentId}`,
              });
            }
          }
          const gradeCalc =
            marks !== null
              ? calculateGrade(marks, subject.fullMarks)
              : { grade: null, gradePoint: null };
          processedGrades.push({
            studentId: new ObjectId(g.studentId),
            marks,
            grade: gradeCalc.grade,
            gradePoint: gradeCalc.gradePoint,
            remarks: g.remarks || "",
          });
        }
      }

      const auditEntry = {
        action: "created",
        userId: req.userId,
        userName: req.user?.name || "Unknown",
        role: req.userRole,
        comment: "",
        timestamp: new Date(),
      };

      const newSubmission = {
        organizationId: req.organizationId,
        examId: new ObjectId(examId),
        classId: new ObjectId(classId),
        sectionId: new ObjectId(sectionId),
        subjectId: new ObjectId(subjectId),
        teacherId: teacherDoc._id,
        moderatorId: null,
        status: "draft",
        grades: processedGrades,
        reviewComment: null,
        rejectionReason: null,
        auditHistory: [auditEntry],
        submittedAt: null,
        reviewedAt: null,
        approvedAt: null,
        publishedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await gradeSubmissionsCollection.insertOne(
        newSubmission
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "grade_submission",
        result.insertedId,
        {
          after: {
            examId,
            classId,
            sectionId,
            subjectId,
            studentCount: processedGrades.length,
          },
        },
        req
      );

      const created = await gradeSubmissionsCollection.findOne({
        _id: result.insertedId,
      });

      res.status(201).json({
        success: true,
        message: "Grade submission draft created successfully",
        data: {
          ...created,
          examName: exam.name,
          className: classDoc.name,
          sectionName: section.name,
          subjectName: subject.name,
        },
      });
    } catch (error) {
      if (error.code === 11000) {
        return res.status(409).json({
          success: false,
          message:
            "A grade submission already exists for this exam, class, section, and subject",
        });
      }
      logger.error("Error creating grade submission:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to create grade submission",
        error: error.message,
      });
    }
  }
);

// GET /grade-submissions - List grade submissions
app.get(
  "/grade-submissions",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_grade_draft"),
  async (req, res) => {
    try {
      const {
        examId,
        classId,
        sectionId,
        subjectId,
        status,
        teacherId,
        page = 1,
        limit = 20,
      } = req.query;

      const query = { organizationId: req.organizationId };

      // Teachers can only see their own submissions
      if (req.userRole === "teacher") {
        const teacherDoc = await teachersCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
          status: "active",
        });
        if (teacherDoc) {
          query.teacherId = teacherDoc._id;
        }
      }

      if (examId && ObjectId.isValid(examId)) {
        query.examId = new ObjectId(examId);
      }
      if (classId && ObjectId.isValid(classId)) {
        query.classId = new ObjectId(classId);
      }
      if (sectionId && ObjectId.isValid(sectionId)) {
        query.sectionId = new ObjectId(sectionId);
      }
      if (subjectId && ObjectId.isValid(subjectId)) {
        query.subjectId = new ObjectId(subjectId);
      }
      if (status) query.status = status;
      if (teacherId && ObjectId.isValid(teacherId)) {
        query.teacherId = new ObjectId(teacherId);
      }

      const total = await gradeSubmissionsCollection.countDocuments(
        query
      );
      const submissions = await gradeSubmissionsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ updatedAt: -1 })
        .toArray();

      // Enrich
      const examIds = [
        ...new Set(submissions.map((s) => String(s.examId))),
      ];
      const classIds = [
        ...new Set(submissions.map((s) => String(s.classId))),
      ];
      const sectionIds = [
        ...new Set(submissions.map((s) => String(s.sectionId))),
      ];
      const subjectIds = [
        ...new Set(submissions.map((s) => String(s.subjectId))),
      ];
      const teacherObjIds = [
        ...new Set(
          submissions
            .filter((s) => s.teacherId)
            .map((s) => String(s.teacherId))
        ),
      ];

      const [exams, classes, sections, subjects, teachers] =
        await Promise.all([
          examIds.length
            ? examsCollection
                .find({
                  _id: { $in: examIds.map((e) => new ObjectId(e)) },
                })
                .toArray()
            : [],
          classIds.length
            ? classesCollection
                .find({
                  _id: {
                    $in: classIds.map((c) => new ObjectId(c)),
                  },
                })
                .toArray()
            : [],
          sectionIds.length
            ? sectionsCollection
                .find({
                  _id: {
                    $in: sectionIds.map((s) => new ObjectId(s)),
                  },
                })
                .toArray()
            : [],
          subjectIds.length
            ? subjectsCollection
                .find({
                  _id: {
                    $in: subjectIds.map((s) => new ObjectId(s)),
                  },
                })
                .toArray()
            : [],
          teacherObjIds.length
            ? teachersCollection
                .find({
                  _id: {
                    $in: teacherObjIds.map((t) => new ObjectId(t)),
                  },
                })
                .toArray()
            : [],
        ]);

      const teacherUserIds = teachers
        .filter((t) => t.userId)
        .map((t) => t.userId);
      const teacherUsers = teacherUserIds.length
        ? await usersCollection
            .find(
              { _id: { $in: teacherUserIds } },
              { projection: { name: 1 } }
            )
            .toArray()
        : [];
      const teacherUserMap = {};
      teacherUsers.forEach(
        (u) => (teacherUserMap[String(u._id)] = u.name)
      );

      const examMap = {};
      exams.forEach((e) => (examMap[String(e._id)] = e.name));
      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));
      const sectionMap = {};
      sections.forEach((s) => (sectionMap[String(s._id)] = s.name));
      const subjectMap = {};
      subjects.forEach((s) => (subjectMap[String(s._id)] = s.name));
      const teacherNameMap = {};
      teachers.forEach(
        (t) =>
          (teacherNameMap[String(t._id)] =
            teacherUserMap[String(t.userId)] || "Unknown")
      );

      const enriched = submissions.map((sub) => ({
        ...sub,
        examName: examMap[String(sub.examId)] || "Unknown",
        className: classMap[String(sub.classId)] || "Unknown",
        sectionName: sectionMap[String(sub.sectionId)] || "Unknown",
        subjectName: subjectMap[String(sub.subjectId)] || "Unknown",
        teacherName:
          teacherNameMap[String(sub.teacherId)] || "Unknown",
        studentCount: sub.grades ? sub.grades.length : 0,
      }));

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching grade submissions:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch grade submissions",
        error: error.message,
      });
    }
  }
);

// GET /grade-submissions/:id - Get submission detail with audit history
app.get(
  "/grade-submissions/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_grade_draft"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid submission ID",
        });
      }

      const submission = await gradeSubmissionsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!submission) {
        return res.status(404).json({
          success: false,
          message: "Grade submission not found",
        });
      }

      // Fetch related data
      const [exam, classDoc, section, subject] = await Promise.all([
        examsCollection.findOne({ _id: submission.examId }),
        classesCollection.findOne({ _id: submission.classId }),
        sectionsCollection.findOne({ _id: submission.sectionId }),
        subjectsCollection.findOne({ _id: submission.subjectId }),
      ]);

      // Get teacher name
      let teacherName = "Unknown";
      if (submission.teacherId) {
        const teacher = await teachersCollection.findOne({
          _id: submission.teacherId,
        });
        if (teacher && teacher.userId) {
          const teacherUser = await usersCollection.findOne(
            { _id: teacher.userId },
            { projection: { name: 1 } }
          );
          teacherName = teacherUser?.name || "Unknown";
        }
      }

      // Enrich student grades with names
      const studentIds = submission.grades.map((g) => g.studentId);
      const students = studentIds.length
        ? await studentsCollection
            .find({ _id: { $in: studentIds } })
            .toArray()
        : [];
      const studentUserIds = students
        .filter((s) => s.userId)
        .map((s) => s.userId);
      const studentUsers = studentUserIds.length
        ? await usersCollection
            .find(
              { _id: { $in: studentUserIds } },
              { projection: { name: 1 } }
            )
            .toArray()
        : [];
      const studentUserMap = {};
      studentUsers.forEach(
        (u) => (studentUserMap[String(u._id)] = u.name)
      );
      const studentMap = {};
      students.forEach((s) => {
        studentMap[String(s._id)] = {
          name: studentUserMap[String(s.userId)] || "Unknown",
          rollNumber: s.rollNumber,
          admissionNumber: s.admissionNumber,
        };
      });

      const enrichedGrades = submission.grades.map((g) => ({
        ...g,
        studentName:
          studentMap[String(g.studentId)]?.name || "Unknown",
        rollNumber:
          studentMap[String(g.studentId)]?.rollNumber || null,
        admissionNumber:
          studentMap[String(g.studentId)]?.admissionNumber || null,
      }));

      res.json({
        success: true,
        data: {
          ...submission,
          grades: enrichedGrades,
          examName: exam?.name || "Unknown",
          className: classDoc?.name || "Unknown",
          sectionName: section?.name || "Unknown",
          subjectName: subject?.name || "Unknown",
          subjectCode: subject?.subjectCode || "",
          fullMarks: subject?.fullMarks || 100,
          passMarks: subject?.passMarks || 33,
          teacherName,
        },
      });
    } catch (error) {
      logger.error("Error fetching grade submission:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch grade submission",
        error: error.message,
      });
    }
  }
);

// PATCH /grade-submissions/:id - Update draft grades
app.patch(
  "/grade-submissions/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_grade_draft"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { grades } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid submission ID",
        });
      }

      const submission = await gradeSubmissionsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!submission) {
        return res.status(404).json({
          success: false,
          message: "Grade submission not found",
        });
      }

      if (submission.status !== "draft") {
        return res.status(400).json({
          success: false,
          message: `Cannot edit grades: submission status is '${submission.status}', must be 'draft'`,
        });
      }

      // Verify ownership - teacher can only edit their own drafts
      if (req.userRole === "teacher") {
        const teacherDoc = await getTeacherDocForCurrentUser(
          req.organizationId,
          req.userId
        );
        if (
          !teacherDoc ||
          String(teacherDoc._id) !== String(submission.teacherId)
        ) {
          return res.status(403).json({
            success: false,
            message: "You can only edit your own draft submissions",
          });
        }
      }

      if (!grades || !Array.isArray(grades)) {
        return res.status(400).json({
          success: false,
          message: "grades array is required",
        });
      }

      // Get subject for fullMarks validation
      const subject = await subjectsCollection.findOne({
        _id: submission.subjectId,
      });
      const fullMarks = subject?.fullMarks || 100;

      // Process grades
      const processedGrades = [];
      for (const g of grades) {
        if (!g.studentId || !ObjectId.isValid(g.studentId)) {
          return res.status(400).json({
            success: false,
            message: `Invalid studentId: ${g.studentId}`,
          });
        }
        const marks =
          g.marks !== undefined && g.marks !== null
            ? Number(g.marks)
            : null;
        if (marks !== null) {
          if (isNaN(marks) || marks < 0 || marks > fullMarks) {
            return res.status(400).json({
              success: false,
              message: `Marks must be between 0 and ${fullMarks} for student ${g.studentId}`,
            });
          }
        }
        const gradeCalc =
          marks !== null
            ? calculateGrade(marks, fullMarks)
            : { grade: null, gradePoint: null };
        processedGrades.push({
          studentId: new ObjectId(g.studentId),
          marks,
          grade: gradeCalc.grade,
          gradePoint: gradeCalc.gradePoint,
          remarks: g.remarks || "",
        });
      }

      await gradeSubmissionsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            grades: processedGrades,
            updatedAt: new Date(),
          },
        }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "grade_submission",
        id,
        {
          after: { studentCount: processedGrades.length },
        },
        req
      );

      const updated = await gradeSubmissionsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Grade submission updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating grade submission:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to update grade submission",
        error: error.message,
      });
    }
  }
);

// POST /grade-submissions/:id/submit - Submit for review (draft -> submitted)
app.post(
  "/grade-submissions/:id/submit",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("submit_grades"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { comment } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid submission ID",
        });
      }

      const submission = await gradeSubmissionsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!submission) {
        return res.status(404).json({
          success: false,
          message: "Grade submission not found",
        });
      }

      if (submission.status !== "draft") {
        return res.status(400).json({
          success: false,
          message: `Cannot submit: current status is '${submission.status}', expected 'draft'`,
        });
      }

      // Verify ownership
      const teacherDoc = await getTeacherDocForCurrentUser(
        req.organizationId,
        req.userId
      );
      if (
        !teacherDoc ||
        String(teacherDoc._id) !== String(submission.teacherId)
      ) {
        return res.status(403).json({
          success: false,
          message: "You can only submit your own draft submissions",
        });
      }

      // Validate: all active students in the class+section must have marks
      const activeStudents = await studentsCollection
        .find({
          organizationId: req.organizationId,
          classId: submission.classId,
          sectionId: submission.sectionId,
          status: "active",
        })
        .toArray();

      const gradedStudentIds = new Set(
        submission.grades.map((g) => String(g.studentId))
      );
      const missingStudents = activeStudents.filter(
        (s) => !gradedStudentIds.has(String(s._id))
      );

      if (missingStudents.length > 0) {
        return res.status(400).json({
          success: false,
          message: `All active students must have marks entered. Missing ${missingStudents.length} student(s).`,
          data: {
            missingStudentIds: missingStudents.map((s) =>
              String(s._id)
            ),
          },
        });
      }

      // Validate all grades have marks (not null)
      const subject = await subjectsCollection.findOne({
        _id: submission.subjectId,
      });
      const fullMarks = subject?.fullMarks || 100;

      const gradesWithNullMarks = submission.grades.filter(
        (g) => g.marks === null || g.marks === undefined
      );
      if (gradesWithNullMarks.length > 0) {
        return res.status(400).json({
          success: false,
          message: `All students must have marks entered. ${gradesWithNullMarks.length} student(s) have no marks.`,
        });
      }

      // Recalculate grades on submit
      const recalculatedGrades = submission.grades.map((g) => {
        const gradeCalc = calculateGrade(g.marks, fullMarks);
        return {
          ...g,
          grade: gradeCalc.grade,
          gradePoint: gradeCalc.gradePoint,
        };
      });

      const auditEntry = {
        action: "submitted",
        userId: req.userId,
        userName: req.user?.name || "Unknown",
        role: req.userRole,
        comment: comment || "",
        timestamp: new Date(),
      };

      const result =
        await gradeSubmissionsCollection.findOneAndUpdate(
          {
            _id: new ObjectId(id),
            organizationId: req.organizationId,
            status: "draft",
          },
          {
            $set: {
              status: "submitted",
              grades: recalculatedGrades,
              submittedAt: new Date(),
              rejectionReason: null,
              updatedAt: new Date(),
            },
            $push: { auditHistory: auditEntry },
          },
          { returnDocument: "after" }
        );

      if (!result) {
        return res.status(400).json({
          success: false,
          message:
            "Submission could not be updated. It may have been modified by another process.",
        });
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "submitted",
        "grade_submission",
        id,
        { after: { status: "submitted" } },
        req
      );

      // Notify moderators
      const moderators = await usersCollection
        .find({
          organizationId: req.organizationId,
          role: "moderator",
          status: "active",
        })
        .project({ _id: 1 })
        .toArray();

      if (moderators.length > 0) {
        const subjectName = subject?.name || "Unknown";
        await createBulkNotifications(
          moderators.map((m) => m._id),
          req.organizationId,
          "grade_submitted",
          "New Grade Submission for Review",
          `${subjectName} grades submitted by ${req.user?.name || "a teacher"} and ready for review`,
          {
            resourceType: "grade_submission",
            resourceId: String(id),
            link: `/grade-submissions/${id}`,
          }
        );
      }

      res.json({
        success: true,
        message: "Grade submission submitted for review",
        data: result,
      });
    } catch (error) {
      logger.error("Error submitting grade submission:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to submit grade submission",
        error: error.message,
      });
    }
  }
);

// POST /grade-submissions/:id/start-review - Start review (submitted -> under_review)
app.post(
  "/grade-submissions/:id/start-review",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("review_grades"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid submission ID",
        });
      }

      const auditEntry = {
        action: "review_started",
        userId: req.userId,
        userName: req.user?.name || "Unknown",
        role: req.userRole,
        comment: "",
        timestamp: new Date(),
      };

      // Atomic update - prevents race conditions
      const result =
        await gradeSubmissionsCollection.findOneAndUpdate(
          {
            _id: new ObjectId(id),
            organizationId: req.organizationId,
            status: "submitted",
          },
          {
            $set: {
              status: "under_review",
              moderatorId: req.userId,
              reviewedAt: new Date(),
              updatedAt: new Date(),
            },
            $push: { auditHistory: auditEntry },
          },
          { returnDocument: "after" }
        );

      if (!result) {
        return res.status(400).json({
          success: false,
          message:
            "Cannot start review: submission not found or status is not 'submitted'",
        });
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "review_started",
        "grade_submission",
        id,
        { after: { status: "under_review" } },
        req
      );

      res.json({
        success: true,
        message: "Review started",
        data: result,
      });
    } catch (error) {
      logger.error("Error starting review:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to start review",
        error: error.message,
      });
    }
  }
);

// POST /grade-submissions/:id/approve - Approve (under_review -> approved)
app.post(
  "/grade-submissions/:id/approve",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("approve_grades"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { comment } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid submission ID",
        });
      }

      const auditEntry = {
        action: "approved",
        userId: req.userId,
        userName: req.user?.name || "Unknown",
        role: req.userRole,
        comment: comment || "",
        timestamp: new Date(),
      };

      const result =
        await gradeSubmissionsCollection.findOneAndUpdate(
          {
            _id: new ObjectId(id),
            organizationId: req.organizationId,
            status: "under_review",
          },
          {
            $set: {
              status: "approved",
              reviewComment: comment || null,
              approvedAt: new Date(),
              updatedAt: new Date(),
            },
            $push: { auditHistory: auditEntry },
          },
          { returnDocument: "after" }
        );

      if (!result) {
        return res.status(400).json({
          success: false,
          message:
            "Cannot approve: submission not found or status is not 'under_review'",
        });
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "approved",
        "grade_submission",
        id,
        { after: { status: "approved" } },
        req
      );

      // Notify admins and org_owner
      const admins = await usersCollection
        .find({
          organizationId: req.organizationId,
          role: { $in: ["admin", "org_owner"] },
          status: "active",
        })
        .project({ _id: 1 })
        .toArray();

      if (admins.length > 0) {
        await createBulkNotifications(
          admins.map((a) => a._id),
          req.organizationId,
          "grade_approved",
          "Grade Submission Approved",
          `A grade submission has been approved and is ready for publishing`,
          {
            resourceType: "grade_submission",
            resourceId: String(id),
            link: `/grade-submissions/${id}`,
          }
        );
      }

      res.json({
        success: true,
        message: "Grade submission approved",
        data: result,
      });
    } catch (error) {
      logger.error("Error approving grade submission:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to approve grade submission",
        error: error.message,
      });
    }
  }
);

// POST /grade-submissions/:id/reject - Reject (under_review -> draft)
app.post(
  "/grade-submissions/:id/reject",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("reject_grades"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { rejectionReason } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid submission ID",
        });
      }

      if (!rejectionReason || !rejectionReason.trim()) {
        return res.status(400).json({
          success: false,
          message: "rejectionReason is required when rejecting",
        });
      }

      const auditEntry = {
        action: "rejected",
        userId: req.userId,
        userName: req.user?.name || "Unknown",
        role: req.userRole,
        comment: rejectionReason.trim(),
        timestamp: new Date(),
      };

      // Reject sets status back to "draft" so teacher can edit and resubmit
      const result =
        await gradeSubmissionsCollection.findOneAndUpdate(
          {
            _id: new ObjectId(id),
            organizationId: req.organizationId,
            status: "under_review",
          },
          {
            $set: {
              status: "draft",
              rejectionReason: rejectionReason.trim(),
              updatedAt: new Date(),
            },
            $push: { auditHistory: auditEntry },
          },
          { returnDocument: "after" }
        );

      if (!result) {
        return res.status(400).json({
          success: false,
          message:
            "Cannot reject: submission not found or status is not 'under_review'",
        });
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "rejected",
        "grade_submission",
        id,
        {
          after: {
            status: "draft",
            rejectionReason: rejectionReason.trim(),
          },
        },
        req
      );

      // Notify the teacher
      if (result.teacherId) {
        const teacher = await teachersCollection.findOne({
          _id: result.teacherId,
        });
        if (teacher && teacher.userId) {
          await createNotification(
            teacher.userId,
            req.organizationId,
            "grade_rejected",
            "Grade Submission Rejected",
            `Your grade submission was rejected: ${rejectionReason.trim()}`,
            {
              resourceType: "grade_submission",
              resourceId: String(id),
              link: `/grade-submissions/${id}`,
            }
          );
        }
      }

      res.json({
        success: true,
        message:
          "Grade submission rejected and returned to draft for revision",
        data: result,
      });
    } catch (error) {
      logger.error("Error rejecting grade submission:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to reject grade submission",
        error: error.message,
      });
    }
  }
);

// POST /grade-submissions/:id/publish - Publish (approved -> published)
app.post(
  "/grade-submissions/:id/publish",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("publish_grades"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid submission ID",
        });
      }

      const auditEntry = {
        action: "published",
        userId: req.userId,
        userName: req.user?.name || "Unknown",
        role: req.userRole,
        comment: "",
        timestamp: new Date(),
      };

      const result =
        await gradeSubmissionsCollection.findOneAndUpdate(
          {
            _id: new ObjectId(id),
            organizationId: req.organizationId,
            status: "approved",
          },
          {
            $set: {
              status: "published",
              publishedAt: new Date(),
              updatedAt: new Date(),
            },
            $push: { auditHistory: auditEntry },
          },
          { returnDocument: "after" }
        );

      if (!result) {
        return res.status(400).json({
          success: false,
          message:
            "Cannot publish: submission not found or status is not 'approved'",
        });
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "published",
        "grade_submission",
        id,
        { after: { status: "published" } },
        req
      );

      // Notify students in class+section and their parents
      const studentDocs = await studentsCollection
        .find({
          organizationId: req.organizationId,
          classId: result.classId,
          sectionId: result.sectionId,
          status: "active",
        })
        .toArray();

      const studentUserIds = studentDocs
        .filter((s) => s.userId)
        .map((s) => s.userId);

      // Find parents of these students
      const studentObjIds = studentDocs.map((s) => s._id);
      const parentDocs = studentObjIds.length
        ? await parentsCollection
            .find({
              organizationId: req.organizationId,
              children: { $in: studentObjIds },
            })
            .toArray()
        : [];
      const parentUserIds = parentDocs
        .filter((p) => p.userId)
        .map((p) => p.userId);

      const allRecipientIds = [
        ...studentUserIds,
        ...parentUserIds,
      ];

      if (allRecipientIds.length > 0) {
        // Get exam and subject names for notification message
        const [exam, subject] = await Promise.all([
          examsCollection.findOne({ _id: result.examId }),
          subjectsCollection.findOne({ _id: result.subjectId }),
        ]);

        await createBulkNotifications(
          allRecipientIds,
          req.organizationId,
          "grade_published",
          "Results Published",
          `Results for ${exam?.name || "exam"} - ${subject?.name || "subject"} are now available`,
          {
            resourceType: "grade_submission",
            resourceId: String(id),
            link: `/results`,
          }
        );
      }

      res.json({
        success: true,
        message: "Grades published successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error publishing grade submission:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to publish grade submission",
        error: error.message,
      });
    }
  }
);

// --- Published Results Endpoints ---

// GET /results - Published results
app.get(
  "/results",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_published_grades"),
  async (req, res) => {
    try {
      const {
        examId,
        classId,
        sectionId,
        page = 1,
        limit = 20,
      } = req.query;

      const query = {
        organizationId: req.organizationId,
        status: "published",
      };

      if (examId && ObjectId.isValid(examId)) {
        query.examId = new ObjectId(examId);
      }
      if (classId && ObjectId.isValid(classId)) {
        query.classId = new ObjectId(classId);
      }
      if (sectionId && ObjectId.isValid(sectionId)) {
        query.sectionId = new ObjectId(sectionId);
      }

      // Student/parent restrictions: only see results for their class/children
      if (req.userRole === "student") {
        const studentDoc = await studentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
          status: "active",
        });
        if (!studentDoc) {
          return res.json({ success: true, data: [], pagination: { page: 1, limit: Number(limit), total: 0, pages: 0 } });
        }
        query.classId = studentDoc.classId;
        query.sectionId = studentDoc.sectionId;
        query["grades.studentId"] = studentDoc._id;
      }

      if (req.userRole === "parent") {
        const parentDoc = await parentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
        });
        if (
          !parentDoc ||
          !parentDoc.children ||
          parentDoc.children.length === 0
        ) {
          return res.json({ success: true, data: [], pagination: { page: 1, limit: Number(limit), total: 0, pages: 0 } });
        }
        query["grades.studentId"] = {
          $in: parentDoc.children,
        };
      }

      const total = await gradeSubmissionsCollection.countDocuments(
        query
      );
      const submissions = await gradeSubmissionsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ publishedAt: -1 })
        .toArray();

      // Enrich
      const examIds = [
        ...new Set(submissions.map((s) => String(s.examId))),
      ];
      const classIds = [
        ...new Set(submissions.map((s) => String(s.classId))),
      ];
      const sectionIds = [
        ...new Set(submissions.map((s) => String(s.sectionId))),
      ];
      const subjectIds = [
        ...new Set(submissions.map((s) => String(s.subjectId))),
      ];

      const [exams, classes, sections, subjects] = await Promise.all([
        examIds.length
          ? examsCollection
              .find({
                _id: { $in: examIds.map((e) => new ObjectId(e)) },
              })
              .toArray()
          : [],
        classIds.length
          ? classesCollection
              .find({
                _id: { $in: classIds.map((c) => new ObjectId(c)) },
              })
              .toArray()
          : [],
        sectionIds.length
          ? sectionsCollection
              .find({
                _id: {
                  $in: sectionIds.map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
        subjectIds.length
          ? subjectsCollection
              .find({
                _id: {
                  $in: subjectIds.map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
      ]);

      const examMap = {};
      exams.forEach((e) => (examMap[String(e._id)] = e.name));
      const classMap = {};
      classes.forEach((c) => (classMap[String(c._id)] = c.name));
      const sectionMap = {};
      sections.forEach((s) => (sectionMap[String(s._id)] = s.name));
      const subjectMap = {};
      subjects.forEach((s) => (subjectMap[String(s._id)] = s));

      const enriched = submissions.map((sub) => {
        const subjectDoc = subjectMap[String(sub.subjectId)];
        return {
          _id: sub._id,
          examId: sub.examId,
          examName: examMap[String(sub.examId)] || "Unknown",
          classId: sub.classId,
          className: classMap[String(sub.classId)] || "Unknown",
          sectionId: sub.sectionId,
          sectionName: sectionMap[String(sub.sectionId)] || "Unknown",
          subjectId: sub.subjectId,
          subjectName: subjectDoc?.name || "Unknown",
          fullMarks: subjectDoc?.fullMarks || 100,
          passMarks: subjectDoc?.passMarks || 33,
          studentCount: sub.grades ? sub.grades.length : 0,
          publishedAt: sub.publishedAt,
        };
      });

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching results:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch results",
        error: error.message,
      });
    }
  }
);

// GET /results/student/:studentId - All published results for a student
app.get(
  "/results/student/:studentId",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_published_grades"),
  async (req, res) => {
    try {
      const { studentId } = req.params;
      const { examId } = req.query;

      if (!ObjectId.isValid(studentId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid student ID",
        });
      }

      const student = await studentsCollection.findOne({
        _id: new ObjectId(studentId),
        organizationId: req.organizationId,
      });

      if (!student) {
        return res.status(404).json({
          success: false,
          message: "Student not found",
        });
      }

      // Access control: students can only see their own, parents only their children's
      if (req.userRole === "student") {
        if (String(student.userId) !== String(req.userId)) {
          return res.status(403).json({
            success: false,
            message: "You can only view your own results",
          });
        }
      }
      if (req.userRole === "parent") {
        const parentDoc = await parentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
        });
        if (
          !parentDoc ||
          !parentDoc.children.some(
            (c) => String(c) === studentId
          )
        ) {
          return res.status(403).json({
            success: false,
            message:
              "You can only view results for your own children",
          });
        }
      }

      const query = {
        organizationId: req.organizationId,
        status: "published",
        "grades.studentId": new ObjectId(studentId),
      };
      if (examId && ObjectId.isValid(examId)) {
        query.examId = new ObjectId(examId);
      }

      const submissions = await gradeSubmissionsCollection
        .find(query)
        .sort({ publishedAt: -1 })
        .toArray();

      // Enrich
      const examIds = [
        ...new Set(submissions.map((s) => String(s.examId))),
      ];
      const subjectIds = [
        ...new Set(submissions.map((s) => String(s.subjectId))),
      ];

      const [exams, subjects] = await Promise.all([
        examIds.length
          ? examsCollection
              .find({
                _id: { $in: examIds.map((e) => new ObjectId(e)) },
              })
              .toArray()
          : [],
        subjectIds.length
          ? subjectsCollection
              .find({
                _id: {
                  $in: subjectIds.map((s) => new ObjectId(s)),
                },
              })
              .toArray()
          : [],
      ]);

      const examMap = {};
      exams.forEach((e) => (examMap[String(e._id)] = e));
      const subjectMap = {};
      subjects.forEach((s) => (subjectMap[String(s._id)] = s));

      // Get student user name
      let studentName = "Unknown";
      if (student.userId) {
        const studentUser = await usersCollection.findOne(
          { _id: student.userId },
          { projection: { name: 1 } }
        );
        studentName = studentUser?.name || "Unknown";
      }

      // Get class and section names
      const [classDoc, sectionDoc] = await Promise.all([
        student.classId
          ? classesCollection.findOne({ _id: student.classId })
          : null,
        student.sectionId
          ? sectionsCollection.findOne({ _id: student.sectionId })
          : null,
      ]);

      const results = submissions.map((sub) => {
        const studentGrade = sub.grades.find(
          (g) => String(g.studentId) === studentId
        );
        const subjectDoc = subjectMap[String(sub.subjectId)];
        const examDoc = examMap[String(sub.examId)];
        return {
          examId: sub.examId,
          examName: examDoc?.name || "Unknown",
          academicYear: examDoc?.academicYear || "",
          subjectId: sub.subjectId,
          subjectName: subjectDoc?.name || "Unknown",
          subjectCode: subjectDoc?.subjectCode || "",
          fullMarks: subjectDoc?.fullMarks || 100,
          passMarks: subjectDoc?.passMarks || 33,
          obtainedMarks: studentGrade?.marks ?? null,
          grade: studentGrade?.grade || null,
          gradePoint: studentGrade?.gradePoint ?? null,
          passed: studentGrade
            ? studentGrade.marks >= (subjectDoc?.passMarks || 33)
            : null,
          remarks: studentGrade?.remarks || "",
          publishedAt: sub.publishedAt,
        };
      });

      res.json({
        success: true,
        data: {
          student: {
            _id: student._id,
            name: studentName,
            admissionNumber: student.admissionNumber,
            rollNumber: student.rollNumber,
            className: classDoc?.name || "Unknown",
            sectionName: sectionDoc?.name || "Unknown",
          },
          results,
        },
      });
    } catch (error) {
      logger.error("Error fetching student results:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch student results",
        error: error.message,
      });
    }
  }
);

// GET /results/report-card/:studentId/:examId - Full report card
app.get(
  "/results/report-card/:studentId/:examId",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_published_grades"),
  async (req, res) => {
    try {
      const { studentId, examId } = req.params;

      if (
        !ObjectId.isValid(studentId) ||
        !ObjectId.isValid(examId)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid student ID or exam ID",
        });
      }

      const [student, exam] = await Promise.all([
        studentsCollection.findOne({
          _id: new ObjectId(studentId),
          organizationId: req.organizationId,
        }),
        examsCollection.findOne({
          _id: new ObjectId(examId),
          organizationId: req.organizationId,
        }),
      ]);

      if (!student) {
        return res.status(404).json({
          success: false,
          message: "Student not found",
        });
      }
      if (!exam) {
        return res.status(404).json({
          success: false,
          message: "Exam not found",
        });
      }

      // Access control
      if (req.userRole === "student") {
        if (String(student.userId) !== String(req.userId)) {
          return res.status(403).json({
            success: false,
            message: "You can only view your own report card",
          });
        }
      }
      if (req.userRole === "parent") {
        const parentDoc = await parentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
        });
        if (
          !parentDoc ||
          !parentDoc.children.some(
            (c) => String(c) === studentId
          )
        ) {
          return res.status(403).json({
            success: false,
            message:
              "You can only view report cards for your own children",
          });
        }
      }

      // Get all published submissions for this exam that include this student
      const submissions = await gradeSubmissionsCollection
        .find({
          organizationId: req.organizationId,
          examId: new ObjectId(examId),
          status: "published",
          "grades.studentId": new ObjectId(studentId),
        })
        .toArray();

      if (submissions.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "No published results found for this student in this exam",
        });
      }

      // Get student info
      let studentName = "Unknown";
      if (student.userId) {
        const studentUser = await usersCollection.findOne(
          { _id: student.userId },
          { projection: { name: 1 } }
        );
        studentName = studentUser?.name || "Unknown";
      }

      const [classDoc, sectionDoc] = await Promise.all([
        classesCollection.findOne({ _id: student.classId }),
        sectionsCollection.findOne({ _id: student.sectionId }),
      ]);

      // Get subjects and teacher names
      const subjectIds = submissions.map((s) => s.subjectId);
      const subjects = await subjectsCollection
        .find({ _id: { $in: subjectIds } })
        .toArray();
      const subjectMap = {};
      subjects.forEach((s) => (subjectMap[String(s._id)] = s));

      const teacherIds = subjects
        .filter((s) => s.teacherId)
        .map((s) => s.teacherId);
      const teachers = teacherIds.length
        ? await teachersCollection
            .find({ _id: { $in: teacherIds } })
            .toArray()
        : [];
      const teacherUserIds = teachers
        .filter((t) => t.userId)
        .map((t) => t.userId);
      const teacherUsers = teacherUserIds.length
        ? await usersCollection
            .find(
              { _id: { $in: teacherUserIds } },
              { projection: { name: 1 } }
            )
            .toArray()
        : [];
      const teacherUserMap = {};
      teacherUsers.forEach(
        (u) => (teacherUserMap[String(u._id)] = u.name)
      );
      const teacherNameMap = {};
      teachers.forEach(
        (t) =>
          (teacherNameMap[String(t._id)] =
            teacherUserMap[String(t.userId)] || "Unknown")
      );

      // Build subject results
      const subjectResults = submissions.map((sub) => {
        const studentGrade = sub.grades.find(
          (g) => String(g.studentId) === studentId
        );
        const subjectDoc = subjectMap[String(sub.subjectId)];
        const fullMarks = subjectDoc?.fullMarks || 100;
        const passMarks = subjectDoc?.passMarks || 33;
        return {
          subjectName: subjectDoc?.name || "Unknown",
          subjectCode: subjectDoc?.subjectCode || "",
          fullMarks,
          passMarks,
          obtainedMarks: studentGrade?.marks ?? 0,
          grade: studentGrade?.grade || "F",
          gradePoint: studentGrade?.gradePoint ?? 0,
          passed: (studentGrade?.marks ?? 0) >= passMarks,
          remarks: studentGrade?.remarks || "",
          teacherName:
            teacherNameMap[String(subjectDoc?.teacherId)] ||
            "Unknown",
        };
      });

      // Calculate summary
      const totalSubjects = subjectResults.length;
      const totalFullMarks = subjectResults.reduce(
        (sum, s) => sum + s.fullMarks,
        0
      );
      const totalObtainedMarks = subjectResults.reduce(
        (sum, s) => sum + s.obtainedMarks,
        0
      );
      const averagePercentage =
        totalFullMarks > 0
          ? Math.round(
              (totalObtainedMarks / totalFullMarks) * 100 * 100
            ) / 100
          : 0;
      const gpa =
        totalSubjects > 0
          ? Math.round(
              (subjectResults.reduce(
                (sum, s) => sum + s.gradePoint,
                0
              ) /
                totalSubjects) *
                100
            ) / 100
          : 0;
      const passedSubjects = subjectResults.filter(
        (s) => s.passed
      ).length;
      const failedSubjects = totalSubjects - passedSubjects;

      const sorted = [...subjectResults].sort(
        (a, b) => b.obtainedMarks - a.obtainedMarks
      );

      // Get organization info
      const org = await organizationsCollection.findOne({
        _id: new ObjectId(req.organizationId),
      });

      res.json({
        success: true,
        data: {
          student: {
            _id: student._id,
            name: studentName,
            admissionNumber: student.admissionNumber,
            rollNumber: student.rollNumber,
            className: classDoc?.name || "Unknown",
            sectionName: sectionDoc?.name || "Unknown",
            academicYear: exam.academicYear,
          },
          exam: {
            _id: exam._id,
            name: exam.name,
            startDate: exam.startDate,
            endDate: exam.endDate,
            academicYear: exam.academicYear,
          },
          subjects: subjectResults,
          summary: {
            totalSubjects,
            totalFullMarks,
            totalObtainedMarks,
            averagePercentage,
            gpa,
            highestMarks: sorted.length > 0
              ? {
                  subjectName: sorted[0].subjectName,
                  marks: sorted[0].obtainedMarks,
                }
              : null,
            lowestMarks: sorted.length > 0
              ? {
                  subjectName: sorted[sorted.length - 1].subjectName,
                  marks: sorted[sorted.length - 1].obtainedMarks,
                }
              : null,
            passedSubjects,
            failedSubjects,
            overallResult:
              failedSubjects === 0 ? "Passed" : "Failed",
          },
          publishedAt: submissions[0]?.publishedAt,
          organization: {
            name: org?.name || "Unknown",
            logo: org?.logo || null,
          },
        },
      });
    } catch (error) {
      logger.error("Error generating report card:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate report card",
        error: error.message,
      });
    }
  }
);

// --- Notification Endpoints ---

// GET /notifications - List user's notifications
app.get(
  "/notifications",
  ensureDBConnection,
  authenticateUser,
  async (req, res) => {
    try {
      const { isRead, page = 1, limit = 20 } = req.query;

      const query = { userId: req.userId };
      if (isRead !== undefined) {
        query.isRead = isRead === "true";
      }

      const total = await notificationsCollection.countDocuments(
        query
      );
      const notifications = await notificationsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ createdAt: -1 })
        .toArray();

      const unreadCount = await notificationsCollection.countDocuments(
        { userId: req.userId, isRead: false }
      );

      res.json({
        success: true,
        data: notifications,
        unreadCount,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching notifications:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch notifications",
        error: error.message,
      });
    }
  }
);

// PATCH /notifications/read-all - Mark all as read (MUST be before /:id route)
app.patch(
  "/notifications/read-all",
  ensureDBConnection,
  authenticateUser,
  async (req, res) => {
    try {
      const result = await notificationsCollection.updateMany(
        { userId: req.userId, isRead: false },
        { $set: { isRead: true } }
      );

      res.json({
        success: true,
        message: `${result.modifiedCount} notification(s) marked as read`,
        data: { modifiedCount: result.modifiedCount },
      });
    } catch (error) {
      logger.error("Error marking all notifications as read:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to mark notifications as read",
        error: error.message,
      });
    }
  }
);

// PATCH /notifications/:id/read - Mark single notification as read
app.patch(
  "/notifications/:id/read",
  ensureDBConnection,
  authenticateUser,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid notification ID",
        });
      }

      const result = await notificationsCollection.findOneAndUpdate(
        { _id: new ObjectId(id), userId: req.userId },
        { $set: { isRead: true } },
        { returnDocument: "after" }
      );

      if (!result) {
        return res.status(404).json({
          success: false,
          message: "Notification not found",
        });
      }

      res.json({
        success: true,
        message: "Notification marked as read",
        data: result,
      });
    } catch (error) {
      logger.error("Error marking notification as read:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to mark notification as read",
        error: error.message,
      });
    }
  }
);

// ==================== PHASE 5: FINANCE & FEE MANAGEMENT ====================

// ========== Fee Structure Endpoints ==========

// POST /fee-structures - Create fee structure
app.post(
  "/fee-structures",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_fee_structures"),
  async (req, res) => {
    try {
      const { name, classId, academicYear, monthlyAmount, components } =
        req.body;

      if (!name || !classId || !academicYear || !monthlyAmount) {
        return res.status(400).json({
          success: false,
          message:
            "Name, classId, academicYear, and monthlyAmount are required",
        });
      }

      if (!ObjectId.isValid(classId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid class ID",
        });
      }

      // Verify class exists
      const classDoc = await classesCollection.findOne({
        _id: new ObjectId(classId),
        organizationId: req.organizationId,
      });

      if (!classDoc) {
        return res.status(404).json({
          success: false,
          message: "Class not found",
        });
      }

      // Validate components sum matches monthlyAmount
      if (components && components.length > 0) {
        const componentTotal = components.reduce(
          (sum, c) => sum + (c.amount || 0),
          0
        );
        if (Math.abs(componentTotal - monthlyAmount) > 0.01) {
          return res.status(400).json({
            success: false,
            message: `Component total (${componentTotal}) does not match monthlyAmount (${monthlyAmount})`,
          });
        }
      }

      const feeStructure = {
        organizationId: req.organizationId,
        name,
        classId: new ObjectId(classId),
        academicYear,
        monthlyAmount: Number(monthlyAmount),
        components: components || [],
        isActive: true,
        createdBy: req.userId,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await monthlyFeeStructuresCollection.insertOne(
        feeStructure
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "fee_structure",
        result.insertedId,
        { after: feeStructure },
        req
      );

      res.status(201).json({
        success: true,
        message: "Fee structure created successfully",
        data: { ...feeStructure, _id: result.insertedId },
      });
    } catch (error) {
      logger.error("Error creating fee structure:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to create fee structure",
        error: error.message,
      });
    }
  }
);

// GET /fee-structures - List fee structures
app.get(
  "/fee-structures",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_fee_structures"),
  async (req, res) => {
    try {
      const { classId, academicYear, isActive } = req.query;

      const query = { organizationId: req.organizationId };
      if (classId && ObjectId.isValid(classId)) {
        query.classId = new ObjectId(classId);
      }
      if (academicYear) query.academicYear = academicYear;
      if (isActive !== undefined) query.isActive = isActive === "true";

      const feeStructures = await monthlyFeeStructuresCollection
        .find(query)
        .sort({ createdAt: -1 })
        .toArray();

      // Enrich with class names
      const classIds = [
        ...new Set(feeStructures.map((f) => f.classId.toString())),
      ];
      const classes = await classesCollection
        .find({
          _id: { $in: classIds.map((id) => new ObjectId(id)) },
        })
        .toArray();
      const classMap = {};
      classes.forEach((c) => (classMap[c._id.toString()] = c.name));

      const enriched = feeStructures.map((f) => ({
        ...f,
        className: classMap[f.classId.toString()] || "Unknown",
      }));

      res.json({
        success: true,
        data: enriched,
        total: enriched.length,
      });
    } catch (error) {
      logger.error("Error fetching fee structures:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch fee structures",
        error: error.message,
      });
    }
  }
);

// PATCH /fee-structures/:id - Update fee structure
app.patch(
  "/fee-structures/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_fee_structures"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid fee structure ID",
        });
      }

      const existing = await monthlyFeeStructuresCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Fee structure not found",
        });
      }

      const allowedFields = [
        "name",
        "monthlyAmount",
        "components",
        "isActive",
      ];
      const updates = {};
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      if (updates.monthlyAmount) {
        updates.monthlyAmount = Number(updates.monthlyAmount);
      }

      // Validate components if both provided
      if (updates.components && updates.monthlyAmount) {
        const componentTotal = updates.components.reduce(
          (sum, c) => sum + (c.amount || 0),
          0
        );
        if (Math.abs(componentTotal - updates.monthlyAmount) > 0.01) {
          return res.status(400).json({
            success: false,
            message: `Component total (${componentTotal}) does not match monthlyAmount (${updates.monthlyAmount})`,
          });
        }
      }

      updates.updatedAt = new Date();

      const result = await monthlyFeeStructuresCollection.findOneAndUpdate(
        { _id: new ObjectId(id), organizationId: req.organizationId },
        { $set: updates },
        { returnDocument: "after" }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "fee_structure",
        id,
        { before: existing, after: result },
        req
      );

      res.json({
        success: true,
        message: "Fee structure updated successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error updating fee structure:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to update fee structure",
        error: error.message,
      });
    }
  }
);

// DELETE /fee-structures/:id - Delete fee structure
app.delete(
  "/fee-structures/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_fee_structures"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid fee structure ID",
        });
      }

      const existing = await monthlyFeeStructuresCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Fee structure not found",
        });
      }

      // Check if any student fees reference this structure
      const linkedFees = await studentMonthlyFeesCollection.countDocuments({
        organizationId: req.organizationId,
        feeStructureId: new ObjectId(id),
      });

      if (linkedFees > 0) {
        return res.status(409).json({
          success: false,
          message: `Cannot delete: ${linkedFees} student fee record(s) reference this structure. Deactivate it instead.`,
        });
      }

      await monthlyFeeStructuresCollection.deleteOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "fee_structure",
        id,
        { before: existing },
        req
      );

      res.json({
        success: true,
        message: "Fee structure deleted successfully",
      });
    } catch (error) {
      logger.error("Error deleting fee structure:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to delete fee structure",
        error: error.message,
      });
    }
  }
);

// ========== Student Monthly Fees Endpoints ==========

// POST /student-fees/generate - Bulk generate monthly fees for a class
app.post(
  "/student-fees/generate",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_fee_structures"),
  async (req, res) => {
    try {
      const { feeStructureId, month, dueDate } = req.body;

      if (!feeStructureId || !month) {
        return res.status(400).json({
          success: false,
          message: "feeStructureId and month (YYYY-MM) are required",
        });
      }

      // Validate month format
      if (!/^\d{4}-\d{2}$/.test(month)) {
        return res.status(400).json({
          success: false,
          message: "Month must be in YYYY-MM format",
        });
      }

      if (!ObjectId.isValid(feeStructureId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid fee structure ID",
        });
      }

      // Get fee structure
      const feeStructure = await monthlyFeeStructuresCollection.findOne({
        _id: new ObjectId(feeStructureId),
        organizationId: req.organizationId,
        isActive: true,
      });

      if (!feeStructure) {
        return res.status(404).json({
          success: false,
          message: "Active fee structure not found",
        });
      }

      // Get all active students in this class
      const students = await studentsCollection
        .find({
          organizationId: req.organizationId,
          classId: feeStructure.classId,
          status: "active",
        })
        .toArray();

      if (students.length === 0) {
        return res.status(400).json({
          success: false,
          message: "No active students found in this class",
        });
      }

      // Generate fee records (skip if already exists - unique index will catch duplicates)
      let created = 0;
      let skipped = 0;

      for (const student of students) {
        try {
          await studentMonthlyFeesCollection.insertOne({
            organizationId: req.organizationId,
            studentId: student._id,
            feeStructureId: feeStructure._id,
            month,
            payableAmount: feeStructure.monthlyAmount,
            discount: 0,
            paidAmount: 0,
            status: "pending",
            dueDate: dueDate ? new Date(dueDate) : null,
            createdAt: new Date(),
            updatedAt: new Date(),
          });
          created++;
        } catch (insertError) {
          // Duplicate key error = already exists for this student+month
          if (insertError.code === 11000) {
            skipped++;
          } else {
            throw insertError;
          }
        }
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "student_monthly_fees",
        feeStructure._id,
        {
          after: {
            month,
            classId: feeStructure.classId,
            created,
            skipped,
          },
        },
        req
      );

      res.status(201).json({
        success: true,
        message: `Generated ${created} fee record(s), skipped ${skipped} (already existed)`,
        data: {
          created,
          skipped,
          totalStudents: students.length,
          month,
          classId: feeStructure.classId,
          monthlyAmount: feeStructure.monthlyAmount,
        },
      });
    } catch (error) {
      logger.error("Error generating student fees:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate student fees",
        error: error.message,
      });
    }
  }
);

// GET /student-fees - List student monthly fees
app.get(
  "/student-fees",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_fees"),
  async (req, res) => {
    try {
      const {
        studentId,
        classId,
        month,
        status,
        page = 1,
        limit = 50,
      } = req.query;

      const query = { organizationId: req.organizationId };

      // Students see only their own fees
      if (req.userRole === "student") {
        const studentDoc = await studentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
        });
        if (!studentDoc) {
          return res.status(403).json({
            success: false,
            message: "Student profile not found",
          });
        }
        query.studentId = studentDoc._id;
      } else if (req.userRole === "parent") {
        const parentDoc = await parentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
        });
        if (!parentDoc || !parentDoc.children?.length) {
          return res.status(403).json({
            success: false,
            message: "No children linked to your account",
          });
        }
        query.studentId = { $in: parentDoc.children };
      } else {
        if (studentId && ObjectId.isValid(studentId)) {
          query.studentId = new ObjectId(studentId);
        }
      }

      if (month) query.month = month;
      if (status) query.status = status;

      // If filtering by class, find all students in that class
      if (classId && ObjectId.isValid(classId) && !query.studentId) {
        const classStudents = await studentsCollection
          .find({
            organizationId: req.organizationId,
            classId: new ObjectId(classId),
            status: "active",
          })
          .toArray();
        query.studentId = {
          $in: classStudents.map((s) => s._id),
        };
      }

      const total = await studentMonthlyFeesCollection.countDocuments(query);
      const fees = await studentMonthlyFeesCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ month: -1, createdAt: -1 })
        .toArray();

      // Enrich with student names
      const studentIds = [
        ...new Set(fees.map((f) => f.studentId.toString())),
      ];
      const students = await studentsCollection
        .find({
          _id: { $in: studentIds.map((id) => new ObjectId(id)) },
        })
        .toArray();

      const studentMap = {};
      for (const s of students) {
        const user = await usersCollection.findOne({ _id: s.userId });
        studentMap[s._id.toString()] = {
          name: user?.name || "Unknown",
          admissionNumber: s.admissionNumber,
          rollNumber: s.rollNumber,
          classId: s.classId,
          sectionId: s.sectionId,
        };
      }

      const enriched = fees.map((f) => ({
        ...f,
        studentInfo: studentMap[f.studentId.toString()] || null,
      }));

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching student fees:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch student fees",
        error: error.message,
      });
    }
  }
);

// PATCH /student-fees/:id - Update fee record (discount, etc.)
app.patch(
  "/student-fees/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_fee_structures"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid fee record ID",
        });
      }

      const existing = await studentMonthlyFeesCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Fee record not found",
        });
      }

      const updates = {};
      if (req.body.discount !== undefined) {
        updates.discount = Number(req.body.discount);
        if (updates.discount < 0) {
          return res.status(400).json({
            success: false,
            message: "Discount cannot be negative",
          });
        }
        if (updates.discount > existing.payableAmount) {
          return res.status(400).json({
            success: false,
            message: "Discount cannot exceed payable amount",
          });
        }
      }
      if (req.body.dueDate !== undefined) {
        updates.dueDate = req.body.dueDate ? new Date(req.body.dueDate) : null;
      }

      // Recalculate status
      const discount = updates.discount !== undefined ? updates.discount : existing.discount;
      const effectiveAmount = existing.payableAmount - discount;
      const paidAmount = existing.paidAmount || 0;
      const dueDate = updates.dueDate !== undefined ? updates.dueDate : existing.dueDate;
      updates.status = calculateFeeStatus(effectiveAmount, paidAmount, dueDate);
      updates.updatedAt = new Date();

      const result = await studentMonthlyFeesCollection.findOneAndUpdate(
        { _id: new ObjectId(id), organizationId: req.organizationId },
        { $set: updates },
        { returnDocument: "after" }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "student_monthly_fee",
        id,
        { before: existing, after: result },
        req
      );

      res.json({
        success: true,
        message: "Fee record updated successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error updating student fee:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to update fee record",
        error: error.message,
      });
    }
  }
);

// ========== Payment Endpoints ==========

// POST /payments - Record a payment
app.post(
  "/payments",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("collect_payment"),
  async (req, res) => {
    try {
      const {
        studentMonthlyFeeId,
        amount,
        paymentMode,
        transactionId,
        notes,
        paymentDate,
      } = req.body;

      if (!studentMonthlyFeeId || !amount || !paymentMode) {
        return res.status(400).json({
          success: false,
          message:
            "studentMonthlyFeeId, amount, and paymentMode are required",
        });
      }

      if (!ObjectId.isValid(studentMonthlyFeeId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid student monthly fee ID",
        });
      }

      const validModes = ["cash", "bank", "online", "cheque"];
      if (!validModes.includes(paymentMode)) {
        return res.status(400).json({
          success: false,
          message: `Invalid payment mode. Must be one of: ${validModes.join(", ")}`,
        });
      }

      if (Number(amount) <= 0) {
        return res.status(400).json({
          success: false,
          message: "Amount must be greater than 0",
        });
      }

      // Get the fee record
      const feeRecord = await studentMonthlyFeesCollection.findOne({
        _id: new ObjectId(studentMonthlyFeeId),
        organizationId: req.organizationId,
      });

      if (!feeRecord) {
        return res.status(404).json({
          success: false,
          message: "Student fee record not found",
        });
      }

      const effectiveAmount =
        feeRecord.payableAmount - (feeRecord.discount || 0);
      const currentPaid = feeRecord.paidAmount || 0;
      const remaining = effectiveAmount - currentPaid;

      if (Number(amount) > remaining) {
        return res.status(400).json({
          success: false,
          message: `Payment amount (${amount}) exceeds remaining balance (${remaining})`,
        });
      }

      // Generate receipt number
      const receiptNumber = await generateReceiptNumber(
        req.organizationId
      );

      const payment = {
        organizationId: req.organizationId,
        studentMonthlyFeeId: new ObjectId(studentMonthlyFeeId),
        studentId: feeRecord.studentId,
        amount: Number(amount),
        paymentMode,
        transactionId: transactionId || null,
        receiptNumber,
        receivedBy: req.userId,
        notes: notes || null,
        paymentDate: paymentDate ? new Date(paymentDate) : new Date(),
        createdAt: new Date(),
      };

      const paymentResult = await paymentsCollection.insertOne(payment);

      // Update the fee record
      const newPaidAmount = currentPaid + Number(amount);
      const newStatus = calculateFeeStatus(
        effectiveAmount,
        newPaidAmount,
        feeRecord.dueDate
      );

      await studentMonthlyFeesCollection.updateOne(
        { _id: new ObjectId(studentMonthlyFeeId) },
        {
          $set: {
            paidAmount: newPaidAmount,
            status: newStatus,
            updatedAt: new Date(),
          },
        }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "payment",
        paymentResult.insertedId,
        {
          after: {
            ...payment,
            feeMonth: feeRecord.month,
            newPaidAmount,
            newStatus,
          },
        },
        req
      );

      // Notify student about payment received
      const student = await studentsCollection.findOne({
        _id: feeRecord.studentId,
      });
      if (student) {
        await createNotification(
          student.userId,
          req.organizationId,
          "fee_payment",
          "Payment Received",
          `Payment of ${amount} received for ${feeRecord.month}. Receipt: ${receiptNumber}`,
          {
            resourceType: "payment",
            resourceId: paymentResult.insertedId.toString(),
          }
        );
      }

      res.status(201).json({
        success: true,
        message: "Payment recorded successfully",
        data: {
          ...payment,
          _id: paymentResult.insertedId,
          feeStatus: newStatus,
          totalPaid: newPaidAmount,
          remaining: effectiveAmount - newPaidAmount,
        },
      });
    } catch (error) {
      logger.error("Error recording payment:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to record payment",
        error: error.message,
      });
    }
  }
);

// GET /payments - List payments
app.get(
  "/payments",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("collect_payment"),
  async (req, res) => {
    try {
      const {
        studentId,
        paymentMode,
        startDate,
        endDate,
        page = 1,
        limit = 50,
      } = req.query;

      const query = { organizationId: req.organizationId };

      if (studentId && ObjectId.isValid(studentId)) {
        query.studentId = new ObjectId(studentId);
      }
      if (paymentMode) query.paymentMode = paymentMode;

      if (startDate || endDate) {
        query.paymentDate = {};
        if (startDate) query.paymentDate.$gte = new Date(startDate);
        if (endDate) query.paymentDate.$lte = new Date(endDate);
      }

      const total = await paymentsCollection.countDocuments(query);
      const payments = await paymentsCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ paymentDate: -1 })
        .toArray();

      // Enrich with student names
      const studentIds = [
        ...new Set(payments.map((p) => p.studentId.toString())),
      ];
      const students = await studentsCollection
        .find({
          _id: { $in: studentIds.map((id) => new ObjectId(id)) },
        })
        .toArray();

      const studentMap = {};
      for (const s of students) {
        const user = await usersCollection.findOne({ _id: s.userId });
        studentMap[s._id.toString()] = {
          name: user?.name || "Unknown",
          admissionNumber: s.admissionNumber,
          rollNumber: s.rollNumber,
        };
      }

      // Enrich with receiver names
      const receiverIds = [
        ...new Set(payments.map((p) => p.receivedBy.toString())),
      ];
      const receivers = await usersCollection
        .find({
          _id: { $in: receiverIds.map((id) => new ObjectId(id)) },
        })
        .toArray();
      const receiverMap = {};
      receivers.forEach(
        (r) => (receiverMap[r._id.toString()] = r.name)
      );

      const enriched = payments.map((p) => ({
        ...p,
        studentInfo: studentMap[p.studentId.toString()] || null,
        receivedByName: receiverMap[p.receivedBy.toString()] || "Unknown",
      }));

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching payments:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch payments",
        error: error.message,
      });
    }
  }
);

// GET /payments/receipt/:id - Get payment receipt data
app.get(
  "/payments/receipt/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_fees"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid payment ID",
        });
      }

      const payment = await paymentsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!payment) {
        return res.status(404).json({
          success: false,
          message: "Payment not found",
        });
      }

      // Get student details
      const student = await studentsCollection.findOne({
        _id: payment.studentId,
      });
      const studentUser = student
        ? await usersCollection.findOne({ _id: student.userId })
        : null;

      // Get class/section details
      const classDoc = student
        ? await classesCollection.findOne({ _id: student.classId })
        : null;
      const sectionDoc = student
        ? await sectionsCollection.findOne({ _id: student.sectionId })
        : null;

      // Get fee record
      const feeRecord = await studentMonthlyFeesCollection.findOne({
        _id: payment.studentMonthlyFeeId,
      });

      // Get fee structure
      const feeStructure = feeRecord
        ? await monthlyFeeStructuresCollection.findOne({
            _id: feeRecord.feeStructureId,
          })
        : null;

      // Get organization
      const org = await organizationsCollection.findOne({
        _id: new ObjectId(req.organizationId),
      });

      // Get receiver
      const receiver = await usersCollection.findOne({
        _id: payment.receivedBy,
      });

      res.json({
        success: true,
        data: {
          receipt: {
            receiptNumber: payment.receiptNumber,
            paymentDate: payment.paymentDate,
            amount: payment.amount,
            paymentMode: payment.paymentMode,
            transactionId: payment.transactionId,
            notes: payment.notes,
          },
          student: {
            name: studentUser?.name || "Unknown",
            admissionNumber: student?.admissionNumber,
            rollNumber: student?.rollNumber,
            className: classDoc?.name || "Unknown",
            sectionName: sectionDoc?.name || "Unknown",
          },
          fee: {
            month: feeRecord?.month,
            payableAmount: feeRecord?.payableAmount,
            discount: feeRecord?.discount || 0,
            totalPaid: feeRecord?.paidAmount || 0,
            remaining:
              feeRecord
                ? feeRecord.payableAmount -
                  (feeRecord.discount || 0) -
                  (feeRecord.paidAmount || 0)
                : 0,
            status: feeRecord?.status,
            components: feeStructure?.components || [],
          },
          organization: {
            name: org?.name || "Unknown",
            email: org?.email,
            phone: org?.phone,
            address: org?.address,
            logo: org?.logo || null,
          },
          receivedBy: receiver?.name || "Unknown",
        },
      });
    } catch (error) {
      logger.error("Error fetching payment receipt:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch payment receipt",
        error: error.message,
      });
    }
  }
);

// ========== Fee Reports Endpoints ==========

// GET /fees/dues - Outstanding dues report
app.get(
  "/fees/dues",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_fees"),
  async (req, res) => {
    try {
      const { classId, month } = req.query;

      const matchStage = {
        organizationId: req.organizationId,
        status: { $in: ["pending", "partial", "overdue"] },
      };

      if (month) matchStage.month = month;

      // If classId provided, get student IDs in that class
      if (classId && ObjectId.isValid(classId)) {
        const classStudents = await studentsCollection
          .find({
            organizationId: req.organizationId,
            classId: new ObjectId(classId),
            status: "active",
          })
          .toArray();
        matchStage.studentId = {
          $in: classStudents.map((s) => s._id),
        };
      }

      const dues = await studentMonthlyFeesCollection
        .find(matchStage)
        .sort({ month: -1 })
        .toArray();

      // Enrich with student info
      const studentIds = [
        ...new Set(dues.map((d) => d.studentId.toString())),
      ];
      const students = await studentsCollection
        .find({
          _id: { $in: studentIds.map((id) => new ObjectId(id)) },
        })
        .toArray();

      const studentMap = {};
      for (const s of students) {
        const user = await usersCollection.findOne({ _id: s.userId });
        const classDoc = await classesCollection.findOne({
          _id: s.classId,
        });
        const sectionDoc = await sectionsCollection.findOne({
          _id: s.sectionId,
        });
        studentMap[s._id.toString()] = {
          name: user?.name || "Unknown",
          admissionNumber: s.admissionNumber,
          rollNumber: s.rollNumber,
          className: classDoc?.name || "Unknown",
          sectionName: sectionDoc?.name || "Unknown",
        };
      }

      const enriched = dues.map((d) => ({
        ...d,
        studentInfo: studentMap[d.studentId.toString()] || null,
        dueAmount:
          d.payableAmount - (d.discount || 0) - (d.paidAmount || 0),
      }));

      // Summary
      const totalDue = enriched.reduce((sum, d) => sum + d.dueAmount, 0);
      const totalStudents = new Set(
        enriched.map((d) => d.studentId.toString())
      ).size;

      res.json({
        success: true,
        data: enriched,
        summary: {
          totalRecords: enriched.length,
          totalStudents,
          totalDue,
          byStatus: {
            pending: enriched.filter((d) => d.status === "pending").length,
            partial: enriched.filter((d) => d.status === "partial").length,
            overdue: enriched.filter((d) => d.status === "overdue").length,
          },
        },
      });
    } catch (error) {
      logger.error("Error fetching fee dues:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch fee dues",
        error: error.message,
      });
    }
  }
);

// GET /fees/reports - Fee collection reports
app.get(
  "/fees/reports",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_fees"),
  async (req, res) => {
    try {
      const { month, startMonth, endMonth, classId } = req.query;

      // Monthly collection summary
      const feeQuery = { organizationId: req.organizationId };
      if (month) {
        feeQuery.month = month;
      } else if (startMonth || endMonth) {
        feeQuery.month = {};
        if (startMonth) feeQuery.month.$gte = startMonth;
        if (endMonth) feeQuery.month.$lte = endMonth;
      }

      if (classId && ObjectId.isValid(classId)) {
        const classStudents = await studentsCollection
          .find({
            organizationId: req.organizationId,
            classId: new ObjectId(classId),
            status: "active",
          })
          .toArray();
        feeQuery.studentId = {
          $in: classStudents.map((s) => s._id),
        };
      }

      const allFees = await studentMonthlyFeesCollection
        .find(feeQuery)
        .toArray();

      // Group by month
      const monthlyData = {};
      allFees.forEach((f) => {
        if (!monthlyData[f.month]) {
          monthlyData[f.month] = {
            month: f.month,
            totalPayable: 0,
            totalDiscount: 0,
            totalCollected: 0,
            totalDue: 0,
            studentCount: 0,
            paidCount: 0,
            partialCount: 0,
            pendingCount: 0,
            overdueCount: 0,
          };
        }
        const m = monthlyData[f.month];
        m.totalPayable += f.payableAmount;
        m.totalDiscount += f.discount || 0;
        m.totalCollected += f.paidAmount || 0;
        m.totalDue +=
          f.payableAmount - (f.discount || 0) - (f.paidAmount || 0);
        m.studentCount++;
        if (f.status === "paid") m.paidCount++;
        else if (f.status === "partial") m.partialCount++;
        else if (f.status === "overdue") m.overdueCount++;
        else m.pendingCount++;
      });

      const monthlyReport = Object.values(monthlyData).sort((a, b) =>
        b.month.localeCompare(a.month)
      );

      // Payment mode breakdown
      const paymentQuery = { organizationId: req.organizationId };
      if (month) {
        // Get fee IDs for this month
        const monthFeeIds = allFees.map((f) => f._id);
        paymentQuery.studentMonthlyFeeId = { $in: monthFeeIds };
      }

      const allPayments = await paymentsCollection
        .find(paymentQuery)
        .toArray();

      const modeBreakdown = {};
      allPayments.forEach((p) => {
        if (!modeBreakdown[p.paymentMode]) {
          modeBreakdown[p.paymentMode] = { count: 0, total: 0 };
        }
        modeBreakdown[p.paymentMode].count++;
        modeBreakdown[p.paymentMode].total += p.amount;
      });

      // Overall totals
      const totalPayable = allFees.reduce(
        (sum, f) => sum + f.payableAmount,
        0
      );
      const totalDiscount = allFees.reduce(
        (sum, f) => sum + (f.discount || 0),
        0
      );
      const totalCollected = allFees.reduce(
        (sum, f) => sum + (f.paidAmount || 0),
        0
      );
      const totalDue = totalPayable - totalDiscount - totalCollected;
      const collectionRate =
        totalPayable - totalDiscount > 0
          ? Math.round(
              (totalCollected / (totalPayable - totalDiscount)) * 100 * 100
            ) / 100
          : 0;

      res.json({
        success: true,
        data: {
          monthly: monthlyReport,
          paymentModes: modeBreakdown,
          overall: {
            totalPayable,
            totalDiscount,
            totalCollected,
            totalDue,
            collectionRate,
            totalStudentFeeRecords: allFees.length,
            totalPayments: allPayments.length,
          },
        },
      });
    } catch (error) {
      logger.error("Error generating fee reports:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate fee reports",
        error: error.message,
      });
    }
  }
);

// ========== Expense Endpoints ==========

// POST /expenses - Create expense
app.post(
  "/expenses",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_expenses"),
  async (req, res) => {
    try {
      const {
        title,
        description,
        amount,
        category,
        expenseMonth,
        expenseDate,
        receiptUrl,
      } = req.body;

      if (!title || !amount || !category || !expenseMonth) {
        return res.status(400).json({
          success: false,
          message:
            "Title, amount, category, and expenseMonth are required",
        });
      }

      const validCategories = [
        "utilities",
        "salary",
        "maintenance",
        "supplies",
        "transport",
        "events",
        "others",
      ];
      if (!validCategories.includes(category)) {
        return res.status(400).json({
          success: false,
          message: `Invalid category. Must be one of: ${validCategories.join(", ")}`,
        });
      }

      if (!/^\d{4}-\d{2}$/.test(expenseMonth)) {
        return res.status(400).json({
          success: false,
          message: "expenseMonth must be in YYYY-MM format",
        });
      }

      const expense = {
        organizationId: req.organizationId,
        title,
        description: description || null,
        amount: Number(amount),
        category,
        expenseMonth,
        paidBy: req.userId,
        expenseDate: expenseDate ? new Date(expenseDate) : new Date(),
        receiptUrl: receiptUrl || null,
        createdBy: req.userId,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await expensesCollection.insertOne(expense);

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "expense",
        result.insertedId,
        { after: expense },
        req
      );

      res.status(201).json({
        success: true,
        message: "Expense created successfully",
        data: { ...expense, _id: result.insertedId },
      });
    } catch (error) {
      logger.error("Error creating expense:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to create expense",
        error: error.message,
      });
    }
  }
);

// GET /expenses - List expenses
app.get(
  "/expenses",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_expenses"),
  async (req, res) => {
    try {
      const {
        category,
        expenseMonth,
        startDate,
        endDate,
        page = 1,
        limit = 50,
      } = req.query;

      const query = { organizationId: req.organizationId };
      if (category) query.category = category;
      if (expenseMonth) query.expenseMonth = expenseMonth;

      if (startDate || endDate) {
        query.expenseDate = {};
        if (startDate) query.expenseDate.$gte = new Date(startDate);
        if (endDate) query.expenseDate.$lte = new Date(endDate);
      }

      const total = await expensesCollection.countDocuments(query);
      const expenses = await expensesCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ expenseDate: -1 })
        .toArray();

      // Enrich with creator names
      const creatorIds = [
        ...new Set(expenses.map((e) => e.createdBy.toString())),
      ];
      const creators = await usersCollection
        .find({
          _id: { $in: creatorIds.map((id) => new ObjectId(id)) },
        })
        .toArray();
      const creatorMap = {};
      creators.forEach(
        (c) => (creatorMap[c._id.toString()] = c.name)
      );

      const enriched = expenses.map((e) => ({
        ...e,
        createdByName: creatorMap[e.createdBy.toString()] || "Unknown",
      }));

      res.json({
        success: true,
        data: enriched,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching expenses:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch expenses",
        error: error.message,
      });
    }
  }
);

// PATCH /expenses/:id - Update expense
app.patch(
  "/expenses/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_expenses"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid expense ID",
        });
      }

      const existing = await expensesCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Expense not found",
        });
      }

      const allowedFields = [
        "title",
        "description",
        "amount",
        "category",
        "expenseMonth",
        "expenseDate",
        "receiptUrl",
      ];
      const updates = {};
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      if (updates.amount) updates.amount = Number(updates.amount);
      if (updates.expenseDate)
        updates.expenseDate = new Date(updates.expenseDate);

      if (updates.category) {
        const validCategories = [
          "utilities",
          "salary",
          "maintenance",
          "supplies",
          "transport",
          "events",
          "others",
        ];
        if (!validCategories.includes(updates.category)) {
          return res.status(400).json({
            success: false,
            message: `Invalid category. Must be one of: ${validCategories.join(", ")}`,
          });
        }
      }

      updates.updatedAt = new Date();

      const result = await expensesCollection.findOneAndUpdate(
        { _id: new ObjectId(id), organizationId: req.organizationId },
        { $set: updates },
        { returnDocument: "after" }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "expense",
        id,
        { before: existing, after: result },
        req
      );

      res.json({
        success: true,
        message: "Expense updated successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error updating expense:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to update expense",
        error: error.message,
      });
    }
  }
);

// DELETE /expenses/:id - Delete expense
app.delete(
  "/expenses/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_expenses"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid expense ID",
        });
      }

      const existing = await expensesCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Expense not found",
        });
      }

      await expensesCollection.deleteOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "expense",
        id,
        { before: existing },
        req
      );

      res.json({
        success: true,
        message: "Expense deleted successfully",
      });
    } catch (error) {
      logger.error("Error deleting expense:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to delete expense",
        error: error.message,
      });
    }
  }
);

// ========== Salary Endpoints ==========

// POST /salaries - Create salary record
app.post(
  "/salaries",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_salaries"),
  async (req, res) => {
    try {
      const {
        staffId,
        month,
        baseSalary,
        allowances,
        deductions,
      } = req.body;

      if (!staffId || !month || baseSalary === undefined) {
        return res.status(400).json({
          success: false,
          message: "staffId, month, and baseSalary are required",
        });
      }

      if (!ObjectId.isValid(staffId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid staff ID",
        });
      }

      if (!/^\d{4}-\d{2}$/.test(month)) {
        return res.status(400).json({
          success: false,
          message: "Month must be in YYYY-MM format",
        });
      }

      // Verify staff exists and get info
      const staffUser = await usersCollection.findOne({
        _id: new ObjectId(staffId),
        organizationId: req.organizationId,
      });

      if (!staffUser) {
        return res.status(404).json({
          success: false,
          message: "Staff member not found",
        });
      }

      const netAmount =
        Number(baseSalary) +
        Number(allowances || 0) -
        Number(deductions || 0);

      const salary = {
        organizationId: req.organizationId,
        staffId: new ObjectId(staffId),
        staffName: staffUser.name,
        staffRole: staffUser.role,
        month,
        baseSalary: Number(baseSalary),
        allowances: Number(allowances || 0),
        deductions: Number(deductions || 0),
        netAmount,
        status: "pending",
        paidDate: null,
        paidBy: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await salariesCollection.insertOne(salary);

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "salary",
        result.insertedId,
        { after: salary },
        req
      );

      res.status(201).json({
        success: true,
        message: "Salary record created successfully",
        data: { ...salary, _id: result.insertedId },
      });
    } catch (error) {
      if (error.code === 11000) {
        return res.status(409).json({
          success: false,
          message:
            "Salary record already exists for this staff member in this month",
        });
      }
      logger.error("Error creating salary:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to create salary record",
        error: error.message,
      });
    }
  }
);

// POST /salaries/generate - Generate monthly salary records for all active staff
app.post(
  "/salaries/generate",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_salaries"),
  async (req, res) => {
    try {
      const { month, defaultBaseSalary } = req.body;

      if (!month) {
        return res.status(400).json({
          success: false,
          message: "month (YYYY-MM) is required",
        });
      }

      if (!/^\d{4}-\d{2}$/.test(month)) {
        return res.status(400).json({
          success: false,
          message: "Month must be in YYYY-MM format",
        });
      }

      // Get all active staff (teachers, admins, moderators, org_owner)
      const staffRoles = [
        "org_owner",
        "admin",
        "moderator",
        "teacher",
      ];
      const staffMembers = await usersCollection
        .find({
          organizationId: req.organizationId,
          role: { $in: staffRoles },
          status: "active",
        })
        .toArray();

      if (staffMembers.length === 0) {
        return res.status(400).json({
          success: false,
          message: "No active staff members found",
        });
      }

      let created = 0;
      let skipped = 0;

      for (const staff of staffMembers) {
        try {
          const baseSalary = Number(defaultBaseSalary || 0);
          const netAmount = baseSalary;

          await salariesCollection.insertOne({
            organizationId: req.organizationId,
            staffId: staff._id,
            staffName: staff.name,
            staffRole: staff.role,
            month,
            baseSalary,
            allowances: 0,
            deductions: 0,
            netAmount,
            status: "pending",
            paidDate: null,
            paidBy: null,
            createdAt: new Date(),
            updatedAt: new Date(),
          });
          created++;
        } catch (insertError) {
          if (insertError.code === 11000) {
            skipped++;
          } else {
            throw insertError;
          }
        }
      }

      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "salaries_bulk",
        null,
        {
          after: { month, created, skipped },
        },
        req
      );

      res.status(201).json({
        success: true,
        message: `Generated ${created} salary record(s), skipped ${skipped} (already existed)`,
        data: {
          created,
          skipped,
          totalStaff: staffMembers.length,
          month,
        },
      });
    } catch (error) {
      logger.error("Error generating salaries:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate salary records",
        error: error.message,
      });
    }
  }
);

// GET /salaries - List salaries
app.get(
  "/salaries",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_salaries"),
  async (req, res) => {
    try {
      const {
        month,
        status,
        staffRole,
        page = 1,
        limit = 50,
      } = req.query;

      const query = { organizationId: req.organizationId };
      if (month) query.month = month;
      if (status) query.status = status;
      if (staffRole) query.staffRole = staffRole;

      const total = await salariesCollection.countDocuments(query);
      const salaries = await salariesCollection
        .find(query)
        .skip((Number(page) - 1) * Number(limit))
        .limit(Number(limit))
        .sort({ month: -1, staffName: 1 })
        .toArray();

      res.json({
        success: true,
        data: salaries,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching salaries:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch salaries",
        error: error.message,
      });
    }
  }
);

// PATCH /salaries/:id - Update salary (mark as paid, adjust amounts)
app.patch(
  "/salaries/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_salaries"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid salary ID",
        });
      }

      const existing = await salariesCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Salary record not found",
        });
      }

      const updates = {};

      // Allow updating amounts if still pending
      if (existing.status === "pending") {
        if (req.body.baseSalary !== undefined)
          updates.baseSalary = Number(req.body.baseSalary);
        if (req.body.allowances !== undefined)
          updates.allowances = Number(req.body.allowances);
        if (req.body.deductions !== undefined)
          updates.deductions = Number(req.body.deductions);

        // Recalculate net if any amount changed
        if (
          updates.baseSalary !== undefined ||
          updates.allowances !== undefined ||
          updates.deductions !== undefined
        ) {
          const base =
            updates.baseSalary !== undefined
              ? updates.baseSalary
              : existing.baseSalary;
          const allow =
            updates.allowances !== undefined
              ? updates.allowances
              : existing.allowances;
          const deduct =
            updates.deductions !== undefined
              ? updates.deductions
              : existing.deductions;
          updates.netAmount = base + allow - deduct;
        }
      }

      // Mark as paid
      if (req.body.status === "paid" && existing.status === "pending") {
        updates.status = "paid";
        updates.paidDate = new Date();
        updates.paidBy = req.userId;
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid updates provided",
        });
      }

      updates.updatedAt = new Date();

      const result = await salariesCollection.findOneAndUpdate(
        { _id: new ObjectId(id), organizationId: req.organizationId },
        { $set: updates },
        { returnDocument: "after" }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "salary",
        id,
        { before: existing, after: result },
        req
      );

      // Notify staff if paid
      if (updates.status === "paid") {
        await createNotification(
          existing.staffId,
          req.organizationId,
          "salary_paid",
          "Salary Paid",
          `Your salary for ${existing.month} (${result.netAmount}) has been processed.`,
          {
            resourceType: "salary",
            resourceId: id,
          }
        );
      }

      res.json({
        success: true,
        message:
          updates.status === "paid"
            ? "Salary marked as paid"
            : "Salary record updated successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error updating salary:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to update salary record",
        error: error.message,
      });
    }
  }
);

// GET /salaries/reports - Salary reports
app.get(
  "/salaries/reports",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("manage_salaries"),
  async (req, res) => {
    try {
      const { month, startMonth, endMonth } = req.query;

      const query = { organizationId: req.organizationId };
      if (month) {
        query.month = month;
      } else if (startMonth || endMonth) {
        query.month = {};
        if (startMonth) query.month.$gte = startMonth;
        if (endMonth) query.month.$lte = endMonth;
      }

      const salaries = await salariesCollection.find(query).toArray();

      // Group by month
      const monthlyData = {};
      salaries.forEach((s) => {
        if (!monthlyData[s.month]) {
          monthlyData[s.month] = {
            month: s.month,
            totalBaseSalary: 0,
            totalAllowances: 0,
            totalDeductions: 0,
            totalNetAmount: 0,
            staffCount: 0,
            paidCount: 0,
            pendingCount: 0,
          };
        }
        const m = monthlyData[s.month];
        m.totalBaseSalary += s.baseSalary;
        m.totalAllowances += s.allowances;
        m.totalDeductions += s.deductions;
        m.totalNetAmount += s.netAmount;
        m.staffCount++;
        if (s.status === "paid") m.paidCount++;
        else m.pendingCount++;
      });

      const monthlyReport = Object.values(monthlyData).sort((a, b) =>
        b.month.localeCompare(a.month)
      );

      // Group by role
      const roleData = {};
      salaries.forEach((s) => {
        if (!roleData[s.staffRole]) {
          roleData[s.staffRole] = {
            role: s.staffRole,
            staffCount: 0,
            totalNetAmount: 0,
          };
        }
        roleData[s.staffRole].staffCount++;
        roleData[s.staffRole].totalNetAmount += s.netAmount;
      });

      // Overall totals
      const totalNet = salaries.reduce(
        (sum, s) => sum + s.netAmount,
        0
      );
      const totalPaid = salaries
        .filter((s) => s.status === "paid")
        .reduce((sum, s) => sum + s.netAmount, 0);
      const totalPending = totalNet - totalPaid;

      res.json({
        success: true,
        data: {
          monthly: monthlyReport,
          byRole: Object.values(roleData),
          overall: {
            totalRecords: salaries.length,
            totalNetAmount: totalNet,
            totalPaid,
            totalPending,
            paidCount: salaries.filter((s) => s.status === "paid")
              .length,
            pendingCount: salaries.filter(
              (s) => s.status === "pending"
            ).length,
          },
        },
      });
    } catch (error) {
      logger.error("Error generating salary reports:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate salary reports",
        error: error.message,
      });
    }
  }
);

// ==================== PHASE 6: COMMUNICATION, DOCUMENTS & REPORTS ====================

// -------------------- ANNOUNCEMENTS --------------------

// POST /announcements - Create announcement
app.post(
  "/announcements",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_announcement"),
  async (req, res) => {
    try {
      const { title, message, target, targetId, targetRole, priority, expiresAt } = req.body;

      // Validate required fields
      if (!title || !message || !target) {
        return res.status(400).json({
          success: false,
          message: "Required fields: title, message, target",
        });
      }

      // Validate target enum
      const validTargets = ["school", "class", "section", "role"];
      if (!validTargets.includes(target)) {
        return res.status(400).json({
          success: false,
          message: `Invalid target. Must be one of: ${validTargets.join(", ")}`,
        });
      }

      // Validate priority enum
      const validPriorities = ["normal", "important", "urgent"];
      const announcementPriority = priority || "normal";
      if (!validPriorities.includes(announcementPriority)) {
        return res.status(400).json({
          success: false,
          message: `Invalid priority. Must be one of: ${validPriorities.join(", ")}`,
        });
      }

      // If target is class or section, targetId is required
      if ((target === "class" || target === "section") && !targetId) {
        return res.status(400).json({
          success: false,
          message: `targetId is required when target is '${target}'`,
        });
      }

      // If target is role, targetRole is required
      if (target === "role" && !targetRole) {
        return res.status(400).json({
          success: false,
          message: "targetRole is required when target is 'role'",
        });
      }

      const validRoles = ["teacher", "student", "parent"];
      if (target === "role" && !validRoles.includes(targetRole)) {
        return res.status(400).json({
          success: false,
          message: `Invalid targetRole. Must be one of: ${validRoles.join(", ")}`,
        });
      }

      // Validate targetId if provided
      if (targetId && !ObjectId.isValid(targetId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid targetId",
        });
      }

      // Validate class/section exists in org
      if (target === "class" && targetId) {
        const classDoc = await classesCollection.findOne({
          _id: new ObjectId(targetId),
          organizationId: req.organizationId,
        });
        if (!classDoc) {
          return res.status(404).json({
            success: false,
            message: "Class not found in your organization",
          });
        }
      }

      if (target === "section" && targetId) {
        const sectionDoc = await sectionsCollection.findOne({
          _id: new ObjectId(targetId),
          organizationId: req.organizationId,
        });
        if (!sectionDoc) {
          return res.status(404).json({
            success: false,
            message: "Section not found in your organization",
          });
        }
      }

      // Teacher restriction: can only create for their assigned classes
      if (req.userRole === "teacher" && (target === "class" || target === "section")) {
        const teacherDoc = await getTeacherDocForCurrentUser(
          req.organizationId,
          req.userId
        );
        if (!teacherDoc) {
          return res.status(403).json({
            success: false,
            message: "Teacher profile not found or inactive",
          });
        }

        let classIdToCheck = targetId;
        if (target === "section") {
          const sectionDoc = await sectionsCollection.findOne({
            _id: new ObjectId(targetId),
            organizationId: req.organizationId,
          });
          classIdToCheck = sectionDoc?.classId?.toString();
        }

        const hasSubjectInClass = await subjectsCollection.findOne({
          organizationId: req.organizationId,
          classId: new ObjectId(classIdToCheck),
          teacherId: teacherDoc._id,
        });

        if (!hasSubjectInClass) {
          return res.status(403).json({
            success: false,
            message: "You can only create announcements for your assigned classes",
          });
        }
      }

      // Teachers cannot create school-wide or role-targeted announcements
      if (req.userRole === "teacher" && (target === "school" || target === "role")) {
        return res.status(403).json({
          success: false,
          message: "Teachers can only create class or section announcements",
        });
      }

      // Build announcement document
      const announcement = {
        organizationId: req.organizationId,
        title,
        message,
        target,
        targetId: targetId ? new ObjectId(targetId) : null,
        targetRole: target === "role" ? targetRole : null,
        priority: announcementPriority,
        createdBy: req.userId,
        isActive: true,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await announcementsCollection.insertOne(announcement);

      // Send notifications to targeted users
      try {
        let notifyUserIds = [];

        if (target === "school") {
          const orgUsers = await usersCollection
            .find({
              organizationId: req.organizationId,
              _id: { $ne: req.userId },
            })
            .project({ _id: 1 })
            .toArray();
          notifyUserIds = orgUsers.map((u) => u._id);
        } else if (target === "class") {
          const classStudents = await studentsCollection
            .find({
              organizationId: req.organizationId,
              classId: new ObjectId(targetId),
              status: "active",
            })
            .project({ userId: 1, parentId: 1 })
            .toArray();

          for (const s of classStudents) {
            if (s.userId) notifyUserIds.push(s.userId);
            if (s.parentId) {
              const parentDoc = await parentsCollection.findOne({ _id: s.parentId });
              if (parentDoc?.userId) notifyUserIds.push(parentDoc.userId);
            }
          }
        } else if (target === "section") {
          const sectionStudents = await studentsCollection
            .find({
              organizationId: req.organizationId,
              sectionId: new ObjectId(targetId),
              status: "active",
            })
            .project({ userId: 1, parentId: 1 })
            .toArray();

          for (const s of sectionStudents) {
            if (s.userId) notifyUserIds.push(s.userId);
            if (s.parentId) {
              const parentDoc = await parentsCollection.findOne({ _id: s.parentId });
              if (parentDoc?.userId) notifyUserIds.push(parentDoc.userId);
            }
          }
        } else if (target === "role") {
          const roleUsers = await usersCollection
            .find({
              organizationId: req.organizationId,
              role: targetRole,
              _id: { $ne: req.userId },
            })
            .project({ _id: 1 })
            .toArray();
          notifyUserIds = roleUsers.map((u) => u._id);
        }

        if (notifyUserIds.length > 0) {
          await createBulkNotifications(
            notifyUserIds,
            req.organizationId,
            "announcement",
            `${announcementPriority === "urgent" ? "[URGENT] " : announcementPriority === "important" ? "[IMPORTANT] " : ""}${title}`,
            message.substring(0, 200),
            {
              resourceType: "announcement",
              resourceId: result.insertedId.toString(),
            }
          );
        }
      } catch (notifyError) {
        logger.error("Error sending announcement notifications:", {
          error: notifyError.message,
        });
      }

      // Log activity
      await logActivity(
        req.userId,
        req.organizationId,
        "created",
        "announcement",
        result.insertedId,
        { after: announcement },
        req
      );

      res.status(201).json({
        success: true,
        message: "Announcement created successfully",
        data: { ...announcement, _id: result.insertedId },
      });
    } catch (error) {
      logger.error("Error creating announcement:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to create announcement",
        error: error.message,
      });
    }
  }
);

// GET /announcements - List announcements with role-based filtering
app.get(
  "/announcements",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_announcements"),
  async (req, res) => {
    try {
      const { target, priority, page = 1, limit = 20 } = req.query;
      const skip = (Number(page) - 1) * Number(limit);

      // Base query: org-scoped, active, not expired
      const query = {
        organizationId: req.organizationId,
        isActive: true,
        $or: [
          { expiresAt: null },
          { expiresAt: { $gt: new Date() } },
        ],
      };

      // Apply optional filters
      if (target) query.target = target;
      if (priority) query.priority = priority;

      // Role-based visibility filtering
      const role = req.userRole;

      if (role === "student") {
        // Students see: school-wide + their class + their section + role=student
        const studentDoc = await studentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
          status: "active",
        });

        const visibilityConditions = [
          { target: "school" },
          { target: "role", targetRole: "student" },
        ];

        if (studentDoc) {
          if (studentDoc.classId) {
            visibilityConditions.push({ target: "class", targetId: studentDoc.classId });
          }
          if (studentDoc.sectionId) {
            visibilityConditions.push({ target: "section", targetId: studentDoc.sectionId });
          }
        }

        query.$and = [{ $or: visibilityConditions }];
      } else if (role === "parent") {
        // Parents see: school-wide + their children's classes/sections + role=parent
        const parentDoc = await parentsCollection.findOne({
          organizationId: req.organizationId,
          userId: req.userId,
        });

        const visibilityConditions = [
          { target: "school" },
          { target: "role", targetRole: "parent" },
        ];

        if (parentDoc?.children && parentDoc.children.length > 0) {
          const childStudents = await studentsCollection
            .find({
              _id: { $in: parentDoc.children },
              organizationId: req.organizationId,
              status: "active",
            })
            .project({ classId: 1, sectionId: 1 })
            .toArray();

          for (const child of childStudents) {
            if (child.classId) {
              visibilityConditions.push({ target: "class", targetId: child.classId });
            }
            if (child.sectionId) {
              visibilityConditions.push({ target: "section", targetId: child.sectionId });
            }
          }
        }

        query.$and = [{ $or: visibilityConditions }];
      } else if (role === "teacher") {
        // Teachers see: school-wide + their assigned class announcements + role=teacher
        const teacherDoc = await getTeacherDocForCurrentUser(
          req.organizationId,
          req.userId
        );

        const visibilityConditions = [
          { target: "school" },
          { target: "role", targetRole: "teacher" },
        ];

        if (teacherDoc) {
          const teacherSubjects = await subjectsCollection
            .find({
              organizationId: req.organizationId,
              teacherId: teacherDoc._id,
            })
            .project({ classId: 1 })
            .toArray();

          const classIds = [...new Set(teacherSubjects.map((s) => s.classId.toString()))];

          for (const cid of classIds) {
            visibilityConditions.push({ target: "class", targetId: new ObjectId(cid) });
          }

          // Also show section announcements for their classes
          const classSections = await sectionsCollection
            .find({
              organizationId: req.organizationId,
              classId: { $in: classIds.map((id) => new ObjectId(id)) },
            })
            .project({ _id: 1 })
            .toArray();

          for (const sec of classSections) {
            visibilityConditions.push({ target: "section", targetId: sec._id });
          }
        }

        query.$and = [{ $or: visibilityConditions }];
      }
      // org_owner, admin, moderator see all announcements (no additional filter)

      const [announcements, total] = await Promise.all([
        announcementsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(Number(limit))
          .toArray(),
        announcementsCollection.countDocuments(query),
      ]);

      // Enrich with creator names
      const creatorIds = [...new Set(announcements.map((a) => a.createdBy.toString()))];
      const creators = await usersCollection
        .find({ _id: { $in: creatorIds.map((id) => new ObjectId(id)) } })
        .project({ _id: 1, name: 1 })
        .toArray();
      const creatorMap = {};
      creators.forEach((c) => {
        creatorMap[c._id.toString()] = c.name;
      });

      const enrichedAnnouncements = announcements.map((a) => ({
        ...a,
        createdByName: creatorMap[a.createdBy.toString()] || "Unknown",
      }));

      res.json({
        success: true,
        data: enrichedAnnouncements,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching announcements:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch announcements",
        error: error.message,
      });
    }
  }
);

// PATCH /announcements/:id - Update announcement
app.patch(
  "/announcements/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_announcement"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid announcement ID",
        });
      }

      const existing = await announcementsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Announcement not found",
        });
      }

      // Only creator can update unless admin/org_owner
      if (
        req.userRole === "teacher" &&
        existing.createdBy.toString() !== req.userId.toString()
      ) {
        return res.status(403).json({
          success: false,
          message: "You can only update your own announcements",
        });
      }

      const allowedFields = [
        "title",
        "message",
        "target",
        "targetId",
        "targetRole",
        "priority",
        "isActive",
        "expiresAt",
      ];

      const updates = {};
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          if (field === "targetId") {
            updates[field] = req.body[field] ? new ObjectId(req.body[field]) : null;
          } else if (field === "expiresAt") {
            updates[field] = req.body[field] ? new Date(req.body[field]) : null;
          } else {
            updates[field] = req.body[field];
          }
        }
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No valid fields to update",
        });
      }

      // Validate target if being updated
      if (updates.target) {
        const validTargets = ["school", "class", "section", "role"];
        if (!validTargets.includes(updates.target)) {
          return res.status(400).json({
            success: false,
            message: `Invalid target. Must be one of: ${validTargets.join(", ")}`,
          });
        }
      }

      // Validate priority if being updated
      if (updates.priority) {
        const validPriorities = ["normal", "important", "urgent"];
        if (!validPriorities.includes(updates.priority)) {
          return res.status(400).json({
            success: false,
            message: `Invalid priority. Must be one of: ${validPriorities.join(", ")}`,
          });
        }
      }

      updates.updatedAt = new Date();

      await announcementsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      await logActivity(
        req.userId,
        req.organizationId,
        "updated",
        "announcement",
        id,
        { before: existing, after: updates },
        req
      );

      const updated = await announcementsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({
        success: true,
        message: "Announcement updated successfully",
        data: updated,
      });
    } catch (error) {
      logger.error("Error updating announcement:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to update announcement",
        error: error.message,
      });
    }
  }
);

// DELETE /announcements/:id - Delete announcement
app.delete(
  "/announcements/:id",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("create_announcement"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid announcement ID",
        });
      }

      const existing = await announcementsCollection.findOne({
        _id: new ObjectId(id),
        organizationId: req.organizationId,
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Announcement not found",
        });
      }

      // Only creator can delete unless admin/org_owner
      if (
        req.userRole === "teacher" &&
        existing.createdBy.toString() !== req.userId.toString()
      ) {
        return res.status(403).json({
          success: false,
          message: "You can only delete your own announcements",
        });
      }

      await announcementsCollection.deleteOne({ _id: new ObjectId(id) });

      await logActivity(
        req.userId,
        req.organizationId,
        "deleted",
        "announcement",
        id,
        { before: existing },
        req
      );

      res.json({
        success: true,
        message: "Announcement deleted successfully",
      });
    } catch (error) {
      logger.error("Error deleting announcement:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to delete announcement",
        error: error.message,
      });
    }
  }
);

// -------------------- REPORTS --------------------

// GET /reports/attendance - Attendance analytics
app.get(
  "/reports/attendance",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_reports"),
  async (req, res) => {
    try {
      const { classId, sectionId, startDate, endDate, month } = req.query;

      // Build attendance query
      const query = { organizationId: req.organizationId };

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({ success: false, message: "Invalid classId" });
        }
        query.classId = new ObjectId(classId);
      }

      if (sectionId) {
        if (!ObjectId.isValid(sectionId)) {
          return res.status(400).json({ success: false, message: "Invalid sectionId" });
        }
        query.sectionId = new ObjectId(sectionId);
      }

      // Date filtering
      if (startDate || endDate) {
        query.date = {};
        if (startDate) query.date.$gte = new Date(startDate);
        if (endDate) query.date.$lte = new Date(endDate);
      } else if (month) {
        // month format: YYYY-MM
        if (!/^\d{4}-\d{2}$/.test(month)) {
          return res.status(400).json({ success: false, message: "Month must be YYYY-MM format" });
        }
        const [year, mon] = month.split("-").map(Number);
        query.date = {
          $gte: new Date(year, mon - 1, 1),
          $lt: new Date(year, mon, 1),
        };
      }

      // Teacher restriction: only their assigned classes
      if (req.userRole === "teacher") {
        const teacherDoc = await getTeacherDocForCurrentUser(
          req.organizationId,
          req.userId
        );
        if (!teacherDoc) {
          return res.status(403).json({
            success: false,
            message: "Teacher profile not found or inactive",
          });
        }

        const teacherSubjects = await subjectsCollection
          .find({
            organizationId: req.organizationId,
            teacherId: teacherDoc._id,
          })
          .project({ classId: 1 })
          .toArray();

        const teacherClassIds = [...new Set(teacherSubjects.map((s) => s.classId.toString()))];

        if (classId && !teacherClassIds.includes(classId)) {
          return res.status(403).json({
            success: false,
            message: "You can only view reports for your assigned classes",
          });
        }

        if (!classId) {
          query.classId = { $in: teacherClassIds.map((id) => new ObjectId(id)) };
        }
      }

      const attendanceRecords = await attendanceCollection
        .find(query)
        .sort({ date: -1 })
        .toArray();

      // Aggregate status counts from all records
      let totalPresent = 0;
      let totalAbsent = 0;
      let totalLate = 0;
      let totalExcused = 0;
      let totalStudentEntries = 0;

      const dailyData = {};
      const classData = {};

      for (const record of attendanceRecords) {
        const dateKey = record.date.toISOString().split("T")[0];
        const classKey = record.classId.toString();

        if (!dailyData[dateKey]) {
          dailyData[dateKey] = { date: dateKey, present: 0, absent: 0, late: 0, excused: 0, total: 0 };
        }

        if (!classData[classKey]) {
          classData[classKey] = { classId: classKey, present: 0, absent: 0, late: 0, excused: 0, total: 0 };
        }

        for (const entry of record.records || []) {
          totalStudentEntries++;
          const status = entry.status;

          if (status === "present") {
            totalPresent++;
            dailyData[dateKey].present++;
            classData[classKey].present++;
          } else if (status === "absent") {
            totalAbsent++;
            dailyData[dateKey].absent++;
            classData[classKey].absent++;
          } else if (status === "late") {
            totalLate++;
            dailyData[dateKey].late++;
            classData[classKey].late++;
          } else if (status === "excused") {
            totalExcused++;
            dailyData[dateKey].excused++;
            classData[classKey].excused++;
          }

          dailyData[dateKey].total++;
          classData[classKey].total++;
        }
      }

      // Enrich class data with names
      const classIds = Object.keys(classData);
      const classes = classIds.length > 0
        ? await classesCollection
            .find({ _id: { $in: classIds.map((id) => new ObjectId(id)) } })
            .project({ _id: 1, name: 1 })
            .toArray()
        : [];

      const classNameMap = {};
      classes.forEach((c) => {
        classNameMap[c._id.toString()] = c.name;
      });

      const classBreakdown = Object.values(classData).map((cd) => ({
        ...cd,
        className: classNameMap[cd.classId] || "Unknown",
        attendancePercentage:
          cd.total > 0
            ? Number(((cd.present / cd.total) * 100).toFixed(2))
            : 0,
      }));

      const dailyTrend = Object.values(dailyData).sort(
        (a, b) => new Date(a.date) - new Date(b.date)
      );

      res.json({
        success: true,
        data: {
          summary: {
            totalRecords: attendanceRecords.length,
            totalStudentEntries,
            totalDays: Object.keys(dailyData).length,
            present: totalPresent,
            absent: totalAbsent,
            late: totalLate,
            excused: totalExcused,
            attendancePercentage:
              totalStudentEntries > 0
                ? Number(((totalPresent / totalStudentEntries) * 100).toFixed(2))
                : 0,
          },
          classBreakdown,
          dailyTrend,
        },
      });
    } catch (error) {
      logger.error("Error generating attendance report:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate attendance report",
        error: error.message,
      });
    }
  }
);

// GET /reports/academic - Academic performance analytics
app.get(
  "/reports/academic",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_reports"),
  async (req, res) => {
    try {
      const { examId, classId, subjectId, academicYear } = req.query;

      // Build query for published grade submissions
      const query = {
        organizationId: req.organizationId,
        status: "published",
      };

      if (examId) {
        if (!ObjectId.isValid(examId)) {
          return res.status(400).json({ success: false, message: "Invalid examId" });
        }
        query.examId = new ObjectId(examId);
      }

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({ success: false, message: "Invalid classId" });
        }
        query.classId = new ObjectId(classId);
      }

      if (subjectId) {
        if (!ObjectId.isValid(subjectId)) {
          return res.status(400).json({ success: false, message: "Invalid subjectId" });
        }
        query.subjectId = new ObjectId(subjectId);
      }

      // Filter by academic year via exam lookup
      if (academicYear) {
        const examsInYear = await examsCollection
          .find({
            organizationId: req.organizationId,
            academicYear,
          })
          .project({ _id: 1 })
          .toArray();

        const examIds = examsInYear.map((e) => e._id);
        if (examIds.length === 0) {
          return res.json({
            success: true,
            data: {
              summary: { totalSubmissions: 0, averageMarks: 0, passRate: 0 },
              gradeDistribution: {},
              subjectBreakdown: [],
              topPerformers: [],
            },
          });
        }

        if (!examId) {
          query.examId = { $in: examIds };
        }
      }

      // Teacher restriction
      if (req.userRole === "teacher") {
        const teacherDoc = await getTeacherDocForCurrentUser(
          req.organizationId,
          req.userId
        );
        if (!teacherDoc) {
          return res.status(403).json({
            success: false,
            message: "Teacher profile not found or inactive",
          });
        }

        const teacherSubjects = await subjectsCollection
          .find({
            organizationId: req.organizationId,
            teacherId: teacherDoc._id,
          })
          .project({ _id: 1, classId: 1 })
          .toArray();

        const teacherSubjectIds = teacherSubjects.map((s) => s._id);
        const teacherClassIds = [...new Set(teacherSubjects.map((s) => s.classId))];

        if (subjectId && !teacherSubjectIds.some((id) => id.toString() === subjectId)) {
          return res.status(403).json({
            success: false,
            message: "You can only view reports for your assigned subjects",
          });
        }

        if (!subjectId) {
          query.subjectId = { $in: teacherSubjectIds };
        }
        if (!classId) {
          query.classId = { $in: teacherClassIds };
        }
      }

      const submissions = await gradeSubmissionsCollection
        .find(query)
        .toArray();

      // Aggregate academic data
      let totalMarks = 0;
      let totalFullMarks = 0;
      let totalStudentGrades = 0;
      let passCount = 0;
      const gradeDistribution = {};
      const subjectData = {};
      const studentScores = {};

      for (const submission of submissions) {
        const subjectKey = submission.subjectId.toString();

        if (!subjectData[subjectKey]) {
          subjectData[subjectKey] = {
            subjectId: subjectKey,
            totalMarks: 0,
            totalFullMarks: 0,
            studentCount: 0,
            passCount: 0,
            grades: {},
          };
        }

        for (const grade of submission.grades || []) {
          totalStudentGrades++;
          const marks = Number(grade.marksObtained || 0);
          const fullMarks = Number(submission.fullMarks || 100);

          totalMarks += marks;
          totalFullMarks += fullMarks;

          subjectData[subjectKey].totalMarks += marks;
          subjectData[subjectKey].totalFullMarks += fullMarks;
          subjectData[subjectKey].studentCount++;

          const { grade: letterGrade } = calculateGrade(marks, fullMarks);

          // Grade distribution
          gradeDistribution[letterGrade] = (gradeDistribution[letterGrade] || 0) + 1;
          subjectData[subjectKey].grades[letterGrade] =
            (subjectData[subjectKey].grades[letterGrade] || 0) + 1;

          // Pass if >= 40%
          const percentage = (marks / fullMarks) * 100;
          if (percentage >= 40) {
            passCount++;
            subjectData[subjectKey].passCount++;
          }

          // Track student scores for top performers
          const studentKey = grade.studentId.toString();
          if (!studentScores[studentKey]) {
            studentScores[studentKey] = { totalMarks: 0, totalFullMarks: 0, count: 0 };
          }
          studentScores[studentKey].totalMarks += marks;
          studentScores[studentKey].totalFullMarks += fullMarks;
          studentScores[studentKey].count++;
        }
      }

      // Enrich subject data with names
      const subjectIds = Object.keys(subjectData);
      const subjects = subjectIds.length > 0
        ? await subjectsCollection
            .find({ _id: { $in: subjectIds.map((id) => new ObjectId(id)) } })
            .project({ _id: 1, name: 1 })
            .toArray()
        : [];

      const subjectNameMap = {};
      subjects.forEach((s) => {
        subjectNameMap[s._id.toString()] = s.name;
      });

      const subjectBreakdown = Object.values(subjectData).map((sd) => ({
        subjectId: sd.subjectId,
        subjectName: subjectNameMap[sd.subjectId] || "Unknown",
        averageMarks:
          sd.studentCount > 0
            ? Number(((sd.totalMarks / sd.totalFullMarks) * 100).toFixed(2))
            : 0,
        passRate:
          sd.studentCount > 0
            ? Number(((sd.passCount / sd.studentCount) * 100).toFixed(2))
            : 0,
        totalStudents: sd.studentCount,
        gradeDistribution: sd.grades,
      }));

      // Top performers (by average percentage)
      const topPerformerEntries = Object.entries(studentScores)
        .map(([studentId, scores]) => ({
          studentId,
          averagePercentage: Number(
            ((scores.totalMarks / scores.totalFullMarks) * 100).toFixed(2)
          ),
          subjectsCount: scores.count,
        }))
        .sort((a, b) => b.averagePercentage - a.averagePercentage)
        .slice(0, 10);

      // Enrich top performers with student names
      const topStudentIds = topPerformerEntries.map((t) => new ObjectId(t.studentId));
      const topStudents = topStudentIds.length > 0
        ? await studentsCollection
            .find({ _id: { $in: topStudentIds } })
            .project({ _id: 1, name: 1, rollNumber: 1 })
            .toArray()
        : [];

      const studentNameMap = {};
      topStudents.forEach((s) => {
        studentNameMap[s._id.toString()] = { name: s.name, rollNumber: s.rollNumber };
      });

      const topPerformers = topPerformerEntries.map((t) => ({
        ...t,
        studentName: studentNameMap[t.studentId]?.name || "Unknown",
        rollNumber: studentNameMap[t.studentId]?.rollNumber || null,
      }));

      res.json({
        success: true,
        data: {
          summary: {
            totalSubmissions: submissions.length,
            totalStudentGrades,
            averageMarks:
              totalStudentGrades > 0
                ? Number(((totalMarks / totalFullMarks) * 100).toFixed(2))
                : 0,
            passRate:
              totalStudentGrades > 0
                ? Number(((passCount / totalStudentGrades) * 100).toFixed(2))
                : 0,
          },
          gradeDistribution,
          subjectBreakdown,
          topPerformers,
        },
      });
    } catch (error) {
      logger.error("Error generating academic report:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate academic report",
        error: error.message,
      });
    }
  }
);

// GET /reports/finance - Financial summary
app.get(
  "/reports/finance",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_reports"),
  async (req, res) => {
    try {
      const { month, startDate, endDate } = req.query;

      // Build date filter for payments and expenses
      const dateFilter = {};
      if (startDate || endDate) {
        if (startDate) dateFilter.$gte = new Date(startDate);
        if (endDate) dateFilter.$lte = new Date(endDate);
      } else if (month) {
        if (!/^\d{4}-\d{2}$/.test(month)) {
          return res.status(400).json({ success: false, message: "Month must be YYYY-MM format" });
        }
        const [year, mon] = month.split("-").map(Number);
        dateFilter.$gte = new Date(year, mon - 1, 1);
        dateFilter.$lt = new Date(year, mon, 1);
      }

      // 1. Payment/Income data
      const paymentQuery = { organizationId: req.organizationId };
      if (Object.keys(dateFilter).length > 0) {
        paymentQuery.paymentDate = dateFilter;
      }

      const payments = await paymentsCollection.find(paymentQuery).toArray();

      const totalIncome = payments.reduce((sum, p) => sum + (p.amount || 0), 0);
      const paymentByMode = {};
      for (const p of payments) {
        const mode = p.paymentMode || "other";
        paymentByMode[mode] = (paymentByMode[mode] || 0) + (p.amount || 0);
      }

      // 2. Expense data
      const expenseQuery = { organizationId: req.organizationId };
      if (month) {
        expenseQuery.expenseMonth = month;
      } else if (Object.keys(dateFilter).length > 0) {
        expenseQuery.expenseDate = dateFilter;
      }

      const expenses = await expensesCollection.find(expenseQuery).toArray();

      const totalExpenses = expenses.reduce((sum, e) => sum + (e.amount || 0), 0);
      const expenseByCategory = {};
      for (const e of expenses) {
        const cat = e.category || "other";
        expenseByCategory[cat] = (expenseByCategory[cat] || 0) + (e.amount || 0);
      }

      // 3. Fee dues
      const feeQuery = { organizationId: req.organizationId };
      if (month) {
        feeQuery.month = month;
      }

      const fees = await studentMonthlyFeesCollection.find(feeQuery).toArray();

      const totalPayable = fees.reduce((sum, f) => sum + (f.payableAmount || 0) - (f.discount || 0), 0);
      const totalPaid = fees.reduce((sum, f) => sum + (f.paidAmount || 0), 0);
      const totalOutstanding = totalPayable - totalPaid;
      const overdueCount = fees.filter(
        (f) => f.status === "overdue" || (f.dueDate && new Date(f.dueDate) < new Date() && f.paidAmount < (f.payableAmount - (f.discount || 0)))
      ).length;
      const feeStatusCounts = {};
      for (const f of fees) {
        feeStatusCounts[f.status] = (feeStatusCounts[f.status] || 0) + 1;
      }

      // 4. Salary data
      const salaryQuery = { organizationId: req.organizationId };
      if (month) {
        salaryQuery.month = month;
      }

      const salaries = await salariesCollection.find(salaryQuery).toArray();

      const totalNetSalary = salaries.reduce((sum, s) => sum + (s.netAmount || 0), 0);
      const totalSalaryPaid = salaries
        .filter((s) => s.status === "paid")
        .reduce((sum, s) => sum + (s.netAmount || 0), 0);
      const totalSalaryPending = totalNetSalary - totalSalaryPaid;

      res.json({
        success: true,
        data: {
          income: {
            totalCollected: totalIncome,
            paymentCount: payments.length,
            byPaymentMode: paymentByMode,
          },
          expenses: {
            totalExpenses,
            expenseCount: expenses.length,
            byCategory: expenseByCategory,
          },
          feeDues: {
            totalPayable,
            totalPaid,
            totalOutstanding,
            overdueCount,
            totalFeeRecords: fees.length,
            byStatus: feeStatusCounts,
          },
          salaries: {
            totalNetSalary,
            totalPaid: totalSalaryPaid,
            totalPending: totalSalaryPending,
            totalRecords: salaries.length,
            paidCount: salaries.filter((s) => s.status === "paid").length,
            pendingCount: salaries.filter((s) => s.status === "pending").length,
          },
          netPosition: {
            totalIncome,
            totalExpenses,
            totalSalaryPaid,
            netBalance: totalIncome - totalExpenses - totalSalaryPaid,
          },
        },
      });
    } catch (error) {
      logger.error("Error generating finance report:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate finance report",
        error: error.message,
      });
    }
  }
);

// GET /reports/teacher-workload - Teacher assignments and submission counts
app.get(
  "/reports/teacher-workload",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_reports"),
  async (req, res) => {
    try {
      const { academicYear } = req.query;

      // Get all active teachers in org
      const teacherQuery = {
        organizationId: req.organizationId,
        status: "active",
      };

      const teachers = await teachersCollection.find(teacherQuery).toArray();

      if (teachers.length === 0) {
        return res.json({
          success: true,
          data: { teachers: [], summary: { totalTeachers: 0 } },
        });
      }

      // Get all subjects for the org
      const subjectQuery = { organizationId: req.organizationId };
      const allSubjects = await subjectsCollection.find(subjectQuery).toArray();

      // Get class names for enrichment
      const classIds = [...new Set(allSubjects.map((s) => s.classId.toString()))];
      const classes = classIds.length > 0
        ? await classesCollection
            .find({ _id: { $in: classIds.map((id) => new ObjectId(id)) } })
            .project({ _id: 1, name: 1 })
            .toArray()
        : [];

      const classNameMap = {};
      classes.forEach((c) => {
        classNameMap[c._id.toString()] = c.name;
      });

      // Get grade submissions
      const gradeQuery = { organizationId: req.organizationId };
      if (academicYear) {
        const examsInYear = await examsCollection
          .find({ organizationId: req.organizationId, academicYear })
          .project({ _id: 1 })
          .toArray();
        if (examsInYear.length > 0) {
          gradeQuery.examId = { $in: examsInYear.map((e) => e._id) };
        }
      }

      const allGradeSubmissions = await gradeSubmissionsCollection
        .find(gradeQuery)
        .project({ teacherId: 1, status: 1 })
        .toArray();

      // Get attendance data for teachers
      const allAttendance = await attendanceCollection
        .find({ organizationId: req.organizationId })
        .project({ markedBy: 1 })
        .toArray();

      // Build per-teacher workload
      const teacherWorkloads = teachers.map((teacher) => {
        const teacherId = teacher._id.toString();

        // Subjects assigned to this teacher
        const teacherSubjects = allSubjects.filter(
          (s) => s.teacherId && s.teacherId.toString() === teacherId
        );

        const subjectList = teacherSubjects.map((s) => ({
          subjectId: s._id.toString(),
          subjectName: s.name,
          classId: s.classId.toString(),
          className: classNameMap[s.classId.toString()] || "Unknown",
        }));

        const uniqueClassIds = [...new Set(teacherSubjects.map((s) => s.classId.toString()))];

        // Grade submissions by this teacher
        const teacherGrades = allGradeSubmissions.filter(
          (g) => g.teacherId && g.teacherId.toString() === teacherId
        );

        const gradesByStatus = {};
        for (const g of teacherGrades) {
          gradesByStatus[g.status] = (gradesByStatus[g.status] || 0) + 1;
        }

        // Attendance marked by this teacher
        const attendanceMarked = allAttendance.filter(
          (a) => a.markedBy && a.markedBy.toString() === teacher.userId?.toString()
        ).length;

        return {
          teacherId,
          teacherName: teacher.name,
          totalSubjects: teacherSubjects.length,
          totalClasses: uniqueClassIds.length,
          subjects: subjectList,
          gradeSubmissions: {
            total: teacherGrades.length,
            byStatus: gradesByStatus,
          },
          attendanceMarked,
        };
      });

      // Sort by total subjects descending
      teacherWorkloads.sort((a, b) => b.totalSubjects - a.totalSubjects);

      res.json({
        success: true,
        data: {
          teachers: teacherWorkloads,
          summary: {
            totalTeachers: teachers.length,
            totalSubjects: allSubjects.length,
            totalGradeSubmissions: allGradeSubmissions.length,
          },
        },
      });
    } catch (error) {
      logger.error("Error generating teacher workload report:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to generate teacher workload report",
        error: error.message,
      });
    }
  }
);

// -------------------- EXPORT --------------------

// GET /export/students - Export students as CSV
app.get(
  "/export/students",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("export_data"),
  async (req, res) => {
    try {
      const { classId, sectionId, status } = req.query;

      const query = { organizationId: req.organizationId };

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({ success: false, message: "Invalid classId" });
        }
        query.classId = new ObjectId(classId);
      }

      if (sectionId) {
        if (!ObjectId.isValid(sectionId)) {
          return res.status(400).json({ success: false, message: "Invalid sectionId" });
        }
        query.sectionId = new ObjectId(sectionId);
      }

      if (status) {
        query.status = status;
      }

      const students = await studentsCollection.find(query).sort({ name: 1 }).toArray();

      // Get class and section names
      const classIds = [...new Set(students.map((s) => s.classId?.toString()).filter(Boolean))];
      const sectionIds = [...new Set(students.map((s) => s.sectionId?.toString()).filter(Boolean))];

      const [classes, sections] = await Promise.all([
        classIds.length > 0
          ? classesCollection
              .find({ _id: { $in: classIds.map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1 })
              .toArray()
          : [],
        sectionIds.length > 0
          ? sectionsCollection
              .find({ _id: { $in: sectionIds.map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1 })
              .toArray()
          : [],
      ]);

      const classNameMap = {};
      classes.forEach((c) => { classNameMap[c._id.toString()] = c.name; });

      const sectionNameMap = {};
      sections.forEach((s) => { sectionNameMap[s._id.toString()] = s.name; });

      const headers = [
        "Name", "Admission Number", "Roll Number", "Class", "Section",
        "Gender", "Date of Birth", "Guardian Name", "Phone", "Email", "Status",
      ];

      const rows = students.map((s) => [
        s.name || "",
        s.admissionNumber || "",
        s.rollNumber || "",
        classNameMap[s.classId?.toString()] || "",
        sectionNameMap[s.sectionId?.toString()] || "",
        s.gender || "",
        s.dateOfBirth ? new Date(s.dateOfBirth).toISOString().split("T")[0] : "",
        s.guardianName || "",
        s.phone || "",
        s.email || "",
        s.status || "",
      ]);

      const csv = buildCsvString(headers, rows);

      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", 'attachment; filename="students_export.csv"');
      res.send(csv);
    } catch (error) {
      logger.error("Error exporting students:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to export students",
        error: error.message,
      });
    }
  }
);

// GET /export/attendance - Export attendance as CSV
app.get(
  "/export/attendance",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("export_data"),
  async (req, res) => {
    try {
      const { classId, sectionId, startDate, endDate } = req.query;

      const query = { organizationId: req.organizationId };

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({ success: false, message: "Invalid classId" });
        }
        query.classId = new ObjectId(classId);
      }

      if (sectionId) {
        if (!ObjectId.isValid(sectionId)) {
          return res.status(400).json({ success: false, message: "Invalid sectionId" });
        }
        query.sectionId = new ObjectId(sectionId);
      }

      if (startDate || endDate) {
        query.date = {};
        if (startDate) query.date.$gte = new Date(startDate);
        if (endDate) query.date.$lte = new Date(endDate);
      }

      const attendanceRecords = await attendanceCollection
        .find(query)
        .sort({ date: -1 })
        .toArray();

      // Get all student IDs from records
      const allStudentIds = new Set();
      for (const record of attendanceRecords) {
        for (const entry of record.records || []) {
          allStudentIds.add(entry.studentId.toString());
        }
      }

      // Get student and class/section names
      const students = allStudentIds.size > 0
        ? await studentsCollection
            .find({ _id: { $in: [...allStudentIds].map((id) => new ObjectId(id)) } })
            .project({ _id: 1, name: 1, rollNumber: 1 })
            .toArray()
        : [];

      const studentMap = {};
      students.forEach((s) => {
        studentMap[s._id.toString()] = { name: s.name, rollNumber: s.rollNumber };
      });

      const classIds = [...new Set(attendanceRecords.map((r) => r.classId.toString()))];
      const sectionIds = [...new Set(attendanceRecords.map((r) => r.sectionId.toString()))];

      const [classes, sections] = await Promise.all([
        classIds.length > 0
          ? classesCollection
              .find({ _id: { $in: classIds.map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1 })
              .toArray()
          : [],
        sectionIds.length > 0
          ? sectionsCollection
              .find({ _id: { $in: sectionIds.map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1 })
              .toArray()
          : [],
      ]);

      const classNameMap = {};
      classes.forEach((c) => { classNameMap[c._id.toString()] = c.name; });

      const sectionNameMap = {};
      sections.forEach((s) => { sectionNameMap[s._id.toString()] = s.name; });

      const headers = ["Date", "Class", "Section", "Student Name", "Roll Number", "Status"];

      const rows = [];
      for (const record of attendanceRecords) {
        const dateStr = record.date ? new Date(record.date).toISOString().split("T")[0] : "";
        const className = classNameMap[record.classId?.toString()] || "";
        const sectionName = sectionNameMap[record.sectionId?.toString()] || "";

        for (const entry of record.records || []) {
          const student = studentMap[entry.studentId?.toString()];
          rows.push([
            dateStr,
            className,
            sectionName,
            student?.name || "",
            student?.rollNumber || "",
            entry.status || "",
          ]);
        }
      }

      const csv = buildCsvString(headers, rows);

      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", 'attachment; filename="attendance_export.csv"');
      res.send(csv);
    } catch (error) {
      logger.error("Error exporting attendance:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to export attendance",
        error: error.message,
      });
    }
  }
);

// GET /export/fees - Export fees as CSV
app.get(
  "/export/fees",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("export_data"),
  async (req, res) => {
    try {
      const { month, classId, status } = req.query;

      const feeQuery = { organizationId: req.organizationId };

      if (month) {
        if (!/^\d{4}-\d{2}$/.test(month)) {
          return res.status(400).json({ success: false, message: "Month must be YYYY-MM format" });
        }
        feeQuery.month = month;
      }

      if (status) {
        feeQuery.status = status;
      }

      const fees = await studentMonthlyFeesCollection.find(feeQuery).toArray();

      // Get student details
      const studentIds = [...new Set(fees.map((f) => f.studentId.toString()))];
      const students = studentIds.length > 0
        ? await studentsCollection
            .find({ _id: { $in: studentIds.map((id) => new ObjectId(id)) } })
            .project({ _id: 1, name: 1, admissionNumber: 1, classId: 1, sectionId: 1 })
            .toArray()
        : [];

      const studentMap = {};
      students.forEach((s) => {
        studentMap[s._id.toString()] = s;
      });

      // Filter by classId if provided (via student lookup)
      let filteredFees = fees;
      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({ success: false, message: "Invalid classId" });
        }
        filteredFees = fees.filter((f) => {
          const student = studentMap[f.studentId.toString()];
          return student && student.classId?.toString() === classId;
        });
      }

      // Get class and section names
      const classIds = [...new Set(students.map((s) => s.classId?.toString()).filter(Boolean))];
      const sectionIds = [...new Set(students.map((s) => s.sectionId?.toString()).filter(Boolean))];

      const [classes, sections] = await Promise.all([
        classIds.length > 0
          ? classesCollection
              .find({ _id: { $in: classIds.map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1 })
              .toArray()
          : [],
        sectionIds.length > 0
          ? sectionsCollection
              .find({ _id: { $in: sectionIds.map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1 })
              .toArray()
          : [],
      ]);

      const classNameMap = {};
      classes.forEach((c) => { classNameMap[c._id.toString()] = c.name; });

      const sectionNameMap = {};
      sections.forEach((s) => { sectionNameMap[s._id.toString()] = s.name; });

      const headers = [
        "Student Name", "Admission Number", "Class", "Section", "Month",
        "Payable Amount", "Discount", "Paid Amount", "Balance", "Status", "Due Date",
      ];

      const rows = filteredFees.map((f) => {
        const student = studentMap[f.studentId.toString()];
        const payable = (f.payableAmount || 0) - (f.discount || 0);
        const balance = payable - (f.paidAmount || 0);

        return [
          student?.name || "",
          student?.admissionNumber || "",
          classNameMap[student?.classId?.toString()] || "",
          sectionNameMap[student?.sectionId?.toString()] || "",
          f.month || "",
          f.payableAmount || 0,
          f.discount || 0,
          f.paidAmount || 0,
          balance,
          f.status || "",
          f.dueDate ? new Date(f.dueDate).toISOString().split("T")[0] : "",
        ];
      });

      const csv = buildCsvString(headers, rows);

      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", 'attachment; filename="fees_export.csv"');
      res.send(csv);
    } catch (error) {
      logger.error("Error exporting fees:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to export fees",
        error: error.message,
      });
    }
  }
);

// GET /export/results - Export results as CSV
app.get(
  "/export/results",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("export_data"),
  async (req, res) => {
    try {
      const { examId, classId } = req.query;

      const query = {
        organizationId: req.organizationId,
        status: "published",
      };

      if (examId) {
        if (!ObjectId.isValid(examId)) {
          return res.status(400).json({ success: false, message: "Invalid examId" });
        }
        query.examId = new ObjectId(examId);
      }

      if (classId) {
        if (!ObjectId.isValid(classId)) {
          return res.status(400).json({ success: false, message: "Invalid classId" });
        }
        query.classId = new ObjectId(classId);
      }

      const submissions = await gradeSubmissionsCollection.find(query).toArray();

      // Get all related data
      const allStudentIds = new Set();
      for (const sub of submissions) {
        for (const grade of sub.grades || []) {
          allStudentIds.add(grade.studentId.toString());
        }
      }

      const subjectIds = [...new Set(submissions.map((s) => s.subjectId.toString()))];
      const classIds = [...new Set(submissions.map((s) => s.classId.toString()))];
      const sectionIds = [...new Set(submissions.map((s) => s.sectionId?.toString()).filter(Boolean))];

      const [students, subjects, classes, sections] = await Promise.all([
        allStudentIds.size > 0
          ? studentsCollection
              .find({ _id: { $in: [...allStudentIds].map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1, rollNumber: 1 })
              .toArray()
          : [],
        subjectIds.length > 0
          ? subjectsCollection
              .find({ _id: { $in: subjectIds.map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1 })
              .toArray()
          : [],
        classIds.length > 0
          ? classesCollection
              .find({ _id: { $in: classIds.map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1 })
              .toArray()
          : [],
        sectionIds.length > 0
          ? sectionsCollection
              .find({ _id: { $in: sectionIds.map((id) => new ObjectId(id)) } })
              .project({ _id: 1, name: 1 })
              .toArray()
          : [],
      ]);

      const studentMap = {};
      students.forEach((s) => { studentMap[s._id.toString()] = s; });

      const subjectNameMap = {};
      subjects.forEach((s) => { subjectNameMap[s._id.toString()] = s.name; });

      const classNameMap = {};
      classes.forEach((c) => { classNameMap[c._id.toString()] = c.name; });

      const sectionNameMap = {};
      sections.forEach((s) => { sectionNameMap[s._id.toString()] = s.name; });

      const headers = [
        "Student Name", "Roll Number", "Class", "Section", "Subject",
        "Marks Obtained", "Full Marks", "Percentage", "Grade", "Grade Point",
      ];

      const rows = [];
      for (const sub of submissions) {
        const subjectName = subjectNameMap[sub.subjectId?.toString()] || "";
        const className = classNameMap[sub.classId?.toString()] || "";
        const sectionName = sectionNameMap[sub.sectionId?.toString()] || "";
        const fullMarks = sub.fullMarks || 100;

        for (const grade of sub.grades || []) {
          const student = studentMap[grade.studentId?.toString()];
          const marks = Number(grade.marksObtained || 0);
          const percentage = Number(((marks / fullMarks) * 100).toFixed(2));
          const { grade: letterGrade, gradePoint } = calculateGrade(marks, fullMarks);

          rows.push([
            student?.name || "",
            student?.rollNumber || "",
            className,
            sectionName,
            subjectName,
            marks,
            fullMarks,
            percentage,
            letterGrade,
            gradePoint,
          ]);
        }
      }

      const csv = buildCsvString(headers, rows);

      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", 'attachment; filename="results_export.csv"');
      res.send(csv);
    } catch (error) {
      logger.error("Error exporting results:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to export results",
        error: error.message,
      });
    }
  }
);

// -------------------- ACTIVITY LOGS --------------------

// GET /activity-logs - View activity logs
app.get(
  "/activity-logs",
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission("view_activity_logs"),
  async (req, res) => {
    try {
      const {
        action,
        resource,
        userId,
        startDate,
        endDate,
        page = 1,
        limit = 20,
      } = req.query;

      const skip = (Number(page) - 1) * Number(limit);

      const query = { organizationId: req.organizationId };

      if (action) query.action = action;
      if (resource) query.resource = resource;

      if (userId) {
        if (!ObjectId.isValid(userId)) {
          return res.status(400).json({ success: false, message: "Invalid userId" });
        }
        query.userId = new ObjectId(userId);
      }

      if (startDate || endDate) {
        query.createdAt = {};
        if (startDate) query.createdAt.$gte = new Date(startDate);
        if (endDate) query.createdAt.$lte = new Date(endDate);
      }

      const [logs, total] = await Promise.all([
        activityLogsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(Number(limit))
          .toArray(),
        activityLogsCollection.countDocuments(query),
      ]);

      res.json({
        success: true,
        data: logs,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching activity logs:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch activity logs",
        error: error.message,
      });
    }
  }
);

// ==================== PHASE 7: SUPER ADMIN DASHBOARD & PLATFORM MANAGEMENT ====================

// GROUP 1: Platform Dashboard & Statistics

// 1.1 GET /super-admin/dashboard - Platform overview statistics
app.get(
  "/super-admin/dashboard",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      // Platform Stats
      const [
        totalOrganizations,
        activeOrganizations,
        suspendedOrganizations,
        totalUsers,
        totalStudents,
        totalTeachers,
      ] = await Promise.all([
        organizationsCollection.countDocuments({}),
        organizationsCollection.countDocuments({ status: "active" }),
        organizationsCollection.countDocuments({ status: "suspended" }),
        usersCollection.countDocuments({}),
        usersCollection.countDocuments({ role: "student" }),
        usersCollection.countDocuments({ role: "teacher" }),
      ]);

      // Subscription Stats
      const [freeCount, basicCount, professionalCount, enterpriseCount] =
        await Promise.all([
          subscriptionsCollection.countDocuments({ tier: "free" }),
          subscriptionsCollection.countDocuments({ tier: "basic" }),
          subscriptionsCollection.countDocuments({ tier: "professional" }),
          subscriptionsCollection.countDocuments({ tier: "enterprise" }),
        ]);

      const trialOrganizations = await subscriptionsCollection.countDocuments({
        status: "trial",
      });
      const activeSubscriptions = await subscriptionsCollection.countDocuments({
        status: "active",
      });

      // Recent Activity
      const now = new Date();
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
      const newOrganizationsThisMonth =
        await organizationsCollection.countDocuments({
          createdAt: { $gte: startOfMonth },
        });

      const pendingSubscriptionRequests =
        await subscriptionRequestsCollection.countDocuments({
          status: "pending",
        });
      const pendingReactivationRequests =
        await reactivationRequestsCollection.countDocuments({
          status: "pending",
        });

      // Revenue Stats
      const [monthlyRevenue, yearlyRevenue] = await Promise.all([
        subscriptionsCollection
          .aggregate([
            { $match: { billingCycle: "monthly", status: "active" } },
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ])
          .toArray(),
        subscriptionsCollection
          .aggregate([
            { $match: { billingCycle: "yearly", status: "active" } },
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ])
          .toArray(),
      ]);

      const totalMonthlyRevenue =
        (monthlyRevenue[0]?.total || 0) + (yearlyRevenue[0]?.total || 0) / 12;
      const totalYearlyRevenue =
        (monthlyRevenue[0]?.total || 0) * 12 + (yearlyRevenue[0]?.total || 0);

      res.json({
        success: true,
        data: {
          platformStats: {
            totalOrganizations,
            activeOrganizations,
            suspendedOrganizations,
            totalUsers,
            totalStudents,
            totalTeachers,
          },
          subscriptionStats: {
            free: freeCount,
            basic: basicCount,
            professional: professionalCount,
            enterprise: enterpriseCount,
            trialOrganizations,
            activeSubscriptions,
          },
          recentActivity: {
            newOrganizationsThisMonth,
            pendingSubscriptionRequests,
            pendingReactivationRequests,
          },
          revenueStats: {
            monthlyRevenue: Math.round(totalMonthlyRevenue),
            yearlyRevenue: Math.round(totalYearlyRevenue),
            currency: "BDT",
          },
        },
      });
    } catch (error) {
      logger.error("Error fetching super admin dashboard:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch dashboard data",
        error: error.message,
      });
    }
  }
);

// 1.2 GET /super-admin/analytics - Growth and usage analytics
app.get(
  "/super-admin/analytics",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { period = "30days" } = req.query;

      // Calculate date range
      const now = new Date();
      let startDate;
      if (period === "90days") {
        startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
      } else if (period === "1year") {
        startDate = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
      } else {
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      }

      // Organization Growth (aggregated by month)
      const orgGrowth = await organizationsCollection
        .aggregate([
          { $match: { createdAt: { $gte: startDate } } },
          {
            $group: {
              _id: {
                year: { $year: "$createdAt" },
                month: { $month: "$createdAt" },
              },
              count: { $sum: 1 },
            },
          },
          { $sort: { "_id.year": 1, "_id.month": 1 } },
        ])
        .toArray();

      const organizationGrowth = orgGrowth.map((item, index, arr) => {
        const month = `${item._id.year}-${String(item._id.month).padStart(
          2,
          "0"
        )}`;
        const change =
          index > 0
            ? `${(
                ((item.count - arr[index - 1].count) / arr[index - 1].count) *
                100
              ).toFixed(0)}%`
            : "N/A";
        return { month, count: item.count, change };
      });

      // Tier Distribution
      const tierCounts = await subscriptionsCollection
        .aggregate([
          { $group: { _id: "$tier", count: { $sum: 1 } } },
        ])
        .toArray();

      const total = tierCounts.reduce((sum, t) => sum + t.count, 0);
      const tierDistribution = {};
      ["free", "basic", "professional", "enterprise"].forEach((tier) => {
        const found = tierCounts.find((t) => t._id === tier);
        const count = found ? found.count : 0;
        tierDistribution[tier] = {
          count,
          percentage: total > 0 ? Math.round((count / total) * 100) : 0,
        };
      });

      // Usage Trends
      const orgs = await organizationsCollection
        .find({}, { projection: { usage: 1 } })
        .toArray();

      const averageStudentsPerOrg =
        orgs.length > 0
          ? Math.round(
              orgs.reduce(
                (sum, org) => sum + (org.usage?.currentStudents || 0),
                0
              ) / orgs.length
            )
          : 0;
      const averageTeachersPerOrg =
        orgs.length > 0
          ? Math.round(
              orgs.reduce(
                (sum, org) => sum + (org.usage?.currentTeachers || 0),
                0
              ) / orgs.length
            )
          : 0;
      const averageClassesPerOrg =
        orgs.length > 0
          ? Math.round(
              orgs.reduce(
                (sum, org) => sum + (org.usage?.currentClasses || 0),
                0
              ) / orgs.length
            )
          : 0;

      res.json({
        success: true,
        data: {
          growthMetrics: {
            organizationGrowth,
          },
          tierDistribution,
          usageTrends: {
            averageStudentsPerOrg,
            averageTeachersPerOrg,
            averageClassesPerOrg,
          },
        },
      });
    } catch (error) {
      logger.error("Error fetching analytics:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch analytics",
        error: error.message,
      });
    }
  }
);

// 1.3 GET /super-admin/feature-usage - Feature adoption metrics
app.get(
  "/super-admin/feature-usage",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const totalOrgs = await organizationsCollection.countDocuments({});

      const [
        attendanceOrgs,
        examsOrgs,
        feesOrgs,
        announcementsOrgs,
      ] = await Promise.all([
        attendanceCollection.distinct("organizationId"),
        examsCollection.distinct("organizationId"),
        paymentsCollection.distinct("organizationId"),
        announcementsCollection.distinct("organizationId"),
      ]);

      const featureUsage = {
        attendance: {
          orgCount: attendanceOrgs.length,
          usagePercentage:
            totalOrgs > 0
              ? Math.round((attendanceOrgs.length / totalOrgs) * 100)
              : 0,
        },
        exams: {
          orgCount: examsOrgs.length,
          usagePercentage:
            totalOrgs > 0 ? Math.round((examsOrgs.length / totalOrgs) * 100) : 0,
        },
        fees: {
          orgCount: feesOrgs.length,
          usagePercentage:
            totalOrgs > 0 ? Math.round((feesOrgs.length / totalOrgs) * 100) : 0,
        },
        announcements: {
          orgCount: announcementsOrgs.length,
          usagePercentage:
            totalOrgs > 0
              ? Math.round((announcementsOrgs.length / totalOrgs) * 100)
              : 0,
        },
      };

      res.json({
        success: true,
        data: { featureUsage },
      });
    } catch (error) {
      logger.error("Error fetching feature usage:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch feature usage",
        error: error.message,
      });
    }
  }
);

// 1.4 GET /super-admin/activity-logs - Platform-wide activity logs
app.get(
  "/super-admin/activity-logs",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const {
        organizationId,
        userId,
        action,
        resource,
        startDate,
        endDate,
        isSuperAdminAction,
        page = 1,
        limit = 50,
      } = req.query;

      const query = {};

      if (organizationId) {
        query.organizationId = new ObjectId(organizationId);
      }
      if (userId) {
        query.userId = new ObjectId(userId);
      }
      if (action) {
        query.action = action;
      }
      if (resource) {
        query.resource = resource;
      }
      if (isSuperAdminAction !== undefined) {
        query.isSuperAdminAction = isSuperAdminAction === "true";
      }
      if (startDate || endDate) {
        query.createdAt = {};
        if (startDate) {
          query.createdAt.$gte = new Date(startDate);
        }
        if (endDate) {
          query.createdAt.$lte = new Date(endDate);
        }
      }

      const skip = (Number(page) - 1) * Number(limit);

      const [logs, total] = await Promise.all([
        activityLogsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(Number(limit))
          .toArray(),
        activityLogsCollection.countDocuments(query),
      ]);

      // Enrich with organization names
      const enrichedLogs = await Promise.all(
        logs.map(async (log) => {
          if (log.organizationId) {
            const org = await organizationsCollection.findOne(
              { _id: log.organizationId },
              { projection: { name: 1 } }
            );
            return { ...log, organizationName: org?.name || "Unknown" };
          }
          return { ...log, organizationName: "Platform" };
        })
      );

      res.json({
        success: true,
        data: enrichedLogs,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching super admin activity logs:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch activity logs",
        error: error.message,
      });
    }
  }
);

// 1.5 POST /super-admin/announcements - Create platform-wide announcement
app.post(
  "/super-admin/announcements",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { title, message, priority = "normal", expiresAt } = req.body;

      if (!title || !message) {
        return res.status(400).json({
          success: false,
          message: "Title and message are required",
        });
      }

      if (
        priority &&
        !["low", "normal", "high", "urgent"].includes(priority)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid priority. Must be: low, normal, high, or urgent",
        });
      }

      const announcement = {
        organizationId: null, // Platform-wide
        title,
        message,
        target: "platform",
        targetId: null,
        targetRole: null,
        priority,
        createdBy: req.userId,
        isActive: true,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await announcementsCollection.insertOne(announcement);

      // Send notifications to all active organization users
      const activeOrgs = await organizationsCollection
        .find({ status: "active" }, { projection: { _id: 1 } })
        .toArray();
      const orgIds = activeOrgs.map((org) => org._id);

      const allUsers = await usersCollection
        .find(
          { organizationId: { $in: orgIds }, status: "active" },
          { projection: { _id: 1 } }
        )
        .toArray();

      if (allUsers.length > 0) {
        await createBulkNotifications(
          allUsers.map((u) => u._id),
          null, // organizationId is null for platform announcements
          "platform_announcement",
          title,
          message,
          { announcementId: result.insertedId }
        );
      }

      await logActivity(
        req.userId,
        null,
        "created",
        "platform_announcement",
        result.insertedId,
        { after: announcement },
        req
      );

      res.status(201).json({
        success: true,
        message: "Platform announcement created successfully",
        data: { _id: result.insertedId, ...announcement },
      });
    } catch (error) {
      logger.error("Error creating platform announcement:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to create platform announcement",
        error: error.message,
      });
    }
  }
);

// GROUP 2: Organization Management

// 2.1 GET /super-admin/organizations - List all organizations
app.get(
  "/super-admin/organizations",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const {
        status,
        subscriptionTier,
        search,
        page = 1,
        limit = 20,
      } = req.query;

      const query = {};

      if (status) {
        query.status = status;
      }
      if (subscriptionTier) {
        query.subscriptionTier = subscriptionTier;
      }
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
          { slug: { $regex: search, $options: "i" } },
        ];
      }

      const skip = (Number(page) - 1) * Number(limit);

      const [orgs, total] = await Promise.all([
        organizationsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(Number(limit))
          .toArray(),
        organizationsCollection.countDocuments(query),
      ]);

      // Enrich with owner and subscription data
      const enrichedOrgs = await Promise.all(
        orgs.map(async (org) => {
          const [owner, subscription] = await Promise.all([
            usersCollection.findOne(
              { _id: org.ownerId },
              { projection: { name: 1, email: 1 } }
            ),
            subscriptionsCollection.findOne({ organizationId: org._id }),
          ]);

          const usagePercentages = {
            students:
              org.limits?.maxStudents > 0
                ? Math.round(
                    ((org.usage?.currentStudents || 0) /
                      org.limits.maxStudents) *
                      100
                  )
                : 0,
            classes:
              org.limits?.maxClasses > 0
                ? Math.round(
                    ((org.usage?.currentClasses || 0) /
                      org.limits.maxClasses) *
                      100
                  )
                : 0,
            teachers:
              org.limits?.maxTeachers > 0
                ? Math.round(
                    ((org.usage?.currentTeachers || 0) /
                      org.limits.maxTeachers) *
                      100
                  )
                : 0,
          };

          return {
            ...org,
            ownerName: owner?.name || "Unknown",
            ownerEmail: owner?.email || "Unknown",
            subscriptionStatus: subscription?.status || "N/A",
            usagePercentages,
          };
        })
      );

      res.json({
        success: true,
        data: enrichedOrgs,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching organizations:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch organizations",
        error: error.message,
      });
    }
  }
);

// 2.2 GET /super-admin/organizations/:id - Get detailed organization info
app.get(
  "/super-admin/organizations/:id",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const org = await organizationsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!org) {
        return res.status(404).json({
          success: false,
          message: "Organization not found",
        });
      }

      const [owner, subscription, plan] = await Promise.all([
        usersCollection.findOne(
          { _id: org.ownerId },
          { projection: { name: 1, email: 1, phone: 1, lastLogin: 1 } }
        ),
        subscriptionsCollection.findOne({ organizationId: org._id }),
        subscriptionPlansCollection.findOne({
          tier: org.subscriptionTier,
        }),
      ]);

      const [
        totalUsers,
        totalStudents,
        totalTeachers,
        totalClasses,
        recentActivity,
      ] = await Promise.all([
        usersCollection.countDocuments({ organizationId: org._id }),
        studentsCollection.countDocuments({ organizationId: org._id }),
        teachersCollection.countDocuments({ organizationId: org._id }),
        classesCollection.countDocuments({ organizationId: org._id }),
        activityLogsCollection
          .find({ organizationId: org._id })
          .sort({ createdAt: -1 })
          .limit(10)
          .toArray(),
      ]);

      const usagePercentages = {
        students:
          org.limits?.maxStudents > 0 && org.limits.maxStudents !== -1
            ? Math.round(
                ((org.usage?.currentStudents || 0) / org.limits.maxStudents) *
                  100
              )
            : 0,
        classes:
          org.limits?.maxClasses > 0 && org.limits.maxClasses !== -1
            ? Math.round(
                ((org.usage?.currentClasses || 0) / org.limits.maxClasses) *
                  100
              )
            : 0,
        teachers:
          org.limits?.maxTeachers > 0 && org.limits.maxTeachers !== -1
            ? Math.round(
                ((org.usage?.currentTeachers || 0) / org.limits.maxTeachers) *
                  100
              )
            : 0,
        storage:
          org.limits?.maxStorage > 0
            ? Math.round(
                ((org.usage?.storageUsed || 0) / org.limits.maxStorage) * 100
              )
            : 0,
      };

      res.json({
        success: true,
        data: {
          organization: org,
          owner,
          subscription: subscription
            ? { ...subscription, planDetails: plan }
            : null,
          statistics: {
            totalUsers,
            totalStudents,
            totalTeachers,
            totalClasses,
            usagePercentages,
          },
          recentActivity,
        },
      });
    } catch (error) {
      logger.error("Error fetching organization details:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch organization details",
        error: error.message,
      });
    }
  }
);

// 2.3 PATCH /super-admin/organizations/:id - Update organization
app.patch(
  "/super-admin/organizations/:id",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, email, phone, address, status, settings, branding } =
        req.body;

      const org = await organizationsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!org) {
        return res.status(404).json({
          success: false,
          message: "Organization not found",
        });
      }

      const updates = { updatedAt: new Date() };

      if (name !== undefined) updates.name = name;
      if (email !== undefined) updates.email = email;
      if (phone !== undefined) updates.phone = phone;
      if (address !== undefined) updates.address = address;
      if (status !== undefined) updates.status = status;
      if (settings !== undefined) updates.settings = settings;
      if (branding !== undefined) updates.branding = branding;

      const result = await organizationsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      await logActivity(
        req.userId,
        null,
        "updated",
        "organization",
        id,
        { before: org, after: updates },
        req
      );

      res.json({
        success: true,
        message: "Organization updated successfully",
        data: { ...org, ...updates },
      });
    } catch (error) {
      logger.error("Error updating organization:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update organization",
        error: error.message,
      });
    }
  }
);

// 2.4 POST /super-admin/organizations/:id/suspend - Suspend organization
app.post(
  "/super-admin/organizations/:id/suspend",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { reason, notifyOwner = true } = req.body;

      if (!reason) {
        return res.status(400).json({
          success: false,
          message: "Suspension reason is required",
        });
      }

      const org = await organizationsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!org) {
        return res.status(404).json({
          success: false,
          message: "Organization not found",
        });
      }

      if (org.status === "suspended") {
        return res.status(400).json({
          success: false,
          message: "Organization is already suspended",
        });
      }

      // Update organization
      await organizationsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: "suspended",
            suspensionReason: reason,
            suspendedAt: new Date(),
            updatedAt: new Date(),
          },
        }
      );

      // Update subscription
      await subscriptionsCollection.updateOne(
        { organizationId: new ObjectId(id) },
        { $set: { status: "suspended", updatedAt: new Date() } }
      );

      // Notify owner
      if (notifyOwner && org.ownerId) {
        await createNotification(
          org.ownerId,
          org._id,
          "organization_suspended",
          "Organization Suspended",
          `Your organization has been suspended. Reason: ${reason}`,
          { reason }
        );
      }

      await logActivity(
        req.userId,
        null,
        "suspended",
        "organization",
        id,
        { reason },
        req
      );

      res.json({
        success: true,
        message: "Organization suspended successfully",
      });
    } catch (error) {
      logger.error("Error suspending organization:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to suspend organization",
        error: error.message,
      });
    }
  }
);

// 2.5 POST /super-admin/organizations/:id/reactivate - Reactivate organization
app.post(
  "/super-admin/organizations/:id/reactivate",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { comment } = req.body;

      const org = await organizationsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!org) {
        return res.status(404).json({
          success: false,
          message: "Organization not found",
        });
      }

      if (org.status !== "suspended") {
        return res.status(400).json({
          success: false,
          message: "Organization is not suspended",
        });
      }

      // Update organization
      await organizationsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: "active",
            suspensionReason: null,
            suspendedAt: null,
            updatedAt: new Date(),
          },
        }
      );

      // Update subscription
      await subscriptionsCollection.updateOne(
        { organizationId: new ObjectId(id) },
        { $set: { status: "active", updatedAt: new Date() } }
      );

      // Notify owner
      if (org.ownerId) {
        await createNotification(
          org.ownerId,
          org._id,
          "organization_reactivated",
          "Organization Reactivated",
          `Your organization has been reactivated.${
            comment ? ` Comment: ${comment}` : ""
          }`,
          { comment }
        );
      }

      await logActivity(
        req.userId,
        null,
        "reactivated",
        "organization",
        id,
        { comment },
        req
      );

      res.json({
        success: true,
        message: "Organization reactivated successfully",
      });
    } catch (error) {
      logger.error("Error reactivating organization:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to reactivate organization",
        error: error.message,
      });
    }
  }
);

// 2.6 POST /super-admin/organizations/:id/override-limits - Override usage limits
app.post(
  "/super-admin/organizations/:id/override-limits",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { maxStudents, maxClasses, maxTeachers, maxStorage, reason } =
        req.body;

      if (!reason) {
        return res.status(400).json({
          success: false,
          message: "Reason is required for overriding limits",
        });
      }

      if (
        maxStudents === undefined &&
        maxClasses === undefined &&
        maxTeachers === undefined &&
        maxStorage === undefined
      ) {
        return res.status(400).json({
          success: false,
          message: "At least one limit must be provided",
        });
      }

      const org = await organizationsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!org) {
        return res.status(404).json({
          success: false,
          message: "Organization not found",
        });
      }

      const newLimits = { ...org.limits };

      if (maxStudents !== undefined) newLimits.maxStudents = maxStudents;
      if (maxClasses !== undefined) newLimits.maxClasses = maxClasses;
      if (maxTeachers !== undefined) newLimits.maxTeachers = maxTeachers;
      if (maxStorage !== undefined) newLimits.maxStorage = maxStorage;

      await organizationsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { limits: newLimits, updatedAt: new Date() } }
      );

      // Notify owner
      if (org.ownerId) {
        await createNotification(
          org.ownerId,
          org._id,
          "limits_overridden",
          "Usage Limits Updated",
          `Your organization's usage limits have been updated. ${reason}`,
          { limits: newLimits, reason }
        );
      }

      await logActivity(
        req.userId,
        null,
        "updated",
        "organization_limits",
        id,
        { before: org.limits, after: newLimits, reason },
        req
      );

      res.json({
        success: true,
        message: "Usage limits overridden successfully",
        data: { limits: newLimits },
      });
    } catch (error) {
      logger.error("Error overriding limits:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to override limits",
        error: error.message,
      });
    }
  }
);

// 2.7 DELETE /super-admin/organizations/:id - Delete organization permanently
app.delete(
  "/super-admin/organizations/:id",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { confirmation, deleteAllData = false } = req.body;

      const org = await organizationsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!org) {
        return res.status(404).json({
          success: false,
          message: "Organization not found",
        });
      }

      if (confirmation !== org.name) {
        return res.status(400).json({
          success: false,
          message:
            "Confirmation failed. Please provide exact organization name.",
        });
      }

      let deletedRecords = 0;

      if (deleteAllData) {
        // Delete all organization data
        const [
          usersDeleted,
          studentsDeleted,
          teachersDeleted,
          parentsDeleted,
          classesDeleted,
          sectionsDeleted,
          subjectsDeleted,
          attendanceDeleted,
          examsDeleted,
          gradesDeleted,
          feesDeleted,
          paymentsDeleted,
          expensesDeleted,
          salariesDeleted,
          announcementsDeleted,
          subscriptionDeleted,
        ] = await Promise.all([
          usersCollection.deleteMany({ organizationId: org._id }),
          studentsCollection.deleteMany({ organizationId: org._id }),
          teachersCollection.deleteMany({ organizationId: org._id }),
          parentsCollection.deleteMany({ organizationId: org._id }),
          classesCollection.deleteMany({ organizationId: org._id }),
          sectionsCollection.deleteMany({ organizationId: org._id }),
          subjectsCollection.deleteMany({ organizationId: org._id }),
          attendanceCollection.deleteMany({ organizationId: org._id }),
          examsCollection.deleteMany({ organizationId: org._id }),
          gradeSubmissionsCollection.deleteMany({ organizationId: org._id }),
          studentMonthlyFeesCollection.deleteMany({ organizationId: org._id }),
          paymentsCollection.deleteMany({ organizationId: org._id }),
          expensesCollection.deleteMany({ organizationId: org._id }),
          salariesCollection.deleteMany({ organizationId: org._id }),
          announcementsCollection.deleteMany({ organizationId: org._id }),
          subscriptionsCollection.deleteMany({ organizationId: org._id }),
        ]);

        deletedRecords =
          usersDeleted.deletedCount +
          studentsDeleted.deletedCount +
          teachersDeleted.deletedCount +
          parentsDeleted.deletedCount +
          classesDeleted.deletedCount +
          sectionsDeleted.deletedCount +
          subjectsDeleted.deletedCount +
          attendanceDeleted.deletedCount +
          examsDeleted.deletedCount +
          gradesDeleted.deletedCount +
          feesDeleted.deletedCount +
          paymentsDeleted.deletedCount +
          expensesDeleted.deletedCount +
          salariesDeleted.deletedCount +
          announcementsDeleted.deletedCount +
          subscriptionDeleted.deletedCount;
      }

      // Delete organization
      await organizationsCollection.deleteOne({ _id: new ObjectId(id) });

      await logActivity(
        req.userId,
        null,
        "deleted",
        "organization",
        id,
        { before: org, deleteAllData, deletedRecords },
        req
      );

      res.json({
        success: true,
        message: "Organization and all data permanently deleted",
        deletedRecords,
      });
    } catch (error) {
      logger.error("Error deleting organization:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to delete organization",
        error: error.message,
      });
    }
  }
);

// 2.8 GET /super-admin/organizations/:id/users - List users in organization
app.get(
  "/super-admin/organizations/:id/users",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role, status, page = 1, limit = 20 } = req.query;

      const query = { organizationId: new ObjectId(id) };

      if (role) query.role = role;
      if (status) query.status = status;

      const skip = (Number(page) - 1) * Number(limit);

      const [users, total] = await Promise.all([
        usersCollection
          .find(query)
          .project({ password: 0 })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(Number(limit))
          .toArray(),
        usersCollection.countDocuments(query),
      ]);

      res.json({
        success: true,
        data: users,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching organization users:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch organization users",
        error: error.message,
      });
    }
  }
);

// GROUP 3: User Management

// 3.1 GET /super-admin/users - List all users across all organizations
app.get(
  "/super-admin/users",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const {
        organizationId,
        role,
        status,
        search,
        page = 1,
        limit = 20,
      } = req.query;

      const query = {};

      if (organizationId) {
        query.organizationId = new ObjectId(organizationId);
      }
      if (role) query.role = role;
      if (status) query.status = status;
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
          { phone: { $regex: search, $options: "i" } },
        ];
      }

      const skip = (Number(page) - 1) * Number(limit);

      const [users, total] = await Promise.all([
        usersCollection
          .find(query)
          .project({ password: 0 })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(Number(limit))
          .toArray(),
        usersCollection.countDocuments(query),
      ]);

      // Enrich with organization names
      const enrichedUsers = await Promise.all(
        users.map(async (user) => {
          if (user.organizationId) {
            const org = await organizationsCollection.findOne(
              { _id: user.organizationId },
              { projection: { name: 1, slug: 1 } }
            );
            return { ...user, organizationName: org?.name || "Unknown" };
          }
          return { ...user, organizationName: "Platform" };
        })
      );

      res.json({
        success: true,
        data: enrichedUsers,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching users:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch users",
        error: error.message,
      });
    }
  }
);

// 3.2 GET /super-admin/users/:id - Get detailed user info
app.get(
  "/super-admin/users/:id",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const user = await usersCollection.findOne(
        { _id: new ObjectId(id) },
        { projection: { password: 0 } }
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      const data = { user };

      // Get organization if applicable
      if (user.organizationId) {
        data.organization = await organizationsCollection.findOne(
          { _id: user.organizationId },
          { projection: { name: 1, slug: 1, email: 1 } }
        );
      }

      // Get role-specific profile
      if (user.role === "student") {
        data.studentProfile = await studentsCollection.findOne({
          userId: user._id,
        });
      } else if (user.role === "teacher") {
        data.teacherProfile = await teachersCollection.findOne({
          userId: user._id,
        });
      } else if (user.role === "parent") {
        const parent = await parentsCollection.findOne({ userId: user._id });
        if (parent && parent.children && parent.children.length > 0) {
          const childrenData = await studentsCollection
            .find({ _id: { $in: parent.children } })
            .project({ _id: 1, userId: 1 })
            .toArray();
          const childUserIds = childrenData.map((c) => c.userId);
          const childUsers = await usersCollection
            .find({ _id: { $in: childUserIds } })
            .project({ name: 1 })
            .toArray();
          data.parentProfile = {
            ...parent,
            childrenNames: childUsers.map((u) => u.name),
          };
        } else {
          data.parentProfile = parent;
        }
      }

      // Activity summary
      const [totalActions, recentActivity] = await Promise.all([
        activityLogsCollection.countDocuments({ userId: user._id }),
        activityLogsCollection
          .find({ userId: user._id })
          .sort({ createdAt: -1 })
          .limit(5)
          .toArray(),
      ]);

      data.activitySummary = {
        lastLogin: user.lastLogin,
        totalActions,
        recentActivity,
      };

      res.json({
        success: true,
        data,
      });
    } catch (error) {
      logger.error("Error fetching user details:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch user details",
        error: error.message,
      });
    }
  }
);

// 3.3 PATCH /super-admin/users/:id/role - Change user role
app.patch(
  "/super-admin/users/:id/role",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role, reason } = req.body;

      if (!role || !reason) {
        return res.status(400).json({
          success: false,
          message: "Role and reason are required",
        });
      }

      const validRoles = [
        "org_owner",
        "admin",
        "moderator",
        "teacher",
        "student",
        "parent",
      ];
      if (!validRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          message: `Invalid role. Must be one of: ${validRoles.join(", ")}`,
        });
      }

      const user = await usersCollection.findOne({ _id: new ObjectId(id) });

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      if (user.role === "super_admin" || user.isSuperAdmin) {
        return res.status(403).json({
          success: false,
          message: "Cannot change role to/from super_admin",
        });
      }

      const newPermissions = ROLE_PERMISSIONS[role] || [];

      await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            role,
            permissions: newPermissions,
            updatedAt: new Date(),
          },
        }
      );

      // Notify user
      await createNotification(
        user._id,
        user.organizationId,
        "role_changed",
        "Your Role Has Changed",
        `Your role has been changed to ${role}. Reason: ${reason}`,
        { newRole: role, reason }
      );

      await logActivity(
        req.userId,
        null,
        "updated",
        "user_role",
        id,
        { before: user.role, after: role, reason },
        req
      );

      res.json({
        success: true,
        message: "User role updated successfully",
        data: { role, permissions: newPermissions },
      });
    } catch (error) {
      logger.error("Error changing user role:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to change user role",
        error: error.message,
      });
    }
  }
);

// 3.4 PATCH /super-admin/users/:id/status - Change user status
app.patch(
  "/super-admin/users/:id/status",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status, reason } = req.body;

      if (!status || !reason) {
        return res.status(400).json({
          success: false,
          message: "Status and reason are required",
        });
      }

      const validStatuses = ["active", "inactive", "suspended"];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: `Invalid status. Must be one of: ${validStatuses.join(
            ", "
          )}`,
        });
      }

      const user = await usersCollection.findOne({ _id: new ObjectId(id) });

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status, updatedAt: new Date() } }
      );

      // Notify user if suspended
      if (status === "suspended") {
        await createNotification(
          user._id,
          user.organizationId,
          "account_suspended",
          "Account Suspended",
          `Your account has been suspended. Reason: ${reason}`,
          { reason }
        );
      }

      await logActivity(
        req.userId,
        null,
        "updated",
        "user_status",
        id,
        { before: user.status, after: status, reason },
        req
      );

      res.json({
        success: true,
        message: "User status updated successfully",
        data: { status },
      });
    } catch (error) {
      logger.error("Error changing user status:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to change user status",
        error: error.message,
      });
    }
  }
);

// GROUP 4: Subscription Management

// 4.1 GET /super-admin/subscriptions - List all subscriptions
app.get(
  "/super-admin/subscriptions",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const {
        tier,
        status,
        billingCycle,
        organizationId,
        page = 1,
        limit = 20,
      } = req.query;

      const query = {};

      if (tier) query.tier = tier;
      if (status) query.status = status;
      if (billingCycle) query.billingCycle = billingCycle;
      if (organizationId) {
        query.organizationId = new ObjectId(organizationId);
      }

      const skip = (Number(page) - 1) * Number(limit);

      const [subscriptions, total] = await Promise.all([
        subscriptionsCollection
          .find(query)
          .sort({ nextBillingDate: 1 })
          .skip(skip)
          .limit(Number(limit))
          .toArray(),
        subscriptionsCollection.countDocuments(query),
      ]);

      // Enrich with organization and owner data
      const enrichedSubs = await Promise.all(
        subscriptions.map(async (sub) => {
          const org = await organizationsCollection.findOne(
            { _id: sub.organizationId },
            { projection: { name: 1, slug: 1 } }
          );
          const owner = org
            ? await usersCollection.findOne(
                { _id: org.ownerId },
                { projection: { email: 1 } }
              )
            : null;

          return {
            ...sub,
            organizationName: org?.name || "Unknown",
            ownerEmail: owner?.email || "Unknown",
            revenueContribution: sub.amount || 0,
          };
        })
      );

      res.json({
        success: true,
        data: enrichedSubs,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching subscriptions:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch subscriptions",
        error: error.message,
      });
    }
  }
);

// 4.2 GET /super-admin/subscriptions/:id - Get detailed subscription info
app.get(
  "/super-admin/subscriptions/:id",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const subscription = await subscriptionsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!subscription) {
        return res.status(404).json({
          success: false,
          message: "Subscription not found",
        });
      }

      const [plan, org] = await Promise.all([
        subscriptionPlansCollection.findOne({ tier: subscription.tier }),
        organizationsCollection.findOne(
          { _id: subscription.organizationId },
          { projection: { name: 1, email: 1, slug: 1 } }
        ),
      ]);

      res.json({
        success: true,
        data: {
          subscription,
          plan,
          organization: org,
          billingHistory: [], // Not implemented in Phase 1
        },
      });
    } catch (error) {
      logger.error("Error fetching subscription details:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch subscription details",
        error: error.message,
      });
    }
  }
);

// 4.3 PATCH /super-admin/subscriptions/:id - Update subscription
app.patch(
  "/super-admin/subscriptions/:id",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        tier,
        status,
        billingCycle,
        currentPeriodEnd,
        nextBillingDate,
        cancelAtPeriodEnd,
      } = req.body;

      const subscription = await subscriptionsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!subscription) {
        return res.status(404).json({
          success: false,
          message: "Subscription not found",
        });
      }

      const updates = { updatedAt: new Date() };

      // If tier changed, update org limits
      if (tier && tier !== subscription.tier) {
        const plan = await subscriptionPlansCollection.findOne({ tier });
        if (!plan) {
          return res.status(400).json({
            success: false,
            message: "Invalid tier",
          });
        }

        await organizationsCollection.updateOne(
          { _id: subscription.organizationId },
          {
            $set: {
              subscriptionTier: tier,
              limits: plan.limits,
              updatedAt: new Date(),
            },
          }
        );

        updates.tier = tier;
        updates.amount =
          billingCycle === "yearly" ? plan.yearlyPrice : plan.monthlyPrice;
      }

      if (status !== undefined) updates.status = status;
      if (billingCycle !== undefined) updates.billingCycle = billingCycle;
      if (currentPeriodEnd !== undefined)
        updates.currentPeriodEnd = new Date(currentPeriodEnd);
      if (nextBillingDate !== undefined)
        updates.nextBillingDate = new Date(nextBillingDate);
      if (cancelAtPeriodEnd !== undefined)
        updates.cancelAtPeriodEnd = cancelAtPeriodEnd;

      await subscriptionsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      await logActivity(
        req.userId,
        null,
        "updated",
        "subscription",
        id,
        { before: subscription, after: updates },
        req
      );

      res.json({
        success: true,
        message: "Subscription updated successfully",
        data: { ...subscription, ...updates },
      });
    } catch (error) {
      logger.error("Error updating subscription:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update subscription",
        error: error.message,
      });
    }
  }
);

// 4.4 GET /super-admin/subscription-requests - List pending subscription requests
app.get(
  "/super-admin/subscription-requests",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const {
        status = "pending",
        requestedTier,
        page = 1,
        limit = 20,
      } = req.query;

      const query = {};

      if (status) query.status = status;
      if (requestedTier) query.requestedTier = requestedTier;

      const skip = (Number(page) - 1) * Number(limit);

      const [requests, total] = await Promise.all([
        subscriptionRequestsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(Number(limit))
          .toArray(),
        subscriptionRequestsCollection.countDocuments(query),
      ]);

      // Enrich with organization and user data
      const enrichedRequests = await Promise.all(
        requests.map(async (req) => {
          const [org, user] = await Promise.all([
            organizationsCollection.findOne(
              { _id: req.organizationId },
              { projection: { name: 1 } }
            ),
            usersCollection.findOne(
              { _id: req.requestedBy },
              { projection: { name: 1 } }
            ),
          ]);

          return {
            ...req,
            organizationName: org?.name || "Unknown",
            requestedByName: user?.name || "Unknown",
          };
        })
      );

      res.json({
        success: true,
        data: enrichedRequests,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching subscription requests:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch subscription requests",
        error: error.message,
      });
    }
  }
);

// 4.5 POST /super-admin/subscription-requests/:id/approve - Approve subscription request
app.post(
  "/super-admin/subscription-requests/:id/approve",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { comment, effectiveDate } = req.body;

      const request = await subscriptionRequestsCollection.findOneAndUpdate(
        { _id: new ObjectId(id), status: "pending" },
        {
          $set: {
            status: "approved",
            reviewedBy: req.userId,
            reviewedAt: new Date(),
            comment: comment || null,
          },
        },
        { returnDocument: "after" }
      );

      if (!request) {
        return res.status(400).json({
          success: false,
          message: "Request already processed or not found",
        });
      }

      // Fetch new plan
      const plan = await subscriptionPlansCollection.findOne({
        tier: request.requestedTier,
      });

      if (!plan) {
        return res.status(400).json({
          success: false,
          message: "Invalid requested tier",
        });
      }

      const effective = effectiveDate ? new Date(effectiveDate) : new Date();
      const periodEnd = new Date(effective);
      if (request.requestedBillingCycle === "yearly") {
        periodEnd.setFullYear(periodEnd.getFullYear() + 1);
      } else {
        periodEnd.setMonth(periodEnd.getMonth() + 1);
      }

      // Update organization
      await organizationsCollection.updateOne(
        { _id: request.organizationId },
        {
          $set: {
            subscriptionTier: request.requestedTier,
            limits: plan.limits,
            updatedAt: new Date(),
          },
        }
      );

      // Update subscription
      await subscriptionsCollection.updateOne(
        { organizationId: request.organizationId },
        {
          $set: {
            tier: request.requestedTier,
            status: "active",
            billingCycle: request.requestedBillingCycle,
            amount:
              request.requestedBillingCycle === "yearly"
                ? plan.yearlyPrice
                : plan.monthlyPrice,
            currentPeriodStart: effective,
            currentPeriodEnd: periodEnd,
            nextBillingDate: periodEnd,
            updatedAt: new Date(),
          },
        }
      );

      // Notify org owner
      const org = await organizationsCollection.findOne({
        _id: request.organizationId,
      });
      if (org && org.ownerId) {
        await createNotification(
          org.ownerId,
          org._id,
          "subscription_approved",
          "Subscription Request Approved",
          `Your subscription request to ${request.requestedTier} has been approved.${
            comment ? ` Comment: ${comment}` : ""
          }`,
          { tier: request.requestedTier, comment }
        );
      }

      await logActivity(
        req.userId,
        null,
        "approved",
        "subscription_request",
        id,
        { request, comment },
        req
      );

      res.json({
        success: true,
        message: "Subscription request approved successfully",
      });
    } catch (error) {
      logger.error("Error approving subscription request:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to approve subscription request",
        error: error.message,
      });
    }
  }
);

// 4.6 POST /super-admin/subscription-requests/:id/reject - Reject subscription request
app.post(
  "/super-admin/subscription-requests/:id/reject",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { reason } = req.body;

      if (!reason) {
        return res.status(400).json({
          success: false,
          message: "Rejection reason is required",
        });
      }

      const request = await subscriptionRequestsCollection.findOneAndUpdate(
        { _id: new ObjectId(id), status: "pending" },
        {
          $set: {
            status: "rejected",
            reviewedBy: req.userId,
            reviewedAt: new Date(),
            rejectionReason: reason,
          },
        },
        { returnDocument: "after" }
      );

      if (!request) {
        return res.status(400).json({
          success: false,
          message: "Request already processed or not found",
        });
      }

      // Notify org owner
      const org = await organizationsCollection.findOne({
        _id: request.organizationId,
      });
      if (org && org.ownerId) {
        await createNotification(
          org.ownerId,
          org._id,
          "subscription_rejected",
          "Subscription Request Rejected",
          `Your subscription request to ${request.requestedTier} has been rejected. Reason: ${reason}`,
          { tier: request.requestedTier, reason }
        );
      }

      await logActivity(
        req.userId,
        null,
        "rejected",
        "subscription_request",
        id,
        { request, reason },
        req
      );

      res.json({
        success: true,
        message: "Subscription request rejected",
      });
    } catch (error) {
      logger.error("Error rejecting subscription request:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to reject subscription request",
        error: error.message,
      });
    }
  }
);

// 4.7 POST /super-admin/subscriptions/:id/extend-trial - Extend trial period
app.post(
  "/super-admin/subscriptions/:id/extend-trial",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { days, reason } = req.body;

      if (!days || !reason) {
        return res.status(400).json({
          success: false,
          message: "Days and reason are required",
        });
      }

      if (days < 1 || days > 90) {
        return res.status(400).json({
          success: false,
          message: "Days must be between 1 and 90",
        });
      }

      const subscription = await subscriptionsCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!subscription) {
        return res.status(404).json({
          success: false,
          message: "Subscription not found",
        });
      }

      const extension = days * 24 * 60 * 60 * 1000; // Convert days to milliseconds
      const newTrialEndDate = new Date(
        subscription.trialEndDate.getTime() + extension
      );
      const newPeriodEnd = new Date(
        subscription.currentPeriodEnd.getTime() + extension
      );
      const newBillingDate = new Date(
        subscription.nextBillingDate.getTime() + extension
      );

      await subscriptionsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            trialEndDate: newTrialEndDate,
            currentPeriodEnd: newPeriodEnd,
            nextBillingDate: newBillingDate,
            updatedAt: new Date(),
          },
        }
      );

      // Notify org owner
      const org = await organizationsCollection.findOne({
        _id: subscription.organizationId,
      });
      if (org && org.ownerId) {
        await createNotification(
          org.ownerId,
          org._id,
          "trial_extended",
          "Trial Period Extended",
          `Your trial period has been extended by ${days} days. ${reason}`,
          { days, reason }
        );
      }

      await logActivity(
        req.userId,
        null,
        "extended",
        "trial",
        id,
        { days, reason },
        req
      );

      res.json({
        success: true,
        message: "Trial period extended successfully",
        data: {
          newTrialEndDate,
          newPeriodEnd,
          newBillingDate,
        },
      });
    } catch (error) {
      logger.error("Error extending trial:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to extend trial",
        error: error.message,
      });
    }
  }
);

// GROUP 5: Reactivation Requests

// 5.1 GET /super-admin/reactivation-requests - List reactivation requests
app.get(
  "/super-admin/reactivation-requests",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { status = "pending", page = 1, limit = 20 } = req.query;

      const query = {};
      if (status) query.status = status;

      const skip = (Number(page) - 1) * Number(limit);

      const [requests, total] = await Promise.all([
        reactivationRequestsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(Number(limit))
          .toArray(),
        reactivationRequestsCollection.countDocuments(query),
      ]);

      // Enrich with organization and user data
      const enrichedRequests = await Promise.all(
        requests.map(async (req) => {
          const [org, user] = await Promise.all([
            organizationsCollection.findOne(
              { _id: req.organizationId },
              { projection: { name: 1 } }
            ),
            usersCollection.findOne(
              { _id: req.requestedBy },
              { projection: { name: 1 } }
            ),
          ]);

          return {
            ...req,
            organizationName: org?.name || "Unknown",
            requestedByName: user?.name || "Unknown",
          };
        })
      );

      res.json({
        success: true,
        data: enrichedRequests,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      logger.error("Error fetching reactivation requests:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to fetch reactivation requests",
        error: error.message,
      });
    }
  }
);

// 5.2 POST /super-admin/reactivation-requests/:id/approve - Approve reactivation
app.post(
  "/super-admin/reactivation-requests/:id/approve",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { comment } = req.body;

      const request = await reactivationRequestsCollection.findOneAndUpdate(
        { _id: new ObjectId(id), status: "pending" },
        {
          $set: {
            status: "approved",
            reviewedBy: req.userId,
            reviewedAt: new Date(),
            comment: comment || null,
          },
        },
        { returnDocument: "after" }
      );

      if (!request) {
        return res.status(400).json({
          success: false,
          message: "Request already processed or not found",
        });
      }

      // Update organization
      await organizationsCollection.updateOne(
        { _id: request.organizationId },
        {
          $set: {
            status: "active",
            suspensionReason: null,
            suspendedAt: null,
            updatedAt: new Date(),
          },
        }
      );

      // Update subscription
      await subscriptionsCollection.updateOne(
        { organizationId: request.organizationId },
        { $set: { status: "active", updatedAt: new Date() } }
      );

      // Notify org owner
      const org = await organizationsCollection.findOne({
        _id: request.organizationId,
      });
      if (org && org.ownerId) {
        await createNotification(
          org.ownerId,
          org._id,
          "organization_reactivated",
          "Organization Reactivated",
          `Your organization has been reactivated.${
            comment ? ` Comment: ${comment}` : ""
          }`,
          { comment }
        );
      }

      await logActivity(
        req.userId,
        null,
        "approved",
        "reactivation_request",
        id,
        { request, comment },
        req
      );

      res.json({
        success: true,
        message: "Reactivation request approved successfully",
      });
    } catch (error) {
      logger.error("Error approving reactivation request:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to approve reactivation request",
        error: error.message,
      });
    }
  }
);

// 5.3 POST /super-admin/reactivation-requests/:id/reject - Reject reactivation
app.post(
  "/super-admin/reactivation-requests/:id/reject",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { reason } = req.body;

      if (!reason) {
        return res.status(400).json({
          success: false,
          message: "Rejection reason is required",
        });
      }

      const request = await reactivationRequestsCollection.findOneAndUpdate(
        { _id: new ObjectId(id), status: "pending" },
        {
          $set: {
            status: "rejected",
            reviewedBy: req.userId,
            reviewedAt: new Date(),
            rejectionReason: reason,
          },
        },
        { returnDocument: "after" }
      );

      if (!request) {
        return res.status(400).json({
          success: false,
          message: "Request already processed or not found",
        });
      }

      // Notify org owner
      const org = await organizationsCollection.findOne({
        _id: request.organizationId,
      });
      if (org && org.ownerId) {
        await createNotification(
          org.ownerId,
          org._id,
          "reactivation_rejected",
          "Reactivation Request Rejected",
          `Your reactivation request has been rejected. Reason: ${reason}`,
          { reason }
        );
      }

      await logActivity(
        req.userId,
        null,
        "rejected",
        "reactivation_request",
        id,
        { request, reason },
        req
      );

      res.json({
        success: true,
        message: "Reactivation request rejected",
      });
    } catch (error) {
      logger.error("Error rejecting reactivation request:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to reject reactivation request",
        error: error.message,
      });
    }
  }
);

// GROUP 6: Subscription Plans Management

// 6.1 GET /super-admin/plans - List all subscription plans
app.get(
  "/super-admin/plans",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const plans = await subscriptionPlansCollection
        .find({})
        .sort({ displayOrder: 1 })
        .toArray();

      res.json({
        success: true,
        data: plans,
      });
    } catch (error) {
      logger.error("Error fetching plans:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch plans",
        error: error.message,
      });
    }
  }
);

// 6.2 POST /super-admin/plans - Create new subscription plan
app.post(
  "/super-admin/plans",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const {
        tier,
        name,
        description,
        monthlyPrice,
        yearlyPrice,
        currency = "BDT",
        limits,
        displayOrder,
        isActive = true,
      } = req.body;

      if (!tier || !name || !description || !limits) {
        return res.status(400).json({
          success: false,
          message: "Tier, name, description, and limits are required",
        });
      }

      // Check if tier already exists
      const existing = await subscriptionPlansCollection.findOne({ tier });
      if (existing) {
        return res.status(400).json({
          success: false,
          message: "Plan with this tier already exists",
        });
      }

      const plan = {
        tier,
        name,
        description,
        monthlyPrice: monthlyPrice || 0,
        yearlyPrice: yearlyPrice || 0,
        currency,
        limits,
        displayOrder: displayOrder || 999,
        isActive,
        createdAt: new Date(),
      };

      const result = await subscriptionPlansCollection.insertOne(plan);

      await logActivity(
        req.userId,
        null,
        "created",
        "subscription_plan",
        result.insertedId,
        { after: plan },
        req
      );

      res.status(201).json({
        success: true,
        message: "Subscription plan created successfully",
        data: { _id: result.insertedId, ...plan },
      });
    } catch (error) {
      logger.error("Error creating plan:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to create plan",
        error: error.message,
      });
    }
  }
);

// 6.3 PATCH /super-admin/plans/:id - Update subscription plan
app.patch(
  "/super-admin/plans/:id",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        name,
        description,
        monthlyPrice,
        yearlyPrice,
        currency,
        limits,
        displayOrder,
        isActive,
      } = req.body;

      const plan = await subscriptionPlansCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!plan) {
        return res.status(404).json({
          success: false,
          message: "Plan not found",
        });
      }

      const updates = {};

      if (name !== undefined) updates.name = name;
      if (description !== undefined) updates.description = description;
      if (monthlyPrice !== undefined) updates.monthlyPrice = monthlyPrice;
      if (yearlyPrice !== undefined) updates.yearlyPrice = yearlyPrice;
      if (currency !== undefined) updates.currency = currency;
      if (limits !== undefined) updates.limits = limits;
      if (displayOrder !== undefined) updates.displayOrder = displayOrder;
      if (isActive !== undefined) updates.isActive = isActive;

      await subscriptionPlansCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updates }
      );

      await logActivity(
        req.userId,
        null,
        "updated",
        "subscription_plan",
        id,
        { before: plan, after: updates },
        req
      );

      res.json({
        success: true,
        message: "Subscription plan updated successfully",
        data: { ...plan, ...updates },
      });
    } catch (error) {
      logger.error("Error updating plan:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update plan",
        error: error.message,
      });
    }
  }
);

// 6.4 DELETE /super-admin/plans/:id - Soft delete plan
app.delete(
  "/super-admin/plans/:id",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const plan = await subscriptionPlansCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!plan) {
        return res.status(404).json({
          success: false,
          message: "Plan not found",
        });
      }

      // Check for active subscriptions
      const activeSubscriptions = await subscriptionsCollection.countDocuments({
        tier: plan.tier,
        status: "active",
      });

      if (activeSubscriptions > 0) {
        return res.status(400).json({
          success: false,
          message: `Cannot delete plan with ${activeSubscriptions} active subscriptions`,
        });
      }

      await subscriptionPlansCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { isActive: false } }
      );

      await logActivity(
        req.userId,
        null,
        "deleted",
        "subscription_plan",
        id,
        { before: plan },
        req
      );

      res.json({
        success: true,
        message: "Subscription plan soft deleted successfully",
      });
    } catch (error) {
      logger.error("Error deleting plan:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to delete plan",
        error: error.message,
      });
    }
  }
);

// GROUP 7: Platform Settings

// 7.1 GET /super-admin/settings - Get all platform settings
app.get(
  "/super-admin/settings",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const settings = await platformSettingsCollection.find({}).toArray();

      // Return default settings if none exist
      if (settings.length === 0) {
        const defaultSettings = [
          {
            key: "platform_name",
            value: "RootX School Management System",
            category: "general",
          },
          {
            key: "support_email",
            value: "support@rootx.com",
            category: "contact",
          },
          { key: "trial_days", value: 14, category: "subscription" },
          { key: "smtp_host", value: "smtp.gmail.com", category: "email" },
        ];
        return res.json({ success: true, data: { settings: defaultSettings } });
      }

      res.json({
        success: true,
        data: { settings },
      });
    } catch (error) {
      logger.error("Error fetching settings:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to fetch settings",
        error: error.message,
      });
    }
  }
);

// 7.2 PATCH /super-admin/settings - Update platform settings
app.patch(
  "/super-admin/settings",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { settings } = req.body;

      if (!settings || !Array.isArray(settings)) {
        return res.status(400).json({
          success: false,
          message: "Settings array is required",
        });
      }

      const updates = [];

      for (const setting of settings) {
        const { key, value } = setting;
        if (!key) continue;

        const category = setting.category || "general";

        await platformSettingsCollection.updateOne(
          { key },
          {
            $set: {
              value,
              category,
              updatedAt: new Date(),
            },
          },
          { upsert: true }
        );

        updates.push({ key, value, category });
      }

      await logActivity(
        req.userId,
        null,
        "updated",
        "platform_settings",
        null,
        { settings: updates },
        req
      );

      res.json({
        success: true,
        message: "Platform settings updated successfully",
        data: { settings: updates },
      });
    } catch (error) {
      logger.error("Error updating settings:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to update settings",
        error: error.message,
      });
    }
  }
);

// GROUP 8: Platform Reports & CSV Export

// 8.1 GET /super-admin/reports - Generate platform reports
app.get(
  "/super-admin/reports",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { reportType = "organizations" } = req.query;

      let reportData = {};

      if (reportType === "organizations") {
        // Organization stats by tier
        const tierStats = await subscriptionsCollection
          .aggregate([
            {
              $group: {
                _id: "$tier",
                count: { $sum: 1 },
                activeCount: {
                  $sum: { $cond: [{ $eq: ["$status", "active"] }, 1, 0] },
                },
              },
            },
          ])
          .toArray();

        reportData = { tierStats };
      } else if (reportType === "revenue") {
        // Revenue breakdown
        const revenueByTier = await subscriptionsCollection
          .aggregate([
            { $match: { status: "active" } },
            {
              $group: {
                _id: { tier: "$tier", billingCycle: "$billingCycle" },
                totalRevenue: { $sum: "$amount" },
                count: { $sum: 1 },
              },
            },
          ])
          .toArray();

        reportData = { revenueByTier };
      } else if (reportType === "growth") {
        // Growth trends
        const last6Months = new Date();
        last6Months.setMonth(last6Months.getMonth() - 6);

        const signups = await organizationsCollection
          .aggregate([
            { $match: { createdAt: { $gte: last6Months } } },
            {
              $group: {
                _id: {
                  year: { $year: "$createdAt" },
                  month: { $month: "$createdAt" },
                },
                count: { $sum: 1 },
              },
            },
            { $sort: { "_id.year": 1, "_id.month": 1 } },
          ])
          .toArray();

        reportData = { signups };
      } else if (reportType === "usage") {
        // Feature usage
        const totalOrgs = await organizationsCollection.countDocuments({});
        const [
          attendanceOrgs,
          examsOrgs,
          feesOrgs,
          announcementsOrgs,
        ] = await Promise.all([
          attendanceCollection.distinct("organizationId"),
          examsCollection.distinct("organizationId"),
          paymentsCollection.distinct("organizationId"),
          announcementsCollection.distinct("organizationId"),
        ]);

        reportData = {
          totalOrganizations: totalOrgs,
          featureUsage: {
            attendance: attendanceOrgs.length,
            exams: examsOrgs.length,
            fees: feesOrgs.length,
            announcements: announcementsOrgs.length,
          },
        };
      }

      res.json({
        success: true,
        data: { reportType, ...reportData },
      });
    } catch (error) {
      logger.error("Error generating report:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to generate report",
        error: error.message,
      });
    }
  }
);

// 8.2 GET /super-admin/export/organizations - Export organizations to CSV
app.get(
  "/super-admin/export/organizations",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { status, subscriptionTier } = req.query;

      const query = {};
      if (status) query.status = status;
      if (subscriptionTier) query.subscriptionTier = subscriptionTier;

      const orgs = await organizationsCollection.find(query).toArray();

      // Enrich data
      const enrichedData = await Promise.all(
        orgs.map(async (org) => {
          const [owner, subscription] = await Promise.all([
            usersCollection.findOne(
              { _id: org.ownerId },
              { projection: { name: 1, email: 1 } }
            ),
            subscriptionsCollection.findOne({ organizationId: org._id }),
          ]);

          return {
            Name: org.name || "",
            Slug: org.slug || "",
            Email: org.email || "",
            Phone: org.phone || "",
            Status: org.status || "",
            "Subscription Tier": org.subscriptionTier || "",
            "Subscription Status": subscription?.status || "N/A",
            "Owner Name": owner?.name || "Unknown",
            "Owner Email": owner?.email || "Unknown",
            "Students (current/max)": `${org.usage?.currentStudents || 0}/${
              org.limits?.maxStudents || 0
            }`,
            "Classes (current/max)": `${org.usage?.currentClasses || 0}/${
              org.limits?.maxClasses || 0
            }`,
            "Teachers (current/max)": `${org.usage?.currentTeachers || 0}/${
              org.limits?.maxTeachers || 0
            }`,
            "Created At": org.createdAt?.toISOString() || "",
          };
        })
      );

      const headers = [
        "Name",
        "Slug",
        "Email",
        "Phone",
        "Status",
        "Subscription Tier",
        "Subscription Status",
        "Owner Name",
        "Owner Email",
        "Students (current/max)",
        "Classes (current/max)",
        "Teachers (current/max)",
        "Created At",
      ];

      const rows = enrichedData.map((org) =>
        headers.map((header) => org[header])
      );

      const csv = buildCsvString(headers, rows);

      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="organizations-${Date.now()}.csv"`
      );
      res.send(csv);
    } catch (error) {
      logger.error("Error exporting organizations:", { error: error.message });
      res.status(500).json({
        success: false,
        message: "Failed to export organizations",
        error: error.message,
      });
    }
  }
);

// 8.3 GET /super-admin/export/subscriptions - Export subscriptions to CSV
app.get(
  "/super-admin/export/subscriptions",
  ensureDBConnection,
  authenticateUser,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const { tier, status } = req.query;

      const query = {};
      if (tier) query.tier = tier;
      if (status) query.status = status;

      const subscriptions = await subscriptionsCollection.find(query).toArray();

      // Enrich data
      const enrichedData = await Promise.all(
        subscriptions.map(async (sub) => {
          const org = await organizationsCollection.findOne(
            { _id: sub.organizationId },
            { projection: { name: 1, email: 1 } }
          );

          return {
            "Organization Name": org?.name || "Unknown",
            "Org Email": org?.email || "Unknown",
            Tier: sub.tier || "",
            Status: sub.status || "",
            "Billing Cycle": sub.billingCycle || "",
            Amount: sub.amount || 0,
            Currency: sub.currency || "BDT",
            "Trial Start": sub.trialStartDate?.toISOString() || "",
            "Trial End": sub.trialEndDate?.toISOString() || "",
            "Current Period Start": sub.currentPeriodStart?.toISOString() || "",
            "Current Period End": sub.currentPeriodEnd?.toISOString() || "",
            "Next Billing Date": sub.nextBillingDate?.toISOString() || "",
            "Created At": sub.createdAt?.toISOString() || "",
          };
        })
      );

      const headers = [
        "Organization Name",
        "Org Email",
        "Tier",
        "Status",
        "Billing Cycle",
        "Amount",
        "Currency",
        "Trial Start",
        "Trial End",
        "Current Period Start",
        "Current Period End",
        "Next Billing Date",
        "Created At",
      ];

      const rows = enrichedData.map((sub) =>
        headers.map((header) => sub[header])
      );

      const csv = buildCsvString(headers, rows);

      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="subscriptions-${Date.now()}.csv"`
      );
      res.send(csv);
    } catch (error) {
      logger.error("Error exporting subscriptions:", {
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: "Failed to export subscriptions",
        error: error.message,
      });
    }
  }
);

// ==================== SERVER START ====================

if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => {
    logger.info(`Server running on port ${port}`);
  });
}

export default app;
