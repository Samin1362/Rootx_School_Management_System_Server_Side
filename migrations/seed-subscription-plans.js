import { MongoClient, ServerApiVersion } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

const user = encodeURIComponent(process.env.DB_USER);
const pass = encodeURIComponent(process.env.DB_PASS);
const uri = `mongodb+srv://${user}:${pass}@cluster0.izyiyn6.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const plans = [
  {
    tier: "free",
    name: "Free",
    description: "Perfect for small schools getting started with digital management.",
    monthlyPrice: 0,
    yearlyPrice: 0,
    currency: "BDT",
    limits: {
      maxStudents: 50,
      maxClasses: 5,
      maxTeachers: 3,
      maxStorage: 100,
      features: ["students", "classes", "basic_reports"],
    },
    displayOrder: 1,
    isActive: true,
    createdAt: new Date(),
  },
  {
    tier: "basic",
    name: "Basic",
    description: "For growing schools that need attendance tracking and fee management.",
    monthlyPrice: 3000,
    yearlyPrice: 30000,
    currency: "BDT",
    limits: {
      maxStudents: 300,
      maxClasses: 15,
      maxTeachers: 15,
      maxStorage: 1024,
      features: [
        "students",
        "classes",
        "attendance",
        "fees",
        "basic_reports",
        "email_notifications",
      ],
    },
    displayOrder: 2,
    isActive: true,
    createdAt: new Date(),
  },
  {
    tier: "professional",
    name: "Professional",
    description: "Complete school management with exams, grade workflows, and analytics.",
    monthlyPrice: 7000,
    yearlyPrice: 70000,
    currency: "BDT",
    limits: {
      maxStudents: 1500,
      maxClasses: 50,
      maxTeachers: 50,
      maxStorage: 10240,
      features: [
        "students",
        "classes",
        "attendance",
        "fees",
        "exams",
        "grade_management",
        "advanced_reports",
        "analytics",
        "email_notifications",
      ],
    },
    displayOrder: 3,
    isActive: true,
    createdAt: new Date(),
  },
  {
    tier: "enterprise",
    name: "Enterprise",
    description: "Unlimited capacity with priority support and advanced features.",
    monthlyPrice: 20000,
    yearlyPrice: 200000,
    currency: "BDT",
    limits: {
      maxStudents: -1,
      maxClasses: -1,
      maxTeachers: -1,
      maxStorage: 51200,
      features: [
        "all_features",
        "api_access",
        "custom_domain",
        "priority_support",
        "advanced_analytics",
        "data_export",
      ],
    },
    displayOrder: 4,
    isActive: true,
    createdAt: new Date(),
  },
];

async function seed() {
  try {
    await client.connect();
    const db = client.db("rootx_school_management");
    const collection = db.collection("subscription_plans");

    // Clear existing plans
    const deleteResult = await collection.deleteMany({});
    console.log(`Cleared ${deleteResult.deletedCount} existing plans.`);

    // Insert new plans
    const insertResult = await collection.insertMany(plans);
    console.log(`Inserted ${insertResult.insertedCount} subscription plans.`);

    // Create unique index on tier
    await collection.createIndex({ tier: 1 }, { unique: true });
    console.log("Created unique index on tier.");

    console.log("Seed completed successfully.");
  } catch (error) {
    console.error("Seed failed:", error.message);
  } finally {
    await client.close();
  }
}

seed();
