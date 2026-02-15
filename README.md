# RootX School Management System - Backend API

A comprehensive multi-tenant SaaS backend for school management built with Express.js and MongoDB.

## Table of Contents
- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Architecture](#architecture)
- [Database Collections](#database-collections)
- [Authentication & Authorization](#authentication--authorization)
- [API Routes](#api-routes)
- [Middleware Chain](#middleware-chain)
- [Error Handling](#error-handling)
- [Development Notes](#development-notes)

---

## Overview

The RootX School Management System backend is a single-file Express server (~17,257 lines) that provides a complete REST API for managing educational institutions. It supports multi-tenant architecture with organization isolation, role-based access control, and comprehensive features for academic, administrative, and financial operations.

### Key Features
- **Multi-tenant SaaS** with organization-level data isolation
- **7 Role-based access control** (super_admin, org_owner, admin, moderator, teacher, student, parent)
- **165+ API endpoints** covering all school operations
- **Firebase Authentication** integration
- **Real-time notifications** system
- **Comprehensive reporting** and data export
- **Audit logging** for all mutations
- **Subscription management** with usage limits

---

## Tech Stack

- **Runtime**: Node.js (ES Modules)
- **Framework**: Express.js 5.x
- **Database**: MongoDB Atlas
- **Authentication**: Firebase Auth (x-user-email header for Phase 1)
- **Logging**: Winston (custom logger utility)
- **Security**: CORS, organization isolation middleware

### NPM Dependencies
```json
{
  "express": "^5.x",
  "mongodb": "^6.x",
  "cors": "^2.x",
  "dotenv": "^16.x"
}
```

---

## Getting Started

### Prerequisites
- Node.js 18+ with ES modules support
- MongoDB Atlas account
- Firebase project (for authentication)

### Installation

1. Clone the repository:
```bash
cd rootx_school_ms_server_side
```

2. Install dependencies:
```bash
npm install
```

3. Create `.env` file (see [Environment Variables](#environment-variables))

4. Start the server:
```bash
# Development
npm run dev

# Production
npm start
```

The server will start on `http://localhost:3000` (or PORT specified in .env)

---

## Environment Variables

Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# MongoDB Atlas
DB_USER=your_mongodb_username
DB_PASS=your_mongodb_password

# Firebase Configuration (if needed for server-side verification)
FIREBASE_PROJECT_ID=your_firebase_project_id
FIREBASE_CLIENT_EMAIL=your_firebase_client_email
FIREBASE_PRIVATE_KEY=your_firebase_private_key

# JWT Secret (if using JWT instead of Firebase)
JWT_SECRET=your_jwt_secret_key

# CORS Origins (comma-separated)
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:5174

# Other
LOG_LEVEL=info
```

---

## Architecture

### Multi-Tenant Design
- Every collection has an `organizationId` field
- All queries automatically scoped to user's organization
- Cross-organization data leakage prevented by middleware
- Usage limits enforced per organization subscription tier

### Data Flow Pattern
```
Request → ensureDBConnection → authenticateUser → enforceOrganizationIsolation
       → checkOrganizationSuspension → requirePermission(permissions) → Route Handler
```

### Subscription Tiers
- **Free**: Limited features, trial period
- **Basic**: Standard school features
- **Professional**: Advanced features + analytics
- **Enterprise**: Custom limits + priority support

---

## Database Collections

### Phase 1: Foundation & Authentication
- **organizations** - School/institution records
- **users** - All user accounts (multi-role)
- **subscriptions** - Organization subscription details
- **subscription_plans** - Available subscription tiers
- **platform_settings** - Global platform configuration
- **activity_logs** - Audit trail of all mutations

### Phase 2: Academic Structure & People
- **classes** - Class/grade levels
- **sections** - Class divisions
- **subjects** - Subjects with teacher assignments
- **students** - Student records
- **teachers** - Teacher profiles
- **parents** - Parent/guardian profiles
- **documents** - File uploads/attachments

### Phase 3: Attendance
- **attendance** - Daily attendance records (one per class+section+date)

### Phase 4: Exams & Grades
- **exams** - Exam definitions
- **grade_submissions** - Grade entry and workflow (6 states: draft → submitted → under_review → approved/rejected → published)
- **notifications** - User notifications

### Phase 5: Finance & Fees
- **monthly_fee_structures** - Fee templates per class
- **student_monthly_fees** - Individual student fee records
- **payments** - Fee payments with receipts
- **expenses** - School expense tracking
- **salaries** - Staff salary records

### Phase 6: Communication & Reports
- **announcements** - School/class/role-targeted announcements

### Phase 7: Super Admin (Partial)
- **subscription_requests** - Tier upgrade/downgrade requests
- **reactivation_requests** - Suspended org reactivation requests

---

## Authentication & Authorization

### Authentication
- **Method**: Firebase Authentication (Phase 1 uses x-user-email header)
- **Token**: JWT or Firebase ID token in Authorization header: `Bearer <token>`
- **User Context**: `req.user`, `req.userId`, `req.userRole`, `req.organizationId` populated by middleware

### Role Hierarchy

| Role | Level | Description |
|------|-------|-------------|
| `super_admin` | 0 | Platform administrator (all organizations) |
| `org_owner` | 1 | Organization owner (full org control) |
| `admin` | 2 | School administrator |
| `moderator` | 3 | Academic moderator (grade review) |
| `teacher` | 4 | Teaching staff |
| `student` | 5 | Student account |
| `parent` | 6 | Parent/guardian account |

### Permission System

**super_admin** and **org_owner**: All permissions (`["all"]`)

**admin**:
- manage_org_settings, manage_users, invite_users
- Full CRUD on students, teachers, classes, sections, subjects
- mark_attendance, view_attendance
- manage_exams, review_grades, approve_grades, publish_grades
- manage_fee_structures, collect_payment, manage_expenses, manage_salaries
- create_announcement, view_reports, export_data, view_activity_logs

**moderator**:
- view_students, view_teachers, view_attendance
- review_grades, approve_grades, reject_grades, view_published_grades
- view_announcements, view_reports

**teacher**:
- view_students, mark_attendance, view_attendance
- create_exam, create_grade_draft, submit_grades, view_published_grades
- create_announcement (class-scoped only), view_announcements
- upload_own_documents, view_reports

**student**:
- view_attendance (own), view_published_grades (own), view_fees (own)
- view_announcements, upload_own_documents

**parent**:
- view_attendance (children), view_published_grades (children), view_fees (children)
- view_announcements

---

## API Routes

### 1. Health & Status

#### `GET /health`
Health check endpoint
- **Auth**: Public
- **Response**: `{ success: true, message: string, timestamp: ISO, dbConnected: boolean }`

#### `GET /`
API information
- **Auth**: Public
- **Response**: `{ success: true, name: string, version: string, status: string }`

---

### 2. Subscription & Plans

#### `GET /subscriptions/plans`
List all active subscription plans
- **Auth**: Public
- **Response**: `{ success: true, data: Plan[] }`

#### `GET /subscriptions/organization/:orgId`
Get organization subscription details
- **Auth**: Required
- **Params**: `orgId` (ObjectId)
- **Response**: `{ success: true, data: { subscription, planDetails } }`

---

### 3. Organizations

#### `POST /organizations`
Public organization signup
- **Auth**: Public
- **Body**:
  ```json
  {
    "name": "string (required)",
    "slug": "string (required, unique)",
    "email": "string (required, unique)",
    "phone": "string",
    "address": "string",
    "ownerName": "string",
    "ownerEmail": "string (required)",
    "ownerPassword": "string",
    "ownerPhotoURL": "string",
    "ownerFirebaseUid": "string"
  }
  ```
- **Response**: `{ success: true, data: { organization, owner, subscription } }`

#### `GET /organizations/:id`
Get organization details
- **Auth**: Required (org member or super admin)
- **Response**: `{ success: true, data: organization }`

#### `PATCH /organizations/:id`
Update organization settings
- **Auth**: Required
- **Permission**: `manage_org_settings`
- **Body**: `{ name?, phone?, address?, logo?, settings?, branding? }`
- **Response**: `{ success: true, message: string, data: organization }`

#### `GET /organizations/:id/stats`
Get organization statistics
- **Auth**: Required (org member or super admin)
- **Response**: `{ success: true, data: { usage, limits, totalUsers, totalStudents, ... } }`

---

### 4. User Management

#### `POST /users/register`
Public user registration
- **Auth**: Public
- **Body**:
  ```json
  {
    "name": "string (required)",
    "email": "string (required)",
    "password": "string",
    "phone": "string",
    "firebaseUid": "string",
    "photoURL": "string"
  }
  ```
- **Response**: `{ success: true, data: user, message: string }`

#### `GET /users/me`
Get current user profile
- **Auth**: Required
- **Response**: `{ success: true, data: user }`

#### `GET /users`
List users in organization
- **Auth**: Required
- **Permission**: `manage_users`
- **Query**: `role?, status?, page?, limit?`
- **Response**: `{ success: true, data: user[], pagination: {...} }`

#### `POST /users/invite`
Invite new user to organization
- **Auth**: Required
- **Permission**: `invite_users`
- **Body**: `{ email: string, role: string, firstName?: string }`
- **Response**: `{ success: true, data: { inviteCode, user } }`

#### `PATCH /users/:id/role`
Update user role
- **Auth**: Required
- **Permission**: `manage_users`
- **Body**: `{ role: string }`
- **Response**: `{ success: true, message: string, data: user }`

#### `DELETE /users/:id`
Delete user
- **Auth**: Required
- **Permission**: `manage_users`
- **Response**: `{ success: true, message: string }`

---

### 5. Class Management

#### `GET /classes`
List classes
- **Auth**: Required
- **Query**: `status?, page?, limit?`
- **Response**: `{ success: true, data: classes[], pagination: {...} }`

#### `POST /classes`
Create class
- **Auth**: Required
- **Permission**: `manage_classes`
- **Body**: `{ name: string, classCode?: string, level?: string, academicYear?: string }`
- **Response**: `{ success: true, message: string, data: class }`

#### `PATCH /classes/:id`
Update class
- **Auth**: Required
- **Permission**: `manage_classes`
- **Body**: `{ name?, classCode?, level?, academicYear? }`
- **Response**: `{ success: true, message: string, data: class }`

#### `DELETE /classes/:id`
Delete class (soft delete, cascade to sections/subjects/students)
- **Auth**: Required
- **Permission**: `manage_classes`
- **Response**: `{ success: true, message: string }`

---

### 6. Section Management

#### `GET /sections`
List sections
- **Auth**: Required
- **Query**: `classId?, page?, limit?`
- **Response**: `{ success: true, data: sections[], pagination: {...} }`

#### `POST /sections`
Create section
- **Auth**: Required
- **Permission**: `manage_sections`
- **Body**: `{ name: string, classId: ObjectId, capacity?: number }`
- **Response**: `{ success: true, message: string, data: section }`

#### `PATCH /sections/:id`
Update section
- **Auth**: Required
- **Permission**: `manage_sections`
- **Body**: `{ name?, capacity? }`
- **Response**: `{ success: true, message: string, data: section }`

#### `DELETE /sections/:id`
Delete section
- **Auth**: Required
- **Permission**: `manage_sections`
- **Response**: `{ success: true, message: string }`

---

### 7. Subject Management

#### `GET /subjects`
List subjects
- **Auth**: Required
- **Query**: `classId?, teacherId?, page?, limit?`
- **Response**: `{ success: true, data: subjects[], pagination: {...} }`

#### `POST /subjects`
Create subject and assign teacher
- **Auth**: Required
- **Permission**: `manage_subjects`
- **Body**: `{ name: string, code?: string, classId: ObjectId, teacherId: ObjectId, fullMarks?: number }`
- **Response**: `{ success: true, message: string, data: subject }`

#### `PATCH /subjects/:id`
Update subject
- **Auth**: Required
- **Permission**: `manage_subjects`
- **Body**: `{ name?, code?, teacherId?, fullMarks? }`
- **Response**: `{ success: true, message: string, data: subject }`

#### `DELETE /subjects/:id`
Delete subject
- **Auth**: Required
- **Permission**: `manage_subjects`
- **Response**: `{ success: true, message: string }`

---

### 8. Student Management

#### `GET /students`
List students
- **Auth**: Required
- **Query**: `classId?, sectionId?, status?, page?, limit?`
- **Response**: `{ success: true, data: students[], pagination: {...} }`

#### `GET /students/:id`
Get student details
- **Auth**: Required (role-scoped)
- **Response**: `{ success: true, data: student }`

#### `POST /students`
Create student
- **Auth**: Required
- **Permission**: `create_student`
- **Body**:
  ```json
  {
    "name": "string (required)",
    "email": "string (required)",
    "classId": "ObjectId (required)",
    "sectionId": "ObjectId (required)",
    "parentId": "ObjectId",
    "phone": "string",
    "firebaseUid": "string",
    "photoURL": "string"
  }
  ```
- **Response**: `{ success: true, message: string, data: student }`

#### `PATCH /students/:id`
Update student
- **Auth**: Required
- **Permission**: `update_student`
- **Body**: `{ name?, classId?, sectionId?, parentId?, phone? }`
- **Response**: `{ success: true, message: string, data: student }`

#### `DELETE /students/:id`
Delete student (soft delete)
- **Auth**: Required
- **Permission**: `delete_student`
- **Response**: `{ success: true, message: string }`

#### `GET /students/:id/attendance`
Get student attendance summary
- **Auth**: Required (student sees own, parent sees children's)
- **Response**: `{ success: true, data: { total, present, absent, late, excused, percentage, records[] } }`

#### `GET /students/:id/grades`
Get student grades (published only)
- **Auth**: Required (role-scoped)
- **Response**: `{ success: true, data: gradeSubmissions[] }`

#### `GET /students/:id/fees`
Get student fee records with payment history
- **Auth**: Required (role-scoped)
- **Response**: `{ success: true, data: { fees[], total, paid, due } }`

---

### 9. Teacher Management

#### `GET /teachers`
List teachers
- **Auth**: Required
- **Query**: `status?, page?, limit?`
- **Response**: `{ success: true, data: teachers[], pagination: {...} }`

#### `GET /teachers/:id`
Get teacher details
- **Auth**: Required
- **Response**: `{ success: true, data: teacher }`

#### `POST /teachers`
Create teacher (auto-creates user account)
- **Auth**: Required
- **Permission**: `create_teacher`
- **Body**:
  ```json
  {
    "name": "string (required)",
    "email": "string (required)",
    "phone": "string",
    "employeeId": "string",
    "qualification": "string",
    "specialization": "string",
    "joiningDate": "ISO date",
    "firebaseUid": "string",
    "photoURL": "string"
  }
  ```
- **Response**: `{ success: true, message: string, data: teacher }`

#### `PATCH /teachers/:id`
Update teacher
- **Auth**: Required
- **Permission**: `update_teacher`
- **Body**: `{ employeeId?, qualification?, specialization? }`
- **Response**: `{ success: true, message: string, data: teacher }`

#### `DELETE /teachers/:id`
Delete teacher
- **Auth**: Required
- **Permission**: `delete_teacher`
- **Response**: `{ success: true, message: string }`

#### `GET /teachers/:id/classes`
Get classes assigned to teacher
- **Auth**: Required
- **Response**: `{ success: true, data: classes[] }`

#### `GET /teachers/:id/submissions`
Get teacher's grade submissions
- **Auth**: Required
- **Response**: `{ success: true, data: gradeSubmissions[], pagination: {...} }`

---

### 10. Parent Management

#### `GET /parents`
List parents
- **Auth**: Required
- **Query**: `page?, limit?`
- **Response**: `{ success: true, data: parents[], pagination: {...} }`

#### `GET /parents/:id`
Get parent details with children
- **Auth**: Required (role-scoped)
- **Response**: `{ success: true, data: parent }`

#### `POST /parents`
Create parent and link to students
- **Auth**: Required
- **Permission**: `manage_users`
- **Body**:
  ```json
  {
    "name": "string (required)",
    "email": "string (required)",
    "phone": "string",
    "occupation": "string",
    "relationship": "string",
    "children": "ObjectId[] (student IDs)",
    "firebaseUid": "string",
    "photoURL": "string"
  }
  ```
- **Response**: `{ success: true, message: string, data: parent }`

#### `PATCH /parents/:id`
Update parent
- **Auth**: Required
- **Permission**: `manage_users`
- **Body**: `{ occupation?, relationship?, children? }`
- **Response**: `{ success: true, message: string, data: parent }`

#### `DELETE /parents/:id`
Delete parent
- **Auth**: Required
- **Permission**: `manage_users`
- **Response**: `{ success: true, message: string }`

---

### 11. Document Management

#### `GET /documents`
List documents
- **Auth**: Required
- **Query**: `type?, page?, limit?`
- **Response**: `{ success: true, data: documents[], pagination: {...} }`

#### `POST /documents`
Upload document
- **Auth**: Required
- **Body**: `{ filename: string, fileUrl: string, type?: string }`
- **Response**: `{ success: true, message: string, data: document }`

#### `DELETE /documents/:id`
Delete document
- **Auth**: Required
- **Response**: `{ success: true, message: string }`

---

### 12. Attendance

#### `POST /attendance`
Mark/upsert attendance for class+section on date
- **Auth**: Required
- **Permission**: `mark_attendance`
- **Body**:
  ```json
  {
    "classId": "ObjectId (required)",
    "sectionId": "ObjectId (required)",
    "date": "ISO date (required, not future)",
    "records": [
      { "studentId": "ObjectId", "status": "present|absent|late|excused" }
    ]
  }
  ```
- **Restrictions**: Teachers can only mark for assigned classes
- **Response**: `{ success: true, message: string, data: { action: "created"|"updated" } }`

#### `GET /attendance`
List attendance records
- **Auth**: Required
- **Permission**: `view_attendance`
- **Query**: `classId?, sectionId?, date?, page?, limit?`
- **Response**: `{ success: true, data: attendanceRecords[], pagination: {...} }`

#### `GET /attendance/reports`
Get aggregated attendance reports
- **Auth**: Required
- **Permission**: `view_attendance`
- **Query**: `classId?, sectionId?, startDate?, endDate?`
- **Response**: `{ success: true, data: { totalPresent, totalAbsent, trends[], classBreakdown[] } }`

#### `GET /attendance/student/:studentId`
Get student attendance summary
- **Auth**: Required (role-scoped)
- **Response**: `{ success: true, data: { total, present, absent, late, excused, percentage, records[] } }`

---

### 13. Exams

#### `POST /exams`
Create exam
- **Auth**: Required
- **Permission**: `create_exam`
- **Body**:
  ```json
  {
    "name": "string (required)",
    "classId": "ObjectId (required)",
    "academicYear": "string (required)",
    "startDate": "ISO (required)",
    "endDate": "ISO (required)"
  }
  ```
- **Response**: `{ success: true, message: string, data: exam }`

#### `GET /exams`
List exams with submission counts
- **Auth**: Required
- **Permission**: `create_exam`
- **Query**: `classId?, academicYear?, status?, page?, limit?`
- **Response**: `{ success: true, data: exams[], pagination: {...} }`

#### `GET /exams/:id`
Get exam details
- **Auth**: Required
- **Permission**: `create_exam`
- **Response**: `{ success: true, data: exam }`

#### `PATCH /exams/:id`
Update exam
- **Auth**: Required
- **Permission**: `create_exam`
- **Body**: `{ name?, startDate?, endDate? }`
- **Response**: `{ success: true, message: string, data: exam }`

#### `DELETE /exams/:id`
Delete exam
- **Auth**: Required
- **Permission**: `create_exam`
- **Response**: `{ success: true, message: string }`

---

### 14. Grade Submissions

**6-State Workflow**: `draft → submitted → under_review → approved/rejected → published`

#### `POST /grade-submissions`
Create grade submission (draft)
- **Auth**: Required
- **Permission**: `submit_grades`
- **Body**:
  ```json
  {
    "examId": "ObjectId (required)",
    "classId": "ObjectId (required)",
    "sectionId": "ObjectId (required)",
    "subjectId": "ObjectId (required)",
    "grades": [
      { "studentId": "ObjectId", "marks": "number|null" }
    ]
  }
  ```
- **Response**: `{ success: true, message: string, data: submission }`

#### `GET /grade-submissions`
List grade submissions (role-filtered)
- **Auth**: Required
- **Permission**: `submit_grades`
- **Query**: `examId?, classId?, status?, page?, limit?`
- **Response**: `{ success: true, data: submissions[], pagination: {...} }`

#### `GET /grade-submissions/:id`
Get submission details
- **Auth**: Required
- **Response**: `{ success: true, data: submission }`

#### `PATCH /grade-submissions/:id`
Update draft submission marks
- **Auth**: Required
- **Permission**: `submit_grades`
- **Body**: `{ grades: [ { studentId, marks } ] }`
- **Response**: `{ success: true, message: string, data: submission }`

#### `POST /grade-submissions/:id/submit`
Submit draft for review (draft → submitted)
- **Auth**: Required
- **Permission**: `submit_grades`
- **Body**: `{ comment?: string }`
- **Response**: `{ success: true, message: string, data: submission }`

#### `POST /grade-submissions/:id/start-review`
Start moderation (submitted → under_review)
- **Auth**: Required
- **Permission**: `review_grades`
- **Body**: `{ comment?: string }`
- **Response**: `{ success: true, message: string, data: submission }`

#### `POST /grade-submissions/:id/approve`
Approve submission (under_review → approved)
- **Auth**: Required
- **Permission**: `review_grades`
- **Body**: `{ comment?: string }`
- **Response**: `{ success: true, message: string, data: submission }`

#### `POST /grade-submissions/:id/reject`
Reject submission (any state → draft)
- **Auth**: Required
- **Permission**: `review_grades`
- **Body**: `{ reason: string }`
- **Response**: `{ success: true, message: string, data: submission }`

#### `POST /grade-submissions/:id/publish`
Publish approved grades (approved → published)
- **Auth**: Required
- **Permission**: `publish_grades`
- **Body**: `{ comment?: string }`
- **Response**: `{ success: true, message: string, data: submission }`

#### `GET /grade-submissions/teacher/my-submissions`
Get current teacher's draft submissions
- **Auth**: Required
- **Permission**: `submit_grades`
- **Response**: `{ success: true, data: submissions[] }`

#### `GET /grade-submissions/moderator/pending`
Get submissions awaiting review
- **Auth**: Required
- **Permission**: `review_grades`
- **Response**: `{ success: true, data: submissions[] }`

#### `GET /grade-submissions/admin/approved`
Get approved submissions awaiting publishing
- **Auth**: Required
- **Permission**: `publish_grades`
- **Response**: `{ success: true, data: submissions[] }`

---

### 15. Results/Grades (Published View)

#### `GET /results`
List published grade submissions
- **Auth**: Required
- **Permission**: `view_published_grades`
- **Query**: `examId?, classId?, page?, limit?`
- **Response**: `{ success: true, data: results[], pagination: {...} }`

#### `GET /results/student/:studentId`
Get student's published grades
- **Auth**: Required (student/parent scoped)
- **Response**: `{ success: true, data: grades[] }`

#### `GET /results/report-card/:studentId/:examId`
Get student report card
- **Auth**: Required (role-scoped)
- **Response**: `{ success: true, data: { student, exam, subjects[], gpa, totalGrade } }`

---

### 16. Notifications

#### `GET /notifications`
Get user notifications (paginated, unread first)
- **Auth**: Required
- **Query**: `read?, page?, limit?`
- **Response**: `{ success: true, data: notifications[], pagination: {...} }`

#### `PATCH /notifications/read-all`
Mark all notifications as read
- **Auth**: Required
- **Response**: `{ success: true, message: string }`

#### `PATCH /notifications/:id/read`
Mark notification as read
- **Auth**: Required
- **Response**: `{ success: true, message: string }`

---

### 17. Fee Structures

#### `POST /fee-structures`
Create monthly fee structure
- **Auth**: Required
- **Permission**: `manage_fee_structures`
- **Body**:
  ```json
  {
    "name": "string (required)",
    "description": "string",
    "classId": "ObjectId (required)",
    "monthlyAmount": "number (required)",
    "currency": "string",
    "startMonth": "YYYY-MM",
    "endMonth": "YYYY-MM",
    "isActive": "boolean"
  }
  ```
- **Response**: `{ success: true, message: string, data: feeStructure }`

#### `GET /fee-structures`
List fee structures
- **Auth**: Required
- **Permission**: `manage_fee_structures`
- **Query**: `classId?, isActive?, page?, limit?`
- **Response**: `{ success: true, data: structures[], pagination: {...} }`

#### `PATCH /fee-structures/:id`
Update fee structure
- **Auth**: Required
- **Permission**: `manage_fee_structures`
- **Body**: `{ name?, description?, monthlyAmount?, isActive? }`
- **Response**: `{ success: true, message: string, data: feeStructure }`

#### `DELETE /fee-structures/:id`
Delete fee structure
- **Auth**: Required
- **Permission**: `manage_fee_structures`
- **Response**: `{ success: true, message: string }`

---

### 18. Student Fees

#### `POST /student-fees/generate`
Bulk generate monthly fees for class
- **Auth**: Required
- **Permission**: `manage_fee_structures`
- **Body**:
  ```json
  {
    "feeStructureId": "ObjectId (required)",
    "month": "YYYY-MM (required)",
    "dueDate": "ISO"
  }
  ```
- **Response**: `{ success: true, message: string, data: { created, skipped, totalStudents } }`

#### `GET /student-fees`
List student fees (role-scoped)
- **Auth**: Required
- **Permission**: `view_fees`
- **Query**: `studentId?, classId?, month?, status?, page?, limit?`
- **Response**: `{ success: true, data: fees[], pagination: {...} }`

#### `PATCH /student-fees/:id`
Update fee record
- **Auth**: Required
- **Permission**: `manage_fee_structures`
- **Body**: `{ discount?, paidAmount?, status? }`
- **Response**: `{ success: true, message: string, data: studentFee }`

---

### 19. Payments

#### `POST /payments`
Record fee payment
- **Auth**: Required
- **Permission**: `collect_payment`
- **Body**:
  ```json
  {
    "studentFeeId": "ObjectId (required)",
    "amount": "number (required)",
    "paymentMode": "cash|card|cheque|online (required)",
    "transactionId": "string",
    "notes": "string",
    "paymentDate": "ISO"
  }
  ```
- **Response**: `{ success: true, message: string, data: payment, receiptNumber: string }`

#### `GET /payments`
List payments
- **Auth**: Required
- **Permission**: `view_fees`
- **Query**: `studentId?, month?, paymentMode?, page?, limit?`
- **Response**: `{ success: true, data: payments[], pagination: {...} }`

#### `GET /payments/receipt/:id`
Get payment receipt
- **Auth**: Required (role-scoped)
- **Response**: `{ success: true, data: receipt }`

---

### 20. Fee Reports

#### `GET /fees/dues`
Get fee dues summary
- **Auth**: Required
- **Permission**: `view_fees`
- **Query**: `classId?, status?`
- **Response**: `{ success: true, data: { totalDue, totalOverdue, byStudent[], byClass[] } }`

#### `GET /fees/reports`
Get fee collection reports
- **Auth**: Required
- **Permission**: `manage_fee_structures`
- **Query**: `startMonth?, endMonth?, classId?, paymentMode?`
- **Response**: `{ success: true, data: { byMonth[], byClass[], byPaymentMode[], totalCollected } }`

---

### 21. Expenses

#### `POST /expenses`
Record expense
- **Auth**: Required
- **Permission**: `manage_expenses`
- **Body**:
  ```json
  {
    "title": "string (required)",
    "description": "string",
    "amount": "number (required)",
    "category": "utilities|salary|maintenance|supplies|transport|events|others (required)",
    "expenseMonth": "YYYY-MM (required)",
    "expenseDate": "ISO",
    "receiptUrl": "string"
  }
  ```
- **Response**: `{ success: true, message: string, data: expense }`

#### `GET /expenses`
List expenses
- **Auth**: Required
- **Permission**: `manage_expenses`
- **Query**: `category?, expenseMonth?, startDate?, endDate?, page?, limit?`
- **Response**: `{ success: true, data: expenses[], pagination: {...} }`

#### `PATCH /expenses/:id`
Update expense
- **Auth**: Required
- **Permission**: `manage_expenses`
- **Body**: `{ title?, description?, amount?, category?, expenseDate?, receiptUrl? }`
- **Response**: `{ success: true, message: string, data: expense }`

#### `DELETE /expenses/:id`
Delete expense
- **Auth**: Required
- **Permission**: `manage_expenses`
- **Response**: `{ success: true, message: string }`

---

### 22. Salaries

#### `POST /salaries`
Record individual salary
- **Auth**: Required
- **Permission**: `manage_salaries`
- **Body**:
  ```json
  {
    "teacherId": "ObjectId (required)",
    "salaryMonth": "YYYY-MM (required)",
    "basicSalary": "number (required)",
    "bonus": "number",
    "deduction": "number",
    "paymentDate": "ISO"
  }
  ```
- **Response**: `{ success: true, message: string, data: salary }`

#### `POST /salaries/generate`
Bulk generate salaries for all teachers
- **Auth**: Required
- **Permission**: `manage_salaries`
- **Body**: `{ month: "YYYY-MM", basicSalary: number }`
- **Response**: `{ success: true, message: string, data: { created, skipped } }`

#### `GET /salaries`
List salaries
- **Auth**: Required
- **Permission**: `manage_salaries`
- **Query**: `teacherId?, month?, page?, limit?`
- **Response**: `{ success: true, data: salaries[], pagination: {...} }`

#### `PATCH /salaries/:id`
Update salary
- **Auth**: Required
- **Permission**: `manage_salaries`
- **Body**: `{ basicSalary?, bonus?, deduction?, paymentDate? }`
- **Response**: `{ success: true, message: string, data: salary }`

#### `GET /salaries/reports`
Get salary reports
- **Auth**: Required
- **Permission**: `manage_salaries`
- **Query**: `startMonth?, endMonth?, role?`
- **Response**: `{ success: true, data: { byMonth[], byRole[], totalSalaryExpense } }`

---

### 23. Announcements

#### `POST /announcements`
Create announcement with targeting
- **Auth**: Required
- **Permission**: `create_announcement`
- **Body**:
  ```json
  {
    "title": "string (required)",
    "message": "string (required)",
    "target": "school|class|section|role (required)",
    "targetId": "ObjectId (for class/section)",
    "targetRole": "string (for role target)",
    "priority": "low|normal|high|urgent",
    "expiresAt": "ISO"
  }
  ```
- **Response**: `{ success: true, message: string, data: announcement }`

#### `GET /announcements`
List announcements (role-filtered)
- **Auth**: Required
- **Permission**: `view_announcements`
- **Query**: `target?, priority?, page?, limit?`
- **Response**: `{ success: true, data: announcements[], pagination: {...} }`

#### `PATCH /announcements/:id`
Update announcement
- **Auth**: Required
- **Permission**: `create_announcement`
- **Body**: `{ title?, message?, priority?, expiresAt? }`
- **Response**: `{ success: true, message: string, data: announcement }`

#### `DELETE /announcements/:id`
Delete announcement
- **Auth**: Required
- **Permission**: `create_announcement`
- **Response**: `{ success: true, message: string }`

---

### 24. Reports

#### `GET /reports/attendance`
Attendance reports
- **Auth**: Required
- **Permission**: `view_reports`
- **Query**: `classId?, sectionId?, startDate?, endDate?`
- **Response**: `{ success: true, data: { totalStudents, statusBreakdown, dailyTrends[], classBreakdown[] } }`

#### `GET /reports/academic`
Academic performance reports
- **Auth**: Required
- **Permission**: `view_reports`
- **Query**: `examId?, classId?`
- **Response**: `{ success: true, data: { gradeDistribution, passRate, subjectBreakdown[], topPerformers[] } }`

#### `GET /reports/finance`
Financial reports
- **Auth**: Required
- **Permission**: `view_reports`
- **Query**: `startMonth?, endMonth?`
- **Response**: `{ success: true, data: { totalIncome, totalExpense, totalDue, totalSalary, netPosition, byPaymentMode[], byCategory[] } }`

#### `GET /reports/teacher-workload`
Teacher workload reports
- **Auth**: Required
- **Permission**: `view_reports`
- **Response**: `{ success: true, data: { teachers[], averageSubjects, averageClasses, submissionStatus[] } }`

---

### 25. Data Export (CSV)

#### `GET /export/students`
Export students as CSV
- **Auth**: Required
- **Permission**: `export_data`
- **Query**: `classId?`
- **Response**: CSV file (Content-Disposition: attachment)

#### `GET /export/attendance`
Export attendance as CSV
- **Auth**: Required
- **Permission**: `export_data`
- **Query**: `classId?, sectionId?, month?`
- **Response**: CSV file

#### `GET /export/fees`
Export fee records as CSV
- **Auth**: Required
- **Permission**: `export_data`
- **Query**: `classId?, month?`
- **Response**: CSV file

#### `GET /export/results`
Export grades as CSV
- **Auth**: Required
- **Permission**: `export_data`
- **Query**: `examId?, classId?`
- **Response**: CSV file

---

### 26. Activity Logs

#### `GET /activity-logs`
Get activity logs (audit trail)
- **Auth**: Required
- **Permission**: `view_activity_logs`
- **Query**: `action?, resource?, userId?, startDate?, endDate?, page?, limit?`
- **Response**: `{ success: true, data: logs[], pagination: {...} }`

---

### 27. Super Admin - Dashboard & Analytics

#### `GET /super-admin/dashboard`
Platform dashboard
- **Auth**: Super admin only
- **Response**: `{ success: true, data: { totalOrgs, activeOrgs, totalUsers, totalRevenue, ... } }`

#### `GET /super-admin/analytics`
Platform analytics
- **Auth**: Super admin only
- **Response**: `{ success: true, data: { orgGrowth[], userGrowth[], subscriptionTiers[] } }`

#### `GET /super-admin/feature-usage`
Feature usage analytics
- **Auth**: Super admin only
- **Response**: `{ success: true, data: { students[], grades[], payments[] } }`

#### `GET /super-admin/activity-logs`
Platform-wide activity logs
- **Auth**: Super admin only
- **Query**: `action?, resource?, startDate?, endDate?, page?, limit?`
- **Response**: `{ success: true, data: logs[], pagination: {...} }`

#### `POST /super-admin/announcements`
Create platform-wide announcement
- **Auth**: Super admin only
- **Body**: `{ title: string, message: string, priority?, expiresAt? }`
- **Response**: `{ success: true, message: string, data: announcement }`

---

### 28. Super Admin - Organization Management

#### `GET /super-admin/organizations`
List all organizations
- **Auth**: Super admin only
- **Query**: `status?, subscriptionTier?, search?, page?, limit?`
- **Response**: `{ success: true, data: orgs[], pagination: {...} }`

#### `GET /super-admin/organizations/:id`
Get organization details
- **Auth**: Super admin only
- **Response**: `{ success: true, data: organization }`

#### `PATCH /super-admin/organizations/:id`
Update organization
- **Auth**: Super admin only
- **Body**: `{ status?, subscriptionTier?, settings? }`
- **Response**: `{ success: true, message: string, data: organization }`

#### `POST /super-admin/organizations/:id/suspend`
Suspend organization
- **Auth**: Super admin only
- **Body**: `{ reason: string }`
- **Response**: `{ success: true, message: string }`

#### `POST /super-admin/organizations/:id/reactivate`
Reactivate organization
- **Auth**: Super admin only
- **Body**: `{ comment?: string }`
- **Response**: `{ success: true, message: string }`

#### `POST /super-admin/organizations/:id/override-limits`
Override usage limits
- **Auth**: Super admin only
- **Body**: `{ maxStudents?, maxClasses?, maxTeachers?, maxStorage?, reason: string }`
- **Response**: `{ success: true, message: string, data: { limits } }`

#### `DELETE /super-admin/organizations/:id`
Delete organization
- **Auth**: Super admin only
- **Body**: `{ confirmation: string, deleteAllData?: boolean }`
- **Response**: `{ success: true, message: string, deletedRecords: number }`

#### `GET /super-admin/organizations/:id/users`
List organization users
- **Auth**: Super admin only
- **Query**: `role?, status?, page?, limit?`
- **Response**: `{ success: true, data: users[], pagination: {...} }`

---

### 29. Super Admin - User Management

#### `GET /super-admin/users`
List all platform users
- **Auth**: Super admin only
- **Query**: `organizationId?, role?, status?, search?, page?, limit?`
- **Response**: `{ success: true, data: users[], pagination: {...} }`

#### `GET /super-admin/users/:id`
Get user details
- **Auth**: Super admin only
- **Response**: `{ success: true, data: user }`

---

### 30. Super Admin - Subscription Management

#### `GET /super-admin/subscription-requests`
List subscription change requests
- **Auth**: Super admin only
- **Query**: `status?, page?, limit?`
- **Response**: `{ success: true, data: requests[], pagination: {...} }`

#### `POST /super-admin/subscription-requests/:id/approve`
Approve subscription change
- **Auth**: Super admin only
- **Body**: `{ comment?: string, effectiveDate?: ISO }`
- **Response**: `{ success: true, message: string }`

#### `POST /super-admin/subscription-requests/:id/reject`
Reject subscription change
- **Auth**: Super admin only
- **Body**: `{ reason: string }`
- **Response**: `{ success: true, message: string }`

#### `POST /super-admin/subscriptions/:id/extend-trial`
Extend trial period
- **Auth**: Super admin only
- **Body**: `{ days: number (1-90), reason: string }`
- **Response**: `{ success: true, message: string, data: { newTrialEndDate } }`

---

### 31. Super Admin - Reactivation Requests

#### `GET /super-admin/reactivation-requests`
List reactivation requests
- **Auth**: Super admin only
- **Query**: `status?, page?, limit?`
- **Response**: `{ success: true, data: requests[], pagination: {...} }`

#### `POST /super-admin/reactivation-requests/:id/approve`
Approve reactivation
- **Auth**: Super admin only
- **Body**: `{ comment?: string }`
- **Response**: `{ success: true, message: string }`

#### `POST /super-admin/reactivation-requests/:id/reject`
Reject reactivation
- **Auth**: Super admin only
- **Body**: `{ reason: string }`
- **Response**: `{ success: true, message: string }`

---

### 32. Super Admin - Subscription Plans

#### `GET /super-admin/plans`
List subscription plans
- **Auth**: Super admin only
- **Response**: `{ success: true, data: plans[] }`

#### `POST /super-admin/plans`
Create subscription plan
- **Auth**: Super admin only
- **Body**:
  ```json
  {
    "tier": "string (unique)",
    "name": "string",
    "description": "string",
    "monthlyPrice": "number",
    "yearlyPrice": "number",
    "currency": "string",
    "limits": {
      "maxStudents": "number",
      "maxClasses": "number",
      "maxTeachers": "number",
      "maxStorage": "number"
    },
    "displayOrder": "number",
    "isActive": "boolean"
  }
  ```
- **Response**: `{ success: true, message: string, data: plan }`

#### `PATCH /super-admin/plans/:id`
Update subscription plan
- **Auth**: Super admin only
- **Body**: `{ name?, description?, monthlyPrice?, yearlyPrice?, limits?, isActive? }`
- **Response**: `{ success: true, message: string, data: plan }`

---

## Middleware Chain

All authenticated routes follow this pattern:

```javascript
app.get('/protected-route',
  ensureDBConnection,
  authenticateUser,
  enforceOrganizationIsolation,
  checkOrganizationSuspension,
  requirePermission('permission_name'),
  async (req, res) => {
    // Route handler
  }
);
```

### Middleware Breakdown

1. **ensureDBConnection**: Ensures MongoDB connection is active
2. **authenticateUser**: Verifies authentication, populates `req.user`, `req.userId`, `req.userRole`, `req.organizationId`
3. **enforceOrganizationIsolation**: Ensures user belongs to the organization in request context
4. **checkOrganizationSuspension**: Blocks suspended organizations
5. **requirePermission(permission)**: Checks if user role has required permission

---

## Error Handling

### Standard Error Response
```json
{
  "success": false,
  "message": "Human-readable error description",
  "error": "Technical error message"
}
```

### HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request (validation errors)
- `401` - Unauthorized (authentication failed)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict (duplicate records)
- `500` - Internal Server Error

### Common Error Scenarios
- **Duplicate key**: Unique constraint violation (e.g., duplicate email)
- **Missing required fields**: Validation error
- **Organization suspended**: 403 with suspension message
- **Usage limit exceeded**: 403 with limit details
- **Permission denied**: 403 with permission name

---

## Development Notes

### Database Indexes
All indexes are automatically created on server startup via `createIndexes()` function. Critical indexes:
- **Unique**: email, firebaseUid (sparse), slug, admissionNumber, receiptNumber
- **Compound**: organizationId + various fields for multi-tenant queries
- **Performance**: createdAt (DESC), date fields, foreign keys

### Helper Functions
- **calculateGrade(marks, fullMarks)**: Converts marks to letter grade (A+, A, A-, B, C, D, F)
- **generateReceiptNumber()**: Format: `SLUG-YYYY-NNNNN`
- **calculateFeeStatus(totalAmount, paidAmount, dueDate)**: Returns "paid", "partial", "overdue", "unpaid"
- **createNotification(userId, type, title, message, link, organizationId)**: Creates notification
- **createBulkNotifications(users, type, title, message, link, organizationId)**: Fan-out notifications
- **logActivity(userId, action, resource, resourceId, details, organizationId)**: Audit logging
- **checkUsageLimits(organizationId, limitType, newCount)**: Subscription limit enforcement
- **getTeacherDocForCurrentUser(userId, organizationId)**: Fetch teacher record from user
- **escapeCsvField(value)**: CSV escaping for exports
- **buildCsvString(rows)**: Build CSV string from array of objects

### Key Patterns
- **Upsert operations**: Attendance and fee generation use unique indexes to prevent duplicates
- **Soft deletes**: Students, classes use `status: "inactive"` instead of deletion
- **Cascade operations**: Deleting class soft-deletes sections, subjects, students
- **Bidirectional links**: Parent.children[] ↔ Student.parentId, Teacher.subjects[] ↔ Subject.teacherId
- **Auto-calculation**: Roll numbers, receipt numbers, grade letters, fee status
- **Atomic state transitions**: Grade submission workflow uses `findOneAndUpdate` for atomicity

### Testing
```bash
# Run tests (if test suite exists)
npm test

# Manual testing with curl
curl http://localhost:3000/health
curl -H "Authorization: Bearer <token>" http://localhost:3000/users/me
```

### Logging
- Uses custom Winston logger from `./utils/logger.js`
- Log levels: error, warn, info, debug
- All errors logged with stack traces
- Activity logs stored in database for audit

---

## API Summary

**Total Endpoints**: 165+

**By Module**:
- Health/Status: 2
- Subscriptions: 2
- Organizations: 4
- Users: 6
- Classes: 4
- Sections: 4
- Subjects: 4
- Students: 7
- Teachers: 7
- Parents: 5
- Documents: 3
- Attendance: 4
- Exams: 5
- Grade Submissions: 11
- Results: 3
- Notifications: 3
- Fee Structures: 4
- Student Fees: 3
- Payments: 3
- Fee Reports: 2
- Expenses: 4
- Salaries: 5
- Announcements: 4
- Reports: 4
- Exports: 4
- Activity Logs: 1
- Super Admin: 30+

---

## Contributing

1. Follow the existing middleware chain pattern
2. Always add `organizationId` scoping to new collections
3. Log all mutations using `logActivity()`
4. Add indexes for new queries
5. Use atomic operations for state transitions
6. Validate inputs and handle errors gracefully

---

## License

Proprietary - RootX School Management System

---

## Support

For issues or questions, contact the development team or file an issue in the project repository.

**Version**: 1.0.0 (Phase 7 in progress)
**Last Updated**: 2026-02-15
