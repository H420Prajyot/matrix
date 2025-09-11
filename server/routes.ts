import type { Express } from "express";
import { createServer, type Server } from "http";
import multer from "multer";
import path from "path";
import fs from "fs";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./replitAuth";
import { insertProjectSchema, insertVulnerabilitySchema, insertUserSchema } from "@shared/schema";

// Configure multer for file uploads
const uploadDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
  }),
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/json'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, DOCX, and JSON files are allowed.'));
    }
  },
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
  }
});

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);

  // Development only - simulate login for testing
  if (process.env.NODE_ENV === 'development') {
    const handleDevLogin = async (req: any, res: any) => {
      try {
        const userId = req.body?.userId || req.query?.userId || 'dev-user';
        const role = req.body?.role || req.query?.role;
        
        let user = await storage.getUser(userId);
        if (!user) {
          // Check if this is the first user (make them admin)
          const existingUsers = await storage.getUsersByRole('admin');
          const isFirstUser = existingUsers.length === 0;
          
          // Determine the role based on intended role or fallback logic
          let userRole: 'admin' | 'pentester' | 'client';
          if (role && ['admin', 'pentester', 'client'].includes(role)) {
            userRole = role as 'admin' | 'pentester' | 'client';
          } else if (isFirstUser) {
            userRole = 'admin';
          } else {
            userRole = 'client';
          }
          
          // Create new user
          user = await storage.upsertUser({
            id: userId,
            email: `${userId}@dev.local`,
            firstName: 'Dev',
            lastName: 'User',
            profileImageUrl: null,
            role: userRole,
          });
        }
        
        // Simulate authenticated session with all required fields
        const userSession = {
          claims: { sub: user.id },
          expires_at: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60), // 7 days from now
          access_token: 'dev-token',
          refresh_token: 'dev-refresh-token'
        };
        
        req.login(userSession, (err: any) => {
          if (err) {
            console.error('Dev login session error:', err);
            return res.status(500).json({ message: 'Login session failed' });
          }
          res.json({ message: 'Login successful', user });
        });
      } catch (error) {
        console.error('Dev login error:', error);
        res.status(500).json({ message: 'Login failed' });
      }
    };

    app.get('/api/dev-login', handleDevLogin);
    app.post('/api/dev-login', handleDevLogin);
  }

  // Auth routes
  app.get('/api/auth/user', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Dashboard statistics
  app.get('/api/dashboard/stats', isAuthenticated, async (req: any, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({ message: "Failed to fetch dashboard statistics" });
    }
  });

  app.get('/api/dashboard/vulnerability-stats', isAuthenticated, async (req: any, res) => {
    try {
      const stats = await storage.getVulnerabilityStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching vulnerability stats:", error);
      res.status(500).json({ message: "Failed to fetch vulnerability statistics" });
    }
  });

  // User management routes (Admin only)
  app.get('/api/users', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      const { role } = req.query;
      let users;
      if (role && ['admin', 'pentester', 'client'].includes(role as string)) {
        users = await storage.getUsersByRole(role as 'admin' | 'pentester' | 'client');
      } else {
        const [admins, pentesters, clients] = await Promise.all([
          storage.getUsersByRole('admin'),
          storage.getUsersByRole('pentester'),
          storage.getUsersByRole('client')
        ]);
        users = [...admins, ...pentesters, ...clients];
      }
      res.json(users);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  app.post('/api/users', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      const userData = insertUserSchema.parse(req.body);
      const user = await storage.createUser(userData);
      
      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'created',
        resourceType: 'user',
        resourceId: user.id,
        details: { role: user.role },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.status(201).json(user);
    } catch (error) {
      console.error("Error creating user:", error);
      res.status(500).json({ message: "Failed to create user" });
    }
  });

  // Update user
  app.put('/api/users/:id', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      const userId = req.params.id;
      const userData = req.body;
      
      // Don't allow updating the user's own account to prevent lockout
      if (userId === currentUser.id && userData.role && userData.role !== 'admin') {
        return res.status(400).json({ message: "Cannot change your own admin role" });
      }

      const user = await storage.updateUser(userId, userData);
      
      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'updated',
        resourceType: 'user',
        resourceId: user.id,
        details: { changes: userData },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(user);
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ message: "Failed to update user" });
    }
  });

  // Delete user
  app.delete('/api/users/:id', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      const userId = req.params.id;
      
      // Don't allow deleting own account
      if (userId === currentUser.id) {
        return res.status(400).json({ message: "Cannot delete your own account" });
      }

      // Check if user exists
      const userToDelete = await storage.getUser(userId);
      if (!userToDelete) {
        return res.status(404).json({ message: "User not found" });
      }

      await storage.deleteUser(userId);
      
      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'deleted',
        resourceType: 'user',
        resourceId: userId,
        details: { deletedUser: userToDelete },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.status(204).send();
    } catch (error) {
      console.error("Error deleting user:", error);
      res.status(500).json({ message: "Failed to delete user" });
    }
  });

  // Project routes
  app.get('/api/projects', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      let projects;

      if (currentUser?.role === 'admin') {
        projects = await storage.getAllProjects();
      } else if (currentUser?.role === 'pentester') {
        projects = await storage.getProjectsByPentester(req.user.claims.sub);
      } else if (currentUser?.role === 'client') {
        projects = await storage.getProjectsByClient(req.user.claims.sub);
      } else {
        return res.status(403).json({ message: "Access denied" });
      }

      res.json(projects);
    } catch (error) {
      console.error("Error fetching projects:", error);
      res.status(500).json({ message: "Failed to fetch projects" });
    }
  });

  app.post('/api/projects', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      const projectData = insertProjectSchema.parse(req.body);
      const project = await storage.createProject(projectData);

      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'created',
        resourceType: 'project',
        resourceId: project.id,
        details: { name: project.name, clientId: project.clientId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.status(201).json(project);
    } catch (error) {
      console.error("Error creating project:", error);
      res.status(500).json({ message: "Failed to create project" });
    }
  });

  app.get('/api/projects/:id', isAuthenticated, async (req: any, res) => {
    try {
      const project = await storage.getProjectById(req.params.id);
      if (!project) {
        return res.status(404).json({ message: "Project not found" });
      }

      const currentUser = await storage.getUser(req.user.claims.sub);
      
      // Check access permissions
      const hasAccess = 
        currentUser?.role === 'admin' ||
        (currentUser?.role === 'client' && project.clientId === req.user.claims.sub) ||
        (currentUser?.role === 'pentester' && project.assignments.some(a => a.pentesterId === req.user.claims.sub));

      if (!hasAccess) {
        return res.status(403).json({ message: "Access denied" });
      }

      res.json(project);
    } catch (error) {
      console.error("Error fetching project:", error);
      res.status(500).json({ message: "Failed to fetch project" });
    }
  });

  app.post('/api/projects/:id/assign', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      const { pentesterId } = req.body;
      const assignment = await storage.assignPentesterToProject(req.params.id, pentesterId);

      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'updated',
        resourceType: 'project',
        resourceId: req.params.id,
        details: { action: 'assigned_pentester', pentesterId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.status(201).json(assignment);
    } catch (error) {
      console.error("Error assigning pentester:", error);
      res.status(500).json({ message: "Failed to assign pentester" });
    }
  });

  app.patch('/api/projects/:id/progress', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'pentester') {
        return res.status(403).json({ message: "Access denied. Pentester role required." });
      }

      const { progress } = req.body;
      const project = await storage.updateProjectProgress(req.params.id, progress);

      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'updated',
        resourceType: 'project',
        resourceId: req.params.id,
        details: { progress },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(project);
    } catch (error) {
      console.error("Error updating project progress:", error);
      res.status(500).json({ message: "Failed to update project progress" });
    }
  });

  // Update project (admin only)
  app.put('/api/projects/:id', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      // Check if project exists
      const existingProject = await storage.getProjectById(req.params.id);
      if (!existingProject) {
        return res.status(404).json({ message: "Project not found" });
      }

      const projectData = insertProjectSchema.parse(req.body);
      const updatedProject = await storage.updateProject(req.params.id, projectData);

      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'updated',
        resourceType: 'project',
        resourceId: req.params.id,
        details: { name: projectData.name, clientId: projectData.clientId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(updatedProject);
    } catch (error) {
      console.error("Error updating project:", error);
      if (error instanceof Error && error.message.includes('validation')) {
        res.status(400).json({ message: error.message });
      } else {
        res.status(500).json({ message: "Failed to update project" });
      }
    }
  });

  // Delete project (admin only)
  app.delete('/api/projects/:id', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      // Check if project exists
      const existingProject = await storage.getProjectById(req.params.id);
      if (!existingProject) {
        return res.status(404).json({ message: "Project not found" });
      }

      await storage.deleteProject(req.params.id);

      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'deleted',
        resourceType: 'project',
        resourceId: req.params.id,
        details: { name: existingProject.name },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.status(204).send();
    } catch (error) {
      console.error("Error deleting project:", error);
      res.status(500).json({ message: "Failed to delete project" });
    }
  });

  // Vulnerability routes
  app.get('/api/vulnerabilities', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      const { projectId } = req.query;

      let vulnerabilities;
      if (projectId) {
        vulnerabilities = await storage.getVulnerabilitiesByProject(projectId as string);
        
        // Check access permissions for the project
        const project = await storage.getProjectById(projectId as string);
        if (!project) {
          return res.status(404).json({ message: "Project not found" });
        }

        const hasAccess = 
          currentUser?.role === 'admin' ||
          (currentUser?.role === 'client' && project.clientId === req.user.claims.sub) ||
          (currentUser?.role === 'pentester' && project.assignments.some(a => a.pentesterId === req.user.claims.sub));

        if (!hasAccess) {
          return res.status(403).json({ message: "Access denied" });
        }
      } else if (currentUser?.role === 'pentester') {
        vulnerabilities = await storage.getVulnerabilitiesByPentester(req.user.claims.sub);
      } else {
        return res.status(400).json({ message: "Project ID required for non-pentester users" });
      }

      res.json(vulnerabilities);
    } catch (error) {
      console.error("Error fetching vulnerabilities:", error);
      res.status(500).json({ message: "Failed to fetch vulnerabilities" });
    }
  });

  app.post('/api/vulnerabilities', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'pentester') {
        return res.status(403).json({ message: "Access denied. Pentester role required." });
      }

      const vulnerabilityData = insertVulnerabilitySchema.parse({
        ...req.body,
        pentesterId: req.user.claims.sub,
      });

      const vulnerability = await storage.createVulnerability(vulnerabilityData);

      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'created',
        resourceType: 'vulnerability',
        resourceId: vulnerability.id,
        details: { title: vulnerability.title, severity: vulnerability.severity, projectId: vulnerability.projectId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Create notification for project client
      const project = await storage.getProjectById(vulnerability.projectId);
      if (project) {
        await storage.createNotification({
          userId: project.clientId,
          title: 'New Vulnerability Found',
          message: `A ${vulnerability.severity} severity vulnerability "${vulnerability.title}" has been discovered in your project "${project.name}".`,
          type: 'vulnerability_found',
          relatedResourceType: 'vulnerability',
          relatedResourceId: vulnerability.id,
        });
      }

      res.status(201).json(vulnerability);
    } catch (error) {
      console.error("Error creating vulnerability:", error);
      res.status(500).json({ message: "Failed to create vulnerability" });
    }
  });

  // Report routes
  app.post('/api/reports/upload', isAuthenticated, upload.single('report'), async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'pentester') {
        return res.status(403).json({ message: "Access denied. Pentester role required." });
      }

      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      const { projectId } = req.body;
      if (!projectId) {
        return res.status(400).json({ message: "Project ID is required" });
      }

      // Mark old reports as not latest
      await storage.markOldReportsAsNotLatest(projectId);

      const reportData = {
        projectId,
        pentesterId: req.user.claims.sub,
        filename: req.file.filename,
        originalName: req.file.originalname,
        fileSize: req.file.size,
        mimeType: req.file.mimetype,
        version: 1, // TODO: Implement proper versioning
        isLatest: true,
      };

      const report = await storage.createReport(reportData);

      // Create audit log
      await storage.createAuditLog({
        userId: req.user.claims.sub,
        action: 'created',
        resourceType: 'report',
        resourceId: report.id,
        details: { projectId, filename: report.originalName },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Create notification for project client
      const project = await storage.getProjectById(projectId);
      if (project) {
        await storage.createNotification({
          userId: project.clientId,
          title: 'New Report Uploaded',
          message: `A new report "${report.originalName}" has been uploaded for your project "${project.name}".`,
          type: 'report_uploaded',
          relatedResourceType: 'report',
          relatedResourceId: report.id,
        });
      }

      res.status(201).json(report);
    } catch (error) {
      console.error("Error uploading report:", error);
      res.status(500).json({ message: "Failed to upload report" });
    }
  });

  app.get('/api/reports/:projectId', isAuthenticated, async (req: any, res) => {
    try {
      const project = await storage.getProjectById(req.params.projectId);
      if (!project) {
        return res.status(404).json({ message: "Project not found" });
      }

      const currentUser = await storage.getUser(req.user.claims.sub);
      
      // Check access permissions
      const hasAccess = 
        currentUser?.role === 'admin' ||
        (currentUser?.role === 'client' && project.clientId === req.user.claims.sub) ||
        (currentUser?.role === 'pentester' && project.assignments.some(a => a.pentesterId === req.user.claims.sub));

      if (!hasAccess) {
        return res.status(403).json({ message: "Access denied" });
      }

      const reports = await storage.getReportsByProject(req.params.projectId);
      res.json(reports);
    } catch (error) {
      console.error("Error fetching reports:", error);
      res.status(500).json({ message: "Failed to fetch reports" });
    }
  });

  app.get('/api/reports/download/:reportId', isAuthenticated, async (req: any, res) => {
    try {
      const { reportId } = req.params;
      const currentUser = await storage.getUser(req.user.claims.sub);
      
      if (!currentUser) {
        return res.status(404).json({ message: "User not found" });
      }

      // Get the report with project details for access control
      const report = await storage.getReportById(reportId);
      if (!report) {
        return res.status(404).json({ message: "Report not found" });
      }

      // Check access permissions:
      // - Admins can download any report
      // - Pentesters can download reports for projects they're assigned to
      // - Clients can download reports for their own projects
      let hasAccess = false;
      
      if (currentUser.role === 'admin') {
        hasAccess = true;
      } else if (currentUser.role === 'client') {
        // Check if this is the client's project
        const project = await storage.getProjectById(report.projectId);
        hasAccess = project?.clientId === currentUser.id;
      } else if (currentUser.role === 'pentester') {
        // Check if pentester is assigned to the project
        const assignments = await storage.getProjectsByPentester(currentUser.id);
        hasAccess = assignments.some(p => p.id === report.projectId);
      }

      if (!hasAccess) {
        return res.status(403).json({ message: "Access denied. You don't have permission to download this report." });
      }

      // Check if file exists
      const filePath = path.join(process.cwd(), 'uploads', report.filename);
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: "Report file not found on server" });
      }

      // Log the download for audit purposes
      await storage.createAuditLog({
        userId: currentUser.id,
        action: 'downloaded',
        resourceType: 'report',
        resourceId: reportId,
        details: { fileName: report.filename }
      });

      // Send the file
      res.download(filePath, report.originalName || report.filename, (err) => {
        if (err) {
          console.error('Download error:', err);
          if (!res.headersSent) {
            res.status(500).json({ message: "Error downloading file" });
          }
        }
      });
    } catch (error) {
      console.error("Error downloading report:", error);
      res.status(500).json({ message: "Failed to download report" });
    }
  });

  // Notification routes
  app.get('/api/notifications', isAuthenticated, async (req: any, res) => {
    try {
      const notifications = await storage.getNotificationsByUser(req.user.claims.sub);
      res.json(notifications);
    } catch (error) {
      console.error("Error fetching notifications:", error);
      res.status(500).json({ message: "Failed to fetch notifications" });
    }
  });

  app.patch('/api/notifications/:id/read', isAuthenticated, async (req: any, res) => {
    try {
      const notification = await storage.markNotificationAsRead(req.params.id);
      res.json(notification);
    } catch (error) {
      console.error("Error marking notification as read:", error);
      res.status(500).json({ message: "Failed to mark notification as read" });
    }
  });

  app.get('/api/notifications/unread-count', isAuthenticated, async (req: any, res) => {
    try {
      const count = await storage.getUnreadNotificationCount(req.user.claims.sub);
      res.json({ count });
    } catch (error) {
      console.error("Error fetching unread notification count:", error);
      res.status(500).json({ message: "Failed to fetch unread notification count" });
    }
  });

  // Audit log routes (Admin only)
  app.get('/api/audit-logs', isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await storage.getUser(req.user.claims.sub);
      if (currentUser?.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      const logs = await storage.getRecentAuditLogs(100);
      res.json(logs);
    } catch (error) {
      console.error("Error fetching audit logs:", error);
      res.status(500).json({ message: "Failed to fetch audit logs" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
