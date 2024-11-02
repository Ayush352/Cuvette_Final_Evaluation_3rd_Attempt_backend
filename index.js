const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
var cors = require('cors')
const dotenv = require('dotenv')
dotenv.config()
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios')
const crypto = require('crypto');

const shareLinks = new Map();

const app = express()

app.use(cors());
app.use(bodyParser.urlencoded({extended:true}))
app.use(bodyParser.json())

const PORT = process.env.PORT || 4000;

app.get('/', (req, res) => {
    res.json({
      status: 'Server is up :)',
      now: new Date()
    })
  })

  const taskUserSchema = new mongoose.Schema({
    name: {
      type: String,
      required: true,
      trim: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true
    },
    password: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  });

  const checklistItemSchema = new mongoose.Schema({
    _id: {
        type: mongoose.Schema.Types.ObjectId,
        auto: true
    },
    text: {
        type: String,
        required: true,
    },
    isCompleted: {
        type: Boolean,
        default: false,
    },
});

const taskSchema = new mongoose.Schema({
  title: {
      type: String,
      required: [true, 'Task title is required'],
      trim: true,
  },
  priority: {
      type: String,
      enum: ['high', 'moderate', 'low'],
      required: [true, 'Priority is required'],
  },
  checklist: {
      type: [checklistItemSchema],
      validate: {
          validator: function(v) {
              return v && v.length > 0;
          },
          message: 'At least one checklist item is required',
      },
      required: true,
  },
  assignTo: {
      type: String,
      trim: true,
  },
  dueDate: {
      type: Date,
  },
  status: {                 
      type: String,
      enum: ['backlog', 'todo', 'inProgress', 'done'],
      default: 'todo',        
      required: true
  },
  createdBy: {               
      type: mongoose.Schema.Types.ObjectId,
      ref: 'TaskUser',
      required: true
  },
}, 
{
  timestamps: true,
}

);

  const Task = mongoose.model('Task', taskSchema);
  
  const TaskUser = mongoose.model('TaskUser', taskUserSchema);
  
  const validateRegistration = (req, res, next) => {
    const { name, email, password, confirmPassword } = req.body;
  
    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }
  
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
  
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }
  
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
  
    next();
  };

  const hasTaskPermission = (task, userId, userEmail) => {
    return task.createdBy.toString() === userId.toString() || task.assignTo === userEmail;
};

const findRelatedTasks = async (task) => {
  return Task.find({
      $and: [
          {
              $or: [
                  {
                      title: task.title,
                      createdBy: task.createdBy,
                      dueDate: task.dueDate,
                      priority: task.priority
                  },
                  {
                      title: task.title,
                      assignTo: { $ne: null },
                      createdBy: task.createdBy,
                      dueDate: task.dueDate,
                      priority: task.priority
                  }
              ]
          }
      ]
  });
};
  
  
  app.post('/register', validateRegistration, async (req, res) => {
    try {
      const { name, email, password } = req.body;
  
      const existingUser = await TaskUser.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'Email already registered' });
      }
  
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
  
      const user = new TaskUser({
        name,
        email,
        password: hashedPassword
      });
  
      await user.save();
  
      const token = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
  
      res.status(201).json({
        message: 'Registration successful',
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email
        }
      });
  
    } catch (error) {
      console.error('Registration error:', error.message); 
      res.status(500).json({ error: 'Server error' });
    }
  });
  
  
  app.post('/login', async (req, res) => {
    try {
      const { email, password } = req.body;
  
      const user = await TaskUser.findOne({ email });
      if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }
  
      const token = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
  
      res.json({
        message: 'Login successful',
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email
        }
      });
  
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  });
  
  const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) {
            throw new Error('No token provided');
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            const currentTimestamp = Math.floor(Date.now() / 1000);
            if (decoded.exp < currentTimestamp) {
                return res.status(401).json({ 
                    error: 'Token expired', 
                    code: 'TOKEN_EXPIRED'
                });
            }

            const user = await TaskUser.findOne({ _id: decoded.userId });
            if (!user) {
                throw new Error('User not found');
            }

            req.user = user;
            req.token = token;
            next();
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ 
                    error: 'Token expired', 
                    code: 'TOKEN_EXPIRED'
                });
            }
            throw error;
        }
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

  app.get('/users', auth, async (req, res) => {
    try {
        const users = await TaskUser.find({})
            .select('-password -__v')
            .sort({ createdAt: -1 });

        const sanitizedUsers = users.map(user => ({
            id: user._id,
            name: user.name,
            email: user.email,
            createdAt: user.createdAt
        }));

        res.json({
            success: true,
            count: users.length,
            users: sanitizedUsers
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ 
            success: false,
            error: 'Error fetching users' 
        });
    }
});

app.get('/getTasks', auth, async (req, res) => {
  try {
      const { filter = 'week' } = req.query;
      
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      let startDate;
      
      switch(filter) {
          case 'today':
              startDate = today;
              break;
              
          case 'week':
              startDate = new Date(today);
              const day = startDate.getDay();
              const diff = startDate.getDate() - day + (day === 0 ? -6 : 1); 
              startDate.setDate(diff);
              startDate.setHours(0, 0, 0, 0);
              break;
              
          case 'month':
              startDate = new Date(today.getFullYear(), today.getMonth(), 1);
              break;
              
          default:
              startDate = new Date(today);
              const defaultDay = startDate.getDay();
              const defaultDiff = startDate.getDate() - defaultDay + (defaultDay === 0 ? -6 : 1);
              startDate.setDate(defaultDiff);
              startDate.setHours(0, 0, 0, 0);
      }

      let endDate = new Date();
      if (filter === 'week') {
          endDate = new Date(startDate);
          endDate.setDate(startDate.getDate() + 6);
          endDate.setHours(23, 59, 59, 999);
      } else if (filter === 'today') {
          endDate.setHours(23, 59, 59, 999);
      }

      const tasks = await Task.find({
          $and: [
              {
                  $or: [
                      { createdBy: req.user._id },
                      { assignTo: req.user.email }
                  ]
              },
              {
                  createdAt: {
                      $gte: startDate,
                      $lte: endDate
                  }
              }
          ]
      })
      .populate({
          path: 'createdBy',
          select: 'name email'
      })
      .sort({ createdAt: -1 });

      const formattedTasks = tasks.map(task => ({
          _id: task._id,
          title: task.title,
          priority: task.priority,
          checklist: task.checklist.map(item => ({
              _id: item._id,
              text: item.text,
              isCompleted: item.isCompleted
          })),
          dueDate: task.dueDate,
          status: task.status || 'todo',
          assignTo: task.assignTo,
          createdBy: {
              name: task.createdBy.name,
              email: task.createdBy.email
          },
          createdAt: task.createdAt
      }));

      res.status(200).json({
          success: true,
          count: tasks.length,
          tasks: formattedTasks,
          dateRange: {
              start: startDate,
              end: endDate
          }
      });

  } catch (error) {
      console.error('Error fetching tasks:', error);
      res.status(500).json({ 
          success: false,
          error: 'Server error while fetching tasks' 
      });
  }
});


app.patch('/tasks/:taskId/checklist/:itemId', auth, async (req, res) => {
  try {
      const { taskId, itemId } = req.params;
      const { isCompleted } = req.body;

      const task = await Task.findById(taskId).populate('createdBy', 'name email');

      if (!task) {
          return res.status(404).json({ error: 'Task not found' });
      }

      const hasPermission = task.createdBy._id.toString() === req.user._id.toString() || 
                          task.assignTo === req.user.email;
                          
      if (!hasPermission) {
          return res.status(403).json({ error: 'No permission to modify this task' });
      }

      const checklistItem = task.checklist.id(itemId);
      if (!checklistItem) {
          return res.status(404).json({ error: 'Checklist item not found' });
      }

      checklistItem.isCompleted = isCompleted;
      await task.save();

      res.json({
          success: true,
          task: {
              ...task.toObject(),
              createdBy: {
                  _id: task.createdBy._id,
                  name: task.createdBy.name,
                  email: task.createdBy.email
              }
          }
      });
  } catch (error) {
      console.error('Error updating checklist item:', error);
      res.status(500).json({ 
          success: false,
          error: 'Server error while updating checklist item'
      });
  }
});


app.post('/tasks', auth, async (req, res) => {
  try {
      const { title, priority, checklist, assignTo, dueDate, status } = req.body;

      if (!title || !priority || !checklist || checklist.length === 0) {
          return res.status(400).json({ error: 'Title, priority, and checklist are required' });
      }

      const task = new Task({
          title,
          priority,
          checklist: checklist.map(item => ({
              text: item.text,
              isCompleted: item.isCompleted || false
          })),
          assignTo,
          dueDate,
          status: status || 'todo',
          createdBy: req.user._id
      });

      const savedTask = await task.save();
      const populatedTask = await Task.findById(savedTask._id);

      res.status(201).json({
          success: true,
          task: populatedTask
      });
  } catch (error) {
      console.error('Error creating task:', error);
      res.status(500).json({ 
          success: false,
          error: 'Server error' 
      });
  }
});

app.patch('/tasks/:taskId/status', auth, async (req, res) => {
  try {
      const { taskId } = req.params;
      const { status } = req.body;

      const task = await Task.findById(taskId);
      if (!task) {
          return res.status(404).json({ error: 'Task not found' });
      }

      const relatedTasks = await Task.find({
          title: task.title,
          createdBy: task.createdBy,
          dueDate: task.dueDate,
          priority: task.priority
      });

      await Promise.all(
          relatedTasks.map(async (relatedTask) => {
              relatedTask.status = status;
              await relatedTask.save();
          })
      );

      res.json({
          success: true,
          task: {
              ...task.toObject(),
              status
          }
      });
  } catch (error) {
      console.error('Error updating task status:', error);
      res.status(500).json({ error: 'Server error' });
  }
});



app.delete('/tasks/:taskId', auth, async (req, res) => {
  try {
      const { taskId } = req.params;
      
      const task = await Task.findById(taskId);
      if (!task) {
          return res.status(404).json({ error: 'Task not found' });
      }

      const relatedTasks = await Task.find({
          title: task.title,
          createdBy: task.createdBy,
          dueDate: task.dueDate,
          priority: task.priority
      });

      await Promise.all(
          relatedTasks.map(async (relatedTask) => {
              await Task.findByIdAndDelete(relatedTask._id);
          })
      );

      res.json({ 
          success: true,
          message: 'Tasks deleted successfully'
      });
  } catch (error) {
      console.error('Error deleting task:', error);
      res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/tasks/:taskId', auth, async (req, res) => {
  try {
      const { taskId } = req.params;
      const updates = req.body;

      const task = await Task.findById(taskId);

      if (!task) {
          return res.status(404).json({ 
              success: false,
              error: 'Task not found'
          });
      }

      if (!hasTaskPermission(task, req.user._id, req.user.email)) {
          return res.status(403).json({ 
              success: false,
              error: 'No permission to modify this task'
          });
      }

      if (updates.checklist) {
          updates.checklist = updates.checklist.map(item => ({
              ...item,
              _id: item._id || new mongoose.Types.ObjectId()
          }));
      }

      const updatedTask = await Task.findOneAndUpdate(
          { _id: taskId },
          {
              ...updates,
              createdBy: task.createdBy 
          },
          { 
              new: true, 
              runValidators: true 
          }
      ).populate('createdBy', 'name email');

      res.json({
          success: true,
          task: {
              ...updatedTask.toObject(),
              createdBy: {
                  _id: updatedTask.createdBy._id,
                  name: updatedTask.createdBy.name,
                  email: updatedTask.createdBy.email
              }
          }
      });
  } catch (error) {
      console.error('Error updating task:', error);
      res.status(500).json({ 
          success: false,
          error: 'Server error while updating task'
      });
  }
});

app.patch('/settings/name', auth, async (req, res) => {
  try {
      const { name } = req.body;
      if (!name.trim()) {
          return res.status(400).json({ error: 'Name is required' });
      }

      const user = await TaskUser.findByIdAndUpdate(
          req.user._id,
          { name },
          { new: true }
      );

      res.json({
          success: true,
          user: {
              id: user._id,
              name: user.name,
              email: user.email
          }
      });
  } catch (error) {
      res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/settings/email', auth, async (req, res) => {
  try {
      const { email } = req.body;
      if (!email.trim()) {
          return res.status(400).json({ error: 'Email is required' });
      }

      const existingUser = await TaskUser.findOne({ email, _id: { $ne: req.user._id } });
      if (existingUser) {
          return res.status(400).json({ error: 'Email already in use' });
      }

      const user = await TaskUser.findByIdAndUpdate(
          req.user._id,
          { email },
          { new: true }
      );

      res.json({
          success: true,
          user: {
              id: user._id,
              name: user.name,
              email: user.email
          }
      });
  } catch (error) {
      res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/settings/password', auth, async (req, res) => {
  try {
      const { oldPassword, newPassword } = req.body;

      const user = await TaskUser.findById(req.user._id);
      
      const isMatch = await bcrypt.compare(oldPassword, user.password);
      if (!isMatch) {
          return res.status(400).json({ error: 'Current password is incorrect' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      user.password = hashedPassword;
      await user.save();

      res.json({ success: true });
  } catch (error) {
      res.status(500).json({ error: 'Server error' });
  }
});


app.post('/inviteUser', auth, async (req, res) => {
  try {
      const { email } = req.body;
      
      const invitedUser = await TaskUser.findOne({ email });
      if (!invitedUser) {
          return res.status(404).json({ error: 'User not found' });
      }

      const currentUserTasks = await Task.find({ 
          createdBy: req.user._id,
      });

      if (currentUserTasks.length === 0) {
          return res.json({
              success: true,
              message: 'No tasks to share'
          });
      }

      await Promise.all(
          currentUserTasks.map(async (task) => {
              task.assignTo = email;
              await task.save();
          })
      );

      res.json({ 
          success: true,
          message: `Successfully shared ${currentUserTasks.length} tasks`
      });

  } catch (error) {
      console.error('Error inviting user:', error);
      res.status(500).json({ error: 'Failed to add user' });
  }
});

app.post('/tasks/:taskId/share', auth, async (req, res) => {
  try {
      const { taskId } = req.params;
      const task = await Task.findById(taskId);
      
      if (!task) {
          return res.status(404).json({ error: 'Task not found' });
      }

      const shareId = crypto.randomBytes(16).toString('hex');
      
      shareLinks.set(shareId, taskId);
      setTimeout(() => shareLinks.delete(shareId), 24 * 60 * 60 * 1000);

      const baseUrl = 'https://cuvette-final-evaluation-3rd-attempt-frontend-heu1.vercel.app';
      const shareUrl = `${baseUrl}/share/${shareId}`;

      res.json({ 
          success: true,
          shareUrl 
      });
  } catch (error) {
      res.status(500).json({ error: 'Failed to generate share link' });
  }
});

app.get('/tasks/share/:shareId', async (req, res) => {
  try {
      const { shareId } = req.params;
      const taskId = shareLinks.get(shareId);

      if (!taskId) {
          return res.status(404).json({ error: 'Share link not found or expired' });
      }

      const task = await Task.findById(taskId)
          .populate('createdBy', 'name email');

      if (!task) {
          return res.status(404).json({ error: 'Task not found' });
      }

      res.json({
          success: true,
          task
      });
  } catch (error) {
      res.status(500).json({ error: 'Failed to fetch shared task' });
  }
});



app.listen(PORT, () => {
    mongoose.connect(process.env.MONGODB_URL)
    .then(() => console.log('Server is running :)'))
    .catch((error) => console.log(error))
  })