// app.js
const express = require('express');
const http = require('http');
const path = require('path');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const app = express();
const server = http.createServer(app);
const io = socketIo(server);
app.set('view engine', 'ejs');


const mongoUri = process.env.MONGO_URL;
mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.error('Error connecting to MongoDB:', error.message);
});

// MongoDB user schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String
});
const User = mongoose.model('User', userSchema);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to check if the user is logged in
const requireLogin = (req, res, next) => {
    if (req.session.user || req.session.admin) {
        next(); // Continue to the next middleware or route handler
    } else {
        res.redirect('/login'); // Redirect to login page if not logged in
    }
};

const requireAdmin = (req, res, next) => {
    if (req.session.admin) {
        next(); 
    } else {
        res.redirect('/login');
    }
};

// Serve admin page
app.get('/admin', requireAdmin, (req, res) => {
    res.render('admin'); // Render admin.ejs
});

const adminCredentials = {
    username: 'admin',
    password: 'admin'
};

app.get('/signup', (req, res) => {
    res.render('signup'); // Render signup.ejs
});

// Handle signup
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.redirect('/login');
});

// Serve login page
app.get('/login', (req, res) => {
    res.render('login'); // Render login.ejs
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (username === adminCredentials.username && password === adminCredentials.password) {
        req.session.admin = true;
        console.log('Admin logged in:', req.session.admin); // Add this line for debugging
        res.redirect('/admin');
        return;
    }

    // Check if the credentials are for a regular user
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.user = user;
        console.log('User logged in:', req.session.user); // Add this line for debugging
        res.redirect('/');
    } else {
        res.redirect('/login');
    }
});

app.get('/', async (req, res) => {
    if (req.session.user || req.session.admin) {
        let username;
        if (req.session.user) {
            try {
                const user = await User.findById(req.session.user._id);
                if (user) {
                    username = user.username;
                }
            } catch (error) {
                console.error('Error fetching user data:', error);
                return res.status(500).send('Internal Server Error');
            }
        } else {
            username = "Admin";
        }
        res.render('index', { username, user: req.session.user }); // Render index.ejs with username and user
    } else {
        res.redirect('/login');
    }
});

io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('stream', (data) => {
        const { userId, username, image } = data;
        socket.broadcast.emit('stream', { userId, username, image });
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected');
    });
});
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error occurred while logging out.');
        }
        res.redirect('/login');
    });
});
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
