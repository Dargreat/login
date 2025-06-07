require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set true for HTTPS
}));

// Database Connection
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function connectDB() {
    try {
        await client.connect();
        console.log("Connected to MongoDB");
    } catch (e) {
        console.error(e);
    }
}
connectDB();

// Routes
app.post('/signup', async (req, res) => {
    const { userType, email, password, ...userData } = req.body;
    const db = client.db();
    
    try {
        // Check existing user
        const existingUser = await db.collection('users').findOne({ email });
        if (existingUser) return res.status(400).send('User already exists');

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user document
        const newUser = {
            email,
            password: hashedPassword,
            userType,
            ...userData,
            createdAt: new Date()
        };

        await db.collection('users').insertOne(newUser);
        res.redirect('/login.html');
    } catch (err) {
        res.status(500).send('Error registering user');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const db = client.db();

    try {
        const user = await db.collection('users').findOne({ email });
        if (!user) return res.status(400).send('Invalid credentials');

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send('Invalid credentials');

        // Create session
        req.session.user = {
            id: user._id,
            email: user.email,
            userType: user.userType
        };

        // Redirect based on user type
        if (user.userType === 'user') {
            res.redirect('/user_dashboard.html');
        } else if (user.userType === 'logistics') {
            res.redirect('/logistics_dashboard.html');
        }
    } catch (err) {
        res.status(500).send('Login error');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login.html');
});

// Add this middleware to protect routes
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login.html');
    }
    next();
};

// Add this route to get current user data
app.get('/api/user', requireAuth, async (req, res) => {
    try {
        const db = client.db();
        const user = await db.collection('users').findOne(
            { _id: new ObjectId(req.session.user.id) },
            { projection: { password: 0 } } // Exclude password
        );
        
        if (user) {
            res.json(user);
        } else {
            res.status(404).send('User not found');
        }
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// Protect dashboard routes
app.get('/user_dashboard.html', requireAuth, (req, res) => {
    if (req.session.user.userType !== 'user') {
        return res.redirect('/login.html');
    }
    res.sendFile(__dirname + '/public/user_dashboard.html');
});

app.get('/logistics_dashboard.html', requireAuth, (req, res) => {
    if (req.session.user.userType !== 'logistics') {
        return res.redirect('/login.html');
    }
    res.sendFile(__dirname + '/public/logistics_dashboard.html');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));