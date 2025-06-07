require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { MongoClient, ObjectId } = require('mongodb'); // Added ObjectId

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session middleware with enhanced security
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // Changed to false for GDPR compliance
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Auto HTTPS in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Database Connection
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

let db; // Use single database connection

async function connectDB() {
    try {
        await client.connect();
        db = client.db();
        console.log("Connected to MongoDB");
    } catch (e) {
        console.error("DB connection failed:", e);
        process.exit(1);
    }
}
connectDB();

// User type validation middleware
const validateUserType = (req, res, next) => {
    const validTypes = ['user', 'logistics'];
    if (!validTypes.includes(req.body.userType)) {
        return res.status(400).send('Invalid user type');
    }
    next();
};

// Routes
app.post('/signup', validateUserType, async (req, res) => {
    const { userType, email, password, ...userData } = req.body;
    
    try {
        // Check existing user across all types
        const existingUser = await db.collection('users').findOne({ email });
        if (existingUser) {
            return res.status(400).send('Email already registered');
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create user document with type validation
        const newUser = {
            email,
            password: hashedPassword,
            userType,
            ...userData,
            createdAt: new Date(),
            verified: false // Add verification status
        };

        await db.collection('users').insertOne(newUser);
        res.redirect('/login.html');
    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).send('Error registering user');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await db.collection('users').findOne({ email });
        
        // Combined security message
        if (!user) return res.status(401).send('Invalid email or password');
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).send('Invalid email or password');

        // Verify account type exists
        if (!user.userType || !['user', 'logistics'].includes(user.userType)) {
            return res.status(403).send('Account type invalid');
        }

        // Create session
        req.session.user = {
            id: user._id,
            email: user.email,
            userType: user.userType
        };

        // Redirect based on verified user type
        res.redirect(`/${user.userType}_dashboard.html`);
        
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).send('Login error');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error('Session destruction error:', err);
        res.redirect('/login.html');
    });
});

// Route protection middleware
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login.html');
    }
    next();
};

// User data endpoint
app.get('/api/user', requireAuth, async (req, res) => {
    try {
        const user = await db.collection('users').findOne(
            { _id: new ObjectId(req.session.user.id) },
            { projection: { password: 0 } }
        );
        
        user 
            ? res.json(user) 
            : res.status(404).send('User not found');
    } catch (err) {
        console.error("User data error:", err);
        res.status(500).send('Server error');
    }
});

// Protected dashboard routes with type validation
const requireUserType = (type) => (req, res, next) => {
    if (req.session.user?.userType !== type) {
        return res.redirect('/login.html');
    }
    next();
};

app.get('/user_dashboard.html', requireAuth, requireUserType('user'), (req, res) => {
    res.sendFile(__dirname + '/public/user_dashboard.html');
});

app.get('/logistics_dashboard.html', requireAuth, requireUserType('logistics'), (req, res) => {
    res.sendFile(__dirname + '/public/logistics_dashboard.html');
});

// Handle 404 errors
app.use((req, res) => {
    res.status(404).send('Page not found');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
