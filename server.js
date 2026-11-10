const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve index.html as the homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve other static website files and assets
app.use((req, res, next) => {
    const protectedFiles = [
        '/server.js',
        '/package.json',
        '/package-lock.json',
        '/.env'
    ];

    if (protectedFiles.includes(req.path)) {
        return res.sendStatus(404);
    }

    next();
});

app.use(express.static(__dirname, {
    dotfiles: 'deny',
    index: false
}));

// Temporary user storage
const users = [];
const resetTokens = new Map();

// Get all users
app.get('/users', (req, res) => {
    res.json(users);
});

// Register a user
app.post('/users', async (req, res) => {
    try {
        const { firstname, lastname, email, password } = req.body;

        const existingUser = users.find(user => user.email === email);

        if (existingUser) {
            return res.status(400).send('Entity already exist');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = {
            firstname,
            lastname,
            email,
            password: hashedPassword
        };

        users.push(user);

        res.status(201).send('Entity created successfully');

    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// Login
app.post('/users/login', async (req, res) => {
    try {
        const user = users.find(user => user.email === req.body.email);

        if (!user) {
            return res.status(400).send('Entity does not exist');
        }

        const passwordMatches = await bcrypt.compare(
            req.body.password,
            user.password
        );

        if (passwordMatches) {
            return res.send('Success');
        }

        res.status(400).send('Invalid Password');

    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// Forgot password
app.post('/users/forgot-password', (req, res) => {
    const user = users.find(u => u.email === req.body.email);

    if (!user) {
        return res.status(404).send('Entity does not exist');
    }

    const token = Math.random().toString(36).substring(2, 15);

    resetTokens.set(token, user.email);

    res.status(200).json({
        message: 'Reset token generated',
        token
    });
});

// Reset password
app.post('/users/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        const userEmail = resetTokens.get(token);

        if (!userEmail) {
            return res.status(400).send('Invalid or expired token');
        }

        const userIndex = users.findIndex(
            u => u.email === userEmail
        );

        if (userIndex === -1) {
            return res.status(404).send('Entity no longer exists');
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        users[userIndex].password = hashedPassword;

        resetTokens.delete(token);

        res.status(200).send('Password updated successfully');

    } catch (error) {
        console.error(error);
        res.status(500).send('Error resetting password');
    }
});

// Vercel uses the exported Express app
module.exports = app;

// Allow local development
if (require.main === module) {
    const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}
