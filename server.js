const cors = require('cors');
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
require('dotenv').config(); 

app.use(cors());
app.use(express.json());

const users = [];

app.get('/users', (req, res) => {
    res.json(users);
});

app.post('/users', async (req, res) => {
try {
    // 1. Check if a user with this email already exists
    const existingUser = users.find(user => user.email === req.body.email);
    if (existingUser) {
        return res.status(400).send('Entity already exist');
    }
    // 2. If not, proceed with hashing and saving
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { 
            firstname: req.body.firstname, 
            lastname: req.body.lastname,
            email: req.body.email, 
            password: hashedPassword
        }
        users.push(user);
        res.status(201).send('Entity created successfully')
    } catch {
        res.status(500).send()
    }
});

app.post('/users/login', async (req,res) => {
    const user = users.find(user => user.email === req.body.email);
    if (user == null) {
        return res.status(400).send('Entity does not exist');
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            res.send('Success');
        } else {
            res.send('Invalid Password');
        }
    } catch {
        res.status(500).send();
    }
});


// This is just a simple way to store tokens temporarily
const resetTokens = new Map(); 

app.post('/users/forgot-password', (req, res) => {
    const user = users.find(u => u.email === req.body.email);

    if (!user) {
        // For security, some people prefer saying "Check your email" 
        // even if the user doesn't exist to prevent "email fishing."
        return res.status(404).send('Entity does not exist');
    }

    // Generate a simple token (in production, use a library like 'crypto')
    const token = Math.random().toString(36).substring(2, 15);
    
    // Store the token linked to the user's email (valid for 1 hour, for example)
    resetTokens.set(token, user.email);


    // In a real app, you'd send an email here with the token
    res.status(200).send({ message: 'Reset token generated', token: token });
});



app.post('/users/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    // 1. Check if the token is valid
    const userEmail = resetTokens.get(token);

    if (!userEmail) {
        return res.status(400).send('Invalid or expired token');
    }

    try {
        // 2. Find the user in your array
        const userIndex = users.findIndex(u => u.email === userEmail);

        if (userIndex === -1) {
            return res.status(404).send('Entity no longer exists');
        }

        // 3. Hash the new password and update the "database"
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        users[userIndex].password = hashedNewPassword;

        // 4. Delete the token so it can't be used again
        resetTokens.delete(token);

        res.status(200).send('Password updated successfully');
    } catch {
        res.status(500).send('Error resetting password');
    }
});


   
app.listen(3000, () => console.log('Server is running ✅'));


