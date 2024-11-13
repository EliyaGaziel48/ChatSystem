// index.js

require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const http = require("http");
const socketIo = require("socket.io");
const path = require("path");
const session = require('express-session');
const bcrypt = require('bcrypt');



const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const SALT_ROUNDS = 10; // Number of salt rounds for bcrypt

// Middleware
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your_secret_here', // Change this to a long random string for production
    resave: false,
    saveUninitialized: true
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log("Connected to MongoDB");
}).catch((error) => {
    console.error("MongoDB connection error:", error);
});

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log("Connected to MongoDB");
});

const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    avatar: String,
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const messageSchema = new mongoose.Schema({
    sender: String,
    recipient: String,
    message: String,
    timestamp: { type: Date, default: Date.now }
});

const groupSchema = new mongoose.Schema({
    name: String,
    members: [String],
    messages: [{
        sender: String,
        message: String,
        timestamp: { type: Date, default: Date.now }
    }]
});


const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Group = mongoose.model('Group', groupSchema);

// View groups page
app.get('/view_groups', (req, res) => {
    const userId = req.session.userId;
    if (!userId) {
        return res.redirect('/index.html'); // Redirect to login if session userId is not set
    }

    User.findById(userId)
        .then(user => {
            if (!user) {
                throw new Error("User not found");
            }
            Group.find({ members: user.username })
                .then(groups => {
                    res.render('view_groups', { groups });
                })
                .catch(err => {
                    console.error("Error fetching user groups:", err);
                    res.status(500).send("Internal server error");
                });
        })
        .catch(err => {
            console.error("Error fetching user:", err);
            res.status(500).send("Internal Server Error");
        });
});
// Block user endpoint
app.post("/block_user", async (req, res) => {
    const { username } = req.body;
    const userId = req.session.userId; // Check if userId is correctly set in session

    try {
        // Find the user to block
        const userToBlock = await User.findOne({ username: username });
        if (!userToBlock) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // Check if userId is valid
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ success: false, message: "Invalid user ID" });
        }

        // Find the current user
        const currentUser = await User.findById(userId);
        if (!currentUser) {
            return res.status(404).json({ success: false, message: "Current user not found" });
        }

        // Check if already blocked
        if (currentUser.blockedUsers.includes(userToBlock._id)) {
            return res.status(400).json({ success: false, message: "User already blocked" });
        }

        // Block the user (whether online or offline)
        currentUser.blockedUsers.push(userToBlock._id);
        await currentUser.save();

        res.status(200).json({ success: true, message: "User blocked successfully" });
    } catch (err) {
        console.error("Error blocking user:", err);
        res.status(500).json({ success: false, message: "Internal server error: " + err.message });
    }
});


app.get("/messages/:recipient", async (req, res) => {
    const senderId = req.session.userId;
    const { recipient } = req.params;

    try {
        const messages = await Message.find({
            $or: [
                { sender: recipient, recipient: senderId },
                { sender: senderId, recipient: recipient }
            ]
        }).sort({ timestamp: 1 });

        // Filter out the user's own messages
        const filteredMessages = messages.filter(message => message.sender !== senderId);
        res.json(filteredMessages);
    } catch (err) {
        console.error("Error fetching messages:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Unblock user endpoint
app.post("/unblock_user", async (req, res) => {
    const { username } = req.body;
    const userId = req.session.userId; // Check if userId is correctly set in session

    try {
        // Find the user to unblock
        const userToUnblock = await User.findOne({ username: username });
        if (!userToUnblock) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // Check if userId is valid
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ success: false, message: "Invalid user ID" });
        }

        // Find the current user
        const currentUser = await User.findById(userId);
        if (!currentUser) {
            return res.status(404).json({ success: false, message: "Current user not found" });
        }

        // Check if not blocked
        const blockedIndex = currentUser.blockedUsers.indexOf(userToUnblock._id);
        if (blockedIndex === -1) {
            return res.status(400).json({ success: false, message: "User not blocked" });
        }

        // Unblock the user (whether online or offline)
        currentUser.blockedUsers.splice(blockedIndex, 1);
        await currentUser.save();

        res.status(200).json({ success: true, message: "User unblocked successfully" });
    } catch (err) {
        console.error("Error unblocking user:", err);
        res.status(500).json({ success: false, message: "Internal server error: " + err.message });
    }
});

app.get('/search_users', (req, res) => {
    const { q } = req.query;
    
    // Example: Search users by username (you may adjust the search criteria as needed)
    User.find({ username: { $regex: new RegExp(q, 'i') } })
        .then(users => {
            res.json(users);
        })
        .catch(err => {
            console.error('Error searching users:', err);
            res.status(500).send('Internal Server Error');
        });
});
// Signup endpoint
app.post("/sign_up", (req, res) => {
    const { username, email, password } = req.body;

    // Check if username or email already exists
    User.findOne({ $or: [{ username: username }, { email: email }] })
        .then((existingUser) => {
            if (existingUser) {
                console.log("Username or email already exists");
                return res.redirect('/index.html?signup=failed');
            } else {
                // Hash the password before saving
                bcrypt.hash(password, SALT_ROUNDS, (err, hashedPassword) => {
                    if (err) {
                        console.error("Error hashing password:", err);
                        return res.status(500).send("Internal server error");
                    }

                    const newUser = new User({
                        username: username,
                        email: email,
                        password: hashedPassword
                    });

                    newUser.save()
                        .then(() => {
                            console.log("User registered successfully");
                            req.session.userId = newUser._id;
                            res.redirect('/chat.html');
                        })
                        .catch((err) => {
                            console.error("Error registering user:", err);
                            return res.redirect('/index.html?signup=failed');
                        });
                });
            }
        })
        .catch((err) => {
            console.error("Error checking existing user:", err);
            return res.status(500).send("Internal server error");
        });
});

// Login endpoint
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    User.findOne({ username: username })
        .then((user) => {
            if (!user) {
                console.log("User not found");
                return res.redirect('/index.html?login=failed');
            }

            // Compare the hashed password
            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    console.error("Error comparing passwords:", err);
                    return res.status(500).send("Internal server error");
                }

                if (!result) {
                    console.log("Incorrect password");
                    return res.redirect('/index.html?login=failed');
                }

                req.session.userId = user._id;
                res.redirect('/chat.html');
            });
        })
        .catch((err) => {
            console.error("Error finding user:", err);
            res.status(500).send("Internal server error");
        });
});

// Create group page
app.get('/create_group', (req, res) => {
    const userId = req.session.userId;
    if (!userId) {
        return res.redirect('/index.html'); // Redirect to login if session userId is not set
    }

    User.findById(userId)
        .then(user => {
            if (!user) {
                throw new Error("User not found");
            }
            res.render('create_group');
        })
        .catch(err => {
            console.error("Error fetching user:", err);
            res.status(500).send("Internal Server Error");
        });
});

// Create group endpoint
app.post("/create_group", (req, res) => {
    const { groupName, groupMembers } = req.body;
    const members = groupMembers.split(',').map(member => member.trim());

    const newGroup = new Group({ name: groupName, members });

    newGroup.save()
        .then(() => {
            console.log("Group created successfully");
            res.redirect('/chat.html?group_creation=success');
        })
        .catch((err) => {
            console.error("Error creating group:", err);
            res.redirect('/chat.html?group_creation=failed');
        });
});

app.get('/group_messages/:groupId', async (req, res) => {
    const { groupId } = req.params;

    try {
        const group = await Group.findById(groupId);
        if (!group) {
            return res.status(404).json({ message: "Group not found" });
        }

        res.json(group.messages);
    } catch (err) {
        console.error("Error fetching group messages:", err);
        res.status(500).send("Internal Server Error");
    }
});
app.post('/group_message', async (req, res) => {
    const { groupId, message } = req.body;
    const senderId = req.session.userId;

    try {
        const sender = await User.findById(senderId);
        if (!sender) {
            return res.status(404).json({ message: "Sender not found" });
        }

        const group = await Group.findById(groupId);
        if (!group) {
            return res.status(404).json({ message: "Group not found" });
        }

        const newMessage = {
            sender: sender.username,
            message,
            timestamp: new Date()
        };

        group.messages.push(newMessage);
        await group.save();

        // Emit the message to all group members via socket.io
        group.members.forEach(member => {
            io.to(member).emit("newGroupMessage", { groupId, message: newMessage });
        });

        res.json({ message: "Message sent successfully" });
    } catch (err) {
        console.error("Error sending group message:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Fetch group messages endpoint
app.get("/group_messages", async (req, res) => {
    const groupName = req.query.group;

    try {
        const group = await Group.findOne({ name: groupName });
        if (!group) {
            return res.status(404).send("Group not found");
        }

        res.json(group.messages);
    } catch (err) {
        console.error("Error fetching group messages:", err);
        res.status(500).send("Internal server error");
    }
});

// Fetch user's groups endpoint
app.get("/user_groups", (req, res) => {
    const userId = req.session.userId;

    User.findById(userId)
        .then(user => {
            if (!user) {
                throw new Error("User not found");
            }
            Group.find({ members: user.username })
                .then(groups => {
                    res.json(groups);
                })
                .catch(err => {
                    console.error("Error fetching user groups:", err);
                    res.status(500).send("Internal server error");
                });
        })
        .catch(err => {
            console.error("Error fetching user:", err);
            res.status(500).send("Internal Server Error");
        });
});

// Chat page route
app.get('/chat.html', (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.redirect('/index.html'); // Redirect to login if session userId is not set
    }

    User.findById(userId)
        .then(user => {
            if (!user) {
                throw new Error("User not found");
            }
            const username = user.username;

            // Replace 'groupName' with your logic to fetch or pass the group name
            const groupName = "YourGroup"; // Replace with your actual logic to fetch group name

            res.render('chat', { username, groupName });
        })
        .catch(err => {
            console.error("Error fetching user:", err);
            res.status(500).send("Internal Server Error");
        });
});

// Homepage route
app.get("/", (req, res) => {
    res.redirect('/index.html');
});

// Socket.io connections
const users = {};

io.on('connection', (socket) => {
    console.log('a user connected');

    socket.on('setUsername', async (username) => {
        socket.username = username;
        users[username] = socket;
        console.log(`Username set to ${username}`);

        try {
            const messages = await Message.find({ $or: [{ sender: username }, { recipient: username }] })
                .sort('timestamp')
                .exec();

            messages.forEach((message) => {
                socket.emit('message', { username: message.sender, message: message.message });
            });
        } catch (err) {
            console.error("Error fetching messages:", err);
        }
    });

    socket.on('joinGroup', (groupName) => {
        socket.join(groupName);
        console.log(`${socket.username} joined group ${groupName}`);
    });

    socket.on('groupMessage', async (data) => {
        const { groupName, message } = data;
        try {
            const newMessage = new Message({ sender: socket.username, recipient: groupName, message });
            await newMessage.save();
    
            io.to(groupName).emit('groupMessage', { username: socket.username, message });
    
            console.log(`Message sent to group ${groupName} by ${socket.username}: ${message}`);
        } catch (err) {
            console.error("Error sending group message:", err);
        }
    });

    // Private message endpoint with blocking validation
    app.post("/private_message", async (req, res) => {
        const { recipient, message } = req.body;
        const senderId = req.session.userId; // Assuming sender's user ID is stored in session

        try {
            // Find sender and recipient users
            const sender = await User.findById(senderId);
            const recipientUser = await User.findOne({ username: recipient });

            if (!sender || !recipientUser) {
                return res.status(404).json({ success: false, message: "User not found" });
            }

            // Check if recipient has blocked the sender
            if (recipientUser.blockedUsers.includes(sender._id)) {
                return res.status(403).json({ success: false, message: "Recipient has blocked the sender" });
            }

            // Save message to database and emit to recipient if online
            const newMessage = new Message({ sender: sender.username, recipient, message });
            await newMessage.save();

            // Emit message to recipient if online
            if (users[recipient]) {
                users[recipient].emit('message', { username: sender.username, message });
            }

            res.status(200).json({ success: true, message: "Message sent successfully" });
        } catch (err) {
            console.error("Error sending private message:", err);
            res.status(500).json({ success: false, message: "Internal server error" });
        }
    });

    socket.on('disconnect', () => {
        console.log('user disconnected');
        delete users[socket.username];
    });
});

server.listen(3000, () => {
    console.log("Server is running on port 3000");
});
