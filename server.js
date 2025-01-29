const { MongoClient } = require("mongodb");
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(cookieParser());

const url = "mongodb://myUserAdmin:abc123@localhost:27017/admin";
const client = new MongoClient(url, {
	useNewUrlParser: true,
	useUnifiedTopology: true
});

const dbName = "myDatabase";

async function connectToDatabase() {
	try {
		await client.connect();
		console.log("Connected successfully to server");
		return client.db(dbName);
	} catch (error) {
		console.error("Error connecting to the database", error);
		throw error;
	}
}

// User Registration Route
app.post("/register", async (req, res) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res
			.status(400)
			.json({ success: false, message: "Username and password are required" });
	}

	try {
		const db = await connectToDatabase();
		const usersCollection = db.collection("user");

		// Check if user already exists
		const existingUser = await usersCollection.findOne({ username });
		if (existingUser) {
			return res
				.status(409)
				.json({ success: false, message: "Username already exists" });
		}

		// Hash the password before saving
		const saltRounds = 10;
		const hashedPassword = await bcrypt.hash(password, saltRounds);

		// Save the user to the database
		await usersCollection.insertOne({ username, password: hashedPassword });

		res
			.status(201)
			.json({ success: true, message: "User registered successfully" });
	} catch (error) {
		console.error("Registration error:", error);
		res.status(500).json({ success: false, message: "Internal server error" });
	}
});

// User Login Route
app.post("/login", async (req, res) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return res
			.status(400)
			.json({ success: false, message: "Username and password are required" });
	}

	try {
		const db = await connectToDatabase();
		const usersCollection = db.collection("user");

		// Find the user in the database
		const user = await usersCollection.findOne({ username });
		if (!user) {
			return res
				.status(401)
				.json({ success: false, message: "Invalid credentials" });
		}

		// Compare the provided password with the hashed password in the database
		const isPasswordValid = await bcrypt.compare(password, user.password);
		if (!isPasswordValid) {
			return res
				.status(401)
				.json({ success: false, message: "Invalid credentials" });
		}

		// Set a cookie upon successful login
		res.cookie("verified", username, {
			maxAge: 2 * 60 * 60 * 1000, // 2 hours in milliseconds
			httpOnly: true,
			secure: process.env.NODE_ENV === "production" // Use secure in production
		});

		res.json({ success: true, message: "Login successful" });
	} catch (error) {
		console.error("Login error:", error);
		res.status(500).json({ success: false, message: "Internal server error" });
	}
});

const port = 3000;
app.listen(port, () => {
	console.log(`Server running on port ${port}`);
});
