const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Secret key for JWT
const SECRET_KEY = "your_secret_key";

// JSON fayldan foydalanuvchi ma'lumotlarini olish
function getUsers() {
  const data = fs.readFileSync("./users.json");
  return JSON.parse(data).users;
}

// JSON faylga foydalanuvchi ma'lumotlarini yozish
function saveUsers(users) {
  fs.writeFileSync("./users.json", JSON.stringify({ users }, null, 2));
}

// JSON fayldan author ma'lumotlarini olish
function getAuthors() {
  const data = fs.readFileSync("./authors.json");
  return JSON.parse(data).authors;
}

// JSON faylga author ma'lumotlarini yozish
function saveAuthors(authors) {
  fs.writeFileSync("./authors.json", JSON.stringify({ authors }, null, 2));
}

// Helper function to create a slug from title
function createSlug(title) {
  return title
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9\-]/g, "");
}

// Register endpoint (foydalanuvchilarni 'users.json'ga saqlash)
app.post("/register", (req, res) => {
  const { username, email, password } = req.body;
  const users = getUsers();

  if (users.some((user) => user.email === email)) {
    return res.status(400).json({ message: "Email already exists" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = {
    id: users.length + 1,
    username,
    email,
    password: hashedPassword,
  };

  users.push(newUser);
  saveUsers(users);

  res.status(201).json({ message: "User registered successfully" });
});

// Login endpoint (foydalanuvchilarni autentifikatsiya qilish)
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const users = getUsers();

  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  const isPasswordValid = bcrypt.compareSync(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
    expiresIn: "1h",
  });

  res.status(200).json({ message: "Logged in successfully", token });
});

// Middleware for protected routes (only for authenticated users)
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.sendStatus(401);

  jwt.verify(token.split(" ")[1], SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Foydalanuvchidan profil ma'lumotlarini olish (ismini va ishini so'rash)
app.post("/profile", authenticateToken, (req, res) => {
  const { name, job } = req.body;
  const authors = getAuthors();

  // Foydalanuvchini authors.json fayliga qo'shish
  const newAuthor = {
    id: authors.length + 1,
    userId: req.user.id,
    name,
    job,
  };

  authors.push(newAuthor);
  saveAuthors(authors);

  res
    .status(201)
    .json({ message: "Profile updated successfully", author: newAuthor });
});

// Public route: Get posts (accessible by everyone)
app.get("/posts", (req, res) => {
  const posts = getPosts();
  res.json(posts);
});

// Public route: Get authors (accessible by everyone)
app.get("/authors", (req, res) => {
  const authors = getAuthors();
  res.json(authors);
});

// Protected route: Create post (only for authenticated users)
app.post("/posts", authenticateToken, (req, res) => {
  const { title, content, image, excerpt } = req.body;
  const posts = getPosts();
  const slug = createSlug(title);

  const newPost = {
    id: posts.length + 1,
    title,
    slug,
    content,
    image,
    excerpt,
    authorId: req.user.id,
    createdAt: new Date().toISOString(),
  };

  posts.push(newPost);
  savePosts(posts);

  res.status(201).json({ message: "Post created successfully", post: newPost });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
