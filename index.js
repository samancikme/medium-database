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
function getAuthors() {
  const data = fs.readFileSync("./authors.json");
  return JSON.parse(data).authors;
}

// JSON faylga foydalanuvchi ma'lumotlarini yozish
function saveUsers(authors) {
  fs.writeFileSync("./authors.json", JSON.stringify({ authors }, null, 2));
}

// JSON fayldan post ma'lumotlarini olish
function getPosts() {
  const data = fs.readFileSync("./posts.json");
  return JSON.parse(data).posts;
}

// JSON faylga post ma'lumotlarini yozish
function savePosts(posts) {
  fs.writeFileSync("./posts.json", JSON.stringify({ posts }, null, 2));
}

// Register endpoint
app.post("/register", (req, res) => {
  const { username, email, password , job} = req.body;
  const authors = getAuthors();

  // Email allaqachon mavjudligini tekshirish
  if (authors.some((user) => user.email === email)) {
    return res.status(400).json({ message: "Email already exists" });
  }

  // Parolni hashing qilish
  const hashedPassword = bcrypt.hashSync(password, 10);

  const newUser = {
    id: authors.length + 1,
    username,
    email,
    job,
    password: hashedPassword,
  };

  authors.push(newUser);
  saveUsers(authors);

  res.status(201).json({ message: "User registered successfully" });
});

// Login endpoint
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const authors = getAuthors();

  const user = authors.find((user) => user.email === email);
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

// Middleware for protected routes
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.sendStatus(401);

  jwt.verify(token.split(" ")[1], SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Get posts endpoint (protected)
app.get("/posts", authenticateToken, (req, res) => {
  const posts = getPosts();
  res.json(posts);
});

// Create post endpoint (protected)
// Helper function to create a slug from title
function createSlug(title) {
  return title
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9\-]/g, "");
}

// Create post endpoint (protected)
app.post("/posts", authenticateToken, (req, res) => {
  const { title, content , excerpt , image} = req.body;
  const posts = getPosts();

  // Yangi post uchun slug title dan yaratiladi
  const slug = createSlug(title);

  // Yangi post yaratish
  const newPost = {
    id: posts.length + 1,
    title,
    image,
    excerpt,
    slug, // Slug backend tomonidan yaratiladi
    content,
    authorId: req.user.id,
    createdAt: new Date().toISOString(),
  };

  posts.push(newPost);
  savePosts(posts);

  res.status(201).json({ message: "Post created successfully", post: newPost });
});

// Get users endpoint (protected)
app.get("/authors", authenticateToken, (req, res) => {
  const authors = getAuthors();
  res.json(authors);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
