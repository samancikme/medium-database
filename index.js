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

// JSON fayldan post ma'lumotlarini olish
function getPosts() {
  try {
    const data = fs.readFileSync("./posts.json");
    return JSON.parse(data).posts;
  } catch (error) {
    console.error("Error reading posts.json", error);
    return [];
  }
}

// JSON faylga post ma'lumotlarini yozish
function savePosts(posts) {
  fs.writeFileSync("./posts.json", JSON.stringify({ posts }, null, 2));
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
    return res.status(400).json({ message: "Email allaqachon mavjud" });
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

  res
    .status(201)
    .json({ message: "Foydalanuvchi muvaffaqiyatli ro'yxatdan o'tdi" });
});

// Login endpoint (foydalanuvchilarni autentifikatsiya qilish)
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const users = getUsers();

  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(400).json({ message: "Email yoki parol xato" });
  }

  const isPasswordValid = bcrypt.compareSync(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: "Email yoki parol xato" });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
    expiresIn: "1h",
  });

  res.status(200).json({ message: "Kirish muvaffaqiyatli", token });
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
app.post("/profile", (req, res) => {
  const { fullName, job, image, regDate, age } = req.body;
  const authors = getAuthors();

  // Foydalanuvchini authors.json fayliga qo'shish
  const newAuthor = {
    id: authors.length + 1,
    fullName,
    regDate,
    image,
    job,
    age,
  };

  authors.push(newAuthor);
  saveAuthors(authors);

  res
    .status(201)
    .json({ message: "Profil muvaffaqiyatli yangilandi", author: newAuthor });
});

// Public route: Get posts (hamma uchun ochiq)
app.get("/posts", (req, res) => {
  const posts = getPosts();
  res.json(posts);
});

// Public route: Get authors (hamma uchun ochiq)
app.get("/authors", (req, res) => {
  const authors = getAuthors();
  res.json(authors);
});

// Protected route: Create post (faqat autentifikatsiyadan o'tgan foydalanuvchilar uchun)
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
    createdAt: new Date().setFullYear(),
  };

  posts.push(newPost);
  savePosts(posts);

  res
    .status(201)
    .json({ message: "Post muvaffaqiyatli yaratildi", post: newPost });
});

// Protected route: Get profile (faqat autentifikatsiyadan o'tgan foydalanuvchilar uchun)
app.get("/profile", authenticateToken, (req, res) => {
  const authors = getAuthors();
  const author = authors.find((author) => author.userId === req.user.id);

  if (!author) {
    return res.status(404).json({ message: "Profil topilmadi" });
  }

  res.status(200).json({ message: "Profil muvaffaqiyatli olingan", author });
});

app.listen(port, () => {
  console.log(`Server ${port} portda ishlamoqda`);
});
