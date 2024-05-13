require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3005;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");
var ObjectId = require("mongodb").ObjectId;

const userCollection = database.db(mongodb_database).collection("users");

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(express.static(__dirname + "/public"));

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

function isAdmin(req) {
  if (req.session.user_type == "admin") {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("error", { error: "Not Authorized" });
    return;
  } else {
    next();
  }
}

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.render("home");
  } else {
    res.render("loggedin", { user: { username: req.session.username } });
  }
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signupSubmit", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;
  var email = req.body.email;

  //validation
  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password });

  if (validationResult.error != null) {
    console.log(validationResult.error);

    res.render("signupSubmit", {
      errormsg: validationResult.error.details[0].message,
    });
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  const user = await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
  });
  console.log("Inserted user", user);
  req.session.id = user._id;
  req.session.authenticated = true;
  req.session.username = username;
  req.session.email = email;
  req.session.user_type = "user";
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

app.get("/members", (req, res) => {
  const ran = Math.floor(Math.random() * 3) + 1;
  if (!req.session.authenticated) {
    res.redirect("/");
  }

  res.render("members", {
    user: { username: req.session.username },
    // imgsrc: `/${ran}.gif`,
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
  });

  const validationResult = schema.validate({ email });

  if (validationResult.error != null) {
    console.log(validationResult.error);

    res.render("loggingin", {
      errormsg: validationResult.error.details[0].message,
    });

    return;
  }

  //Query through all user that match the email
  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, username: 1, password: 1, _id: 1, user_type: 1 })
    .toArray();

  console.log(result);
  //compare input password vs database harshed password
  if (
    result.length == 1 &&
    (await bcrypt.compare(password, result[0].password))
  ) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session._id = result[0]._id;
    req.session.email = email;
    req.session.username = result[0].username;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/");
    return;
  } else {
    res.send(
      'Invalid email/password combination.<br/><a href="/login">Try again</a>'
    );
  }
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection
    .find()
    .project({ username: 1, _id: 1, user_type: 1 })
    .toArray();

  res.render("admin", { users: result });
});

app.get("/user", sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection
    .find()
    .project({ username: 1, _id: 1, user_type: 1 })
    .toArray();
  const id = result.user();
  res.redirect("/promote/:");
});

app.post("/promote/:id", async (req, res) => {
  await userCollection.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: { user_type: "admin" } }
  );
  console.log(req.session);
  if (req.session._id === req.params.id) {
    req.session.user_type = "admin";
  }
  res.redirect("/admin");
});

app.post("/demote/:id", async (req, res) => {
  await userCollection.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: { user_type: "user" } }
  );
  if (req.session._id === req.params.id) {
    req.session.user_type = "user";
  }
  res.redirect("/admin");
});

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
