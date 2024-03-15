require("dotenv").config();
const express = require("express");
const app = express();
const PORT = process.env.PORT || 5000;
const path = require("path");

const connectDB = require("./config/dbConn");
const corsOptions = require("./config/corsOptionns");
const mongoose = require("mongoose");
const cors = require("cors");
const cookieParser = require("cookie-parser");

connectDB();

app.use(cors(corsOptions));
app.use(cookieParser());
app.use(express.json());
app.use("/", express.static(path.join(__dirname, "public")));

app.use("/", require("./routes/root"));
app.use("/auth", require("./routes/authRoutess"));
app.use("/users", require("./routes/usersRoutess"));


app.all("*", (req, res) => {
  res.status(404);
  if (req.accepts("html")) {
    res.sendFile(path.join(__dirname, "views", "404.html"));
  } else if (req.accepts("json")) {
    res.json({ message: "404 Not Found" });
  } else {
    res.type("txt").send("404 Not Found");
  }
});





mongoose.connection.once("open", () => {
  console.log("Connect to MongooDB server");
  app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`);
  });
});

mongoose.connection.on("error", (err) => {
  console.log(err);
});
