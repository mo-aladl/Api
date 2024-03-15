const User = require("../models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const register = async (req, res) => {
  const { fristName, lastName, email, password } = req.body;
  if (!fristName || !lastName || !email || !password) {
    return res.status(404).json({ message: "All required fields" });
  }
  const foundUser = await User.findOne({ email }).exec();

  if (foundUser) {
    return res.status(401).json({ message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  const newUser = new User({
    fristName,
    lastName,
    email,
    password: hashedPassword,
  });
  const savedUser = await newUser.save();

  const accessToken = jwt.sign(
    { _id: savedUser._id },
    process.env.JWT_SECRET_ACCESS_TOKEN,
    { expiresIn: "15m" }
  );

  const refreshToken = jwt.sign(
    { _id: savedUser._id },
    process.env.JWT_SECRET_REFRESH_TOKEN,
    { expiresIn: "30d" }
  );

  res.cookie("jwt", refreshToken, {
    httpOnly: true,
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    sameSite: "None",
    secure: true,
  });

  res.status(201).json({
    message: "User created successfully",
    accessToken,
    email: savedUser.email,
    fristName: savedUser.fristName,
    lastName: savedUser.lastName,
  });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(404).json({ message: "All required fields" });
  }
  const foundUser = await User.findOne({ email }).exec();

  if (!foundUser) {
    return res.status(401).json({ message: "User does not exist " });
  }

  const matchPassword = await bcrypt.compare(password, foundUser.password);
  if (!matchPassword) {
    return res.status(401).json({ message: "Worng Password" });
  }
  const accessToken = jwt.sign(
    { _id: foundUser._id },
    process.env.JWT_SECRET_ACCESS_TOKEN,
    { expiresIn: "15m" }
  );
  const refreshToken = jwt.sign(
    { _id: foundUser._id },
    process.env.JWT_SECRET_REFRESH_TOKEN,
    { expiresIn: "30d" }
  );
  res.cookie("jwt", refreshToken, {
    httpOnly: true,
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    sameSite: "None",
    secure: true,
  });

  res.status(201).json({
    message: "User logged in successfully",
    accessToken,
    email: foundUser.email,
    fristName: foundUser.fristName,
    lastName: foundUser.lastName,
  });
};

const refrsh = async (req, res) => {
  const cookie = req.cookies;
  if (!cookie) {
    return res.status(404).json({ message: "All required fields" });
  }

  const refreshToken = req.cookies.jwt;
  if (!refreshToken) {
    return res.status(404).json({ message: "All required fields" });
  }

  jwt.verify(
    refreshToken,
    process.env.JWT_SECRET_REFRESH_TOKEN,
    async (err, decoded) => {
      if (err) return res.status(403).json({ message: "Forbidden" });

      const foundUser = await User.findById(decoded.foundUser.id).exec();

      if (!foundUser) {
        return res.status(401).json({ message: "User does not exist " });
      }
      const accessToken = jwt.sign(
        { _id: foundUser._id },
        process.env.JWT_SECRET_ACCESS_TOKEN,
        { expiresIn: "15m" }
      );

      res.cookie("jwt", accessToken, {
        httpOnly: true,
        expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        sameSite: "None",
        secure: true,
      });

      res.status(201).json({
        accessToken,
      });
    }
  );
};

const logout = async (req, res) => {
  const cookie = req.cookies;

  if (!cookie?.jwt) return res.status(204);

  res.clearCookie("jwt" , {
    httpOnly: true,
    sameSite: "None",
    secure: true,
  });



  res.status(201).json({
    message: "User logged out successfully",
  });
};

module.exports = { register, login, refrsh, logout };
