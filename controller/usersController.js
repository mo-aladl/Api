const User = require("../models/User");

const getAllUsers = async (req, res) => {
  const users = await User.find().select("-password").lean().exec();

  if (!users.length) {
    return res.status(400).json({message: "No users found"})
};

  return res.status(200).json(users);

}
module.exports = {
  getAllUsers,
}
