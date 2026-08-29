const { verifyToken, runAdminCommand } = require("./auth_service");

function getUser(token) {
  const userId = verifyToken(token);
  return { id: userId, token: token };
}

function updateUser(token, action) {
  const userId = verifyToken(token);
  if (userId) {
    runAdminCommand(userId, action);
  }
  return userId;
}

module.exports = { getUser, updateUser };
