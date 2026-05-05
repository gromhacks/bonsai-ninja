import { verifyToken, runAdminCommand } from "./auth_service";

interface UserInfo {
  id: string | null;
  token: string;
}

export function getUser(token: string): UserInfo {
  const userId = verifyToken(token);
  return { id: userId, token: token };
}

export function updateUser(token: string, action: string): string | null {
  const userId = verifyToken(token);
  if (userId) {
    runAdminCommand(userId, action);
  }
  return userId;
}
