import { Request, Response } from "express";
import { updateUser } from "./user_service";

function Audited(
  _target: object,
  _propertyKey: string,
  descriptor: PropertyDescriptor,
): PropertyDescriptor {
  return descriptor;
}

export class DecoratedGateway {
  @Audited
  handleRequestDecorated(req: Request, _res: Response): string {
    const token = req.query.token as string;    // source: user input
    const action = req.query.action as string;  // source: user input
    return updateUser(token, action);
  }
}
