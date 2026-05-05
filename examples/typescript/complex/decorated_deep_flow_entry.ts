import { dfcMain } from "./deep_flow_chain";

function Audited(
  _target: object,
  _propertyKey: string,
  descriptor: PropertyDescriptor,
): PropertyDescriptor {
  return descriptor;
}

export class DfcDecoratedEntry {
  @Audited
  async runDecorated(): Promise<void> {
    await dfcMain();
  }
}
