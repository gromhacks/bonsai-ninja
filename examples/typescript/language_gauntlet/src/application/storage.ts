// Re-export through a typed wrapper rather than a bare barrel so the callgraph
// has a real cross-directory function hop to resolve.
import { persist as persistRepository } from "../domain/repository";

export async function persist<T extends { cmd: string }>(data: T): Promise<unknown> {
  return persistRepository(data);
}
