export class AppError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const badRequest = (code: string, msg: string, details?: unknown) => new AppError(400, code, msg, details);
export const unauthorized = (code: string, msg: string) => new AppError(401, code, msg);
export const forbidden = (code: string, msg: string) => new AppError(403, code, msg);
export const notFound = (code: string, msg: string) => new AppError(404, code, msg);
export const conflict = (code: string, msg: string) => new AppError(409, code, msg);
export const locked = (code: string, msg: string, details?: unknown) => new AppError(423, code, msg, details);
