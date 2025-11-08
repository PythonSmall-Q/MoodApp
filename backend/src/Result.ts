export class Result<T = any> {
  constructor(
    public success: boolean,
    public message: string,
    public data?: T
  ) {}
}

export function ThrowErrorIfFailed<T = any>(res: Result<T>): T {
  if (!res.success) {
    throw new Error(res.message || "操作失败");
  }
  // If data is undefined, return as any
  return (res.data as unknown) as T;
}
