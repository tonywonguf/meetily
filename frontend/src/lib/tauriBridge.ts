type InvokeOptions = { headers?: Record<string, string> };

declare global {
  interface Window {
    __TAURI__?: {
      core: {
        invoke<T>(command: string, args?: Record<string, unknown>, options?: InvokeOptions): Promise<T>;
      };
      event: {
        emit<T>(event: string, payload?: T): Promise<void>;
        listen<T>(
          event: string,
          handler: (event: { id: number; event: string; payload: T }) => void,
          options?: { target?: string },
        ): Promise<() => void>;
      };
    };
  }
}

export function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && typeof window.__TAURI__?.core?.invoke === 'function';
}

export class Resource {
  constructor(readonly rid: number) {}

  async close(): Promise<void> {
    await invoke('plugin:resources|close', { rid: this.rid });
  }
}

export class Channel<T = unknown> {
  private readonly native: {
    id: number;
    onmessage: ((message: T) => void) | undefined;
    toJSON(): string;
  };

  constructor(onmessage?: (message: T) => void) {
    if (!isTauriRuntime()) throw new Error('Tauri channels are unavailable in a browser');
    const NativeChannel = (window.__TAURI__!.core as unknown as {
      Channel: new (handler?: (message: T) => void) => Channel<T>['native'];
    }).Channel;
    this.native = new NativeChannel(onmessage);
  }

  get id(): number {
    return this.native.id;
  }

  get onmessage(): ((message: T) => void) | undefined {
    return this.native.onmessage;
  }

  set onmessage(handler: ((message: T) => void) | undefined) {
    this.native.onmessage = handler;
  }

  toJSON(): string {
    return this.native.toJSON();
  }
}

export async function appDataDir(): Promise<string> {
  if (isTauriRuntime()) {
    const tauri = window.__TAURI__ as unknown as { path: { appDataDir(): Promise<string> } };
    return tauri.path.appDataDir();
  }
  return invoke<string>('get_database_directory');
}

export async function invoke<T>(
  command: string,
  args?: Record<string, unknown>,
  options?: InvokeOptions,
): Promise<T> {
  if (isTauriRuntime()) {
    return window.__TAURI__!.core.invoke<T>(command, args, options);
  }

  const response = await fetch('/api/invoke', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...options?.headers },
    body: JSON.stringify({ command, args: args ?? {} }),
  });
  const body = await response.json().catch(() => null) as { error?: string } | T | null;
  if (!response.ok) {
    const message = body && typeof body === 'object' && 'error' in body
      ? body.error
      : `Remote Meetily request failed (${response.status})`;
    throw new Error(message || `Remote Meetily request failed (${response.status})`);
  }
  return body as T;
}
