import { isTauriRuntime } from './tauriBridge';

type TauriEvent<T> = { id: number; event: string; payload: T };
type EventHandler<T> = (event: TauriEvent<T>) => void;

export async function emit<T>(eventName: string, payload: T): Promise<void> {
  if (isTauriRuntime()) {
    return window.__TAURI__!.event.emit(eventName, payload);
  }

  const response = await fetch('/api/emit', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: eventName, payload }),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { error?: string } | null;
    throw new Error(body?.error || `Remote Meetily event failed (${response.status})`);
  }
}

export async function listen<T>(
  eventName: string,
  handler: EventHandler<T>,
  options?: { target?: string },
): Promise<() => void> {
  if (isTauriRuntime()) {
    return window.__TAURI__!.event.listen(eventName, handler, options);
  }

  if (eventName.startsWith('tauri://')) {
    return () => {};
  }

  const source = new EventSource(`/api/events?name=${encodeURIComponent(eventName)}`);
  source.onmessage = (message) => {
    try {
      handler(JSON.parse(message.data) as TauriEvent<T>);
    } catch (error) {
      console.error(`Invalid remote event '${eventName}':`, error);
    }
  };
  return () => source.close();
}
