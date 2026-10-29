'use client';

import { useEffect } from 'react';
import { isTauriRuntime } from '@/lib/tauriBridge';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

type RemoteInvoke = {
  requestId: string;
  command: string;
  args: Record<string, unknown>;
};

export default function RemoteInvokeBridge() {
  useEffect(() => {
    if (!isTauriRuntime()) return;

    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<RemoteInvoke>('remote-ui-invoke', async ({ payload }) => {
      try {
        const result = await invoke(payload.command, payload.args);
        await invoke('remote_ui_reply', {
          reply: { requestId: payload.requestId, success: true, result },
        });
      } catch (error) {
        await invoke('remote_ui_reply', {
          reply: {
            requestId: payload.requestId,
            success: false,
            error: error instanceof Error ? error.message : String(error),
          },
        }).catch((replyError) => {
          console.error('Could not return remote command result:', replyError);
        });
      }
    })
      .then((stopListening) => {
        if (disposed) stopListening();
        else unlisten = stopListening;
      })
      .catch((error) => console.error('Remote Meetily bridge failed to start:', error));

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  return null;
}
