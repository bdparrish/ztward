/**
 * ZTDF React Context
 * Provides ZTDF client instance to the application
 */

import { createContext, useContext } from "react";
import type { KeyMetadata, ZtdfClient } from "@ztward/sdk";

export interface DecryptedFile {
  content: Uint8Array;
  filename?: string;
  contentType?: string;
  accessGranted: boolean;
  accessReason: string;
  appliedRules: string[];
  timestamp: Date;
}

export interface ZtdfContextValue {
  client: ZtdfClient | null;
  isInitialized: boolean;
  isInitializing: boolean;
  error: string | null;
  keyMetadata: KeyMetadata | null;
  initialize: () => Promise<void>;
  decryptFile: (file: File) => Promise<DecryptedFile>;
}

export const ZtdfContext = createContext<ZtdfContextValue | undefined>(undefined);

export function useZtdf(): ZtdfContextValue {
  const context = useContext(ZtdfContext);
  if (!context) {
    throw new Error("useZtdf must be used within a ZtdfProvider");
  }
  return context;
}
