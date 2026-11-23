/**
 * WebCare Pro Security & Firewall - In-Page Dialog & Popover Utilities
 *
 * Provides asynchronous, promise-based confirm and alert modals that anchor directly
 * near the triggering action button or render in-page without blocking the UI or using
 * native browser alert()/confirm() dialogs.
 *
 * Backed by ToastProvider and ConfirmModalHost.
 *
 * Author: Mir Alamin (WebCare Pro)
 */

import { toast } from '../components/ui/ToastProvider';
import { confirmAction, promptAction, ConfirmModalOptions } from '../components/ui/ConfirmModal';

export interface ConfirmOptions extends ConfirmModalOptions {
  anchorEl?: HTMLElement | null;
}

export interface AlertOptions {
  title?: string;
  message: string;
  variant?: 'info' | 'warning' | 'danger' | 'success';
  anchorEl?: HTMLElement | null;
}

/**
 * Display an elegant in-page confirmation modal.
 */
export const showConfirm = async (
  options: ConfirmOptions | string,
  anchorEl?: HTMLElement | null
): Promise<boolean> => {
  const opts: ConfirmModalOptions =
    typeof options === 'string'
      ? { message: options }
      : { ...options };

  return await confirmAction(opts);
};

/**
 * Display an elegant in-page alert or toast.
 */
export const showAlert = async (
  options: AlertOptions | string,
  title?: string,
  anchorEl?: HTMLElement | null
): Promise<void> => {
  const message = typeof options === 'string' ? options : options.message;
  const variant = typeof options === 'string' ? 'info' : (options.variant || 'info');

  if (variant === 'danger') {
    toast.error(message);
  } else if (variant === 'warning') {
    toast.warning(message);
  } else if (variant === 'success') {
    toast.success(message);
  } else {
    toast.info(message);
  }
};

export { toast, confirmAction, promptAction };
