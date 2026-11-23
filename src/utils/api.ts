import apiFetch from '@wordpress/api-fetch';

export const apiRequest = async (options: { path: string; method?: string; data?: any }) => {
  const root = (window as any).webcareScannerSettings?.root;
  const nonce = (window as any).webcareScannerSettings?.nonce;

  if (root) {
    const cleanRoot = root.replace(/\/$/, '');
    const rawSubPath = (options.path || '').replace(/^\/?webcare-pro-security\/v1/, '');
    const normalizedSubPath = rawSubPath.startsWith('/') ? rawSubPath : `/${rawSubPath}`;
    
    // Correctly split path from query string so plain permalinks use & instead of duplicate ?
    const [pathPart, queryPart] = normalizedSubPath.split('?');
    
    let url: string;
    if (cleanRoot.includes('?')) {
      url = `${cleanRoot}${pathPart}`;
      if (queryPart) {
        url += (url.includes('?') ? '&' : '?') + queryPart;
      }
    } else {
      url = `${cleanRoot}${pathPart}`;
      if (queryPart) {
        url += `?${queryPart}`;
      }
    }

    return apiFetch({
      url,
      method: options.method || 'GET',
      data: options.data,
      headers: nonce ? { 'X-WP-Nonce': nonce } : undefined,
    });
  }

  const rawPath = options.path || '';
  const cleanSubPath = rawPath.replace(/^\/?webcare-pro-security\/v1/, '');
  const namespacedPath = rawPath.startsWith('/webcare-pro-security/v1')
    ? rawPath
    : `/webcare-pro-security/v1${cleanSubPath.startsWith('/') ? cleanSubPath : `/${cleanSubPath}`}`;
  return apiFetch({
    ...options,
    path: namespacedPath,
    headers: nonce ? { 'X-WP-Nonce': nonce, ...(options as any).headers } : (options as any).headers,
  });
};
