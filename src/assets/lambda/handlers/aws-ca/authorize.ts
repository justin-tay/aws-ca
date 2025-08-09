import { authenticateUser } from './authenticate';

export async function authorize(authHeader: string) {
  if (!authHeader) {
    throw new Error('Not Authorized');
  }
  if (!authHeader.startsWith('Basic ')) {
    throw new Error('Unsupported Authentication Scheme');
  }
  const encodedString = authHeader.substring(6); // Remove "Basic " prefix
  const decodedString = atob(encodedString);
  const parts = decodedString.split(':');

  if (parts.length === 2) {
    const username = parts[0];
    const password = parts[1];
    return await authenticateUser({ username, password });
  } else {
    throw new Error('Not Authorized');
  }
}
