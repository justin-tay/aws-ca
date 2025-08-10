import { authenticateUser } from './authenticateUser';

export async function authorize(params: {
  authorizationHeader: string;
  clientId?: string;
}) {
  const { authorizationHeader, clientId } = params;
  if (!authorizationHeader) {
    throw new Error('Not Authorized');
  }
  if (!authorizationHeader.startsWith('Basic ')) {
    throw new Error('Unsupported Authentication Scheme');
  }
  const encodedString = authorizationHeader.substring(6); // Remove "Basic " prefix
  const decodedString = atob(encodedString);
  const parts = decodedString.split(':');

  if (parts.length === 2) {
    const username = parts[0];
    const password = parts[1];
    return await authenticateUser({ username, password, clientId });
  } else {
    throw new Error('Not Authorized');
  }
}
