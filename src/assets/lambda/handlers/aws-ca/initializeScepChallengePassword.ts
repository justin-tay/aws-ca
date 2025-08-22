import crypto from 'crypto';
import { loadParameter } from './ca/loadParameter';
import { saveParameter } from './ca/saveParameter';
import { getHandlerConfig } from './getHandlerConfig';

export async function initializeScepChallengePassword() {
  const scepChallengePasswordParameterName =
    getHandlerConfig().scepChallengePasswordParameterName;
  if (scepChallengePasswordParameterName) {
    const value = await loadParameter(scepChallengePasswordParameterName);
    if (value.Parameter?.Value === ' ') {
      saveParameter(scepChallengePasswordParameterName, crypto.randomUUID());
    }
  }
}
