export function getHandlerConfig() {
  return {
    scepChallengePasswordParameterName:
      process.env.SCEP_CHALLENGE_PASSWORD_PARAMETER_NAME ??
      '/prod/aws-ca/scep/challenge-password',
  };
}
