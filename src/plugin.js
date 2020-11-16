const aws = require('aws-amplify');

function validateArg(name, value) {
  if (!value) {
    throw new Error(name + ' is required')
  }
}

function buildCookie(user) {
  const keyPrefix = user.keyPrefix;
  const userKeyPrefix = user.keyPrefix + '.' + user.username;

  const lastAuthUser = keyPrefix + '.LastAuthUser=' + user.username;
  const idToken =
    userKeyPrefix + '.idToken=' + user.signInUserSession.idToken.jwtToken;
  const accessToken =
    userKeyPrefix +
    '.accessToken=' +
    user.signInUserSession.accessToken.jwtToken;

  return lastAuthUser + '; ' + idToken + '; ' + accessToken;
}

async function runAwsAmplifyAuthCookie(context, Username, Password, Region, UserPoolId, WebClientId) {
  validateArg('Username', Username);
  validateArg('Password', Password);
  validateArg('Region', Region);
  validateArg('UserPoolId', UserPoolId);
  validateArg('WebClientId', WebClientId);

  // Check for existing valid cookie first
  const storeKey = [Username, Password, Region, UserPoolId, WebClientId].join(';');
  const storedCookie = await context.store.getItem(storeKey);
  if (storedCookie && storedCookie !== 'error') {
    return storedCookie;
  }

  aws.Amplify.configure({
    Auth: {
      region: Region,
      userPoolId: UserPoolId,
      userPoolWebClientId: WebClientId
    },
  });

  try {
    const user = await aws.Auth.signIn(Username, Password);
    const cookie = buildCookie(user);
    await context.store.setItem(storeKey, cookie);
    return cookie;
  } catch (e) {
    await context.store.setItem(storeKey, 'error');
    return e.message;
  }
}

module.exports.templateTags = [
  {
    run: runAwsAmplifyAuthCookie,
    name: 'AwsAmplifyAuthCookie',
    displayName: 'AWS Amplify Auth Cookie',
    description: 'Insomnia plugin to create an auth cookie for AWS Amplify',
    args: [
      {
        displayName: 'Username',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
      {
        displayName: 'Password',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
      {
        displayName: 'Region',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
      {
        displayName: 'UserPoolId',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
      {
        displayName: 'WebClientId',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
    ],
  },
];
